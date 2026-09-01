// tests/unit/build/check-licenses.test.ts
// TDD unit tests for scripts/check/check-licenses.mjs — Task 7.20 license compliance.
//
// Strategy: test the three exported pure functions without spawning license-checker
// or reading the real .license-allowlist.json. All fixtures are synthetic.
//   - loadAllowlist()    — parses + validates the allowlist JSON shape
//   - classifyLicense()  — core policy decision (allowed / exception / denied)
//   - stripVersion()     — strips @version suffix from package keys
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
// @ts-expect-error — .mjs helper has no type declarations; runtime shape is known.
import {
  classifyLicense,
  stripVersion,
  loadAllowlist,
} from "../../../scripts/check/check-licenses.mjs";

const PNPM_WORKSPACE_URL = new URL("../../../pnpm-workspace.yaml", import.meta.url);

// ---------------------------------------------------------------------------
// Helpers — synthetic allowlists for testing classifyLicense in isolation
// ---------------------------------------------------------------------------

function makeAllowlist(
  overrides: Partial<{
    allowed: string[];
    allowedExpressions: string[];
    exceptions: Record<
      string,
      {
        license?: unknown;
        version?: unknown;
        justification: string;
        risk: string;
        temporary?: boolean;
        owner?: string;
        reviewBy?: string;
        classification?: string;
      }
    >;
  }> = {}
) {
  return {
    allowed: ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "0BSD"],
    allowedExpressions: ["(MIT OR Apache-2.0)", "MIT AND ISC", "MIT*"],
    exceptions: {},
    ...overrides,
  };
}

test("pnpm does not auto-install the unused @lobehub/ui peer subtree", () => {
  const workspace = fs.readFileSync(PNPM_WORKSPACE_URL, "utf8");
  assert.match(
    workspace,
    /^autoInstallPeers:\s*false\s*$/m,
    "pnpm must match npm's legacy-peer-deps posture; @lobehub/ui is not a runtime dependency"
  );
});

// ---------------------------------------------------------------------------
// stripVersion
// ---------------------------------------------------------------------------

test("stripVersion: strips @version from a regular package", () => {
  assert.equal(stripVersion("lodash@4.17.21"), "lodash");
});

test("stripVersion: strips @version from a scoped package", () => {
  assert.equal(stripVersion("@img/sharp-libvips-linux-x64@1.2.4"), "@img/sharp-libvips-linux-x64");
});

test("stripVersion: returns bare name unchanged (no version)", () => {
  assert.equal(stripVersion("lodash"), "lodash");
});

test("stripVersion: handles scoped package without version", () => {
  assert.equal(stripVersion("@scope/pkg"), "@scope/pkg");
});

test("stripVersion: handles nested scope-like name with version", () => {
  assert.equal(
    stripVersion("@aws-sdk/client-bedrock-runtime@3.1063.0"),
    "@aws-sdk/client-bedrock-runtime"
  );
});

// ---------------------------------------------------------------------------
// classifyLicense — allowed
// ---------------------------------------------------------------------------

test("classifyLicense: MIT is allowed", () => {
  const result = classifyLicense("some-pkg@1.0.0", "MIT", makeAllowlist());
  assert.equal(result.status, "allowed");
});

test("classifyLicense: Apache-2.0 is allowed", () => {
  const result = classifyLicense("some-pkg@1.0.0", "Apache-2.0", makeAllowlist());
  assert.equal(result.status, "allowed");
});

test("classifyLicense: ISC is allowed", () => {
  const result = classifyLicense("some-pkg@1.0.0", "ISC", makeAllowlist());
  assert.equal(result.status, "allowed");
});

test("classifyLicense: 0BSD is allowed", () => {
  const result = classifyLicense("some-pkg@1.0.0", "0BSD", makeAllowlist());
  assert.equal(result.status, "allowed");
});

// ---------------------------------------------------------------------------
// classifyLicense — allowed expressions
// ---------------------------------------------------------------------------

test("classifyLicense: (MIT OR Apache-2.0) expression is allowed", () => {
  const result = classifyLicense("some-pkg@1.0.0", "(MIT OR Apache-2.0)", makeAllowlist());
  assert.equal(result.status, "allowed");
});

test("classifyLicense: MIT AND ISC expression is allowed", () => {
  const result = classifyLicense("some-pkg@1.0.0", "MIT AND ISC", makeAllowlist());
  assert.equal(result.status, "allowed");
});

test("classifyLicense: MIT* expression is allowed (e.g. khroma)", () => {
  const result = classifyLicense("khroma@2.1.0", "MIT*", makeAllowlist());
  assert.equal(result.status, "allowed");
});

// ---------------------------------------------------------------------------
// classifyLicense — denied
// ---------------------------------------------------------------------------

test("classifyLicense: GPL-3.0 is denied", () => {
  const result = classifyLicense("gpl-pkg@1.0.0", "GPL-3.0", makeAllowlist());
  assert.equal(result.status, "denied");
  assert.ok(result.reason.includes("GPL-3.0"), `reason should mention license: ${result.reason}`);
});

test("classifyLicense: AGPL-3.0 is denied (strong copyleft)", () => {
  const result = classifyLicense("agpl-pkg@1.0.0", "AGPL-3.0", makeAllowlist());
  assert.equal(result.status, "denied");
});

test("classifyLicense: LGPL-3.0-or-later is denied without exception", () => {
  const result = classifyLicense("lgpl-pkg@1.0.0", "LGPL-3.0-or-later", makeAllowlist());
  assert.equal(result.status, "denied");
});

test("classifyLicense: MPL-2.0 is denied without exception or expression", () => {
  const result = classifyLicense("mpl-pkg@1.0.0", "MPL-2.0", makeAllowlist());
  assert.equal(result.status, "denied");
});

test("classifyLicense: unknown/UNKNOWN license is denied", () => {
  const result = classifyLicense("mystery-pkg@1.0.0", "UNKNOWN", makeAllowlist());
  assert.equal(result.status, "denied");
});

test("classifyLicense: Custom license is denied", () => {
  const result = classifyLicense("custom-pkg@1.0.0", "Custom: LICENSE", makeAllowlist());
  assert.equal(result.status, "denied");
});

// ---------------------------------------------------------------------------
// classifyLicense — exceptions
// ---------------------------------------------------------------------------

test("classifyLicense: LGPL package with registered exception returns 'exception'", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "lgpl-native-pkg": {
        license: "LGPL-3.0-or-later",
        justification: "Dynamically linked native binary; user can replace.",
        risk: "low",
      },
    },
  });
  const result = classifyLicense("lgpl-native-pkg@1.2.3", "LGPL-3.0-or-later", allowlist);
  assert.equal(result.status, "exception");
  assert.ok(
    result.reason.includes("exception"),
    `reason should mention exception: ${result.reason}`
  );
});

test("classifyLicense: scoped package with exception: version is stripped for lookup", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "@img/sharp-libvips-linux-x64": {
        license: "LGPL-3.0-or-later",
        justification: "Prebuilt shared lib.",
        risk: "low",
      },
    },
  });
  const result = classifyLicense(
    "@img/sharp-libvips-linux-x64@1.2.4",
    "LGPL-3.0-or-later",
    allowlist
  );
  assert.equal(result.status, "exception", "scoped exception should be found after version strip");
});

test("classifyLicense: exception does not apply to different package", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "only-this-pkg": {
        license: "GPL-3.0",
        justification: "Special case.",
        risk: "high",
      },
    },
  });
  const result = classifyLicense("other-gpl-pkg@1.0.0", "GPL-3.0", allowlist);
  assert.equal(result.status, "denied", "exception must be per-package, not per-license");
});

test("classifyLicense: exception applies when detected license exactly matches", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "tls-client-node": {
        license: "Custom: LICENSE",
        justification: "Commons Clause + Apache-2.0. TODO: revisar.",
        risk: "medium",
      },
    },
  });
  const result = classifyLicense("tls-client-node@0.2.0", "Custom: LICENSE", allowlist);
  assert.equal(result.status, "exception");
});

test("classifyLicense: version-pinned exception denies a different package version", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "tls-client-node": {
        license: "Custom: LICENSE",
        version: "0.2.0",
        justification: "Only the provenance-audited release is temporarily authorized.",
        risk: "medium",
      },
    },
  });

  const result = classifyLicense("tls-client-node@0.2.1", "Custom: LICENSE", allowlist);
  assert.equal(result.status, "denied");
  assert.match(result.reason, /0\.2\.1/);
  assert.match(result.reason, /0\.2\.0/);
});

test("classifyLicense: version-pinned exception applies to the exact package version", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "tls-client-node": {
        license: "Custom: LICENSE",
        version: "0.2.0",
        justification: "Only the provenance-audited release is temporarily authorized.",
        risk: "medium",
      },
    },
  });

  const result = classifyLicense("tls-client-node@0.2.0", "Custom: LICENSE", allowlist);
  assert.equal(result.status, "exception");
});

test("classifyLicense: version-pinned exception denies an unversioned package key", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "tls-client-node": {
        license: "Custom: LICENSE",
        version: "0.2.0",
        justification: "Only the provenance-audited release is temporarily authorized.",
        risk: "medium",
      },
    },
  });

  const result = classifyLicense("tls-client-node", "Custom: LICENSE", allowlist);
  assert.equal(result.status, "denied");
  assert.match(result.reason, /no version/i);
  assert.match(result.reason, /tls-client-node@0\.2\.0/);
});

test("classifyLicense: version-pinned exception denies malformed package keys", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "tls-client-node": {
        license: "Custom: LICENSE",
        version: "0.2.0",
        justification: "Only the provenance-audited release is temporarily authorized.",
        risk: "medium",
      },
    },
  });

  for (const packageKey of ["tls-client-node@", "tls-client-node@@0.2.0"] as const) {
    const result = classifyLicense(packageKey, "Custom: LICENSE", allowlist);
    assert.equal(result.status, "denied", packageKey);
    assert.match(result.reason, /malformed package key/i);
    assert.match(result.reason, new RegExp(packageKey.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

test("classifyLicense: malformed exception version metadata fails closed", () => {
  for (const declaredVersion of [undefined, "", " 0.2.0", ["0.2.0"]]) {
    const allowlist = makeAllowlist({
      exceptions: {
        "tls-client-node": {
          license: "Custom: LICENSE",
          version: declaredVersion,
          justification: "Malformed version metadata must never authorize a package.",
          risk: "medium",
        },
      },
    });

    const result = classifyLicense("tls-client-node@0.2.0", "Custom: LICENSE", allowlist);
    assert.equal(result.status, "denied");
    assert.match(result.reason, /invalid exception version/i);
    assert.match(result.reason, /tls-client-node/);
  }
});

test("classifyLicense: scoped version-pinned exception uses the version after the package name", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "@scope/native-transport": {
        license: "Custom: LICENSE",
        version: "1.2.3",
        justification: "Only the provenance-audited scoped package release is authorized.",
        risk: "medium",
      },
    },
  });

  const exact = classifyLicense("@scope/native-transport@1.2.3", "Custom: LICENSE", allowlist);
  assert.equal(exact.status, "exception");

  const changed = classifyLicense("@scope/native-transport@1.2.4", "Custom: LICENSE", allowlist);
  assert.equal(changed.status, "denied");
  assert.match(changed.reason, /1\.2\.4/);
  assert.match(changed.reason, /1\.2\.3/);
});

test("classifyLicense: package exception overrides a globally allowed license", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "tls-client-node": {
        license: "Custom: LICENSE",
        justification: "A package-specific review must not be bypassed by the global allowlist.",
        risk: "medium",
      },
    },
  });

  const result = classifyLicense("tls-client-node@0.2.0", "Apache-2.0", allowlist);
  assert.equal(result.status, "denied");
  assert.match(result.reason, /Apache-2\.0/);
  assert.match(result.reason, /Custom: LICENSE/);
  assert.match(result.reason, /match/i);
});

test("classifyLicense: an expired package exception cannot fall through to the global allowlist", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "reviewed-apache-package": {
        license: "Apache-2.0",
        justification: "Temporary package-specific review despite a globally allowed SPDX id.",
        risk: "medium",
        temporary: true,
        owner: "@owner",
        reviewBy: "2026-09-30",
      },
    },
  });

  const result = classifyLicense("reviewed-apache-package@1.0.0", "Apache-2.0", allowlist, {
    now: new Date("2026-10-01T00:00:00.000Z"),
  });
  assert.equal(result.status, "denied");
  assert.match(result.reason, /expired|reviewBy/i);
});

test("classifyLicense: exception denies a GPL license that does not match its declaration", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "tls-client-node": {
        license: "Custom: LICENSE",
        justification: "Exception applies only to the detected custom license.",
        risk: "medium",
      },
    },
  });
  const result = classifyLicense("tls-client-node@0.2.0", "GPL-3.0-only", allowlist);
  assert.equal(result.status, "denied");
  assert.match(result.reason, /GPL-3\.0-only/);
  assert.match(result.reason, /Custom: LICENSE/);
  assert.match(result.reason, /match/i);
});

test("classifyLicense: exception denies UNKNOWN when its declared license is specific", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "tls-client-node": {
        license: "Custom: LICENSE",
        justification: "Exception applies only to the detected custom license.",
        risk: "medium",
      },
    },
  });
  const result = classifyLicense("tls-client-node@0.2.0", "UNKNOWN", allowlist);
  assert.equal(result.status, "denied");
  assert.match(result.reason, /UNKNOWN/);
  assert.match(result.reason, /Custom: LICENSE/);
  assert.match(result.reason, /match/i);
});

test("classifyLicense: exception with a missing or malformed declared license fails closed", () => {
  for (const declaredLicense of [undefined, ["Custom: LICENSE"]]) {
    const allowlist = makeAllowlist({
      exceptions: {
        "tls-client-node": {
          license: declaredLicense,
          justification: "Malformed test exception must never authorize a detected license.",
          risk: "medium",
        },
      },
    });
    const result = classifyLicense("tls-client-node@0.2.0", "Custom: LICENSE", allowlist);
    assert.equal(result.status, "denied");
    assert.match(result.reason, /invalid exception license/i);
    assert.match(result.reason, /tls-client-node/);
  }
});

test("classifyLicense: temporary exception is denied after its reviewBy date", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "tls-client-node": {
        license: "Custom: LICENSE",
        justification: "Temporary non-OSI source-available bridge with an owner.",
        risk: "medium",
        temporary: true,
        owner: "@owner",
        reviewBy: "2026-09-30",
        classification: "non-OSI source-available",
      },
    },
  });

  const beforeExpiry = classifyLicense("tls-client-node@0.2.0", "Custom: LICENSE", allowlist, {
    now: new Date("2026-09-30T23:59:59.999Z"),
  });
  assert.equal(beforeExpiry.status, "exception");

  const expired = classifyLicense("tls-client-node@0.2.0", "Custom: LICENSE", allowlist, {
    now: new Date("2026-10-01T00:00:00.000Z"),
  });
  assert.equal(expired.status, "denied");
  assert.match(expired.reason, /expired|reviewBy/i);
});

test("classifyLicense: malformed temporary exception metadata fails closed", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "tls-client-node": {
        license: "Custom: LICENSE",
        justification: "Temporary exception whose deadline is intentionally invalid.",
        risk: "medium",
        temporary: true,
        owner: "@owner",
        reviewBy: "2026-02-30",
        classification: "non-OSI source-available",
      },
    },
  });
  const result = classifyLicense("tls-client-node@0.2.0", "Custom: LICENSE", allowlist, {
    now: new Date("2026-08-27T00:00:00.000Z"),
  });
  assert.equal(result.status, "denied");
  assert.match(result.reason, /invalid|reviewBy/i);
});

test("classifyLicense: ownerless temporary exception fails closed", () => {
  const allowlist = makeAllowlist({
    exceptions: {
      "tls-client-node": {
        license: "Custom: LICENSE",
        justification: "Temporary exception deliberately missing an accountable owner.",
        risk: "medium",
        temporary: true,
        reviewBy: "2026-09-30",
        classification: "non-OSI source-available",
      },
    },
  });
  const result = classifyLicense("tls-client-node@0.2.0", "Custom: LICENSE", allowlist, {
    now: new Date("2026-08-27T00:00:00.000Z"),
  });
  assert.equal(result.status, "denied");
  assert.match(result.reason, /owner/i);
});

// ---------------------------------------------------------------------------
// classifyLicense — reason field content
// ---------------------------------------------------------------------------

test("classifyLicense: denied result includes package name in reason", () => {
  const result = classifyLicense("bad-pkg@1.0.0", "GPL-3.0", makeAllowlist());
  assert.ok(
    result.reason.includes("bad-pkg"),
    `reason should include package name; got: ${result.reason}`
  );
});

test("classifyLicense: allowed result mentions the matched license", () => {
  const result = classifyLicense("ok-pkg@1.0.0", "MIT", makeAllowlist());
  assert.ok(result.reason.includes("MIT"), `reason should include license; got: ${result.reason}`);
});

// ---------------------------------------------------------------------------
// loadAllowlist — shape validation (reads the real .license-allowlist.json)
// ---------------------------------------------------------------------------

test("loadAllowlist: returns an object with allowed, allowedExpressions, and exceptions keys", () => {
  const allowlist = loadAllowlist();
  assert.ok(typeof allowlist === "object" && allowlist !== null, "should be an object");
  assert.ok(Array.isArray(allowlist.allowed), "allowed should be an array");
  assert.ok(Array.isArray(allowlist.allowedExpressions), "allowedExpressions should be an array");
  assert.ok(typeof allowlist.exceptions === "object", "exceptions should be an object");
});

test("loadAllowlist: allowed includes MIT", () => {
  const allowlist = loadAllowlist();
  assert.ok(allowlist.allowed.includes("MIT"), "MIT must be in allowed");
});

test("loadAllowlist: allowed includes Apache-2.0", () => {
  const allowlist = loadAllowlist();
  assert.ok(allowlist.allowed.includes("Apache-2.0"), "Apache-2.0 must be in allowed");
});

test("loadAllowlist: allowed includes ISC", () => {
  const allowlist = loadAllowlist();
  assert.ok(allowlist.allowed.includes("ISC"), "ISC must be in allowed");
});

test("loadAllowlist: exceptions entries have required fields", () => {
  const allowlist = loadAllowlist();
  for (const [pkgName, exc] of Object.entries(allowlist.exceptions)) {
    assert.ok(
      typeof (exc as any).license === "string",
      `exceptions.${pkgName}.license should be a string`
    );
    assert.ok(
      typeof (exc as any).justification === "string",
      `exceptions.${pkgName}.justification should be a string`
    );
    assert.ok(
      typeof (exc as any).risk === "string",
      `exceptions.${pkgName}.risk should be a string`
    );
    assert.ok(
      (exc as any).justification.length > 10,
      `exceptions.${pkgName}.justification must be non-trivial (> 10 chars)`
    );
  }
});

test("loadAllowlist: tls-client-node exception is temporary, owned, and covers all consumers", () => {
  const allowlist = loadAllowlist();
  const exc = allowlist.exceptions["tls-client-node"] as any;
  assert.ok(exc, "tls-client-node exception must be registered");
  assert.equal(exc.risk, "medium", "tls-client-node is a medium-risk exception (Commons Clause)");
  assert.equal(exc.temporary, true, "Commons Clause exception must not become permanent policy");
  assert.equal(exc.owner, "@diegosouzapw");
  assert.equal(exc.reviewBy, "2026-09-30");
  assert.equal(exc.reviewAt, "v3.9.0");
  assert.equal(exc.version, "0.2.0", "exception must cover only the provenance-audited release");
  assert.equal(exc.classification, "Apache-2.0 with Commons Clause; non-OSI source-available");
  assert.match(exc.justification, /source-available/i);
  assert.match(exc.justification, /commercial deployment/i);
  assert.match(exc.justification, /PR #11742/, "temporary exception must link its tracker");
  for (const provider of [
    "chatgpt-web",
    "claude-web",
    "perplexity-web",
    "grok-web",
    "notion-web",
    "lmarena",
  ]) {
    assert.match(exc.justification, new RegExp(provider), `missing consumer ${provider}`);
  }
});

test("loadAllowlist: LGPL packages have registered exceptions", () => {
  const allowlist = loadAllowlist();
  const lgplPkgs = ["@img/sharp-libvips-linux-x64", "@img/sharp-libvips-linuxmusl-x64"];
  for (const pkg of lgplPkgs) {
    assert.ok(
      allowlist.exceptions[pkg],
      `${pkg} (LGPL-3.0-or-later) must have a registered exception`
    );
  }
});

test("loadAllowlist: MPL-2.0 packages have registered exceptions or allowed expressions", () => {
  const allowlist = loadAllowlist();
  const mplPkgs = ["lightningcss", "lightningcss-linux-x64-gnu", "lightningcss-linux-x64-musl"];
  for (const pkg of mplPkgs) {
    const hasException = Boolean(allowlist.exceptions[pkg]);
    const mplExpr = allowlist.allowedExpressions.some((e: string) => e.includes("MPL"));
    assert.ok(
      hasException || mplExpr,
      `${pkg} (MPL-2.0) must be in exceptions or have an allowed expression`
    );
  }
});

// ---------------------------------------------------------------------------
// Integration: real allowlist correctly classifies known packages
// ---------------------------------------------------------------------------

test("integration: classifyLicense passes MIT packages against real allowlist", () => {
  const allowlist = loadAllowlist();
  const result = classifyLicense("lodash@4.17.21", "MIT", allowlist);
  assert.equal(result.status, "allowed");
});

test("integration: classifyLicense passes tls-client-node as exception against real allowlist", () => {
  const allowlist = loadAllowlist();
  const result = classifyLicense("tls-client-node@0.2.0", "Custom: LICENSE", allowlist);
  assert.equal(result.status, "exception");
});

test("integration: real tls-client-node exception denies an unaudited future version", () => {
  const allowlist = loadAllowlist();
  const result = classifyLicense("tls-client-node@0.2.1", "Custom: LICENSE", allowlist);
  assert.equal(result.status, "denied");
  assert.match(result.reason, /0\.2\.1/);
  assert.match(result.reason, /0\.2\.0/);
});

test("integration: classifyLicense denies GPL-3.0 against real allowlist", () => {
  const allowlist = loadAllowlist();
  const result = classifyLicense("hypothetical-gpl@1.0.0", "GPL-3.0", allowlist);
  assert.equal(result.status, "denied");
});

test("integration: classifyLicense denies AGPL-3.0 against real allowlist", () => {
  const allowlist = loadAllowlist();
  const result = classifyLicense("hypothetical-agpl@1.0.0", "AGPL-3.0", allowlist);
  assert.equal(result.status, "denied");
});
