import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import {
  concreteFromTemplate,
  isLocalOnlyDocPath,
  parseArrayTokens,
  readRegexArray,
  readStringArray,
  resolveIdentifier,
  stripLineComments,
} from "../../../scripts/check/routeGuardConstants.mjs";

const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const GUARD_SRC = fs.readFileSync(
  path.join(ROOT, "src", "server", "authz", "routeGuard.ts"),
  "utf-8"
);

test("parseArrayTokens survives regex literals whose char classes hold ] and ,", () => {
  const src = [
    "export const PATTERNS: ReadonlyArray<RegExp> = [",
    "  /^\\/api\\/providers\\/[^/]+\\/login\\/?$/, // inline note",
    "  /^\\/api\\/x\\/[a-z]{1,3}$/,",
    "];",
  ].join("\n");
  assert.deepEqual(parseArrayTokens(src, "PATTERNS"), [
    "/^\\/api\\/providers\\/[^/]+\\/login\\/?$/",
    "/^\\/api\\/x\\/[a-z]{1,3}$/",
  ]);
});

test("stripLineComments keeps escaped slashes and URLs, drops real comments", () => {
  assert.equal(stripLineComments("/a\\/\\/b/, // note"), "/a\\/\\/b/, ");
  assert.equal(stripLineComments('"https://x", // note'), '"https://x", ');
  assert.equal(stripLineComments("// whole line"), "");
});

test("resolveIdentifier follows a named import to its exported literal", () => {
  const guardSrc = 'import { VNC_ROUTE_PREFIX } from "@/lib/vncSession/manifest";';
  const readFile = (p: string) =>
    p.endsWith(path.join("src", "lib", "vncSession", "manifest.ts"))
      ? 'export const VNC_ROUTE_PREFIX = "/api/vnc-session";'
      : null;
  assert.equal(
    resolveIdentifier("VNC_ROUTE_PREFIX", { guardSrc, root: ROOT, readFile }),
    "/api/vnc-session"
  );
  assert.equal(resolveIdentifier("MISSING", { guardSrc, root: ROOT, readFile }), null);
});

test("readStringArray throws instead of degrading an unresolvable token into a literal", () => {
  const src = 'export const P: ReadonlyArray<string> = ["/api/a", SOME_CONST];';
  assert.throws(
    () => readStringArray(src, "P", { root: ROOT, readFile: () => null }),
    /SOME_CONST/
  );
});

test("concreteFromTemplate replaces OpenAPI placeholders with a slash-free segment", () => {
  assert.equal(concreteFromTemplate("/api/x/{id}/y"), "/api/x/_param_/y");
});

test("isLocalOnlyDocPath honours prefixes AND patterns, and stays closed otherwise", () => {
  const guards = {
    prefixes: ["/api/mcp/", "/api/vnc-session"],
    patterns: [/^\/api\/providers\/[^/]+\/login\/?$/],
  };
  assert.equal(isLocalOnlyDocPath("/api/vnc-session/{params}", guards), true);
  assert.equal(isLocalOnlyDocPath("/api/mcp/tools", guards), true);
  assert.equal(isLocalOnlyDocPath("/api/providers/{provider}/login", guards), true);
  assert.equal(isLocalOnlyDocPath("/api/providers/{provider}/refresh", guards), false);
  assert.equal(isLocalOnlyDocPath("/v1/chat/completions", guards), false);
});

// Regression guard for the real file: reading only LOCAL_ONLY_API_PREFIXES made
// the gate report the VNC (imported constant) and volcengine-plan (regex) routes
// as unprotected, and demand the removal of a correct x-loopback-only annotation.
test("the real routeGuard constants cover the imported-constant and regex-gated routes", () => {
  const guards = {
    prefixes: readStringArray(GUARD_SRC, "LOCAL_ONLY_API_PREFIXES", { root: ROOT }),
    patterns: readRegexArray(GUARD_SRC, "LOCAL_ONLY_API_PATTERNS"),
  };
  assert.ok(guards.prefixes.includes("/api/vnc-session"), "VNC_ROUTE_PREFIX must resolve");
  assert.ok(guards.patterns.length > 0, "pattern list must be parsed");

  for (const documented of [
    "/api/vnc-session",
    "/api/vnc-session/{params}",
    "/api/providers/volcengine-plan/connect/{sessionId}/status",
    "/api/providers/volcengine-plan/connect/{sessionId}/resend",
  ]) {
    assert.equal(isLocalOnlyDocPath(documented, guards), true, `${documented} must be LOCAL_ONLY`);
  }

  // Control: a deliberately remote-reachable provider route stays open.
  assert.equal(isLocalOnlyDocPath("/api/providers/{id}/refresh", guards), false);
});
