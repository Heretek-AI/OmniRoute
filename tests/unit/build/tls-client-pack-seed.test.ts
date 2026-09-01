import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import * as packPolicy from "../../../scripts/build/pack-artifact-policy.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

type RuntimeSeedPathResolver = (platform?: NodeJS.Platform, arch?: string) => string;

function allRuntimeSeedPaths(): string[] {
  const manifest = JSON.parse(
    readFileSync(join(ROOT, "open-sse", "config", "tlsClientNativeManifest.json"), "utf8")
  ) as { assets: Record<string, { file: string }> };
  return Object.values(manifest.assets)
    .map((asset) => `runtime-assets/tls-client/bin/${asset.file}`)
    .sort();
}

test("npm staging keeps and requires every exact manifest-backed TLS client runtime seed", () => {
  const runtimeSeedPaths = allRuntimeSeedPaths();
  assert.equal(runtimeSeedPaths.length, 6, "the pinned manifest currently supports six targets");

  assert.deepEqual(
    packPolicy.findUnexpectedArtifactPaths(runtimeSeedPaths, {
      exactPaths: packPolicy.APP_STAGING_ALLOWED_EXACT_PATHS,
      prefixPaths: packPolicy.APP_STAGING_ALLOWED_PATH_PREFIXES,
      neverAllowedSegments: [],
    }),
    [],
    "prepublish staging must not prune any officially supported runtime seed"
  );
  assert.deepEqual(
    packPolicy.APP_STAGING_ALLOWED_EXACT_PATHS.filter((path) =>
      path.startsWith("runtime-assets/tls-client/bin/")
    ).sort(),
    runtimeSeedPaths,
    "the staging allowlist must enumerate exactly the manifest assets"
  );
  assert.equal(
    packPolicy.APP_STAGING_ALLOWED_PATH_PREFIXES.some((path) =>
      path.startsWith("runtime-assets/tls-client")
    ),
    false,
    "TLS native assets must never be authorized through a broad prefix"
  );
  assert.deepEqual(
    packPolicy.findUnexpectedArtifactPaths(["runtime-assets/unrelated/surprise.bin"], {
      exactPaths: packPolicy.APP_STAGING_ALLOWED_EXACT_PATHS,
      prefixPaths: packPolicy.APP_STAGING_ALLOWED_PATH_PREFIXES,
      neverAllowedSegments: [],
    }),
    ["runtime-assets/unrelated/surprise.bin"],
    "the staging exception must stay scoped to the TLS client binary directory"
  );
  assert.deepEqual(
    packPolicy.findUnexpectedArtifactPaths(
      ["runtime-assets/tls-client/bin/untracked-extra-native.so"],
      {
        exactPaths: packPolicy.APP_STAGING_ALLOWED_EXACT_PATHS,
        prefixPaths: packPolicy.APP_STAGING_ALLOWED_PATH_PREFIXES,
        neverAllowedSegments: [],
      }
    ),
    ["runtime-assets/tls-client/bin/untracked-extra-native.so"],
    "the staging exception must not distribute an untracked native beside the pinned seed"
  );

  const requiredSeedPaths = runtimeSeedPaths.map((path) => `dist/${path}`);
  assert.deepEqual(
    packPolicy.PACK_ARTIFACT_REQUIRED_PATHS.filter((path) =>
      path.startsWith("dist/runtime-assets/tls-client/bin/")
    ).sort(),
    requiredSeedPaths,
    "check:pack-artifact must require every manifest asset and no untracked native"
  );
  for (const requiredSeedPath of requiredSeedPaths) {
    assert.deepEqual(
      packPolicy.findMissingArtifactPaths(
        packPolicy.PACK_ARTIFACT_REQUIRED_PATHS.filter((path) => path !== requiredSeedPath),
        packPolicy.PACK_ARTIFACT_REQUIRED_PATHS
      ),
      [requiredSeedPath],
      `the pack gate must report ${requiredSeedPath} when it is absent`
    );
  }

  const packageJson = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as {
    files: string[];
  };
  assert.ok(packageJson.files.includes("dist/"), "npm files must include the staged dist tree");
  assert.equal(
    packageJson.files.some(
      (entry) => entry.startsWith("!") && /runtime-assets|tls-client|\.(?:so|dylib|dll)/.test(entry)
    ),
    false,
    "npm files exclusions must not remove the exact native seeds after policy validation"
  );
});

test("npm staging retains the TLS manifest and notices inside dist", () => {
  const standaloneLegalPaths = [
    "THIRD_PARTY_NOTICES.md",
    "open-sse/config/tlsClientNativeManifest.json",
  ];

  assert.deepEqual(
    packPolicy.findUnexpectedArtifactPaths(standaloneLegalPaths, {
      exactPaths: packPolicy.APP_STAGING_ALLOWED_EXACT_PATHS,
      prefixPaths: packPolicy.APP_STAGING_ALLOWED_PATH_PREFIXES,
      neverAllowedSegments: [],
    }),
    [],
    "prepublish must not prune legal provenance copied into the standalone"
  );
  for (const filePath of standaloneLegalPaths) {
    assert.ok(
      packPolicy.PACK_ARTIFACT_REQUIRED_PATHS.includes(`dist/${filePath}`),
      `check:pack-artifact must require dist/${filePath}`
    );
  }
});

test("TLS client pack seed resolution fails explicitly on unsupported platforms", () => {
  const resolver = (
    packPolicy as typeof packPolicy & {
      resolveTlsClientRuntimeSeedPath?: RuntimeSeedPathResolver;
    }
  ).resolveTlsClientRuntimeSeedPath;

  assert.equal(typeof resolver, "function", "pack policy must expose manifest-backed resolution");
  assert.throws(
    () => resolver?.("aix", "ppc64"),
    /Unsupported platform for tls-client-node native asset: aix\/ppc64/
  );
});

test("build:cli verifies all TLS client targets before assembly and after final pruning", () => {
  const packageJson = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as {
    scripts: Record<string, string>;
  };
  assert.match(
    packageJson.scripts["build:cli"],
    /(?:^|\s)scripts\/build\/prepublish\.ts(?:\s|$)/,
    "the published build must execute scripts/build/prepublish.ts"
  );

  const prepublish = readFileSync(join(ROOT, "scripts", "build", "prepublish.ts"), "utf8");
  assert.match(
    prepublish,
    /import\s*\{[\s\S]*?fixTlsClientNodeBinary[\s\S]*?TLS_CLIENT_NATIVE_ASSETS[\s\S]*?\}\s*from\s*"\.\/fixTlsClientNodeBinary\.mjs";/,
    "prepublish must use the audited TLS client binary verifier"
  );
  assert.match(prepublish, /Object\.keys\(TLS_CLIENT_NATIVE_ASSETS\)/);
  const fixerCall = prepublish.match(/await\s+fixTlsClientNodeBinary\(\{([\s\S]*?)\}\);/);
  assert.ok(fixerCall, "prepublish must await TLS client seed verification for each platform");
  assert.match(fixerCall[1], /\bplatform\b/);
  assert.match(fixerCall[1], /\barches\b/);
  assert.match(fixerCall[1], /\bstrict:\s*true\b/);
  assert.match(fixerCall[1], /\brequireStandalone:\s*true\b/);

  const allTargetCalls = [
    ...prepublish.matchAll(/await\s+verifyAllTlsClientRuntimeSeeds\(([^)]+)\);/g),
  ];
  assert.equal(allTargetCalls.length, 2, "verify all targets at both npm artifact boundaries");
  assert.equal(allTargetCalls[0][1].trim(), "standaloneDir");
  assert.equal(allTargetCalls[1][1].trim(), "DIST_DIR");

  const sourceFixerIndex = allTargetCalls[0].index ?? -1;
  const assembleIndex = prepublish.indexOf("assembleStandalone({");
  const finalPruneIndex = prepublish.indexOf("const remainingUnexpectedFiles");
  const finalFixerIndex = allTargetCalls[1].index ?? -1;
  const doneIndex = prepublish.indexOf("// ── Done");
  assert.ok(
    sourceFixerIndex >= 0 && sourceFixerIndex < assembleIndex,
    "all-target source verification must precede assembly"
  );
  assert.ok(
    finalPruneIndex < finalFixerIndex && finalFixerIndex < doneIndex,
    "strict all-target digest verification must follow final pruning and precede success"
  );
});
