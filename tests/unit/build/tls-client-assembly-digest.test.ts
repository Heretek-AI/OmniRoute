import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  assembleStandalone,
  syncStandaloneNativeAssets,
} from "../../../scripts/build/assembleStandalone.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

test("async standalone assembly rejects a manifest-named TLS seed with the wrong digest", async () => {
  const manifest = JSON.parse(
    readFileSync(join(ROOT, "open-sse", "config", "tlsClientNativeManifest.json"), "utf8")
  ) as { assets: Record<string, { file: string }> };
  const asset = Object.entries(manifest.assets).find(
    ([target]) => target !== `${process.platform}-${process.arch}`
  )?.[1];
  assert.ok(asset, "the pinned TLS manifest must contain at least one native asset");

  const projectRoot = mkdtempSync(join(tmpdir(), "tls-assembly-digest-project-"));
  const outDir = mkdtempSync(join(tmpdir(), "tls-assembly-digest-output-"));
  const source = join(projectRoot, "node_modules", "tls-client-node", "bin", asset.file);
  const destination = join(outDir, "runtime-assets", "tls-client", "bin", asset.file);

  try {
    mkdirSync(dirname(source), { recursive: true });
    writeFileSync(source, "manifest filename, deliberately untrusted bytes");

    await assert.rejects(
      syncStandaloneNativeAssets(projectRoot, undefined, { log() {} }, outDir),
      /SHA-256|digest|integrity/i
    );
    assert.equal(
      existsSync(destination),
      false,
      "an unverified TLS seed must never be emitted into the standalone output"
    );
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
    rmSync(outDir, { recursive: true, force: true });
  }
});

test("async standalone assembly copies a regular TLS seed whose fixture digest is pinned", async () => {
  const fixture = "verified TLS fixture\n";
  const fixtureAsset = {
    file: "tls-client-test-fixture.so",
    sha256: "3242ea2a8eb1fb8a714e682bba5a62652b33180f76e6a95aea701d7b8b77139c",
  };
  const projectRoot = mkdtempSync(join(tmpdir(), "tls-assembly-valid-project-"));
  const outDir = mkdtempSync(join(tmpdir(), "tls-assembly-valid-output-"));
  const source = join(projectRoot, "node_modules", "tls-client-node", "bin", fixtureAsset.file);
  const destination = join(outDir, "runtime-assets", "tls-client", "bin", fixtureAsset.file);

  try {
    mkdirSync(dirname(source), { recursive: true });
    writeFileSync(source, fixture);

    const changed = await syncStandaloneNativeAssets(projectRoot, undefined, { log() {} }, outDir, {
      tlsClientNativeAssets: { "test-fixture": fixtureAsset },
    });

    assert.equal(changed, true);
    assert.equal(readFileSync(destination, "utf8"), fixture);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
    rmSync(outDir, { recursive: true, force: true });
  }
});

test("sync standalone assembly rejects a manifest-named TLS seed with the wrong digest", () => {
  const manifest = JSON.parse(
    readFileSync(join(ROOT, "open-sse", "config", "tlsClientNativeManifest.json"), "utf8")
  ) as { assets: Record<string, { file: string }> };
  const asset = Object.entries(manifest.assets).find(
    ([target]) => target !== `${process.platform}-${process.arch}`
  )?.[1];
  assert.ok(asset, "the pinned TLS manifest must contain at least one native asset");

  const projectRoot = mkdtempSync(join(tmpdir(), "tls-assembly-sync-digest-project-"));
  const distDir = join(projectRoot, ".build", "next");
  const outDir = join(projectRoot, "dist");
  const source = join(projectRoot, "node_modules", "tls-client-node", "bin", asset.file);
  const destination = join(outDir, "runtime-assets", "tls-client", "bin", asset.file);
  const staleStandaloneSeed = join(
    distDir,
    "standalone",
    "runtime-assets",
    "tls-client",
    "bin",
    asset.file
  );

  try {
    mkdirSync(join(distDir, "standalone"), { recursive: true });
    writeFileSync(join(distDir, "standalone", "server.js"), "// synthetic standalone\n");
    mkdirSync(dirname(staleStandaloneSeed), { recursive: true });
    writeFileSync(staleStandaloneSeed, "stale unverified seed from an earlier assembly");
    mkdirSync(dirname(source), { recursive: true });
    writeFileSync(source, "manifest filename, deliberately untrusted sync bytes");

    assert.throws(
      () =>
        assembleStandalone({
          distDir,
          outDir,
          projectRoot,
          copyNatives: true,
        }),
      /SHA-256|digest|integrity/i
    );
    assert.equal(
      existsSync(destination),
      false,
      "a failed sync assembly must not leave an unverified TLS seed in its output"
    );
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("sync assembly rejects a stale unverified TLS seed when the source install is absent", () => {
  const manifest = JSON.parse(
    readFileSync(join(ROOT, "open-sse", "config", "tlsClientNativeManifest.json"), "utf8")
  ) as { assets: Record<string, { file: string }> };
  const asset = Object.values(manifest.assets)[0];
  assert.ok(asset, "the pinned TLS manifest must contain at least one native asset");

  const projectRoot = mkdtempSync(join(tmpdir(), "tls-assembly-stale-project-"));
  const distDir = join(projectRoot, ".build", "next");
  const outDir = join(projectRoot, "dist");
  const staleStandaloneSeed = join(
    distDir,
    "standalone",
    "runtime-assets",
    "tls-client",
    "bin",
    asset.file
  );
  const destination = join(outDir, "runtime-assets", "tls-client", "bin", asset.file);

  try {
    mkdirSync(dirname(staleStandaloneSeed), { recursive: true });
    writeFileSync(join(distDir, "standalone", "server.js"), "// synthetic standalone\n");
    writeFileSync(staleStandaloneSeed, "stale bytes with no corresponding source install");

    assert.throws(
      () => assembleStandalone({ distDir, outDir, projectRoot, copyNatives: true }),
      /SHA-256|digest|integrity/i
    );
    assert.equal(
      existsSync(destination),
      false,
      "a stale unverified seed copied by the bulk standalone pass must be removed"
    );
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("sync assembly rejects TLS tamper copied through every standalone node_modules root", () => {
  const manifest = JSON.parse(
    readFileSync(join(ROOT, "open-sse", "config", "tlsClientNativeManifest.json"), "utf8")
  ) as { assets: Record<string, { file: string }> };
  const asset = Object.values(manifest.assets)[0];
  assert.ok(asset, "the pinned TLS manifest must contain at least one native asset");

  const layouts = [
    (_projectRoot: string) => ["node_modules", "tls-client-node", "bin"],
    (_projectRoot: string) => [".build", "next", "node_modules", "tls-client-node", "bin"],
    (_projectRoot: string) => ["projects", "OmniRoute", "node_modules", "tls-client-node", "bin"],
    (projectRoot: string) => [basename(projectRoot), "node_modules", "tls-client-node", "bin"],
  ];

  for (const layout of layouts) {
    const projectRoot = mkdtempSync(join(tmpdir(), "tls-assembly-bulk-root-"));
    const distDir = join(projectRoot, ".build", "next");
    const outDir = join(projectRoot, "dist");
    const relativeBin = layout(projectRoot);
    const staleStandaloneSeed = join(distDir, "standalone", ...relativeBin, asset.file);
    const destination = join(outDir, ...relativeBin, asset.file);

    try {
      mkdirSync(dirname(staleStandaloneSeed), { recursive: true });
      writeFileSync(join(distDir, "standalone", "server.js"), "// synthetic standalone\n");
      writeFileSync(staleStandaloneSeed, "manifest-named bytes with an invalid digest");

      assert.throws(
        () => assembleStandalone({ distDir, outDir, projectRoot, copyNatives: true }),
        /SHA-256|digest|integrity/i,
        `bulk-copied TLS seed must be audited at ${relativeBin.join("/")}`
      );
      assert.equal(
        existsSync(destination),
        false,
        `tampered TLS seed must be removed from ${relativeBin.join("/")}`
      );
    } finally {
      rmSync(projectRoot, { recursive: true, force: true });
    }
  }
});

test(
  "sync assembly rejects a writable stale TLS seed even when its digest is valid",
  { skip: process.platform === "win32" },
  () => {
    const fixture = "sync verified TLS fixture\n";
    const fixtureAsset = {
      file: "tls-client-stale-mode-fixture.so",
      sha256: "7729ee26e4baf77e5c5ad8289778943a4412621d275d41b8cff8fe8daa3a496e",
    };
    const projectRoot = mkdtempSync(join(tmpdir(), "tls-assembly-stale-mode-project-"));
    const distDir = join(projectRoot, ".build", "next");
    const outDir = join(projectRoot, "dist");
    const staleStandaloneSeed = join(
      distDir,
      "standalone",
      "runtime-assets",
      "tls-client",
      "bin",
      fixtureAsset.file
    );
    const destination = join(outDir, "runtime-assets", "tls-client", "bin", fixtureAsset.file);

    try {
      mkdirSync(dirname(staleStandaloneSeed), { recursive: true });
      writeFileSync(join(distDir, "standalone", "server.js"), "// synthetic standalone\n");
      writeFileSync(staleStandaloneSeed, fixture);
      chmodSync(staleStandaloneSeed, 0o644);

      assert.throws(
        () =>
          assembleStandalone({
            distDir,
            outDir,
            projectRoot,
            copyNatives: true,
            tlsClientNativeAssets: { "stale-mode-fixture": fixtureAsset },
          }),
        /mode|permission|writable/i
      );
      assert.equal(
        existsSync(destination),
        false,
        "a writable stale seed must be removed instead of being trusted by digest alone"
      );
    } finally {
      rmSync(projectRoot, { recursive: true, force: true });
    }
  }
);

test("sync standalone assembly copies a regular TLS seed whose fixture digest is pinned", () => {
  const fixture = "sync verified TLS fixture\n";
  const fixtureAsset = {
    file: "tls-client-sync-test-fixture.so",
    sha256: "7729ee26e4baf77e5c5ad8289778943a4412621d275d41b8cff8fe8daa3a496e",
  };
  const projectRoot = mkdtempSync(join(tmpdir(), "tls-assembly-sync-valid-project-"));
  const distDir = join(projectRoot, ".build", "next");
  const outDir = join(projectRoot, "dist");
  const source = join(projectRoot, "node_modules", "tls-client-node", "bin", fixtureAsset.file);
  const destination = join(outDir, "runtime-assets", "tls-client", "bin", fixtureAsset.file);

  try {
    mkdirSync(join(distDir, "standalone"), { recursive: true });
    writeFileSync(join(distDir, "standalone", "server.js"), "// synthetic standalone\n");
    mkdirSync(dirname(source), { recursive: true });
    writeFileSync(source, fixture);

    assembleStandalone({
      distDir,
      outDir,
      projectRoot,
      copyNatives: true,
      tlsClientNativeAssets: { "sync-test-fixture": fixtureAsset },
    });

    assert.equal(readFileSync(destination, "utf8"), fixture);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("standalone assembly rejects symlink and oversized TLS seed sources", async () => {
  const manifest = JSON.parse(
    readFileSync(join(ROOT, "open-sse", "config", "tlsClientNativeManifest.json"), "utf8")
  ) as { assets: Record<string, { file: string }> };
  const asset = Object.values(manifest.assets)[0];
  assert.ok(asset, "the pinned TLS manifest must contain at least one native asset");

  const projectRoot = mkdtempSync(join(tmpdir(), "tls-assembly-unsafe-project-"));
  const outDir = mkdtempSync(join(tmpdir(), "tls-assembly-unsafe-output-"));
  const source = join(projectRoot, "node_modules", "tls-client-node", "bin", asset.file);
  const destination = join(outDir, "runtime-assets", "tls-client", "bin", asset.file);
  const symlinkTarget = join(projectRoot, "untrusted-native-bytes");

  try {
    mkdirSync(dirname(source), { recursive: true });
    writeFileSync(symlinkTarget, "untrusted symlink target");
    symlinkSync(symlinkTarget, source);
    await assert.rejects(
      syncStandaloneNativeAssets(projectRoot, undefined, { log() {} }, outDir),
      /symlink\/non-regular file/i
    );
    assert.equal(existsSync(destination), false);

    rmSync(source, { force: true });
    writeFileSync(source, "");
    truncateSync(source, 64 * 1024 * 1024 + 1);
    await assert.rejects(
      syncStandaloneNativeAssets(projectRoot, undefined, { log() {} }, outDir),
      /64 MiB limit/i
    );
    assert.equal(existsSync(destination), false);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
    rmSync(outDir, { recursive: true, force: true });
  }
});

test("standalone assembly rejects a TLS seed beneath a symlink source ancestor", async () => {
  const fixture = "verified TLS fixture\n";
  const fixtureAsset = {
    file: "tls-client-source-ancestor-symlink-fixture.so",
    sha256: "3242ea2a8eb1fb8a714e682bba5a62652b33180f76e6a95aea701d7b8b77139c",
  };
  const temporaryRoot = mkdtempSync(join(tmpdir(), "tls-assembly-source-ancestor-"));
  const projectRoot = join(temporaryRoot, "project");
  const outsideBin = join(temporaryRoot, "outside-bin");
  const sourceBin = join(projectRoot, "node_modules", "tls-client-node", "bin");
  const outsideSource = join(outsideBin, fixtureAsset.file);
  const outDir = join(temporaryRoot, "standalone");
  const destination = join(outDir, "runtime-assets", "tls-client", "bin", fixtureAsset.file);

  try {
    mkdirSync(dirname(sourceBin), { recursive: true });
    mkdirSync(outsideBin, { recursive: true });
    writeFileSync(outsideSource, fixture);
    symlinkSync(outsideBin, sourceBin, "dir");

    await assert.rejects(
      syncStandaloneNativeAssets(projectRoot, undefined, { log() {} }, outDir, {
        tlsClientNativeAssets: { "source-ancestor-symlink-fixture": fixtureAsset },
      }),
      /source ancestor|symlink/i
    );
    assert.equal(
      existsSync(destination),
      false,
      "a TLS seed reached through a source ancestor symlink must not be distributed"
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("standalone assembly rejects a symlink destination without modifying its target", async () => {
  const fixture = "verified TLS fixture\n";
  const fixtureAsset = {
    file: "tls-client-destination-symlink-fixture.so",
    sha256: "3242ea2a8eb1fb8a714e682bba5a62652b33180f76e6a95aea701d7b8b77139c",
  };
  const projectRoot = mkdtempSync(join(tmpdir(), "tls-assembly-dest-project-"));
  const outDir = mkdtempSync(join(tmpdir(), "tls-assembly-dest-output-"));
  const source = join(projectRoot, "node_modules", "tls-client-node", "bin", fixtureAsset.file);
  const destination = join(outDir, "runtime-assets", "tls-client", "bin", fixtureAsset.file);
  const outsideTarget = join(projectRoot, "must-remain-untouched");

  try {
    mkdirSync(dirname(source), { recursive: true });
    writeFileSync(source, fixture);
    writeFileSync(outsideTarget, "outside sentinel");
    mkdirSync(dirname(destination), { recursive: true });
    symlinkSync(outsideTarget, destination);

    await assert.rejects(
      syncStandaloneNativeAssets(projectRoot, undefined, { log() {} }, outDir, {
        tlsClientNativeAssets: { "destination-symlink-fixture": fixtureAsset },
      }),
      /destination \(symlink\/non-regular file\)/i
    );
    assert.equal(existsSync(destination), false);
    assert.equal(readFileSync(outsideTarget, "utf8"), "outside sentinel");
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
    rmSync(outDir, { recursive: true, force: true });
  }
});

test("standalone assembly rejects an output root symlink without writing outside it", async () => {
  const fixture = "verified TLS fixture\n";
  const fixtureAsset = {
    file: "tls-client-output-root-symlink-fixture.so",
    sha256: "3242ea2a8eb1fb8a714e682bba5a62652b33180f76e6a95aea701d7b8b77139c",
  };
  const temporaryRoot = mkdtempSync(join(tmpdir(), "tls-assembly-root-symlink-"));
  const projectRoot = join(temporaryRoot, "project");
  const outsideDir = join(temporaryRoot, "outside");
  const outDir = join(temporaryRoot, "standalone-link");
  const source = join(projectRoot, "node_modules", "tls-client-node", "bin", fixtureAsset.file);
  const escapedDestination = join(
    outsideDir,
    "runtime-assets",
    "tls-client",
    "bin",
    fixtureAsset.file
  );

  try {
    mkdirSync(dirname(source), { recursive: true });
    writeFileSync(source, fixture);
    mkdirSync(outsideDir, { recursive: true });
    symlinkSync(outsideDir, outDir, "dir");

    await assert.rejects(
      syncStandaloneNativeAssets(projectRoot, undefined, { log() {} }, outDir, {
        tlsClientNativeAssets: { "root-symlink-fixture": fixtureAsset },
      }),
      /destination.*(?:root|ancestor)|symlink/i
    );
    assert.equal(
      existsSync(escapedDestination),
      false,
      "a symlinked output root must not redirect an authorized filename outside the bundle"
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});
