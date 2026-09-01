import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { fixTlsClientNodeBinary } from "../../scripts/build/fixTlsClientNodeBinary.mjs";

const ROOT = join(import.meta.dirname, "..", "..");

test("native manifest pins v1.15.1 to GitHub's official digests on every supported platform", () => {
  const manifest = JSON.parse(
    readFileSync(join(ROOT, "open-sse", "config", "tlsClientNativeManifest.json"), "utf8")
  );

  assert.equal(manifest.version, "1.15.1");
  assert.equal(manifest.source, "https://github.com/bogdanfinn/tls-client/releases/tag/v1.15.1");
  assert.deepEqual(manifest.assets, {
    "darwin-arm64": {
      file: "tls-client-darwin-arm64-1.15.1.dylib",
      sha256: "b36167372a93337195b84a8b8e7ed2e63ba654b7bbe3e35cd4f96ad3196458e6",
    },
    "darwin-x64": {
      file: "tls-client-darwin-amd64-1.15.1.dylib",
      sha256: "7cb2c6833dc2b7e4b59bf46798f0e214bac746143e36bf9cd5ec92fde6ec8465",
    },
    "linux-arm64": {
      file: "tls-client-linux-arm64-1.15.1.so",
      sha256: "048b75c4fb0898a306228198d545eece39a7d5348200487f0395fbdc4168fe39",
    },
    "linux-x64": {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: "e393e866060e238bc36509f853293cebf5af8286aede59814462693efb603b1e",
    },
    "win32-ia32": {
      file: "tls-client-windows-32-1.15.1.dll",
      sha256: "46f44779f41c74918a6d1d0ecadc090aa8bd5303e07ca8dd3a0b999467b76a42",
    },
    "win32-x64": {
      file: "tls-client-windows-64-1.15.1.dll",
      sha256: "414b5e5c60f9200948a46afd023865ad00c7d37403056a7e74ceee27ce2b0287",
    },
  });
});

function makeRoot() {
  return mkdtempSync(join(tmpdir(), "fix-tls-client-node-binary-7802-"));
}

function collectLogs() {
  const logs: string[] = [];
  return { logs, log: (m: string) => logs.push(m) };
}

test("replaces a tampered binary with the pinned version and copies only verified bytes", async () => {
  const rootDir = makeRoot();
  try {
    const goodBytes = "verified-native-binary";
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(goodBytes).digest("hex"),
    };
    const tlsClientDir = join(rootDir, "node_modules", "tls-client-node");
    const rootBin = join(tlsClientDir, "bin");
    mkdirSync(rootBin, { recursive: true });
    writeFileSync(join(rootBin, asset.file), "tampered");
    mkdirSync(join(rootDir, "dist", "node_modules", "tls-client-node"), { recursive: true });

    await fixTlsClientNodeBinary({
      rootDir,
      asset,
      strict: true,
      retryDelaysMs: [],
      fetchImpl: async () => new Response(goodBytes, { status: 200 }),
      log() {},
    });

    assert.equal(readFileSync(join(rootBin, asset.file), "utf8"), goodBytes);
    assert.equal(
      readFileSync(
        join(rootDir, "dist", "node_modules", "tls-client-node", "bin", asset.file),
        "utf8"
      ),
      goodBytes
    );
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("host recovery downloads the pinned asset directly and never executes package postinstall", async () => {
  const rootDir = makeRoot();
  try {
    const bytes = Buffer.from("verified-host-direct-download");
    const asset = {
      file: "tls-client-host-direct-test.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const tlsClientDir = join(rootDir, "node_modules", "tls-client-node");
    const rootBin = join(tlsClientDir, "bin");
    const scriptsDir = join(tlsClientDir, "scripts");
    const binaryPath = join(rootBin, asset.file);
    const marker = join(tlsClientDir, ".postinstall-ran");
    const danglingTarget = join(rootDir, "postinstall-must-not-write-here.so");
    mkdirSync(rootBin, { recursive: true });
    mkdirSync(scriptsDir, { recursive: true });
    writeFileSync(
      join(scriptsDir, "postinstall.js"),
      `require("fs").writeFileSync(${JSON.stringify(marker)}, "ran");
       require("fs").symlinkSync(${JSON.stringify(danglingTarget)}, ${JSON.stringify(binaryPath)});`
    );

    const requests: string[] = [];
    let observedSignal = false;
    await fixTlsClientNodeBinary({
      rootDir,
      asset,
      strict: true,
      retryDelaysMs: [],
      fetchImpl: async (input, init) => {
        requests.push(String(input));
        observedSignal = init?.signal instanceof AbortSignal;
        return new Response(bytes, { status: 200 });
      },
      log() {},
    });

    assert.deepEqual(requests, [
      "https://github.com/bogdanfinn/tls-client/releases/download/v1.15.1/" + asset.file,
    ]);
    assert.equal(observedSignal, true);
    assert.equal(existsSync(marker), false);
    assert.equal(existsSync(danglingTarget), false);
    assert.deepEqual(readFileSync(binaryPath), bytes);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("no-ops when node_modules/tls-client-node is absent (module not installed)", async () => {
  const rootDir = makeRoot();
  try {
    const { logs, log } = collectLogs();
    await fixTlsClientNodeBinary({ rootDir, log });
    assert.deepEqual(logs, []);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("copies an already-populated root bin/ into the standalone dist bundle (#7802 item 2)", async () => {
  const rootDir = makeRoot();
  try {
    const binary = "fake-binary";
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(binary).digest("hex"),
    };
    const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
    mkdirSync(rootBin, { recursive: true });
    writeFileSync(join(rootBin, asset.file), binary);

    const distTlsClientDir = join(rootDir, "dist", "node_modules", "tls-client-node");
    mkdirSync(distTlsClientDir, { recursive: true });

    const { log } = collectLogs();
    await fixTlsClientNodeBinary({ rootDir, asset, log });

    const distBin = join(distTlsClientDir, "bin");
    assert.ok(existsSync(distBin), "dist bin/ should have been created");
    assert.deepEqual(readdirSync(distBin), [asset.file]);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("retries the download when root bin/ is empty, and stops once a file appears (#7802 item 3)", async () => {
  const rootDir = makeRoot();
  try {
    const binary = "ok";
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(binary).digest("hex"),
    };
    const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
    mkdirSync(rootBin, { recursive: true });

    let attempts = 0;
    const { logs, log } = collectLogs();
    await fixTlsClientNodeBinary({
      rootDir,
      asset,
      log,
      retryDelaysMs: [1, 1, 1],
      fetchImpl: async () => {
        attempts += 1;
        return attempts === 1
          ? new Response(null, { status: 503 })
          : new Response(binary, { status: 200 });
      },
    });

    assert.equal(attempts, 2);
    assert.ok(existsSync(join(rootBin, asset.file)));
    assert.ok(
      logs.some((m) => m.includes("fetched successfully")),
      "expected a success log once the retry recovered"
    );
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("warns without throwing when every retry leaves bin/ empty (still rate-limited)", async () => {
  const rootDir = makeRoot();
  try {
    const tlsClientDir = join(rootDir, "node_modules", "tls-client-node");
    mkdirSync(join(tlsClientDir, "bin"), { recursive: true });

    const originalWarn = console.warn;
    const warnings: string[] = [];
    console.warn = (m: string) => warnings.push(m);
    try {
      const { log } = collectLogs();
      await assert.doesNotReject(
        fixTlsClientNodeBinary({
          rootDir,
          log,
          retryDelaysMs: [1, 1],
          fetchImpl: async () => new Response(null, { status: 429 }),
        })
      );
    } finally {
      console.warn = originalWarn;
    }

    assert.ok(
      warnings.some((m) => m.includes("Could not fetch tls-client-node")),
      "expected a clear warning pointing at the manual fix, not a silent no-op"
    );
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("strict mode rejects an unverified download instead of shipping it", async () => {
  const rootDir = makeRoot();
  try {
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update("expected").digest("hex"),
    };
    const tlsClientDir = join(rootDir, "node_modules", "tls-client-node");
    mkdirSync(join(tlsClientDir, "bin"), { recursive: true });

    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset,
        strict: true,
        retryDelaysMs: [],
        fetchImpl: async () => new Response("tampered", { status: 200 }),
        log() {},
      }),
      /Could not fetch tls-client-node v1\.15\.1 verified native binary/
    );
    assert.equal(existsSync(join(tlsClientDir, "bin", asset.file)), false);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("strict mode fails closed when the recovered root binary disappears before post-verification", async () => {
  const rootDir = makeRoot();
  try {
    const binary = "verified-then-removed-native-binary";
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(binary).digest("hex"),
    };
    const tlsClientDir = join(rootDir, "node_modules", "tls-client-node");
    const rootBin = join(tlsClientDir, "bin");
    const standaloneDir = join(rootDir, ".build", "next", "standalone");
    const rootBinaryPath = join(rootBin, asset.file);
    const runtimeBinaryPath = join(
      standaloneDir,
      "runtime-assets",
      "tls-client",
      "bin",
      asset.file
    );
    mkdirSync(rootBin, { recursive: true });
    mkdirSync(standaloneDir, { recursive: true });

    const logs: string[] = [];
    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset,
        standaloneDir,
        requireStandalone: true,
        strict: true,
        retryDelaysMs: [],
        fetchImpl: async () => new Response(binary, { status: 200 }),
        log(message) {
          logs.push(message);
          if (message.includes("fetched successfully")) rmSync(rootBinaryPath);
        },
      }),
      /post-recovery verification|recovered.*unverified|no longer verified/i
    );

    assert.ok(logs.some((message) => message.includes("fetched successfully")));
    assert.equal(existsSync(runtimeBinaryPath), false);
    assert.equal(
      logs.some((message) => message.includes("runtime seed")),
      false
    );
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("best-effort mode warns and does not seed standalone after root post-verification fails", async () => {
  const rootDir = makeRoot();
  try {
    const binary = "verified-then-replaced-native-binary";
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(binary).digest("hex"),
    };
    const tlsClientDir = join(rootDir, "node_modules", "tls-client-node");
    const rootBin = join(tlsClientDir, "bin");
    const standaloneDir = join(rootDir, ".build", "next", "standalone");
    const rootBinaryPath = join(rootBin, asset.file);
    const runtimeBinaryPath = join(
      standaloneDir,
      "runtime-assets",
      "tls-client",
      "bin",
      asset.file
    );
    mkdirSync(rootBin, { recursive: true });
    mkdirSync(standaloneDir, { recursive: true });

    const logs: string[] = [];
    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (message: string) => warnings.push(message);
    try {
      await assert.doesNotReject(
        fixTlsClientNodeBinary({
          rootDir,
          asset,
          standaloneDir,
          retryDelaysMs: [],
          fetchImpl: async () => new Response(binary, { status: 200 }),
          log(message) {
            logs.push(message);
            if (message.includes("fetched successfully")) {
              rmSync(rootBinaryPath);
              writeFileSync(rootBinaryPath, "tampered-after-recovery");
            }
          },
        })
      );
    } finally {
      console.warn = originalWarn;
    }

    assert.ok(
      warnings.some(
        (message) =>
          message.includes("failed post-recovery verification") &&
          message.includes("refusing to copy or seed standalone artifacts")
      )
    );
    assert.equal(existsSync(runtimeBinaryPath), false);
    assert.equal(
      logs.some((message) => message.includes("runtime seed")),
      false
    );
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("strict mode rejects a dangling native symlink before attempting recovery", async () => {
  const rootDir = makeRoot();
  try {
    const bytes = "verified-native-binary";
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const tlsClientDir = join(rootDir, "node_modules", "tls-client-node");
    const rootBin = join(tlsClientDir, "bin");
    const scriptsDir = join(tlsClientDir, "scripts");
    const danglingTarget = join(rootDir, "must-not-be-created.so");
    const marker = join(tlsClientDir, ".postinstall-ran");
    mkdirSync(rootBin, { recursive: true });
    mkdirSync(scriptsDir, { recursive: true });
    const binaryPath = join(rootBin, asset.file);
    symlinkSync(danglingTarget, binaryPath);
    writeFileSync(
      join(scriptsDir, "postinstall.js"),
      `require("fs").writeFileSync(${JSON.stringify(marker)}, "ran");
       require("fs").writeFileSync(${JSON.stringify(binaryPath)}, ${JSON.stringify(bytes)});`
    );

    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset,
        strict: true,
        retryDelaysMs: [],
        log() {},
      }),
      /unsafe|symlink|regular file/i
    );
    assert.ok(lstatSync(binaryPath).isSymbolicLink());
    assert.equal(existsSync(marker), false);
    assert.equal(existsSync(danglingTarget), false);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("strict mode rejects an oversized local native file before attempting recovery", async () => {
  const rootDir = makeRoot();
  try {
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update("unreachable").digest("hex"),
    };
    const tlsClientDir = join(rootDir, "node_modules", "tls-client-node");
    const rootBin = join(tlsClientDir, "bin");
    const scriptsDir = join(tlsClientDir, "scripts");
    const marker = join(tlsClientDir, ".postinstall-ran");
    mkdirSync(rootBin, { recursive: true });
    mkdirSync(scriptsDir, { recursive: true });
    const binaryPath = join(rootBin, asset.file);
    writeFileSync(binaryPath, "x");
    truncateSync(binaryPath, 64 * 1024 * 1024 + 1);
    writeFileSync(
      join(scriptsDir, "postinstall.js"),
      `require("fs").writeFileSync(${JSON.stringify(marker)}, "ran");`
    );

    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset,
        strict: true,
        retryDelaysMs: [],
        log() {},
      }),
      /exceeds.*64 MiB|too large/i
    );
    assert.equal(existsSync(marker), false);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("strict mode bounds a source that grows beyond 64 MiB after its initial fstat", async () => {
  const rootDir = makeRoot();
  try {
    const bytes = Buffer.from("small-before-fstat-race");
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
    const binaryPath = join(rootBin, asset.file);
    mkdirSync(rootBin, { recursive: true });
    writeFileSync(binaryPath, bytes);

    let hookCalls = 0;
    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset,
        strict: true,
        retryDelaysMs: [],
        afterSourceStat(observedPath) {
          hookCalls += 1;
          assert.equal(observedPath, binaryPath);
          truncateSync(binaryPath, 64 * 1024 * 1024 + 1);
        },
        log() {},
      }),
      /exceeds.*64 MiB|too large/i
    );

    assert.equal(hookCalls, 1);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("strict standalone verification seeds a public read-execute path outside DATA_DIR", async () => {
  const rootDir = makeRoot();
  try {
    const binary = Buffer.from("verified-standalone-runtime-binary");
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(binary).digest("hex"),
    };
    const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
    const standaloneDir = join(rootDir, ".build", "next", "standalone");
    mkdirSync(rootBin, { recursive: true });
    mkdirSync(standaloneDir, { recursive: true });
    writeFileSync(join(rootBin, asset.file), binary);

    await fixTlsClientNodeBinary({
      rootDir,
      asset,
      standaloneDir,
      requireStandalone: true,
      strict: true,
      retryDelaysMs: [],
      log() {},
    });

    const runtimePath = join(standaloneDir, "runtime-assets", "tls-client", "bin", asset.file);
    assert.deepEqual(readFileSync(runtimePath), binary);
    if (process.platform !== "win32") {
      assert.equal(lstatSync(runtimePath).mode & 0o777, 0o555);
    }
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("strict standalone verification rejects a runtime-assets symlink outside the artifact", async () => {
  const rootDir = makeRoot();
  try {
    const binary = Buffer.from("verified-native-must-stay-inside-artifact");
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(binary).digest("hex"),
    };
    const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
    const standaloneDir = join(rootDir, ".build", "electron-standalone");
    const outsideDir = join(rootDir, "outside-artifact");
    mkdirSync(rootBin, { recursive: true });
    mkdirSync(standaloneDir, { recursive: true });
    mkdirSync(outsideDir, { recursive: true });
    writeFileSync(join(rootBin, asset.file), binary);
    symlinkSync(outsideDir, join(standaloneDir, "runtime-assets"), "dir");

    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset,
        standaloneDir,
        requireStandalone: true,
        strict: true,
        retryDelaysMs: [],
        log() {},
      }),
      /unsafe.*(ancestor|destination|symbolic)|symlink/i
    );

    assert.equal(
      existsSync(join(outsideDir, "tls-client", "bin", asset.file)),
      false,
      "the verifier must not write through an artifact ancestor symlink"
    );
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("strict standalone verification rejects a symlinked artifact root", async () => {
  const rootDir = makeRoot();
  try {
    const binary = Buffer.from("verified-native-must-not-follow-artifact-root");
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(binary).digest("hex"),
    };
    const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
    const standaloneDir = join(rootDir, ".build", "electron-standalone");
    const outsideDir = join(rootDir, "outside-artifact-root");
    mkdirSync(rootBin, { recursive: true });
    mkdirSync(join(rootDir, ".build"), { recursive: true });
    mkdirSync(outsideDir, { recursive: true });
    writeFileSync(join(rootBin, asset.file), binary);
    symlinkSync(outsideDir, standaloneDir, "dir");

    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset,
        standaloneDir,
        requireStandalone: true,
        strict: true,
        retryDelaysMs: [],
        log() {},
      }),
      /unsafe.*(ancestor|destination|symbolic)|symlink/i
    );

    assert.equal(existsSync(join(outsideDir, "runtime-assets")), false);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("strict standalone verification rejects an intermediate ancestor that escapes root", async () => {
  const rootDir = makeRoot();
  const outsideDir = makeRoot();
  try {
    const binary = Buffer.from("verified-native-must-not-follow-build-ancestor");
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(binary).digest("hex"),
    };
    const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
    const outsideBuild = join(outsideDir, "build-target");
    const standaloneDir = join(rootDir, ".build", "next", "standalone");
    const escapedStandaloneDir = join(outsideBuild, "next", "standalone");
    mkdirSync(rootBin, { recursive: true });
    mkdirSync(escapedStandaloneDir, { recursive: true });
    writeFileSync(join(rootBin, asset.file), binary);
    symlinkSync(outsideBuild, join(rootDir, ".build"), "dir");

    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset,
        standaloneDir,
        requireStandalone: true,
        strict: true,
        retryDelaysMs: [],
        log() {},
      }),
      /unsafe.*(ancestor|outside)|symlink/i
    );

    assert.equal(existsSync(join(escapedStandaloneDir, "runtime-assets")), false);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
    rmSync(outsideDir, { recursive: true, force: true });
  }
});

test("strict final npm and Electron gate repairs a present seed by digest, not presence", async () => {
  const rootDir = makeRoot();
  try {
    const binary = Buffer.from("verified-public-artifact-seed");
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(binary).digest("hex"),
    };
    const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
    const standaloneDir = join(rootDir, ".build", "electron-standalone");
    const runtimeBin = join(standaloneDir, "runtime-assets", "tls-client", "bin");
    const runtimePath = join(runtimeBin, asset.file);
    mkdirSync(rootBin, { recursive: true });
    mkdirSync(runtimeBin, { recursive: true });
    writeFileSync(join(rootBin, asset.file), binary);
    writeFileSync(runtimePath, "present-but-tampered");

    await fixTlsClientNodeBinary({
      rootDir,
      asset,
      standaloneDir,
      requireStandalone: true,
      strict: true,
      retryDelaysMs: [],
      log() {},
    });

    assert.deepEqual(readFileSync(runtimePath), binary);
    if (process.platform !== "win32") {
      assert.equal(lstatSync(runtimePath).mode & 0o777, 0o555);
    }
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("strict standalone verification fails when no final artifact was produced", async () => {
  const rootDir = makeRoot();
  try {
    const binary = Buffer.from("verified-root-only-binary");
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(binary).digest("hex"),
    };
    const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
    mkdirSync(rootBin, { recursive: true });
    writeFileSync(join(rootBin, asset.file), binary);

    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset,
        standaloneDir: join(rootDir, ".build", "next", "standalone"),
        requireStandalone: true,
        strict: true,
        retryDelaysMs: [],
        log() {},
      }),
      /standalone.*not found|final.*artifact|runtime.*seed/i
    );
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("strict build helper rejects an asset path that escapes its bin directory", async () => {
  const rootDir = makeRoot();
  try {
    mkdirSync(join(rootDir, "node_modules", "tls-client-node", "bin"), { recursive: true });
    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset: {
          file: "../outside.so",
          sha256: createHash("sha256").update("outside").digest("hex"),
        },
        strict: true,
        retryDelaysMs: [],
        log() {},
      }),
      /invalid.*asset.*path/i
    );
    assert.equal(existsSync(join(rootDir, "node_modules", "tls-client-node", "outside.so")), false);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("multi-target repair downloads and verifies a missing pinned linux-arm64 runtime seed", async () => {
  const rootDir = makeRoot();
  try {
    const x64Bytes = Buffer.from("synthetic-linux-x64-native");
    const arm64Bytes = Buffer.from("synthetic-linux-arm64-native");
    const nativeAssets = {
      "linux-x64": {
        file: "tls-client-linux-x64-test.so",
        sha256: createHash("sha256").update(x64Bytes).digest("hex"),
      },
      "linux-arm64": {
        file: "tls-client-linux-arm64-test.so",
        sha256: createHash("sha256").update(arm64Bytes).digest("hex"),
      },
    };
    const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
    const standaloneDir = join(rootDir, ".build", "electron-standalone");
    const finalBin = join(standaloneDir, "runtime-assets", "tls-client", "bin");
    mkdirSync(rootBin, { recursive: true });
    mkdirSync(standaloneDir, { recursive: true });
    writeFileSync(join(rootBin, nativeAssets["linux-x64"].file), x64Bytes);

    const arm64Seed = join(finalBin, nativeAssets["linux-arm64"].file);
    assert.equal(existsSync(arm64Seed), false, "arm64 must start absent on the x64 host");

    const requests: string[] = [];
    let observedSignal = false;
    const fetchImpl: typeof fetch = async (input, init) => {
      requests.push(String(input));
      observedSignal = init?.signal instanceof AbortSignal;
      return new Response(arm64Bytes, {
        status: 200,
        headers: { "content-length": String(arm64Bytes.byteLength) },
      });
    };

    await fixTlsClientNodeBinary({
      rootDir,
      platform: "linux",
      arches: ["x64", "arm64"],
      nativeAssets,
      fetchImpl,
      standaloneDir,
      requireStandalone: true,
      strict: true,
      retryDelaysMs: [],
      log() {},
    });

    assert.deepEqual(requests, [
      "https://github.com/bogdanfinn/tls-client/releases/download/v1.15.1/" +
        nativeAssets["linux-arm64"].file,
    ]);
    assert.equal(observedSignal, true, "the direct download must be timeout-abortable");
    assert.doesNotMatch(requests[0], /latest/i);
    assert.equal(
      createHash("sha256").update(readFileSync(arm64Seed)).digest("hex"),
      nativeAssets["linux-arm64"].sha256
    );
    const x64Seed = join(finalBin, nativeAssets["linux-x64"].file);
    assert.deepEqual(readFileSync(x64Seed), x64Bytes);
    if (process.platform !== "win32") {
      assert.equal(lstatSync(x64Seed).mode & 0o777, 0o555);
      assert.equal(lstatSync(arm64Seed).mode & 0o777, 0o555);
    }
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("non-host pinned download times out, retries, and then seeds verified bytes", async () => {
  const rootDir = makeRoot();
  try {
    const bytes = Buffer.from("verified-after-timeout-retry");
    const asset = {
      file: "tls-client-non-host-timeout-test.bin",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const targetArch = process.arch === "arm64" ? "x64" : "arm64";
    const standaloneDir = join(rootDir, ".build", "electron-standalone");
    mkdirSync(join(rootDir, "node_modules", "tls-client-node", "bin"), { recursive: true });
    mkdirSync(standaloneDir, { recursive: true });

    let attempts = 0;
    const fetchImpl: typeof fetch = async (_input, init) => {
      attempts += 1;
      if (attempts === 1) {
        return await new Promise<Response>((_resolve, reject) => {
          assert.ok(init?.signal, "download attempt must receive an abort signal");
          init.signal.addEventListener("abort", () => reject(new Error("timed out")), {
            once: true,
          });
        });
      }
      return new Response(bytes, { status: 200 });
    };

    await fixTlsClientNodeBinary({
      rootDir,
      asset,
      platform: process.platform,
      arches: [targetArch],
      fetchImpl,
      downloadTimeoutMs: 5,
      retryDelaysMs: [0],
      standaloneDir,
      requireStandalone: true,
      strict: true,
      log() {},
    });

    assert.equal(attempts, 2);
    assert.deepEqual(
      readFileSync(join(standaloneDir, "runtime-assets", "tls-client", "bin", asset.file)),
      bytes
    );
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("non-host pinned download rejects a declared body above the shared 64 MiB bound", async () => {
  const rootDir = makeRoot();
  try {
    const bytes = Buffer.from("must-not-be-written");
    const asset = {
      file: "tls-client-non-host-oversize-test.bin",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const targetArch = process.arch === "arm64" ? "x64" : "arm64";
    const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
    mkdirSync(rootBin, { recursive: true });

    const logs: string[] = [];
    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset,
        platform: process.platform,
        arches: [targetArch],
        fetchImpl: async () =>
          new Response(bytes, {
            status: 200,
            headers: { "content-length": String(64 * 1024 * 1024 + 1) },
          }),
        retryDelaysMs: [],
        strict: true,
        log(message) {
          logs.push(message);
        },
      }),
      /Could not fetch tls-client-node.*after retries/
    );

    assert.equal(existsSync(join(rootBin, asset.file)), false);
    assert.ok(logs.some((message) => /exceeds the 64 MiB limit/.test(message)));
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});
