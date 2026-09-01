import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { dirname } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..", "..");
const execFileAsync = promisify(execFile);

const TLS_CLIENT_WRAPPERS = [
  "open-sse/services/chatgptTlsClient.ts",
  "open-sse/services/claudeTlsClient.ts",
  "open-sse/services/grokTlsClient.ts",
  "open-sse/services/perplexityTlsClient.ts",
  "open-sse/services/lmarenaTlsClient.ts",
  "open-sse/services/notionTlsClient.ts",
] as const;

const originalDataDir = process.env.DATA_DIR;

afterEach(() => {
  if (originalDataDir === undefined) {
    delete process.env.DATA_DIR;
  } else {
    process.env.DATA_DIR = originalDataDir;
  }
});

async function createTestTlsFetchStreaming({
  providerName,
  tempDirPrefix,
  tailFileVariant = "A",
}: {
  providerName: string;
  tempDirPrefix: string;
  tailFileVariant?: "A" | "B1" | "B2";
}) {
  const { createTlsClientModule } = await import("../../open-sse/services/tlsClientBase.ts");
  const tlsFetchStreaming = createTlsClientModule({
    providerName,
    tlsProfile: "chrome_146",
    domain: "https://example.test",
    tempDirPrefix,
    tailFileVariant,
    responseValidation: tailFileVariant === "A" ? "sse" : "cf",
    exportCloudflareCheck: false,
    exposeStreamingForTesting: true,
  }).__tlsFetchStreamingForTesting;
  assert.ok(tlsFetchStreaming);
  return tlsFetchStreaming;
}

test("resolveTlsClientDownloadDir caches native binary under DATA_DIR/tls-client/bin (#8579)", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-8579-"));
  process.env.DATA_DIR = dataDir;

  const { resolveTlsClientDownloadDir } =
    await import("../../open-sse/services/tlsClientDownloadDir.ts");

  assert.equal(resolveTlsClientDownloadDir(), join(dataDir, "tls-client", "bin"));
});

test("buildNativeTlsClientOptions pins v1.15.1 and passes downloadDir to tls-client-node", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-opts-8579-"));
  process.env.DATA_DIR = dataDir;

  const { buildNativeTlsClientOptions } =
    await import("../../open-sse/services/tlsClientDownloadDir.ts");

  const options = buildNativeTlsClientOptions();

  assert.equal(options.runtimeMode, "native");
  assert.equal(options.version, "1.15.1");
  assert.equal(options.downloadDir, join(dataDir, "tls-client", "bin"));
});

test("runtime downloader verifies v1.15.1 before exposing nativeLibraryPath", async () => {
  const downloadDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-verified-"));
  try {
    const bytes = Buffer.from("verified-runtime-binary");
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const requestedUrls: string[] = [];
    const { resolveVerifiedTlsClientNativeLibrary } =
      await import("../../open-sse/services/tlsClientDownloadDir.ts");

    const libraryPath = await resolveVerifiedTlsClientNativeLibrary({
      asset,
      downloadDir,
      fetchImpl: async (url: string | URL) => {
        requestedUrls.push(String(url));
        return new Response(bytes, { status: 200 });
      },
    });

    assert.deepEqual(requestedUrls, [
      `https://github.com/bogdanfinn/tls-client/releases/download/v1.15.1/${asset.file}`,
    ]);
    assert.equal(libraryPath, join(downloadDir, asset.file));
    assert.deepEqual(readFileSync(libraryPath), bytes);
  } finally {
    rmSync(downloadDir, { recursive: true, force: true });
  }
});

test("runtime downloader rejects bytes that do not match the official digest", async () => {
  const downloadDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-rejected-"));
  try {
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update("expected").digest("hex"),
    };
    const { resolveVerifiedTlsClientNativeLibrary } =
      await import("../../open-sse/services/tlsClientDownloadDir.ts");

    await assert.rejects(
      resolveVerifiedTlsClientNativeLibrary({
        asset,
        downloadDir,
        fetchImpl: async () => new Response("tampered", { status: 200 }),
      }),
      /SHA-256 mismatch for tls-client v1\.15\.1/
    );
    assert.equal(existsSync(join(downloadDir, asset.file)), false);
  } finally {
    rmSync(downloadDir, { recursive: true, force: true });
  }
});

test("runtime downloader rejects an oversized response before buffering it", async () => {
  const downloadDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-oversized-"));
  try {
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update("unused").digest("hex"),
    };
    const { resolveVerifiedTlsClientNativeLibrary } =
      await import("../../open-sse/services/tlsClientDownloadDir.ts");

    await assert.rejects(
      resolveVerifiedTlsClientNativeLibrary({
        asset,
        downloadDir,
        seedDirs: [],
        fetchImpl: async () =>
          new Response("not-read", {
            status: 200,
            headers: { "content-length": String(64 * 1024 * 1024 + 1) },
          }),
      }),
      /exceeds.*64 MiB|too large/i
    );
    assert.deepEqual(readdirSync(downloadDir), []);
  } finally {
    rmSync(downloadDir, { recursive: true, force: true });
  }
});

test("runtime resolver rejects an oversized local cache before reading or reaching the network", async () => {
  const downloadDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-local-oversized-"));
  try {
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update("unreachable").digest("hex"),
    };
    const oversizedPath = join(downloadDir, asset.file);
    writeFileSync(oversizedPath, "x");
    truncateSync(oversizedPath, 64 * 1024 * 1024 + 1);
    let networkReached = false;
    const { resolveVerifiedTlsClientNativeLibrary } =
      await import("../../open-sse/services/tlsClientDownloadDir.ts");

    await assert.rejects(
      resolveVerifiedTlsClientNativeLibrary({
        asset,
        downloadDir,
        seedDirs: [],
        fetchImpl: async () => {
          networkReached = true;
          throw new Error("network must not be reached for an oversized local cache");
        },
      }),
      /exceeds.*64 MiB|too large/i
    );
    assert.equal(networkReached, false);
  } finally {
    rmSync(downloadDir, { recursive: true, force: true });
  }
});

test("runtime resolver rejects a local cache that grows beyond the cap after fstat", async () => {
  const rootDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-growing-cache-"));
  const downloadDir = join(rootDir, "cache");
  const seedDir = join(rootDir, "seed");
  try {
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      // SHA-256 of a sparse, all-zero file exactly 64 MiB + 1 byte long.
      sha256: "91990977345985aaf03af1358f4f989d7eaf985b58529efb72f613c588f6599a",
    };
    mkdirSync(downloadDir, { recursive: true });
    mkdirSync(join(seedDir, asset.file), { recursive: true });
    const cachedPath = join(downloadDir, asset.file);
    writeFileSync(cachedPath, "");
    let cacheStatHooks = 0;
    let networkReached = false;
    const { resolveVerifiedTlsClientNativeLibrary } =
      await import("../../open-sse/services/tlsClientDownloadDir.ts");

    await assert.rejects(
      resolveVerifiedTlsClientNativeLibrary({
        asset,
        downloadDir,
        seedDirs: [seedDir],
        fetchImpl: async () => {
          networkReached = true;
          throw new Error("network must not be reached for a growing local cache");
        },
        testHooks: {
          afterOpenedFileStat: (openedPath) => {
            assert.equal(openedPath, cachedPath);
            cacheStatHooks++;
            truncateSync(cachedPath, 64 * 1024 * 1024 + 1);
          },
        },
      }),
      /exceeds.*64 MiB|too large/i
    );

    assert.equal(cacheStatHooks, 1);
    assert.equal(networkReached, false);
    assert.deepEqual(readdirSync(downloadDir), [asset.file]);
    assert.ok(lstatSync(join(seedDir, asset.file)).isDirectory());
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test(
  "runtime resolver normalizes an existing verified cache file to owner read-execute only",
  { skip: process.platform === "win32" },
  async () => {
    const downloadDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-cache-mode-"));
    try {
      const bytes = Buffer.from("verified-cache-binary-with-a-legacy-mode");
      const asset = {
        file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
        sha256: createHash("sha256").update(bytes).digest("hex"),
      };
      const cachedPath = join(downloadDir, asset.file);
      writeFileSync(cachedPath, bytes);
      chmodSync(cachedPath, 0o755);
      const { resolveVerifiedTlsClientNativeLibrary } =
        await import("../../open-sse/services/tlsClientDownloadDir.ts");

      const resolved = await resolveVerifiedTlsClientNativeLibrary({
        asset,
        downloadDir,
        seedDirs: [],
        fetchImpl: async () => {
          throw new Error("verified cache must avoid the network");
        },
      });

      assert.equal(resolved, cachedPath);
      assert.equal(lstatSync(cachedPath).mode & 0o777, 0o500);
    } finally {
      rmSync(downloadDir, { recursive: true, force: true });
    }
  }
);

test("runtime resolver rejects traversal and a checksum-valid symlink before any network access", async () => {
  const rootDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-path-safety-"));
  const downloadDir = join(rootDir, "cache");
  const outsidePath = join(rootDir, "outside.so");
  try {
    const bytes = Buffer.from("checksum-valid-but-outside-the-cache");
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const { resolveVerifiedTlsClientNativeLibrary } =
      await import("../../open-sse/services/tlsClientDownloadDir.ts");

    await assert.rejects(
      resolveVerifiedTlsClientNativeLibrary({
        asset: { file: "../outside.so", sha256 },
        downloadDir,
        fetchImpl: async () => {
          throw new Error("network must not be reached for an invalid asset path");
        },
      }),
      /invalid.*asset|asset.*path|traversal/i
    );

    writeFileSync(outsidePath, bytes);
    const safeAsset = { file: "tls-client-test.so", sha256 };
    const symlinkPath = join(downloadDir, safeAsset.file);
    await import("node:fs/promises").then(({ mkdir }) => mkdir(downloadDir, { recursive: true }));
    symlinkSync(outsidePath, symlinkPath);

    await assert.rejects(
      resolveVerifiedTlsClientNativeLibrary({
        asset: safeAsset,
        downloadDir,
        fetchImpl: async () => {
          throw new Error("network must not be reached for an unsafe cached symlink");
        },
      }),
      /symlink|regular file|unsafe/i
    );
    assert.ok(lstatSync(symlinkPath).isSymbolicLink(), "resolver must not follow or replace it");
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("runtime resolver retries when a completed owner removes the install lock before lstat", async () => {
  const rootDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-lock-race-"));
  const downloadDir = join(rootDir, "cache");
  const seedDir = join(rootDir, "seed");
  try {
    const bytes = Buffer.from("verified-binary-after-lock-owner-completes");
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const { mkdir, rmdir } = await import("node:fs/promises");
    await mkdir(downloadDir, { recursive: true });
    await mkdir(seedDir, { recursive: true });
    writeFileSync(join(seedDir, asset.file), bytes);
    const lockPath = join(downloadDir, `${asset.file}.lock`);
    await mkdir(lockPath);

    const { resolveVerifiedTlsClientNativeLibrary } =
      await import("../../open-sse/services/tlsClientDownloadDir.ts");
    let contentionHooks = 0;
    const resolved = await resolveVerifiedTlsClientNativeLibrary({
      asset,
      downloadDir,
      seedDirs: [seedDir],
      fetchImpl: async () => {
        throw new Error("verified seed should avoid the network");
      },
      testHooks: {
        afterInstallLockExists: async (observedLockPath) => {
          contentionHooks++;
          assert.equal(observedLockPath, lockPath);
          await rmdir(lockPath);
        },
      },
    });

    assert.equal(contentionHooks, 1);
    assert.equal(resolved, join(downloadDir, asset.file));
    assert.deepEqual(readFileSync(resolved), bytes);
    assert.deepEqual(readdirSync(downloadDir), [asset.file]);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("default runtime cache rejects a symlink below the trusted DATA_DIR", async () => {
  const rootDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-parent-symlink-"));
  const dataDir = join(rootDir, "data");
  const outsideDir = join(rootDir, "outside");
  const seedDir = join(rootDir, "seed");
  try {
    const bytes = Buffer.from("verified-binary-that-must-stay-inside-data-dir");
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const { mkdir } = await import("node:fs/promises");
    await mkdir(dataDir, { recursive: true });
    await mkdir(outsideDir, { recursive: true });
    await mkdir(seedDir, { recursive: true });
    writeFileSync(join(seedDir, asset.file), bytes);
    symlinkSync(outsideDir, join(dataDir, "tls-client"), "dir");
    process.env.DATA_DIR = dataDir;

    const { resolveVerifiedTlsClientNativeLibrary } =
      await import("../../open-sse/services/tlsClientDownloadDir.ts");
    await assert.rejects(
      resolveVerifiedTlsClientNativeLibrary({
        asset,
        seedDirs: [seedDir],
        fetchImpl: async () => {
          throw new Error("verified seed should avoid the network");
        },
      }),
      /unsafe|symlink|trusted.*directory/i
    );
    assert.equal(existsSync(join(outsideDir, "bin", asset.file)), false);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("parallel first-use installs are atomic and every caller receives the verified file", async () => {
  const downloadDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-concurrent-"));
  try {
    const bytes = Buffer.from("one-verified-binary-shared-by-concurrent-providers");
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const { resolveVerifiedTlsClientNativeLibrary } =
      await import("../../open-sse/services/tlsClientDownloadDir.ts");

    const outcomes = await Promise.allSettled(
      Array.from({ length: 100 }, () =>
        resolveVerifiedTlsClientNativeLibrary({
          asset,
          downloadDir,
          fetchImpl: async () => {
            await new Promise((resolve) => setImmediate(resolve));
            return new Response(bytes, { status: 200 });
          },
        })
      )
    );

    assert.equal(
      outcomes.filter((outcome) => outcome.status === "rejected").length,
      0,
      outcomes
        .filter((outcome) => outcome.status === "rejected")
        .map((outcome) => String((outcome as PromiseRejectedResult).reason))
        .join("\n")
    );
    const expectedPath = join(downloadDir, asset.file);
    assert.deepEqual(
      [...new Set(outcomes.map((outcome) => (outcome as PromiseFulfilledResult<string>).value))],
      [expectedPath]
    );
    assert.ok(lstatSync(expectedPath).isFile());
    assert.deepEqual(readFileSync(expectedPath), bytes);
    assert.deepEqual(readdirSync(downloadDir), [asset.file], "no lock or temporary may remain");
  } finally {
    rmSync(downloadDir, { recursive: true, force: true });
  }
});

test("parallel processes share one verified install and leave no lock or temporary", async () => {
  const rootDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-cross-process-"));
  const seedDir = join(rootDir, "seed");
  const downloadDir = join(rootDir, "cache");
  try {
    const bytes = Buffer.from("verified-cross-process-native-binary");
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    await import("node:fs/promises").then(({ mkdir }) => mkdir(seedDir, { recursive: true }));
    writeFileSync(join(seedDir, asset.file), bytes);

    const moduleUrl = pathToFileURL(
      join(ROOT, "open-sse", "services", "tlsClientDownloadDir.ts")
    ).href;
    const childSource = `
      import { resolveVerifiedTlsClientNativeLibrary } from ${JSON.stringify(moduleUrl)};
      const resolved = await resolveVerifiedTlsClientNativeLibrary({
        asset: ${JSON.stringify(asset)},
        downloadDir: ${JSON.stringify(downloadDir)},
        seedDirs: [${JSON.stringify(seedDir)}],
        fetchImpl: async () => { throw new Error("network forbidden"); },
      });
      process.stdout.write(resolved);
    `;

    const children = await Promise.all(
      Array.from({ length: 12 }, () =>
        execFileAsync(
          process.execPath,
          ["--import", "tsx/esm", "--input-type=module", "--eval", childSource],
          { cwd: ROOT, timeout: 90_000, maxBuffer: 1024 * 1024 }
        )
      )
    );
    const expectedPath = join(downloadDir, asset.file);
    assert.deepEqual([...new Set(children.map(({ stdout }) => stdout))], [expectedPath]);
    assert.deepEqual(readdirSync(downloadDir), [asset.file]);
    assert.ok(lstatSync(expectedPath).isFile());
    assert.deepEqual(readFileSync(expectedPath), bytes);
    assert.equal(lstatSync(downloadDir).mode & 0o077, 0, "cache directory must be private");
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("stream fallback sanitizes a request rejection before the first byte", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "omniroute-tls-stream-first-byte-error-"));
  process.env.DATA_DIR = dataDir;
  try {
    const tlsFetchStreaming = await createTestTlsFetchStreaming({
      providerName: "test-provider",
      tempDirPrefix: "tls-stream-first-byte-error-",
    });

    const result = await tlsFetchStreaming(
      {
        request: async () => {
          throw new Error(
            "TLS request rejected at /srv/omniroute/private/tls-client.ts:77:9; " +
              "access_token=first-byte-secret\n" +
              "    at /srv/omniroute/private/stack-frame.ts:88:10"
          );
        },
      },
      "https://example.test/stream",
      {},
      "[DONE]",
      null,
      1_000,
      100
    );

    assert.equal(result.status, 502);
    assert.equal(result.body, null);
    assert.deepEqual([...result.headers], []);
    assert.match(result.text ?? "", /TLS request rejected/);
    assert.match(result.text ?? "", /<path>/);
    assert.doesNotMatch(result.text ?? "", /srv\/omniroute|first-byte-secret|stack-frame\.ts/);
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test("stream fallback sanitizes a request rejection after invalid SSE bytes", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "omniroute-tls-stream-invalid-sse-error-"));
  process.env.DATA_DIR = dataDir;
  try {
    const tlsFetchStreaming = await createTestTlsFetchStreaming({
      providerName: "test-provider",
      tempDirPrefix: "tls-stream-invalid-sse-error-",
    });

    const result = await tlsFetchStreaming(
      {
        request: (_url, options) => {
          const streamOutputPath = options.streamOutputPath;
          assert.equal(typeof streamOutputPath, "string");
          writeFileSync(streamOutputPath, "invalid buffered payload");
          return Promise.reject(
            new Error(
              "TLS request rejected at C:\\OmniRoute\\private\\tls-client.ts:77:9; " +
                "access_token=invalid-sse-secret\n" +
                "    at C:\\OmniRoute\\private\\stack-frame.ts:88:10"
            )
          );
        },
      },
      "https://example.test/stream",
      {},
      "[DONE]",
      null,
      1_000,
      100
    );

    assert.equal(result.status, 502);
    assert.equal(result.body, null);
    assert.deepEqual([...result.headers], []);
    assert.match(result.text ?? "", /TLS request rejected/);
    assert.match(result.text ?? "", /<path>/);
    assert.doesNotMatch(result.text ?? "", /C:\\OmniRoute|invalid-sse-secret|stack-frame\.ts/);

    for (const emptyRejection of ["", null, undefined]) {
      const emptyRejectionResult = await tlsFetchStreaming(
        {
          request: (_url, options) => {
            const streamOutputPath = options.streamOutputPath;
            assert.equal(typeof streamOutputPath, "string");
            writeFileSync(
              streamOutputPath,
              "invalid at /srv/private/invalid-sse.ts; access_token=file-secret"
            );
            return Promise.reject(emptyRejection);
          },
        },
        "https://example.test/stream",
        {},
        "[DONE]",
        null,
        1_000,
        100
      );

      assert.equal(emptyRejectionResult.status, 502);
      assert.equal(emptyRejectionResult.body, null);
      assert.deepEqual([...emptyRejectionResult.headers], []);
      assert.equal(emptyRejectionResult.text, "TLS client request failed");
      assert.doesNotMatch(
        emptyRejectionResult.text,
        /srv\/private|invalid-sse\.ts|file-secret|access_token/
      );
    }
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test("variant B1 closes cleanly when a native request completes without an EOF marker", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "omniroute-tls-stream-b1-clean-close-"));
  process.env.DATA_DIR = dataDir;
  try {
    const tlsFetchStreaming = await createTestTlsFetchStreaming({
      providerName: "test-provider-B1-clean-close",
      tempDirPrefix: "tls-stream-b1-clean-close-",
      tailFileVariant: "B1",
    });

    const result = await tlsFetchStreaming(
      {
        request: (_url, options) => {
          const streamOutputPath = options.streamOutputPath;
          assert.equal(typeof streamOutputPath, "string");
          writeFileSync(streamOutputPath, '{"delta":"ok"}\n');
          return Promise.resolve({ status: 204, headers: { "x-upstream": "present" }, body: "" });
        },
      },
      "https://example.test/stream",
      {},
      "[DONE]",
      null,
      1_000,
      100
    );

    assert.equal(result.status, 200);
    assert.equal(result.text, null);
    assert.equal(result.headers.get("content-type"), "application/x-ndjson");
    assert.equal(result.headers.get("cache-control"), "no-cache");
    assert.ok(result.body);
    assert.equal(await new Response(result.body).text(), '{"delta":"ok"}\n');
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test("stream boundary sanitizes a synchronous native request throw and cleans its temp path", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "omniroute-tls-stream-sync-throw-"));
  process.env.DATA_DIR = dataDir;
  let streamOutputPath = "";
  try {
    const tlsFetchStreaming = await createTestTlsFetchStreaming({
      providerName: "test-provider-sync-throw",
      tempDirPrefix: "tls-stream-sync-throw-",
    });

    const nativeError = new Error(
      "native sync throw at /srv/private/native.ts:7; access_token=sync-secret"
    );
    nativeError.name = "NativeTlsError";

    await assert.rejects(
      tlsFetchStreaming(
        {
          request: (_url, options) => {
            assert.equal(typeof options.streamOutputPath, "string");
            streamOutputPath = options.streamOutputPath;
            throw nativeError;
          },
        },
        "https://example.test/stream",
        {},
        "[DONE]",
        null,
        1_000,
        100
      ),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.notEqual(err, nativeError);
        assert.equal(err.name, "NativeTlsError");
        assert.match(err.message, /native sync throw/);
        assert.match(err.message, /<path>/);
        assert.doesNotMatch(err.message, /srv\/private|sync-secret|access_token/);
        assert.equal(err.stack, `NativeTlsError: ${err.message}`);
        assert.equal(err.cause, undefined);
        return true;
      }
    );

    assert.ok(streamOutputPath);
    assert.equal(existsSync(streamOutputPath), false);
    assert.equal(existsSync(dirname(streamOutputPath)), false);
  } finally {
    if (streamOutputPath) rmSync(dirname(streamOutputPath), { recursive: true, force: true });
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test("stream boundary sanitizes a pre-adapter read failure and cleans its temp root", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "omniroute-tls-stream-peek-error-"));
  process.env.DATA_DIR = dataDir;
  let streamOutputPath = "";
  try {
    const tlsFetchStreaming = await createTestTlsFetchStreaming({
      providerName: "test-provider-peek-error",
      tempDirPrefix: "tls-stream-peek-error-",
    });

    await assert.rejects(
      tlsFetchStreaming(
        {
          request: (_url, options) => {
            assert.equal(typeof options.streamOutputPath, "string");
            streamOutputPath = options.streamOutputPath;
            mkdirSync(streamOutputPath);
            return Promise.resolve({ status: 200, headers: {}, body: "" });
          },
        },
        "https://example.test/stream",
        {},
        "[DONE]",
        null,
        1_000,
        100
      ),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal(err.name, "Error");
        assert.match(err.message, /EISDIR/);
        assert.doesNotMatch(err.message, /tls-stream-peek-error|tlsClientBase\.ts|worktrees/);
        assert.equal(err.stack, `Error: ${err.message}`);
        assert.equal(err.cause, undefined);
        return true;
      }
    );

    assert.ok(streamOutputPath);
    assert.equal(existsSync(streamOutputPath), false);
    assert.equal(existsSync(dirname(streamOutputPath)), false);
  } finally {
    if (streamOutputPath) rmSync(dirname(streamOutputPath), { recursive: true, force: true });
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test("valid SSE streams sanitize terminal request rejections for every tail variant", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "omniroute-tls-stream-terminal-error-"));
  process.env.DATA_DIR = dataDir;
  try {
    for (const tailFileVariant of ["A", "B1", "B2"] as const) {
      const tlsFetchStreaming = await createTestTlsFetchStreaming({
        providerName: `test-provider-${tailFileVariant}`,
        tempDirPrefix: `tls-stream-terminal-error-${tailFileVariant}-`,
        tailFileVariant,
      });

      const nativeError = new Error(
        "TLS request rejected at /srv/omniroute/private/tls-client.ts:77:9; " +
          "access_token=stream-secret\n" +
          "    at /srv/omniroute/private/stack-frame.ts:88:10"
      );
      nativeError.name = "NativeTlsError";

      const result = await tlsFetchStreaming(
        {
          request: (_url, options) => {
            const streamOutputPath = options.streamOutputPath;
            assert.equal(typeof streamOutputPath, "string");
            writeFileSync(streamOutputPath, 'data: {"delta":"ok"}\n\n');
            return Promise.reject(nativeError);
          },
        },
        "https://example.test/stream",
        {},
        "[DONE]",
        null,
        1_000,
        100
      );

      assert.equal(result.status, 200, tailFileVariant);
      assert.equal(result.text, null, tailFileVariant);
      assert.ok(result.body, tailFileVariant);
      const reader = result.body.getReader();
      const firstChunk = await reader.read();
      assert.equal(firstChunk.done, false, tailFileVariant);
      assert.match(Buffer.from(firstChunk.value).toString("utf8"), /^data:/, tailFileVariant);

      await assert.rejects(reader.read(), (err: unknown) => {
        assert.ok(err instanceof Error, tailFileVariant);
        assert.notEqual(err, nativeError, tailFileVariant);
        assert.equal(err.name, "NativeTlsError", tailFileVariant);
        assert.match(err.message, /TLS request rejected/, tailFileVariant);
        assert.doesNotMatch(err.message, /^NativeTlsError:/, tailFileVariant);
        assert.match(err.message, /<path>/, tailFileVariant);
        assert.doesNotMatch(
          err.message,
          /srv\/omniroute|stream-secret|stack-frame\.ts/,
          tailFileVariant
        );
        assert.doesNotMatch(
          err.stack ?? "",
          /srv\/omniroute|stream-secret|stack-frame\.ts|tlsClientBase\.ts/,
          tailFileVariant
        );
        assert.equal(err.cause, undefined, tailFileVariant);
        return true;
      });
    }
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test("valid SSE streams use a stable terminal error for empty rejection values", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "omniroute-tls-stream-empty-error-"));
  process.env.DATA_DIR = dataDir;
  try {
    const maliciousNamedEmptyError = new Error("");
    maliciousNamedEmptyError.name =
      "NativeTlsError\naccess_token=name-secret /srv/private/error-name.ts";
    for (const tailFileVariant of ["A", "B1", "B2"] as const) {
      for (const emptyRejection of [maliciousNamedEmptyError, "", null, undefined]) {
        const tlsFetchStreaming = await createTestTlsFetchStreaming({
          providerName: `test-provider-${tailFileVariant}`,
          tempDirPrefix: `tls-stream-empty-error-${tailFileVariant}-`,
          tailFileVariant,
        });

        const result = await tlsFetchStreaming(
          {
            request: (_url, options) => {
              const streamOutputPath = options.streamOutputPath;
              assert.equal(typeof streamOutputPath, "string");
              writeFileSync(streamOutputPath, 'data: {"delta":"ok"}\n\n');
              return Promise.reject(emptyRejection);
            },
          },
          "https://example.test/stream",
          {},
          "[DONE]",
          null,
          1_000,
          100
        );

        assert.equal(result.status, 200, tailFileVariant);
        assert.ok(result.body, tailFileVariant);
        const reader = result.body.getReader();
        assert.equal((await reader.read()).done, false, tailFileVariant);
        await assert.rejects(reader.read(), (err: unknown) => {
          assert.ok(err instanceof Error, tailFileVariant);
          assert.equal(err.name, "Error", tailFileVariant);
          assert.equal(err.message, "TLS client request failed", tailFileVariant);
          assert.equal(err.stack, "Error: TLS client request failed", tailFileVariant);
          assert.doesNotMatch(err.stack, /name-secret|srv\/private|access_token/, tailFileVariant);
          assert.equal(err.cause, undefined, tailFileVariant);
          return true;
        });
      }
    }
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test("runtime materializes a verified bundled seed without network access", async () => {
  const rootDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-offline-seed-"));
  const seedDir = join(rootDir, "standalone", "runtime-assets", "tls-client", "bin");
  const downloadDir = join(rootDir, "writable-data", "tls-client", "bin");
  try {
    const bytes = Buffer.from("verified-binary-bundled-in-the-standalone-artifact");
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    await import("node:fs/promises").then(({ mkdir }) => mkdir(seedDir, { recursive: true }));
    writeFileSync(join(seedDir, asset.file), bytes);
    const { resolveVerifiedTlsClientNativeLibrary } =
      await import("../../open-sse/services/tlsClientDownloadDir.ts");

    const resolved = await resolveVerifiedTlsClientNativeLibrary({
      asset,
      downloadDir,
      seedDirs: [seedDir],
      fetchImpl: async () => {
        throw new Error("offline runtime must use the bundled verified seed");
      },
    });

    assert.equal(resolved, join(downloadDir, asset.file));
    assert.deepEqual(readFileSync(resolved), bytes);
    assert.ok(lstatSync(resolved).isFile());
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("default seed search follows the installed tls-client-node package outside the CLI cwd", async () => {
  const rootDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-package-seed-"));
  const packageDir = join(rootDir, "package", "node_modules", "tls-client-node");
  const seedDir = join(packageDir, "bin");
  const downloadDir = join(rootDir, "writable-data", "tls-client", "bin");
  try {
    const bytes = Buffer.from("verified-binary-installed-by-the-optional-dependency");
    const asset = {
      file: "tls-client-test-resolved-package.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    mkdirSync(seedDir, { recursive: true });
    writeFileSync(join(packageDir, "package.json"), '{"name":"tls-client-node"}\n');
    writeFileSync(join(seedDir, asset.file), bytes);
    const { resolveVerifiedTlsClientNativeLibrary } =
      await import("../../open-sse/services/tlsClientDownloadDir.ts");
    let networkReached = false;

    const resolved = await resolveVerifiedTlsClientNativeLibrary({
      asset,
      downloadDir,
      fetchImpl: async () => {
        networkReached = true;
        throw new Error("offline CLI runtime must use the package-resolved verified seed");
      },
      testHooks: {
        resolveTlsClientPackageJson: () => join(packageDir, "package.json"),
      },
    });

    assert.equal(networkReached, false);
    assert.equal(resolved, join(downloadDir, asset.file));
    assert.deepEqual(readFileSync(resolved), bytes);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("all web-provider tls clients wire downloadDir through buildNativeTlsClientOptions (#8579)", () => {
  const base = readFileSync(join(ROOT, "open-sse/services/tlsClientBase.ts"), "utf8");
  assert.match(
    base,
    /dependencies\.resolveNativeLibrary\s*\?\?\s*resolveVerifiedTlsClientNativeLibrary/,
    "tlsClientBase.ts must verify the pinned native library before TLSClient loads it"
  );
  assert.match(
    base,
    /buildNativeTlsClientOptions\(nativeLibraryPath\)/,
    "tlsClientBase.ts must pass the verified nativeLibraryPath to TLSClient"
  );
  assert.doesNotMatch(
    base,
    /new TLSClient\(\{\s*runtimeMode:\s*"native"\s*\}\)/,
    "tlsClientBase.ts must not construct TLSClient without downloadDir"
  );

  for (const relPath of TLS_CLIENT_WRAPPERS) {
    const source = readFileSync(join(ROOT, relPath), "utf8");
    assert.match(
      source,
      /createTlsClientModule\(/,
      `${relPath} must go through createTlsClientModule so downloadDir is inherited`
    );
    assert.doesNotMatch(
      source,
      /new TLSClient\(\{\s*runtimeMode:\s*"native"\s*\}\)/,
      `${relPath} must not construct TLSClient without downloadDir`
    );
  }
});
