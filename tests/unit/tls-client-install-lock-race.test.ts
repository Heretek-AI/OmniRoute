import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { lstat, open, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

import { resolveVerifiedTlsClientNativeLibrary } from "../../open-sse/services/tlsClientDownloadDir";

const REPLACEMENT_LOCK_TOKEN = "00000000-0000-4000-8000-0000000000b2";
const execFileAsync = promisify(execFile);

test("runtime resolver retries when its newly-created install lock disappears before lstat", async () => {
  const rootDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-created-lock-race-"));

  try {
    const bytes = Buffer.from("verified-binary-after-created-lock-disappears");
    const asset = {
      file: "tls-client-created-lock-race.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const downloadDir = join(rootDir, "tls-client", "bin");
    let fetchCalls = 0;
    let createdHookCalls = 0;

    const resolvedPath = await resolveVerifiedTlsClientNativeLibrary({
      asset,
      downloadDir,
      seedDirs: [],
      fetchImpl: async () => {
        fetchCalls += 1;
        return new Response(bytes, { status: 200 });
      },
      testHooks: {
        afterInstallLockCreated: async (lockPath) => {
          createdHookCalls += 1;
          await rm(lockPath, { recursive: true });
        },
      },
    });

    assert.equal(resolvedPath, join(downloadDir, asset.file));
    assert.deepEqual(readFileSync(resolvedPath), bytes);
    assert.equal(createdHookCalls, 1, "the scheduling hook must be consumed after one use");
    assert.equal(fetchCalls, 1);
    assert.deepEqual(readdirSync(downloadDir), [asset.file], "no install lock may remain");
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("runtime resolver never claims a replacement install lock created by another owner", async () => {
  const rootDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-replaced-lock-race-"));

  try {
    const bytes = Buffer.from("verified-binary-after-replacement-owner-completes");
    const asset = {
      file: "tls-client-replaced-lock-race.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const downloadDir = join(rootDir, "tls-client", "bin");
    let fetchCalls = 0;
    let createdHookCalls = 0;
    let contentionHookCalls = 0;
    let replacementHandle: Awaited<ReturnType<typeof open>> | undefined;

    try {
      const resolvedPath = await resolveVerifiedTlsClientNativeLibrary({
        asset,
        downloadDir,
        seedDirs: [],
        fetchImpl: async () => {
          fetchCalls += 1;
          return new Response(bytes, { status: 200 });
        },
        testHooks: {
          afterInstallLockCreated: async (lockPath) => {
            createdHookCalls += 1;
            await rm(lockPath);
            replacementHandle = await open(lockPath, "wx", 0o600);
            await replacementHandle.writeFile(REPLACEMENT_LOCK_TOKEN);
            await replacementHandle.sync();
          },
          afterInstallLockExists: async (lockPath) => {
            contentionHookCalls += 1;
            assert.equal(fetchCalls, 0, "the displaced owner must not run the install operation");
            assert.equal(readFileSync(lockPath, "utf8"), REPLACEMENT_LOCK_TOKEN);
            await replacementHandle?.close();
            replacementHandle = undefined;
            await rm(lockPath);
          },
        },
      });

      assert.equal(resolvedPath, join(downloadDir, asset.file));
      assert.deepEqual(readFileSync(resolvedPath), bytes);
      assert.equal(createdHookCalls, 1, "the scheduling hook must be consumed after one use");
      assert.equal(contentionHookCalls, 1, "the replacement lock must be observed as contended");
      assert.equal(fetchCalls, 1);
      assert.deepEqual(readdirSync(downloadDir), [asset.file], "no install lock may remain");
    } finally {
      await replacementHandle?.close();
    }
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("runtime resolver preserves another owner's same-inode lock claim during cleanup", async () => {
  const rootDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-live-lock-race-"));

  try {
    const bytes = Buffer.from("verified-binary-while-another-owner-holds-the-lock");
    const asset = {
      file: "tls-client-live-lock-race.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const downloadDir = join(rootDir, "tls-client", "bin");
    const lockPath = join(downloadDir, `${asset.file}.lock`);
    let replacementIdentity: { dev: number | bigint; ino: number | bigint } | undefined;
    let replacementHandle: Awaited<ReturnType<typeof open>> | undefined;
    let fetchCalls = 0;

    try {
      const resolvedPath = await resolveVerifiedTlsClientNativeLibrary({
        asset,
        downloadDir,
        seedDirs: [],
        fetchImpl: async () => {
          fetchCalls += 1;
          replacementHandle = await open(lockPath, "r+");
          await replacementHandle.truncate(0);
          await replacementHandle.writeFile(REPLACEMENT_LOCK_TOKEN);
          await replacementHandle.sync();
          replacementIdentity = await replacementHandle.stat({ bigint: true });

          return new Response(bytes, { status: 200 });
        },
        testHooks: {
          afterInstallLockCreated: async (observedLockPath) => {
            assert.equal(observedLockPath, lockPath);
          },
        },
      });

      assert.equal(resolvedPath, join(downloadDir, asset.file));
      assert.deepEqual(readFileSync(resolvedPath), bytes);
      assert.equal(fetchCalls, 1, "the displaced owner must not duplicate the install operation");
      assert.ok(replacementIdentity, "the replacement owner must create a regular lockfile");
      const survivingStats = await lstat(lockPath, { bigint: true });
      assert.equal(survivingStats.isFile(), true);
      assert.equal(String(survivingStats.dev), String(replacementIdentity.dev));
      assert.equal(String(survivingStats.ino), String(replacementIdentity.ino));
      assert.equal(readFileSync(lockPath, "utf8"), REPLACEMENT_LOCK_TOKEN);
    } finally {
      await replacementHandle?.close();
      await rm(lockPath, { force: true });
    }
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test(
  "runtime resolver fails closed instead of blocking on a replacement FIFO lock",
  { skip: process.platform === "win32" },
  async () => {
    const rootDir = mkdtempSync(join(tmpdir(), "omniroute-tls-client-fifo-lock-race-"));

    try {
      const bytes = Buffer.from("verified-binary-that-must-not-follow-a-fifo-lock");
      const asset = {
        file: "tls-client-fifo-lock-race.so",
        sha256: createHash("sha256").update(bytes).digest("hex"),
      };
      const downloadDir = join(rootDir, "tls-client", "bin");
      const moduleUrl = pathToFileURL(
        join(process.cwd(), "open-sse", "services", "tlsClientDownloadDir.ts")
      ).href;
      const childSource = `
        import { execFileSync } from "node:child_process";
        import { rm } from "node:fs/promises";
        import { resolveVerifiedTlsClientNativeLibrary } from ${JSON.stringify(moduleUrl)};

        try {
          await resolveVerifiedTlsClientNativeLibrary({
            asset: ${JSON.stringify(asset)},
            downloadDir: ${JSON.stringify(downloadDir)},
            seedDirs: [],
            fetchImpl: async () => { throw new Error("network must not be reached"); },
            testHooks: {
              afterInstallLockCreated: async (lockPath) => {
                await rm(lockPath);
                execFileSync("mkfifo", [lockPath]);
              },
            },
          });
          process.stdout.write("unexpected success");
          process.exitCode = 2;
        } catch (err) {
          process.stdout.write(err instanceof Error ? err.message : String(err));
        }
      `;

      const { stdout } = await execFileAsync(
        process.execPath,
        ["--import", "tsx/esm", "--input-type=module", "--eval", childSource],
        { cwd: process.cwd(), timeout: 8_000, maxBuffer: 1024 * 1024 }
      );

      assert.match(stdout, /Unsafe tls-client install lock/);
    } finally {
      rmSync(rootDir, { recursive: true, force: true });
    }
  }
);
