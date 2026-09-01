import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { chmod, lstat, mkdir, open, realpath, rename, rm, rmdir } from "node:fs/promises";
import { createRequire } from "node:module";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { resolveDataDir } from "@/lib/dataPaths";
import tlsClientNativeManifest from "../config/tlsClientNativeManifest.json";

type TlsClientNativeAsset = {
  file: string;
  sha256: string;
};

type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;
type NativeResolverTestHooks = {
  afterOpenedFileStat?: (filePath: string) => void | Promise<void>;
  afterInstallLockCreated?: (lockPath: string) => void | Promise<void>;
  afterInstallLockExists?: (lockPath: string) => void | Promise<void>;
  resolveTlsClientPackageJson?: () => string;
};

const TLS_CLIENT_NATIVE_ASSETS = tlsClientNativeManifest.assets as Record<
  string,
  TlsClientNativeAsset
>;
const INSTALL_LOCK_TIMEOUT_MS = 75_000;
const STALE_INSTALL_LOCK_MS = 60_000;
const MAX_NATIVE_ASSET_BYTES = 64 * 1024 * 1024;
const NATIVE_ASSET_READ_CHUNK_BYTES = 64 * 1024;
const MAX_INSTALL_LOCK_TOKEN_BYTES = 128;
const moduleRequire = createRequire(import.meta.url);

function validateNativeAsset(asset: TlsClientNativeAsset): void {
  if (
    !asset.file ||
    asset.file === "." ||
    asset.file === ".." ||
    basename(asset.file) !== asset.file ||
    asset.file.includes("/") ||
    asset.file.includes("\\") ||
    asset.file.includes("\0")
  ) {
    throw new Error(`Invalid tls-client native asset path: ${JSON.stringify(asset.file)}`);
  }
  if (!/^[a-f0-9]{64}$/.test(asset.sha256)) {
    throw new Error(`Invalid SHA-256 in tls-client native manifest for ${asset.file}`);
  }
}

async function resolveSafeDirectory(
  directoryPath: string,
  trustedRoot: string = directoryPath
): Promise<string> {
  const absolutePath = resolve(directoryPath);
  const absoluteRoot = resolve(trustedRoot);
  const relativePath = relative(absoluteRoot, absolutePath);
  if (relativePath === ".." || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) {
    throw new Error(`Unsafe tls-client native directory outside trusted root: ${absolutePath}`);
  }

  // The configured DATA_DIR itself is an operator-controlled trust anchor and
  // may legitimately be a symlink (for example to a mounted volume). Every
  // component created below it must be a real directory, never another link.
  await mkdir(absoluteRoot, { recursive: true, mode: 0o700 });
  const canonicalRoot = await realpath(absoluteRoot);
  const rootStats = await lstat(canonicalRoot);
  if (!rootStats.isDirectory()) {
    throw new Error(`Unsafe tls-client trusted directory: ${absoluteRoot}`);
  }

  let currentPath = absoluteRoot;
  const components = relativePath ? relativePath.split(sep).filter(Boolean) : [];
  for (const component of components) {
    currentPath = join(currentPath, component);
    try {
      await mkdir(currentPath, { mode: 0o700 });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    }
    const stats = await lstat(currentPath);
    if (stats.isSymbolicLink() || !stats.isDirectory()) {
      throw new Error(`Unsafe tls-client native directory component: ${currentPath}`);
    }
  }

  const canonicalPath = await realpath(absolutePath);
  const expectedCanonicalPath = resolve(canonicalRoot, relativePath);
  if (canonicalPath !== expectedCanonicalPath) {
    throw new Error(`Unsafe tls-client native directory redirection: ${absolutePath}`);
  }
  await chmod(canonicalPath, 0o700);
  return canonicalPath;
}

function sameFileIdentity(
  left: { dev: number | bigint; ino: number | bigint },
  right: { dev: number | bigint; ino: number | bigint }
): boolean {
  return String(left.dev) === String(right.dev) && String(left.ino) === String(right.ino);
}

async function readInstallLockClaim(lockPath: string) {
  let handle;
  try {
    handle = await open(
      lockPath,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0)
    );
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ELOOP" || code === "EISDIR") return undefined;
    throw err;
  }

  try {
    const openedStats = await handle.stat({ bigint: true });
    if (
      !openedStats.isFile() ||
      openedStats.size <= 0n ||
      openedStats.size > BigInt(MAX_INSTALL_LOCK_TOKEN_BYTES)
    ) {
      return undefined;
    }

    const bytes = Buffer.alloc(Number(openedStats.size));
    let bytesReadTotal = 0;
    while (bytesReadTotal < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        bytesReadTotal,
        bytes.length - bytesReadTotal,
        bytesReadTotal
      );
      if (bytesRead === 0) break;
      bytesReadTotal += bytesRead;
    }

    const verifiedStats = await handle.stat({ bigint: true });
    if (
      bytesReadTotal !== bytes.length ||
      verifiedStats.size !== openedStats.size ||
      !sameFileIdentity(openedStats, verifiedStats)
    ) {
      return undefined;
    }

    let pathStats;
    try {
      pathStats = await lstat(lockPath, { bigint: true });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw err;
    }
    if (
      pathStats.isSymbolicLink() ||
      !pathStats.isFile() ||
      !sameFileIdentity(openedStats, pathStats)
    ) {
      return undefined;
    }

    return { stats: openedStats, token: bytes.toString("utf8") };
  } finally {
    await handle.close();
  }
}

/**
 * Read and verify one regular file without following a final-component symlink.
 * The second lstat closes the ordinary check/read path-swap window: callers only
 * receive bytes when the pathname still identifies the inode that was opened.
 */
async function readVerifiedRegularFile(
  filePath: string,
  expectedSha256: string,
  {
    normalizeMode = false,
    afterOpenedFileStat,
  }: {
    normalizeMode?: boolean;
    afterOpenedFileStat?: NativeResolverTestHooks["afterOpenedFileStat"];
  } = {}
): Promise<Buffer | undefined> {
  let pathStats;
  try {
    pathStats = await lstat(filePath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw err;
  }
  if (pathStats.isSymbolicLink() || !pathStats.isFile()) {
    throw new Error(`Unsafe tls-client native cache entry (symlink/non-regular file): ${filePath}`);
  }

  let handle;
  try {
    handle = await open(filePath, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ELOOP") {
      throw new Error(`Unsafe tls-client native cache entry (symlink): ${filePath}`);
    }
    throw err;
  }

  try {
    const openedStats = await handle.stat();
    if (!openedStats.isFile()) {
      throw new Error(`Unsafe tls-client native cache entry (not a regular file): ${filePath}`);
    }
    if (openedStats.size > MAX_NATIVE_ASSET_BYTES) {
      throw new Error(`Local tls-client native asset exceeds the 64 MiB limit: ${filePath}`);
    }
    await afterOpenedFileStat?.(filePath);

    const readBuffer = Buffer.alloc(openedStats.size);
    let bytesReadTotal = 0;
    while (bytesReadTotal < readBuffer.length) {
      const bytesToRead = Math.min(
        NATIVE_ASSET_READ_CHUNK_BYTES,
        readBuffer.length - bytesReadTotal
      );
      const { bytesRead } = await handle.read(
        readBuffer,
        bytesReadTotal,
        bytesToRead,
        bytesReadTotal
      );
      if (bytesRead === 0) break;
      bytesReadTotal += bytesRead;
    }
    const bytes = readBuffer.subarray(0, bytesReadTotal);
    const verifiedStats = await handle.stat();
    if (verifiedStats.size > MAX_NATIVE_ASSET_BYTES) {
      throw new Error(`Local tls-client native asset exceeds the 64 MiB limit: ${filePath}`);
    }
    if (
      !verifiedStats.isFile() ||
      !sameFileIdentity(openedStats, verifiedStats) ||
      verifiedStats.size !== openedStats.size ||
      bytes.length !== verifiedStats.size
    ) {
      throw new Error(
        `Unsafe tls-client native cache entry changed during verification: ${filePath}`
      );
    }
    const currentStats = await lstat(filePath);
    if (
      currentStats.isSymbolicLink() ||
      !currentStats.isFile() ||
      !sameFileIdentity(openedStats, currentStats)
    ) {
      throw new Error(
        `Unsafe tls-client native cache entry changed during verification: ${filePath}`
      );
    }
    if (createHash("sha256").update(bytes).digest("hex") !== expectedSha256) return undefined;
    if (normalizeMode && process.platform !== "win32") await handle.chmod(0o500);
    return bytes;
  } finally {
    await handle.close();
  }
}

async function installVerifiedBytes(
  downloadDir: string,
  asset: TlsClientNativeAsset,
  bytes: Buffer
): Promise<string> {
  const actualSha256 = createHash("sha256").update(bytes).digest("hex");
  if (actualSha256 !== asset.sha256) {
    throw new Error(
      `SHA-256 mismatch for tls-client v${tlsClientNativeManifest.version} native asset ` +
        `${asset.file}: expected ${asset.sha256}, received ${actualSha256}`
    );
  }

  const safeDir = await resolveSafeDirectory(downloadDir);
  const destinationPath = join(safeDir, asset.file);
  if (dirname(destinationPath) !== safeDir) {
    throw new Error(`Invalid tls-client native asset path: ${asset.file}`);
  }

  const existingBytes = await readVerifiedRegularFile(destinationPath, asset.sha256, {
    normalizeMode: true,
  });
  if (existingBytes) return destinationPath;

  const temporaryPath = join(safeDir, `.${asset.file}.${process.pid}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(
      temporaryPath,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        (fsConstants.O_NOFOLLOW ?? 0),
      0o500
    );
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;

    if (!(await readVerifiedRegularFile(temporaryPath, asset.sha256, { normalizeMode: true }))) {
      throw new Error(`SHA-256 mismatch after writing ${asset.file}`);
    }

    // POSIX rename replaces atomically. No rm-before-rename window means six
    // provider clients can initialize together without deleting each other's
    // verified result. On Windows, accept a concurrently installed valid file.
    try {
      await rename(temporaryPath, destinationPath);
    } catch (err) {
      if (!(await readVerifiedRegularFile(destinationPath, asset.sha256, { normalizeMode: true })))
        throw err;
    }

    if (!(await readVerifiedRegularFile(destinationPath, asset.sha256, { normalizeMode: true }))) {
      throw new Error(`SHA-256 mismatch after installing ${asset.file}`);
    }
    return destinationPath;
  } finally {
    await handle?.close();
    await rm(temporaryPath, { force: true });
  }
}

/**
 * Local-filesystem lease for one native-asset install. O_EXCL + a bounded nonce
 * fences ordinary owner replacement while the handle is live. This is not a
 * distributed NFS/CIFS lock: after the 60-second stale lease, Node has no
 * portable compare-and-unlink primitive, so digest checks and atomic install
 * remain the final safety boundary if an event-loop stall allows overlap.
 */
async function withNativeAssetInstallLock(
  destinationPath: string,
  expectedSha256: string,
  operation: () => Promise<string>,
  testHooks?: NativeResolverTestHooks
): Promise<string> {
  const lockPath = `${destinationPath}.lock`;
  const startedAt = Date.now();
  let acquiredLockHandle: Awaited<ReturnType<typeof open>> | undefined;
  let acquiredLockToken: string | undefined;
  let afterInstallLockCreated = testHooks?.afterInstallLockCreated;

  while (!acquiredLockHandle) {
    let createdLockHandle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      createdLockHandle = await open(
        lockPath,
        fsConstants.O_RDWR |
          fsConstants.O_CREAT |
          fsConstants.O_EXCL |
          (fsConstants.O_NOFOLLOW ?? 0),
        0o600
      );
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    }

    if (createdLockHandle) {
      try {
        const createdToken = randomUUID();
        await createdLockHandle.writeFile(createdToken);
        await createdLockHandle.sync();
        const createdStats = await createdLockHandle.stat({ bigint: true });
        if (!createdStats.isFile()) {
          throw new Error(`Unsafe tls-client install lock: ${lockPath}`);
        }

        // Capture ownership from the O_EXCL handle before exposing the test
        // scheduling seam. A pathname lstat alone could capture a replacement
        // lock created by another process after this owner was descheduled.
        const afterCreated = afterInstallLockCreated;
        afterInstallLockCreated = undefined;
        if (afterCreated) await afterCreated(lockPath);

        const currentClaim = await readInstallLockClaim(lockPath);
        if (
          currentClaim &&
          currentClaim.token === createdToken &&
          sameFileIdentity(createdStats, currentClaim.stats)
        ) {
          acquiredLockHandle = createdLockHandle;
          acquiredLockToken = createdToken;
          createdLockHandle = undefined;
        }
      } finally {
        await createdLockHandle?.close();
      }
      if (acquiredLockHandle) break;
      continue;
    }

    const afterExists = testHooks?.afterInstallLockExists;
    if (afterExists) await afterExists(lockPath);
    let lockStats;
    try {
      lockStats = await lstat(lockPath);
    } catch (lockErr) {
      if ((lockErr as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw lockErr;
    }
    if (lockStats.isSymbolicLink() || (!lockStats.isDirectory() && !lockStats.isFile())) {
      throw new Error(`Unsafe tls-client install lock: ${lockPath}`);
    }
    if (await readVerifiedRegularFile(destinationPath, expectedSha256, { normalizeMode: true })) {
      return destinationPath;
    }
    if (Date.now() - lockStats.mtimeMs > STALE_INSTALL_LOCK_MS) {
      const removed = await (lockStats.isDirectory() ? rmdir(lockPath) : rm(lockPath)).then(
        () => true,
        () => false
      );
      if (removed) continue;
    }
    if (Date.now() - startedAt >= INSTALL_LOCK_TIMEOUT_MS) {
      if (await readVerifiedRegularFile(destinationPath, expectedSha256, { normalizeMode: true })) {
        return destinationPath;
      }
      throw new Error(`Timed out waiting for tls-client native install lock: ${lockPath}`);
    }
    await delay(25);
  }

  const ownerHandle = acquiredLockHandle;
  const ownerToken = acquiredLockToken;
  if (!ownerHandle || !ownerToken) {
    await ownerHandle?.close();
    throw new Error(`Invalid tls-client install lock ownership: ${lockPath}`);
  }
  try {
    if (await readVerifiedRegularFile(destinationPath, expectedSha256, { normalizeMode: true })) {
      return destinationPath;
    }
    return await operation();
  } finally {
    try {
      const ownerStats = await ownerHandle.stat({ bigint: true });
      const currentClaim = await readInstallLockClaim(lockPath);
      if (
        currentClaim &&
        currentClaim.token === ownerToken &&
        sameFileIdentity(ownerStats, currentClaim.stats)
      ) {
        await rm(lockPath);
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    } finally {
      await ownerHandle.close();
    }
  }
}

async function readBoundedNativeAssetResponse(response: Response): Promise<Buffer> {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_NATIVE_ASSET_BYTES) {
    throw new Error("Pinned tls-client native asset exceeds the 64 MiB download limit");
  }
  if (!response.body) return Buffer.alloc(0);

  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_NATIVE_ASSET_BYTES) {
        // Cancellation is best-effort cleanup; its failure must not mask the size-limit error.
        await reader.cancel("native asset exceeds download limit").catch(() => {});
        throw new Error("Pinned tls-client native asset exceeds the 64 MiB download limit");
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, totalBytes);
}

function resolveInstalledTlsClientSeedDir(testHooks?: NativeResolverTestHooks): string | undefined {
  try {
    const packageJsonPath =
      testHooks?.resolveTlsClientPackageJson?.() ??
      moduleRequire.resolve("tls-client-node/package.json");
    return join(dirname(packageJsonPath), "bin");
  } catch {
    // The seed package is optional; configured/runtime paths are still scanned and verified below.
    return undefined;
  }
}

function resolveBundledSeedDirs(testHooks?: NativeResolverTestHooks): string[] {
  const configured = process.env.OMNIROUTE_TLS_CLIENT_SEED_DIR?.trim();
  const installedPackageSeedDir = resolveInstalledTlsClientSeedDir(testHooks);
  return [
    ...new Set([
      ...(configured ? [configured] : []),
      join(process.cwd(), "runtime-assets", "tls-client", "bin"),
      join(process.cwd(), "data", "tls-client", "bin"),
      ...(installedPackageSeedDir ? [installedPackageSeedDir] : []),
      join(process.cwd(), "node_modules", "tls-client-node", "bin"),
    ]),
  ];
}

/**
 * Writable cache directory for tls-client-node's native binary.
 *
 * Without an explicit `downloadDir`, the library defaults to its own package
 * `node_modules/tls-client-node/bin`, which is root-owned on global installs
 * and fails with EACCES for normal users (#8579).
 */
export function resolveTlsClientDownloadDir(): string {
  return join(resolveDataDir(), "tls-client", "bin");
}

/**
 * Materialize only the pinned bogdanfinn/tls-client native library after its
 * GitHub-published SHA-256 has been verified. Passing the resulting path to
 * tls-client-node prevents its unchecked runtime downloader from running.
 */
export async function resolveVerifiedTlsClientNativeLibrary({
  platform = process.platform,
  arch = process.arch,
  asset,
  downloadDir,
  seedDirs,
  fetchImpl = globalThis.fetch,
  testHooks,
}: {
  platform?: NodeJS.Platform;
  arch?: string;
  asset?: TlsClientNativeAsset;
  downloadDir?: string;
  seedDirs?: string[];
  fetchImpl?: FetchLike;
  /** Deterministic filesystem-race seam used only by native resolver tests. */
  testHooks?: NativeResolverTestHooks;
} = {}): Promise<string> {
  const expectedAsset = asset ?? TLS_CLIENT_NATIVE_ASSETS[`${platform}-${arch}`];
  if (!expectedAsset) {
    throw new Error(`Unsupported platform for tls-client native asset: ${platform}/${arch}`);
  }
  validateNativeAsset(expectedAsset);

  const requestedDownloadDir = downloadDir ?? resolveTlsClientDownloadDir();
  const trustedDownloadRoot = downloadDir === undefined ? resolveDataDir() : requestedDownloadDir;
  const safeDownloadDir = await resolveSafeDirectory(requestedDownloadDir, trustedDownloadRoot);
  const resolvedSeedDirs = seedDirs ?? resolveBundledSeedDirs(testHooks);
  const destinationPath = join(safeDownloadDir, expectedAsset.file);
  const cachedBytes = await readVerifiedRegularFile(destinationPath, expectedAsset.sha256, {
    normalizeMode: true,
    afterOpenedFileStat: testHooks?.afterOpenedFileStat,
  });
  if (cachedBytes) return destinationPath;

  return withNativeAssetInstallLock(
    destinationPath,
    expectedAsset.sha256,
    async () => {
      for (const seedDir of resolvedSeedDirs) {
        const seedPath = join(resolve(seedDir), expectedAsset.file);
        if (seedPath === destinationPath) continue;
        const seedBytes = await readVerifiedRegularFile(seedPath, expectedAsset.sha256);
        if (seedBytes) return installVerifiedBytes(safeDownloadDir, expectedAsset, seedBytes);
      }

      const assetUrl =
        `https://github.com/bogdanfinn/tls-client/releases/download/v${tlsClientNativeManifest.version}/` +
        expectedAsset.file;
      const response = await fetchImpl(assetUrl, {
        redirect: "follow",
        signal: AbortSignal.timeout(30_000),
      });
      if (!response.ok) {
        throw new Error(
          `Failed to download pinned tls-client v${tlsClientNativeManifest.version} native asset: ` +
            `${response.status}`
        );
      }

      const bytes = await readBoundedNativeAssetResponse(response);
      return installVerifiedBytes(safeDownloadDir, expectedAsset, bytes);
    },
    testHooks
  );
}

export function buildNativeTlsClientOptions(nativeLibraryPath?: string): {
  runtimeMode: "native";
  version: string;
  downloadDir: string;
  nativeLibraryPath?: string;
} {
  return {
    runtimeMode: "native",
    version: tlsClientNativeManifest.version,
    downloadDir: resolveTlsClientDownloadDir(),
    ...(nativeLibraryPath ? { nativeLibraryPath } : {}),
  };
}
