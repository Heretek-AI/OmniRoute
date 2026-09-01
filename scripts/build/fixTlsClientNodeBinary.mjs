#!/usr/bin/env node

/**
 * tls-client-node postinstall repair (#7802).
 *
 * tls-client-node's own postinstall.js fetches a platform-specific native
 * binary (.so/.dylib/.dll) from the bogdanfinn/tls-client GitHub Releases
 * API. That script is blocked by `npm ci --ignore-scripts` (the Dockerfile
 * builder stage runs with scripts disabled for supply-chain hygiene) and,
 * even when it does run, silently no-ops on a rate-limited/failed GitHub API
 * call instead of raising — so `node_modules/tls-client-node/bin/` can end
 * up empty with no visible signal until the first live request throws
 * TlsClientUnavailableError (chatgpt-web/claude-web/perplexity-web/grok-web/
 * notion-web/lmarena all share this transport).
 *
 * This module:
 *   1. Accepts only bogdanfinn/tls-client v1.15.1 assets whose SHA-256 matches
 *      the digest published by GitHub for the tagged release.
 *   2. Copies the verified root asset into the standalone
 *      `dist/node_modules/tls-client-node/bin/` bundle (same pattern as
 *      fixWreqJsBinary), so the published npm package works even though its
 *      own `files` allowlist never ships the binary.
 *   3. When that verified asset is absent, downloads the exact tagged release
 *      asset directly and retries with exponential backoff.
 *
 * Normal npm postinstall remains best-effort and warns on failure. Docker and
 * release callers use --strict, which fails closed instead of shipping an
 * absent or unverified binary.
 */

import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  readSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

const DEFAULT_RETRY_DELAYS_MS = [1_000, 3_000, 8_000];
const DEFAULT_DOWNLOAD_TIMEOUT_MS = 30_000;
const MAX_NATIVE_ASSET_BYTES = 64 * 1024 * 1024;
const NATIVE_ASSET_READ_CHUNK_BYTES = 64 * 1024;
const TLS_CLIENT_RELEASE_DOWNLOAD_BASE =
  "https://github.com/bogdanfinn/tls-client/releases/download";
const NATIVE_MANIFEST = JSON.parse(
  readFileSync(
    new URL("../../open-sse/config/tlsClientNativeManifest.json", import.meta.url),
    "utf8"
  )
);

export const TLS_CLIENT_NATIVE_VERSION = NATIVE_MANIFEST.version;
export const TLS_CLIENT_NATIVE_ASSETS = NATIVE_MANIFEST.assets;

/** @typedef {{ file: string; sha256: string }} NativeAsset */

/** @param {NativeAsset} asset */
function validateNativeAsset(asset) {
  if (
    !asset?.file ||
    asset.file === "." ||
    asset.file === ".." ||
    basename(asset.file) !== asset.file ||
    asset.file.includes("/") ||
    asset.file.includes("\\") ||
    asset.file.includes("\0")
  ) {
    throw new Error(`Invalid tls-client native asset path: ${JSON.stringify(asset?.file)}`);
  }
  if (!/^[a-f0-9]{64}$/.test(asset.sha256)) {
    throw new Error(`Invalid SHA-256 in tls-client native manifest for ${asset.file}`);
  }
}

/**
 * Resolve the exact native asset supported by tls-client-node@0.2.0.
 *
 * @param {NodeJS.Platform} [platform]
 * @param {string} [arch]
 * @returns {NativeAsset}
 */
export function resolveTlsClientNativeAsset(platform = process.platform, arch = process.arch) {
  const asset = TLS_CLIENT_NATIVE_ASSETS[`${platform}-${arch}`];
  if (!asset) {
    throw new Error(`Unsupported platform for tls-client-node native asset: ${platform}/${arch}`);
  }
  validateNativeAsset(asset);
  return asset;
}

function sameFileIdentity(left, right) {
  return String(left.dev) === String(right.dev) && String(left.ino) === String(right.ino);
}

/** @param {string} filePath */
function lstatIfPresent(filePath) {
  try {
    return lstatSync(filePath);
  } catch (err) {
    if (err?.code === "ENOENT") return undefined;
    throw err;
  }
}

function assertNativeAssetSize(size, label) {
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_NATIVE_ASSET_BYTES) {
    throw new Error(`${label} exceeds the 64 MiB limit`);
  }
}

function pathEscapesRoot(rootPath, candidatePath) {
  const relativePath = relative(rootPath, candidatePath);
  return isAbsolute(relativePath) || relativePath === ".." || relativePath.startsWith(`..${sep}`);
}

function readSafeDirectoryIdentity(directoryPath) {
  const initialStats = lstatIfPresent(directoryPath);
  if (!initialStats) return undefined;
  if (initialStats.isSymbolicLink() || !initialStats.isDirectory()) {
    throw new Error(
      `Unsafe tls-client native destination ancestor (symlink/non-directory): ${directoryPath}`
    );
  }
  const canonicalPath = realpathSync(directoryPath);
  const finalStats = lstatSync(directoryPath);
  if (
    finalStats.isSymbolicLink() ||
    !finalStats.isDirectory() ||
    !sameFileIdentity(initialStats, finalStats)
  ) {
    throw new Error(
      `Unsafe tls-client native destination ancestor changed during verification: ${directoryPath}`
    );
  }
  return canonicalPath;
}

/**
 * Validate every existing directory component without following symlinks. The
 * trusted root itself must already be a real directory; descendants may be
 * absent because the caller creates them only after this check succeeds.
 */
function assertSafeDestinationAncestors(trustedRoot, destinationPath) {
  const resolvedRoot = resolve(trustedRoot);
  const resolvedDestination = resolve(destinationPath);
  const destinationRelativePath = relative(resolvedRoot, resolvedDestination);
  if (
    destinationRelativePath === "" ||
    isAbsolute(destinationRelativePath) ||
    destinationRelativePath === ".." ||
    destinationRelativePath.startsWith(`..${sep}`)
  ) {
    throw new Error(
      `Unsafe tls-client native destination outside trusted root: ${resolvedDestination}`
    );
  }

  const canonicalRoot = readSafeDirectoryIdentity(resolvedRoot);
  if (!canonicalRoot) {
    throw new Error(`Trusted tls-client native destination root not found: ${resolvedRoot}`);
  }

  let currentPath = resolvedRoot;
  const relativeParent = relative(resolvedRoot, dirname(resolvedDestination));
  for (const component of relativeParent.split(sep).filter(Boolean)) {
    currentPath = join(currentPath, component);
    const canonicalPath = readSafeDirectoryIdentity(currentPath);
    if (canonicalPath && pathEscapesRoot(canonicalRoot, canonicalPath)) {
      throw new Error(
        `Unsafe tls-client native destination ancestor outside trusted root: ${currentPath}`
      );
    }
  }

  return resolvedDestination;
}

function collectAllowedNativeAssets(nativeAssets, targetAsset) {
  const assetsByFile = new Map();
  for (const candidate of Object.values(nativeAssets ?? {})) {
    validateNativeAsset(candidate);
    const previous = assetsByFile.get(candidate.file);
    if (previous && previous.sha256 !== candidate.sha256) {
      throw new Error(`Ambiguous SHA-256 for tls-client native asset: ${candidate.file}`);
    }
    assetsByFile.set(candidate.file, candidate);
  }
  if (targetAsset) {
    validateNativeAsset(targetAsset);
    // A deterministic test target intentionally overrides the production asset
    // with the same filename. Production calls do not provide this seam.
    assetsByFile.set(targetAsset.file, targetAsset);
  }
  return assetsByFile;
}

function assertNativeAssetDirectoryInventory(
  trustedRoot,
  binDir,
  allowedAssets,
  verifyDigests = false
) {
  const auditSentinel = join(binDir, ".tls-client-native-audit");
  assertSafeDestinationAncestors(trustedRoot, auditSentinel);
  if (!lstatIfPresent(binDir)) return;

  for (const entryName of readdirSync(binDir)) {
    const expectedAsset = allowedAssets.get(entryName);
    if (!expectedAsset) {
      throw new Error(
        `Unlisted tls-client native sibling is not in the manifest: ${join(binDir, entryName)}`
      );
    }
    const entryPath = join(binDir, entryName);
    const entryStats = lstatIfPresent(entryPath);
    if (!entryStats || entryStats.isSymbolicLink() || !entryStats.isFile()) {
      throw new Error(`Unsafe tls-client native sibling (symlink/non-regular file): ${entryPath}`);
    }
    if (verifyDigests && !isVerifiedBinary(entryPath, expectedAsset)) {
      throw new Error(
        `Manifested tls-client native sibling has an unverified SHA-256: ${entryPath}`
      );
    }
  }
  assertSafeDestinationAncestors(trustedRoot, auditSentinel);
}

function readFileDescriptorBounded(fd, filePath) {
  assertNativeAssetSize(fstatSync(fd).size, `Local tls-client native asset: ${filePath}`);

  const chunks = [];
  let totalBytes = 0;
  while (true) {
    const remainingWithSentinel = MAX_NATIVE_ASSET_BYTES - totalBytes + 1;
    const chunk = Buffer.allocUnsafe(
      Math.min(NATIVE_ASSET_READ_CHUNK_BYTES, remainingWithSentinel)
    );
    const bytesRead = readSync(fd, chunk, 0, chunk.byteLength, null);
    if (bytesRead === 0) break;
    totalBytes += bytesRead;
    assertNativeAssetSize(totalBytes, `Local tls-client native asset: ${filePath}`);
    chunks.push(chunk.subarray(0, bytesRead));
  }

  const finalStats = fstatSync(fd);
  assertNativeAssetSize(finalStats.size, `Local tls-client native asset: ${filePath}`);
  const bytes = Buffer.concat(chunks, totalBytes);
  assertNativeAssetSize(bytes.length, `Local tls-client native asset: ${filePath}`);
  return bytes;
}

/**
 * @param {string} filePath
 * @param {NativeAsset} asset
 * @param {(filePath: string) => void} [afterInitialStat]
 */
function readVerifiedBinary(filePath, asset, afterInitialStat) {
  const pathStats = lstatIfPresent(filePath);
  if (!pathStats) return undefined;
  if (pathStats.isSymbolicLink() || !pathStats.isFile()) {
    throw new Error(`Unsafe tls-client native path (symlink/non-regular file): ${filePath}`);
  }

  const fd = openSync(filePath, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  try {
    const openedStats = fstatSync(fd);
    if (!openedStats.isFile()) {
      throw new Error(`Unsafe tls-client native path (not a regular file): ${filePath}`);
    }
    assertNativeAssetSize(openedStats.size, `Local tls-client native asset: ${filePath}`);
    afterInitialStat?.(filePath);
    const bytes = readFileDescriptorBounded(fd, filePath);
    const currentStats = lstatSync(filePath);
    if (
      currentStats.isSymbolicLink() ||
      !currentStats.isFile() ||
      !sameFileIdentity(openedStats, currentStats)
    ) {
      throw new Error(`Unsafe tls-client native path changed during verification: ${filePath}`);
    }
    if (createHash("sha256").update(bytes).digest("hex") !== asset.sha256) return undefined;
    if (process.platform !== "win32") fchmodSync(fd, 0o555);
    return bytes;
  } finally {
    closeSync(fd);
  }
}

/** @param {string} filePath @param {NativeAsset} asset */
function isVerifiedBinary(filePath, asset) {
  try {
    return Boolean(readVerifiedBinary(filePath, asset));
  } catch {
    return false;
  }
}

/**
 * @param {string} destinationPath
 * @param {Uint8Array} bytes
 * @param {NativeAsset} asset
 * @param {string} trustedRoot
 */
function writeVerifiedBinary(destinationPath, bytes, asset, trustedRoot) {
  assertNativeAssetSize(bytes.byteLength, `tls-client native asset: ${asset.file}`);
  if (createHash("sha256").update(bytes).digest("hex") !== asset.sha256) {
    throw new Error(`SHA-256 mismatch for tls-client native asset: ${asset.file}`);
  }
  const resolvedDestination = assertSafeDestinationAncestors(trustedRoot, destinationPath);
  const destinationStats = lstatIfPresent(resolvedDestination);
  if (destinationStats?.isSymbolicLink() || (destinationStats && !destinationStats.isFile())) {
    throw new Error(`Unsafe tls-client native destination path: ${resolvedDestination}`);
  }
  mkdirSync(dirname(resolvedDestination), { recursive: true });
  assertSafeDestinationAncestors(trustedRoot, resolvedDestination);
  const temporaryPath = join(
    dirname(resolvedDestination),
    `.${asset.file}.${process.pid}.${randomUUID()}.tmp`
  );
  try {
    assertSafeDestinationAncestors(trustedRoot, resolvedDestination);
    writeFileSync(temporaryPath, bytes, { flag: "wx", mode: 0o555 });
    if (!isVerifiedBinary(temporaryPath, asset)) {
      throw new Error(`SHA-256 mismatch after writing ${asset.file}`);
    }
    assertSafeDestinationAncestors(trustedRoot, resolvedDestination);
    renameSync(temporaryPath, resolvedDestination);
    assertSafeDestinationAncestors(trustedRoot, resolvedDestination);
    if (!isVerifiedBinary(resolvedDestination, asset)) {
      throw new Error(`SHA-256 mismatch after installing ${asset.file}`);
    }
    assertSafeDestinationAncestors(trustedRoot, resolvedDestination);
  } finally {
    try {
      assertSafeDestinationAncestors(trustedRoot, temporaryPath);
      removeIfPresent(temporaryPath);
    } catch {
      // Never follow a destination ancestor that changed while the write was in progress.
    }
  }
}

/**
 * @param {string} sourcePath
 * @param {string} destinationPath
 * @param {NativeAsset} asset
 * @param {string} trustedRoot
 */
function copyVerifiedBinary(sourcePath, destinationPath, asset, trustedRoot) {
  assertSafeDestinationAncestors(trustedRoot, sourcePath);
  const bytes = readVerifiedBinary(sourcePath, asset);
  if (!bytes) throw new Error(`Source native binary is absent or unverified: ${sourcePath}`);
  assertSafeDestinationAncestors(trustedRoot, sourcePath);
  writeVerifiedBinary(destinationPath, bytes, asset, trustedRoot);
}

function removeIfPresent(filePath) {
  if (lstatIfPresent(filePath)) unlinkSync(filePath);
}

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function pinnedReleaseAssetUrl(version, asset) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    throw new Error(`Invalid pinned tls-client native version: ${version}`);
  }
  return `${TLS_CLIENT_RELEASE_DOWNLOAD_BASE}/v${version}/${encodeURIComponent(asset.file)}`;
}

async function readBoundedResponseBytes(response, asset) {
  const contentLength = response.headers?.get?.("content-length");
  if (contentLength !== null && contentLength !== undefined) {
    if (!/^\d+$/.test(contentLength)) {
      throw new Error(`Invalid Content-Length for tls-client native asset: ${asset.file}`);
    }
    assertNativeAssetSize(
      Number(contentLength),
      `Downloaded tls-client native asset: ${asset.file}`
    );
  }

  const reader = response.body?.getReader?.();
  if (!reader) {
    throw new Error(`Downloaded tls-client native asset has no readable body: ${asset.file}`);
  }

  const chunks = [];
  let totalBytes = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = Buffer.from(value);
    totalBytes += chunk.byteLength;
    try {
      assertNativeAssetSize(totalBytes, `Downloaded tls-client native asset: ${asset.file}`);
    } catch (err) {
      // Cancellation is advisory after the size violation; preserve the actionable size error.
      await reader.cancel().catch(() => {});
      throw err;
    }
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks, totalBytes);
  assertNativeAssetSize(bytes.length, `Downloaded tls-client native asset: ${asset.file}`);
  return bytes;
}

async function downloadPinnedAssetWithRetry(
  rootTlsClientDir,
  trustedRoot,
  asset,
  version,
  retryDelaysMs,
  downloadTimeoutMs,
  fetchImpl,
  log
) {
  const binaryPath = join(rootTlsClientDir, "bin", asset.file);
  assertSafeDestinationAncestors(trustedRoot, binaryPath);
  const initialStats = lstatIfPresent(binaryPath);
  if (initialStats?.isSymbolicLink() || (initialStats && !initialStats.isFile())) {
    throw new Error(`Unsafe tls-client native path (symlink/non-regular file): ${binaryPath}`);
  }
  if (initialStats && !isVerifiedBinary(binaryPath, asset)) {
    assertSafeDestinationAncestors(trustedRoot, binaryPath);
    removeIfPresent(binaryPath);
    assertSafeDestinationAncestors(trustedRoot, binaryPath);
    log(`  ⚠️  Removed tls-client-node binary with an invalid SHA-256: ${asset.file}`);
    assertSafeDestinationAncestors(trustedRoot, binaryPath);
  }

  if (typeof fetchImpl !== "function") {
    throw new Error("Fetch is unavailable; cannot download the pinned tls-client native asset");
  }
  if (!Number.isFinite(downloadTimeoutMs) || downloadTimeoutMs <= 0) {
    throw new Error(`Invalid tls-client native download timeout: ${downloadTimeoutMs}`);
  }

  const downloadUrl = pinnedReleaseAssetUrl(version, asset);
  for (let attempt = 0; attempt <= retryDelaysMs.length; attempt++) {
    if (attempt > 0) {
      log(
        `  ⏳ tls-client-node ${asset.file} still missing — retrying pinned download ` +
          `(attempt ${attempt + 1}/${retryDelaysMs.length + 1})...`
      );
      await sleep(retryDelaysMs[attempt - 1]);
    }
    assertSafeDestinationAncestors(trustedRoot, binaryPath);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), downloadTimeoutMs);
    timeout.unref?.();
    try {
      const response = await fetchImpl(downloadUrl, { signal: controller.signal });
      if (!response?.ok) {
        throw new Error(`HTTP ${response?.status ?? "unknown"}`);
      }
      const bytes = await readBoundedResponseBytes(response, asset);
      writeVerifiedBinary(binaryPath, bytes, asset, trustedRoot);
    } catch (err) {
      assertSafeDestinationAncestors(trustedRoot, binaryPath);
      log(
        `  ⚠️  Pinned tls-client native download attempt failed for ${asset.file}: ` +
          `${err.message.split("\n")[0]}`
      );
      assertSafeDestinationAncestors(trustedRoot, binaryPath);
    } finally {
      clearTimeout(timeout);
    }

    assertSafeDestinationAncestors(trustedRoot, binaryPath);
    if (isVerifiedBinary(binaryPath, asset)) return true;
    const currentStats = lstatIfPresent(binaryPath);
    if (currentStats?.isSymbolicLink() || (currentStats && !currentStats.isFile())) {
      throw new Error(`Unsafe tls-client native path after download: ${binaryPath}`);
    }
    if (currentStats) {
      assertSafeDestinationAncestors(trustedRoot, binaryPath);
      removeIfPresent(binaryPath);
      assertSafeDestinationAncestors(trustedRoot, binaryPath);
    }
  }

  return false;
}

function normalizeTargetPlatform(platform) {
  if (typeof platform !== "string" || !/^[a-z0-9]+$/.test(platform)) {
    throw new Error(`Invalid tls-client target platform: ${JSON.stringify(platform)}`);
  }
  return platform;
}

function normalizeTargetArches(arches) {
  const values = (Array.isArray(arches) ? arches : [arches])
    .flatMap((arch) => (typeof arch === "string" ? arch.split(",") : []))
    .map((arch) => arch.trim())
    .filter(Boolean);
  if (values.length === 0 || values.some((arch) => !/^[a-z0-9_-]+$/.test(arch))) {
    throw new Error(`Invalid tls-client target arches: ${JSON.stringify(arches)}`);
  }
  return [...new Set(values)];
}

function resolveTargetNativeAsset(platform, arch, nativeAssets) {
  const expectedAsset = nativeAssets?.[`${platform}-${arch}`];
  if (!expectedAsset) {
    throw new Error(`Unsupported platform for tls-client-node native asset: ${platform}/${arch}`);
  }
  validateNativeAsset(expectedAsset);
  return expectedAsset;
}

async function fixTlsClientNodeTarget({
  rootDir,
  rootTlsClientDir,
  distTlsClientDir,
  expectedAsset,
  targetPlatform,
  targetArch,
  version,
  log,
  retryDelaysMs,
  downloadTimeoutMs,
  fetchImpl,
  strict,
  standaloneDir,
  requireStandalone,
  afterSourceStat,
}) {
  const rootBinDir = join(rootTlsClientDir, "bin");
  const rootBinaryPath = join(rootBinDir, expectedAsset.file);

  try {
    assertSafeDestinationAncestors(rootDir, rootBinaryPath);
  } catch (err) {
    if (strict) throw err;
    console.warn(`  ⚠️  ${err.message}`);
    return;
  }
  const rootBinaryStats = lstatIfPresent(rootBinaryPath);
  if (rootBinaryStats?.isSymbolicLink() || (rootBinaryStats && !rootBinaryStats.isFile())) {
    const message = `Unsafe tls-client native source path: ${rootBinaryPath}`;
    if (strict) throw new Error(message);
    console.warn(`  ⚠️  ${message}`);
    return;
  }

  let rootBinaryVerified;
  try {
    rootBinaryVerified = Boolean(
      readVerifiedBinary(rootBinaryPath, expectedAsset, afterSourceStat)
    );
  } catch (err) {
    if (strict) throw err;
    console.warn(`  ⚠️  ${err.message}`);
    return;
  }

  if (!rootBinaryVerified) {
    log(
      `\n  🔧 tls-client-node native binary missing or unverified — fetching pinned ` +
        `v${version} for ${targetPlatform}/${targetArch} and checking SHA-256...\n`
    );
    let recovered = false;
    try {
      recovered = await downloadPinnedAssetWithRetry(
        rootTlsClientDir,
        rootDir,
        expectedAsset,
        version,
        retryDelaysMs,
        downloadTimeoutMs,
        fetchImpl,
        log
      );
    } catch (err) {
      if (strict) throw err;
      console.warn(`  ⚠️  Could not recover tls-client-node binary: ${err.message}`);
      return;
    }
    if (!recovered) {
      const message =
        `Could not fetch tls-client-node v${version} verified native binary ` +
        `(${expectedAsset.file}, ${targetPlatform}/${targetArch}) after retries.`;
      if (strict) throw new Error(message);
      console.warn(`\n  ⚠️  ${message} GitHub may be rate-limited or unreachable.`);
      console.warn(
        "     chatgpt-web/claude-web/perplexity-web/grok-web/notion-web/lmarena will " +
          "raise a clear TlsClientUnavailableError on first use until this is resolved."
      );
      console.warn(
        `     Verified repair: node ${join(rootDir, "scripts", "build", "fixTlsClientNodeBinary.mjs")} --strict\n`
      );
      return;
    }
    try {
      assertSafeDestinationAncestors(rootDir, rootBinaryPath);
    } catch (err) {
      if (strict) throw err;
      console.warn(`  ⚠️  ${err.message}`);
      return;
    }
    log("  ✅ tls-client-node native binary fetched successfully!\n");
    try {
      assertSafeDestinationAncestors(rootDir, rootBinaryPath);
    } catch (err) {
      if (strict) throw err;
      console.warn(`  ⚠️  ${err.message}`);
      return;
    }
  }

  if (!isVerifiedBinary(rootBinaryPath, expectedAsset)) {
    const message =
      `tls-client-node v${version} root native binary failed post-recovery verification ` +
      `(${expectedAsset.file}); refusing to copy or seed standalone artifacts.`;
    if (strict) throw new Error(message);
    console.warn(`  ⚠️  ${message}`);
    return;
  }

  if (existsSync(distTlsClientDir)) {
    const distBinaryPath = join(distTlsClientDir, "bin", expectedAsset.file);
    try {
      assertSafeDestinationAncestors(rootDir, distBinaryPath);
      if (!isVerifiedBinary(distBinaryPath, expectedAsset)) {
        copyVerifiedBinary(rootBinaryPath, distBinaryPath, expectedAsset, rootDir);
        log(
          `  ✅ Verified tls-client-node v${version} native binary copied to standalone ` +
            "dist/node_modules.\n"
        );
      }
    } catch (err) {
      if (strict) throw err;
      console.warn(`  ⚠️  Could not copy tls-client-node binary into dist/: ${err.message}`);
    }
  }

  if (requireStandalone && !standaloneDir) {
    throw new Error("Final standalone artifact path is required for strict verification");
  }
  if (standaloneDir) {
    const resolvedStandaloneDir = resolve(rootDir, standaloneDir);
    if (!existsSync(resolvedStandaloneDir)) {
      const message = `Final standalone artifact not found: ${resolvedStandaloneDir}`;
      if (requireStandalone || strict) throw new Error(message);
      console.warn(`  ⚠️  ${message}`);
      return;
    }
    const runtimeBinaryPath = join(
      resolvedStandaloneDir,
      "runtime-assets",
      "tls-client",
      "bin",
      expectedAsset.file
    );
    try {
      assertSafeDestinationAncestors(rootDir, runtimeBinaryPath);
      if (!isVerifiedBinary(runtimeBinaryPath, expectedAsset)) {
        copyVerifiedBinary(rootBinaryPath, runtimeBinaryPath, expectedAsset, rootDir);
      }
      if (!isVerifiedBinary(runtimeBinaryPath, expectedAsset)) {
        throw new Error(`Final standalone runtime seed is unverified: ${runtimeBinaryPath}`);
      }
      log(`  ✅ Verified tls-client native runtime seed: ${runtimeBinaryPath}\n`);
    } catch (err) {
      if (strict || requireStandalone) throw err;
      console.warn(`  ⚠️  Could not seed standalone TLS runtime binary: ${err.message}`);
    }
  }
}

/**
 * @param {object} opts
 * @param {string} opts.rootDir - repo root
 * @param {(msg: string) => void} [opts.log]
 * @param {number[]} [opts.retryDelaysMs] - override for tests (avoid real sleeps)
 * @param {number} [opts.downloadTimeoutMs] - timeout for each pinned fetch attempt
 * @param {NativeAsset} [opts.asset] - legacy single-target injection for deterministic tests
 * @param {Record<string, NativeAsset>} [opts.nativeAssets] - manifest injection for tests
 * @param {typeof fetch} [opts.fetchImpl] - pinned download boundary, injectable for tests
 * @param {string} [opts.platform] - target platform (defaults to the current host)
 * @param {string|string[]} [opts.arches] - one or more target arches (defaults to host arch)
 * @param {(filePath: string) => void} [opts.afterSourceStat] - deterministic race hook for tests
 * @param {boolean} [opts.strict] - fail instead of warning (Docker/release builds)
 * @param {string} [opts.standaloneDir] - final standalone root to seed and verify
 * @param {boolean} [opts.requireStandalone] - fail if standaloneDir does not exist
 */
export async function fixTlsClientNodeBinary({
  rootDir,
  log = (m) => console.log(m),
  retryDelaysMs = DEFAULT_RETRY_DELAYS_MS,
  downloadTimeoutMs = DEFAULT_DOWNLOAD_TIMEOUT_MS,
  asset,
  nativeAssets = TLS_CLIENT_NATIVE_ASSETS,
  fetchImpl = globalThis.fetch,
  platform = process.platform,
  arches = [process.arch],
  afterSourceStat,
  strict = false,
  standaloneDir,
  requireStandalone = false,
} = {}) {
  const version = TLS_CLIENT_NATIVE_VERSION;
  const rootTlsClientDir = join(rootDir, "node_modules", "tls-client-node");
  const distTlsClientDir = join(rootDir, "dist", "node_modules", "tls-client-node");
  const resolvedStandaloneDir = standaloneDir ? resolve(rootDir, standaloneDir) : undefined;

  if (!existsSync(rootTlsClientDir)) {
    if (strict) throw new Error("tls-client-node is not installed; cannot verify native binary");
    return;
  }
  if (requireStandalone && !standaloneDir) {
    throw new Error("Final standalone artifact path is required for strict verification");
  }
  if (resolvedStandaloneDir) {
    if (!existsSync(resolvedStandaloneDir)) {
      const message = `Final standalone artifact not found: ${resolvedStandaloneDir}`;
      if (requireStandalone || strict) throw new Error(message);
      console.warn(`  ⚠️  ${message}`);
      return;
    }
  }

  let allowedNativeAssets;
  let strictBinDirs;
  if (strict) {
    allowedNativeAssets = collectAllowedNativeAssets(nativeAssets, asset);
    const resolvedRootDir = resolve(rootDir);
    const configuredNextDistDir = resolve(
      resolvedRootDir,
      process.env.NEXT_DIST_DIR || ".build/next"
    );
    if (pathEscapesRoot(resolvedRootDir, configuredNextDistDir)) {
      throw new Error(
        `Unsafe NEXT_DIST_DIR outside tls-client trusted root: ${configuredNextDistDir}`
      );
    }
    const relativeNextDistDir = relative(resolvedRootDir, configuredNextDistDir);
    strictBinDirs = [
      join(rootTlsClientDir, "bin"),
      join(distTlsClientDir, "bin"),
      join(configuredNextDistDir, "node_modules", "tls-client-node", "bin"),
      ...(resolvedStandaloneDir
        ? [
            join(resolvedStandaloneDir, "node_modules", "tls-client-node", "bin"),
            join(
              resolvedStandaloneDir,
              "projects",
              "OmniRoute",
              "node_modules",
              "tls-client-node",
              "bin"
            ),
            join(
              resolvedStandaloneDir,
              basename(resolvedRootDir),
              "node_modules",
              "tls-client-node",
              "bin"
            ),
            join(
              resolvedStandaloneDir,
              relativeNextDistDir,
              "node_modules",
              "tls-client-node",
              "bin"
            ),
            join(resolvedStandaloneDir, "runtime-assets", "tls-client", "bin"),
          ]
        : []),
    ];
    for (const binDir of new Set(strictBinDirs)) {
      assertNativeAssetDirectoryInventory(rootDir, binDir, allowedNativeAssets);
    }
  }

  let targetPlatform;
  let targetArches;
  try {
    targetPlatform = normalizeTargetPlatform(platform);
    targetArches = normalizeTargetArches(arches);
    if (asset && targetArches.length !== 1) {
      throw new Error("A synthetic tls-client asset can only be used with one target arch");
    }
  } catch (err) {
    if (strict) throw err;
    console.warn(`  ⚠️  ${err.message}`);
    return;
  }

  for (const targetArch of targetArches) {
    let expectedAsset;
    try {
      expectedAsset = asset ?? resolveTargetNativeAsset(targetPlatform, targetArch, nativeAssets);
      validateNativeAsset(expectedAsset);
    } catch (err) {
      if (strict) throw err;
      console.warn(`  ⚠️  ${err.message}`);
      continue;
    }

    await fixTlsClientNodeTarget({
      rootDir,
      rootTlsClientDir,
      distTlsClientDir,
      expectedAsset,
      targetPlatform,
      targetArch,
      version,
      log,
      retryDelaysMs,
      downloadTimeoutMs,
      fetchImpl,
      strict,
      standaloneDir,
      requireStandalone,
      afterSourceStat,
    });
  }

  if (strict) {
    for (const binDir of new Set(strictBinDirs)) {
      assertNativeAssetDirectoryInventory(rootDir, binDir, allowedNativeAssets, true);
    }
  }
}

function readCliOptionValues(argv, optionNames) {
  const values = [];
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index];
    const matchingName = optionNames.find(
      (optionName) => argument === optionName || argument.startsWith(`${optionName}=`)
    );
    if (!matchingName) continue;

    if (argument === matchingName) {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error(`${matchingName} requires a value`);
      }
      values.push(value);
      index += 1;
    } else {
      const value = argument.slice(matchingName.length + 1);
      if (!value) throw new Error(`${matchingName} requires a value`);
      values.push(value);
    }
  }
  return values;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const cliArgs = process.argv.slice(2);
    const standaloneValues = readCliOptionValues(cliArgs, ["--standalone-dir"]);
    const platformValues = readCliOptionValues(cliArgs, ["--platform"]);
    const archValues = readCliOptionValues(cliArgs, ["--arch", "--arches"]);
    if (standaloneValues.length > 1) throw new Error("--standalone-dir may only be passed once");
    if (platformValues.length > 1) throw new Error("--platform may only be passed once");

    const standaloneDir = standaloneValues[0];
    await fixTlsClientNodeBinary({
      rootDir: process.cwd(),
      strict: cliArgs.includes("--strict"),
      platform: platformValues[0],
      arches: archValues.length > 0 ? archValues : undefined,
      standaloneDir,
      requireStandalone: standaloneValues.length > 0,
    });
  } catch (err) {
    console.error(`  ❌ ${err.message}`);
    process.exitCode = 1;
  }
}
