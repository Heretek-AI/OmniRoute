import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const MAX_NATIVE_ASSET_BYTES = 64 * 1024 * 1024;
const READ_CHUNK_BYTES = 64 * 1024;

/**
 * Convert the pinned manifest into copy entries while validating every name and
 * digest. Keeping the digest on the entry makes the async and sync assemblers
 * consume one source of truth.
 *
 * @param {Record<string, {file:string, sha256:string}>} nativeAssets
 * @returns {{label:string, src:string[], dest:string[], tlsClientSha256:string}[]}
 */
export function createTlsClientNativeAssetEntries(nativeAssets) {
  const entriesByFile = new Map();
  for (const asset of Object.values(nativeAssets)) {
    const file = asset?.file;
    if (
      typeof file !== "string" ||
      file.length === 0 ||
      file === "." ||
      file === ".." ||
      path.basename(file) !== file ||
      file.includes("/") ||
      file.includes("\\") ||
      file.includes("\0")
    ) {
      throw new Error(`Invalid tls-client native asset path: ${JSON.stringify(file)}`);
    }
    if (!/^[a-f0-9]{64}$/.test(asset.sha256)) {
      throw new Error(`Invalid SHA-256 in tls-client native manifest for ${file}`);
    }
    const prior = entriesByFile.get(file);
    if (prior && prior.tlsClientSha256 !== asset.sha256) {
      throw new Error(`Conflicting SHA-256 values in tls-client native manifest for ${file}`);
    }
    entriesByFile.set(file, {
      label: `manifest-declared tls-client native runtime seed (${file})`,
      src: ["node_modules", "tls-client-node", "bin", file],
      // Keep the public bootstrap seed outside DATA_DIR: Docker deployments
      // commonly mount an empty /app/data volume, which must not hide it.
      dest: ["runtime-assets", "tls-client", "bin", file],
      tlsClientSha256: asset.sha256,
    });
  }
  return [...entriesByFile.values()];
}

function lstatIfPresent(filePath) {
  try {
    return fs.lstatSync(filePath);
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}

function sameFileIdentity(left, right) {
  return String(left.dev) === String(right.dev) && String(left.ino) === String(right.ino);
}

function assertNativeAssetSize(size, filePath) {
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_NATIVE_ASSET_BYTES) {
    throw new Error(
      `[assembleStandalone] tls-client native asset exceeds the 64 MiB limit: ${filePath}`
    );
  }
}

/**
 * Read a native seed through a no-follow descriptor and cap the read itself,
 * not merely the initial stat. This also detects path replacement during the
 * read before a digest can authorize the bytes.
 *
 * @param {string} filePath
 * @returns {Buffer|undefined}
 */
function readBoundedRegularAsset(filePath) {
  const pathStats = lstatIfPresent(filePath);
  if (!pathStats) return undefined;
  if (pathStats.isSymbolicLink() || !pathStats.isFile()) {
    throw new Error(
      `[assembleStandalone] unsafe tls-client native asset (symlink/non-regular file): ${filePath}`
    );
  }

  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const openedStats = fs.fstatSync(fd);
    if (!openedStats.isFile() || !sameFileIdentity(pathStats, openedStats)) {
      throw new Error(
        `[assembleStandalone] unsafe tls-client native asset changed before read: ${filePath}`
      );
    }
    assertNativeAssetSize(openedStats.size, filePath);

    const chunks = [];
    let totalBytes = 0;
    while (true) {
      const remainingWithSentinel = MAX_NATIVE_ASSET_BYTES - totalBytes + 1;
      const chunk = Buffer.allocUnsafe(Math.min(READ_CHUNK_BYTES, remainingWithSentinel));
      const bytesRead = fs.readSync(fd, chunk, 0, chunk.byteLength, null);
      if (bytesRead === 0) break;
      totalBytes += bytesRead;
      assertNativeAssetSize(totalBytes, filePath);
      chunks.push(chunk.subarray(0, bytesRead));
    }

    const finalDescriptorStats = fs.fstatSync(fd);
    const finalPathStats = fs.lstatSync(filePath);
    if (
      !finalDescriptorStats.isFile() ||
      finalPathStats.isSymbolicLink() ||
      !finalPathStats.isFile() ||
      !sameFileIdentity(openedStats, finalDescriptorStats) ||
      !sameFileIdentity(openedStats, finalPathStats)
    ) {
      throw new Error(
        `[assembleStandalone] unsafe tls-client native asset changed during read: ${filePath}`
      );
    }
    assertNativeAssetSize(finalDescriptorStats.size, filePath);
    if (finalDescriptorStats.size !== totalBytes) {
      throw new Error(
        `[assembleStandalone] tls-client native asset size changed during read: ${filePath}`
      );
    }
    return Buffer.concat(chunks, totalBytes);
  } finally {
    fs.closeSync(fd);
  }
}

function assertDigest(bytes, expectedSha256, filePath) {
  const actualSha256 = createHash("sha256").update(bytes).digest("hex");
  if (actualSha256 !== expectedSha256) {
    throw new Error(
      `[assembleStandalone] SHA-256 mismatch for tls-client native asset: ${filePath}`
    );
  }
}

function assertSafeExistingDestinationMode(filePath) {
  if (process.platform === "win32") return;
  const mode = fs.lstatSync(filePath).mode & 0o777;
  if (mode !== 0o555) {
    throw new Error(
      `[assembleStandalone] unsafe tls-client native destination mode ` +
        `(expected 0555, received ${mode.toString(8).padStart(4, "0")}): ${filePath}`
    );
  }
}

function assertContainedPath(rootPath, candidatePath, label) {
  const root = path.resolve(rootPath);
  const candidate = path.resolve(candidatePath);
  const relativeCandidate = path.relative(root, candidate);
  if (
    relativeCandidate === "" ||
    path.isAbsolute(relativeCandidate) ||
    relativeCandidate === ".." ||
    relativeCandidate.startsWith(`..${path.sep}`)
  ) {
    throw new Error(`[assembleStandalone] unsafe tls-client native ${label}: ${candidate}`);
  }
  return { root, candidate, relativeCandidate };
}

function pathEscapesRoot(rootPath, candidatePath) {
  const relativePath = path.relative(rootPath, candidatePath);
  return (
    path.isAbsolute(relativePath) ||
    relativePath === ".." ||
    relativePath.startsWith(`..${path.sep}`)
  );
}

function readSafeDirectoryIdentity(directoryPath, label) {
  const initialStats = lstatIfPresent(directoryPath);
  if (!initialStats) return undefined;
  if (initialStats.isSymbolicLink() || !initialStats.isDirectory()) {
    throw new Error(
      `[assembleStandalone] unsafe tls-client native ${label} ` +
        `(symlink/non-directory): ${directoryPath}`
    );
  }
  const canonicalPath = fs.realpathSync(directoryPath);
  const finalStats = fs.lstatSync(directoryPath);
  if (
    finalStats.isSymbolicLink() ||
    !finalStats.isDirectory() ||
    !sameFileIdentity(initialStats, finalStats)
  ) {
    throw new Error(
      `[assembleStandalone] tls-client native ${label} changed during verification: ${directoryPath}`
    );
  }
  return canonicalPath;
}

function assertSafeAncestorChain(
  rootPath,
  candidatePath,
  { label, createMissing = false, missingIsError = true }
) {
  const { root, relativeCandidate } = assertContainedPath(
    rootPath,
    candidatePath,
    `${label} outside trusted root`
  );
  if (!lstatIfPresent(root) && createMissing) fs.mkdirSync(root, { recursive: true });
  const canonicalRoot = readSafeDirectoryIdentity(root, `${label} root`);
  if (!canonicalRoot) {
    if (!missingIsError) return false;
    throw new Error(`[assembleStandalone] tls-client native ${label} root missing: ${root}`);
  }

  let current = root;
  for (const component of path.dirname(relativeCandidate).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    if (!lstatIfPresent(current) && createMissing) fs.mkdirSync(current);
    const canonicalCurrent = readSafeDirectoryIdentity(current, `${label} ancestor`);
    if (!canonicalCurrent) {
      if (!missingIsError) return false;
      throw new Error(
        `[assembleStandalone] tls-client native ${label} ancestor missing: ${current}`
      );
    }
    if (pathEscapesRoot(canonicalRoot, canonicalCurrent)) {
      throw new Error(
        `[assembleStandalone] unsafe tls-client native ${label} ancestor outside root: ${current}`
      );
    }
  }
  return true;
}

function assertSafeSourceAncestors(sourceRoot, sourcePath) {
  assertSafeAncestorChain(sourceRoot, sourcePath, { label: "source" });
}

function ensureSafeDestinationParent(outDir, destinationPath) {
  assertSafeAncestorChain(outDir, destinationPath, {
    label: "destination",
    createMissing: true,
  });
}

function revalidateSafeDestinationParent(outDir, destinationPath) {
  return assertSafeAncestorChain(outDir, destinationPath, {
    label: "destination",
    missingIsError: false,
  });
}

function assertStillSafeDestinationParent(outDir, destinationPath) {
  if (!revalidateSafeDestinationParent(outDir, destinationPath)) {
    throw new Error(
      `[assembleStandalone] tls-client native destination ancestor disappeared: ${destinationPath}`
    );
  }
}

function removeDirectDestinationSafely(outDir, destinationPath) {
  try {
    if (!revalidateSafeDestinationParent(outDir, destinationPath)) return false;
    if (!lstatIfPresent(destinationPath)) return true;
    if (!revalidateSafeDestinationParent(outDir, destinationPath)) return false;
    fs.rmSync(destinationPath, { recursive: true, force: true });
    return revalidateSafeDestinationParent(outDir, destinationPath);
  } catch {
    // The chain may now resolve through a symlink. Do not traverse it merely
    // to clean up: preserving an external file is safer than an unsafe rmSync.
    return false;
  }
}

function auditNativeBin(outDir, binDir, assetsByFile) {
  const auditSentinel = path.join(binDir, ".tls-client-native-audit");
  if (!revalidateSafeDestinationParent(outDir, auditSentinel)) return;

  for (const entryName of fs.readdirSync(binDir)) {
    const entryPath = path.join(binDir, entryName);
    try {
      const expectedSha256 = assetsByFile.get(entryName);
      if (!expectedSha256) {
        throw new Error(`[assembleStandalone] unlisted tls-client native sibling: ${entryPath}`);
      }
      assertStillSafeDestinationParent(outDir, entryPath);
      const bytes = readBoundedRegularAsset(entryPath);
      assertStillSafeDestinationParent(outDir, entryPath);
      if (!bytes) {
        throw new Error(
          `[assembleStandalone] tls-client native bundle entry disappeared: ${entryPath}`
        );
      }
      assertDigest(bytes, expectedSha256, entryPath);
      assertSafeExistingDestinationMode(entryPath);
      assertStillSafeDestinationParent(outDir, entryPath);
    } catch (error) {
      removeDirectDestinationSafely(outDir, entryPath);
      throw error;
    }
  }
  assertStillSafeDestinationParent(outDir, auditSentinel);
}

/**
 * Audit every tls-client bin topology that Next.js may bulk-copy into a
 * standalone output. This prevents a valid manifest filename with unauthorized
 * bytes from surviving outside runtime-assets merely because a later platform
 * gate verifies only selected target arches.
 *
 * @param {{outDir:string, projectRoot:string, relativeNextDistDir:string, nativeAssets:Record<string, {file:string, sha256:string}>}} options
 */
export function auditTlsClientStandaloneBundle({
  outDir,
  projectRoot,
  relativeNextDistDir,
  nativeAssets,
}) {
  const assetsByFile = new Map(
    createTlsClientNativeAssetEntries(nativeAssets).map((entry) => [
      entry.src.at(-1),
      entry.tlsClientSha256,
    ])
  );
  const projectBasename = path.basename(path.resolve(projectRoot));
  const binDirs = [
    path.join(outDir, "node_modules", "tls-client-node", "bin"),
    path.join(outDir, "projects", "OmniRoute", "node_modules", "tls-client-node", "bin"),
    path.join(outDir, projectBasename, "node_modules", "tls-client-node", "bin"),
    path.join(outDir, relativeNextDistDir, "node_modules", "tls-client-node", "bin"),
    path.join(outDir, "runtime-assets", "tls-client", "bin"),
  ];
  for (const binDir of new Set(binDirs)) auditNativeBin(outDir, binDir, assetsByFile);
}

/**
 * Copy only bytes authorized by the pinned digest, then independently read and
 * verify the emitted file. Any failed verification removes the direct output so
 * a failed assembly cannot leave a distributable manifest-named seed behind.
 *
 * @param {{sourceRoot:string, sourcePath:string, destinationPath:string, expectedSha256:string, outDir:string}} options
 * @returns {boolean} true only when source bytes were copied
 */
export function copyVerifiedTlsClientNativeAsset({
  sourceRoot,
  sourcePath,
  destinationPath,
  expectedSha256,
  outDir,
}) {
  ensureSafeDestinationParent(outDir, destinationPath);
  try {
    const sourcePathStats = lstatIfPresent(sourcePath);
    let sourceBytes;
    if (sourcePathStats) {
      assertSafeSourceAncestors(sourceRoot, sourcePath);
      sourceBytes = readBoundedRegularAsset(sourcePath);
      assertSafeSourceAncestors(sourceRoot, sourcePath);
      if (!sourceBytes) {
        throw new Error(
          `[assembleStandalone] tls-client native source disappeared during verification: ${sourcePath}`
        );
      }
    }
    if (!sourceBytes) {
      // assembleStandalone first bulk-copies a prior Next standalone tree.
      // If the source install is now absent, a manifest-named seed may still
      // have arrived through that pass; authorize it independently or fail and
      // remove it instead of silently distributing stale bytes.
      assertStillSafeDestinationParent(outDir, destinationPath);
      const existingDestinationBytes = readBoundedRegularAsset(destinationPath);
      assertStillSafeDestinationParent(outDir, destinationPath);
      if (!existingDestinationBytes) return false;
      assertDigest(existingDestinationBytes, expectedSha256, destinationPath);
      assertSafeExistingDestinationMode(destinationPath);
      assertStillSafeDestinationParent(outDir, destinationPath);
      return false;
    }
    assertDigest(sourceBytes, expectedSha256, sourcePath);

    assertStillSafeDestinationParent(outDir, destinationPath);
    const destinationStats = lstatIfPresent(destinationPath);
    if (destinationStats?.isSymbolicLink() || (destinationStats && !destinationStats.isFile())) {
      throw new Error(
        `[assembleStandalone] unsafe tls-client native destination (symlink/non-regular file): ${destinationPath}`
      );
    }
    if (!removeDirectDestinationSafely(outDir, destinationPath)) {
      throw new Error(
        `[assembleStandalone] unsafe tls-client native destination changed before removal: ${destinationPath}`
      );
    }
    assertStillSafeDestinationParent(outDir, destinationPath);

    const fd = fs.openSync(
      destinationPath,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        (fs.constants.O_NOFOLLOW ?? 0),
      0o555
    );
    try {
      assertStillSafeDestinationParent(outDir, destinationPath);
      let offset = 0;
      while (offset < sourceBytes.length) {
        const bytesWritten = fs.writeSync(fd, sourceBytes, offset, sourceBytes.length - offset);
        if (bytesWritten <= 0) {
          throw new Error(
            `[assembleStandalone] failed to write tls-client native asset: ${destinationPath}`
          );
        }
        offset += bytesWritten;
      }
      if (process.platform !== "win32") fs.fchmodSync(fd, 0o555);
      assertStillSafeDestinationParent(outDir, destinationPath);
    } finally {
      fs.closeSync(fd);
    }

    assertStillSafeDestinationParent(outDir, destinationPath);
    const destinationBytes = readBoundedRegularAsset(destinationPath);
    assertStillSafeDestinationParent(outDir, destinationPath);
    if (!destinationBytes) {
      throw new Error(
        `[assembleStandalone] copied tls-client native asset disappeared: ${destinationPath}`
      );
    }
    assertDigest(destinationBytes, expectedSha256, destinationPath);
    if (!sourceBytes.equals(destinationBytes)) {
      throw new Error(
        `[assembleStandalone] copied tls-client native asset differs from source: ${destinationPath}`
      );
    }
    assertStillSafeDestinationParent(outDir, destinationPath);
    return true;
  } catch (error) {
    removeDirectDestinationSafely(outDir, destinationPath);
    throw error;
  }
}
