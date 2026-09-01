import fs from "node:fs";
import path from "node:path";

import { copyVerifiedTlsClientNativeAsset } from "./tlsClientAssetCopy.mjs";

/**
 * A bulk standalone copy may already have carried a source symlink or a stale
 * node with the wrong type into a sidecar destination. Skip an identical real
 * target; otherwise clear the direct stale node before the explicit copy.
 */
export function resolvesToSamePath(src, dest) {
  if (path.resolve(src) === path.resolve(dest)) return true;
  if (!fs.existsSync(dest)) return false;
  try {
    return fs.realpathSync(src) === fs.realpathSync(dest);
  } catch {
    // An unresolved path cannot be proven identical, so use the normal stale-destination copy path.
    return false;
  }
}

export function clearStaleDest(dest) {
  try {
    fs.lstatSync(dest);
  } catch {
    // A missing destination is clear; later copy operations surface non-ENOENT access failures.
    return;
  }
  fs.rmSync(dest, { recursive: true, force: true });
}

/**
 * Copy registered native assets and runtime sidecars into an assembled bundle.
 * TLS entries take the digest-verified path; ordinary entries retain the
 * existing recursive-copy behavior.
 *
 * @param {{projectRoot:string, outDir:string, nativeAssetEntries:{label:string,src:string[],dest:string[],tlsClientSha256?:string}[], extraModuleEntries:{label:string,src:string[],dest:string[]}[]}} options
 */
export function copyNativeAssetsAndExtraModules({
  projectRoot,
  outDir,
  nativeAssetEntries,
  extraModuleEntries,
}) {
  for (const asset of nativeAssetEntries) {
    const src = path.join(projectRoot, ...asset.src);
    const dest = path.join(outDir, ...asset.dest);
    if (asset.tlsClientSha256) {
      const copied = copyVerifiedTlsClientNativeAsset({
        sourceRoot: projectRoot,
        sourcePath: src,
        destinationPath: dest,
        expectedSha256: asset.tlsClientSha256,
        outDir,
      });
      if (copied) console.log(`[assembleStandalone] Copied verified native asset: ${asset.label}`);
      continue;
    }
    if (!fs.existsSync(src) || resolvesToSamePath(src, dest)) continue;
    clearStaleDest(dest);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.cpSync(src, dest, { recursive: true, force: true });
    console.log(`[assembleStandalone] Copied native asset: ${asset.label}`);
  }

  for (const mod of extraModuleEntries) {
    const src = path.join(projectRoot, ...mod.src);
    if (!fs.existsSync(src)) continue;
    const dest = path.join(outDir, ...mod.dest);
    if (resolvesToSamePath(src, dest)) continue;
    clearStaleDest(dest);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.cpSync(src, dest, { recursive: true, force: true });
    console.log(`[assembleStandalone] Synced module: ${mod.label}`);
  }
}

/** Repair hollow top-level external package directories emitted by Next/Turbopack. */
export function repairEmptyExternalPackageDirs(projectRoot, bundleNodeModules) {
  const summary = { repaired: 0, packages: [] };
  const sourceNodeModules = path.join(projectRoot, "node_modules");
  if (!fs.existsSync(bundleNodeModules) || !fs.existsSync(sourceNodeModules)) return summary;

  for (const name of fs.readdirSync(bundleNodeModules)) {
    if (name.startsWith(".") || name.startsWith("@")) continue;
    const bundlePkgDir = path.join(bundleNodeModules, name);
    const sourcePkgDir = path.join(sourceNodeModules, name);

    let bundleStat;
    try {
      bundleStat = fs.statSync(bundlePkgDir);
    } catch {
      // An unreadable or vanished entry cannot be classified safely as a hollow repair candidate.
      continue;
    }
    if (!bundleStat.isDirectory()) continue;

    let bundleEntries;
    try {
      bundleEntries = fs.readdirSync(bundlePkgDir);
    } catch {
      // Without a readable listing we cannot prove the destination is hollow enough to replace.
      continue;
    }
    if (bundleEntries.length > 0 || !fs.existsSync(sourcePkgDir)) continue;

    let sourceStat;
    try {
      sourceStat = fs.statSync(sourcePkgDir);
    } catch {
      // An unreadable or vanished source cannot safely repair this optional package copy.
      continue;
    }
    if (!sourceStat.isDirectory() || resolvesToSamePath(sourcePkgDir, bundlePkgDir)) continue;
    clearStaleDest(bundlePkgDir);
    fs.cpSync(sourcePkgDir, bundlePkgDir, { recursive: true, force: true });
    summary.repaired += 1;
    summary.packages.push(name);
  }
  return summary;
}
