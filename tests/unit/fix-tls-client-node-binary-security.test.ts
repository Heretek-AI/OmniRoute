import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import { fixTlsClientNodeBinary } from "../../scripts/build/fixTlsClientNodeBinary.mjs";

function makeRoot() {
  return mkdtempSync(join(tmpdir(), "fix-tls-client-node-binary-security-"));
}

test("strict mode rejects a symlinked node_modules ancestor before recovery writes outside root", async () => {
  const rootDir = makeRoot();
  const outsideDir = makeRoot();
  try {
    const bytes = "verified-native-must-stay-inside-root";
    const asset = {
      file: "tls-client-linux-ubuntu-amd64-1.15.1.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const outsideNodeModules = join(outsideDir, "node_modules");
    const tlsClientDir = join(outsideNodeModules, "tls-client-node");
    const rootBin = join(tlsClientDir, "bin");
    const scriptsDir = join(tlsClientDir, "scripts");
    const outsideBinary = join(rootBin, asset.file);
    const marker = join(tlsClientDir, ".postinstall-ran");
    mkdirSync(rootBin, { recursive: true });
    mkdirSync(scriptsDir, { recursive: true });
    symlinkSync(outsideNodeModules, join(rootDir, "node_modules"), "dir");
    writeFileSync(
      join(scriptsDir, "postinstall.js"),
      `require("fs").writeFileSync(${JSON.stringify(marker)}, "ran");
       require("fs").writeFileSync(${JSON.stringify(outsideBinary)}, ${JSON.stringify(bytes)});`
    );

    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset,
        strict: true,
        retryDelaysMs: [],
        log() {},
      }),
      /unsafe.*(ancestor|outside)|symlink/i
    );
    assert.equal(existsSync(marker), false);
    assert.equal(existsSync(outsideBinary), false);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
    rmSync(outsideDir, { recursive: true, force: true });
  }
});

test("strict mode revalidates root ancestors after fetch before writing recovered bytes", async () => {
  const rootDir = makeRoot();
  const outsideDir = makeRoot();
  try {
    const bytes = Buffer.from("verified-native-after-ancestor-race");
    const asset = {
      file: "tls-client-race-test.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const rootNodeModules = join(rootDir, "node_modules");
    const originalNodeModules = join(rootDir, "node_modules-before-race");
    const outsideNodeModules = join(outsideDir, "node_modules");
    const outsideBin = join(outsideNodeModules, "tls-client-node", "bin");
    const outsideBinary = join(outsideBin, asset.file);
    mkdirSync(join(rootNodeModules, "tls-client-node", "bin"), { recursive: true });
    mkdirSync(outsideBin, { recursive: true });

    const targetArch = process.arch === "arm64" ? "x64" : "arm64";
    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset,
        platform: process.platform,
        arches: [targetArch],
        fetchImpl: async () => {
          renameSync(rootNodeModules, originalNodeModules);
          symlinkSync(outsideNodeModules, rootNodeModules, "dir");
          return new Response(bytes, { status: 200 });
        },
        strict: true,
        retryDelaysMs: [],
        log() {},
      }),
      /unsafe.*(ancestor|outside)|symlink/i
    );

    assert.equal(existsSync(outsideBinary), false);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
    rmSync(outsideDir, { recursive: true, force: true });
  }
});

test("strict mode revalidates root ancestors before recovery can remove an external file", async () => {
  const rootDir = makeRoot();
  const outsideDir = makeRoot();
  try {
    const bytes = Buffer.from("verified-native-after-pre-recovery-check");
    const asset = {
      file: "tls-client-pre-recovery-race-test.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const rootNodeModules = join(rootDir, "node_modules");
    const originalNodeModules = join(rootDir, "node_modules-before-pre-recovery-race");
    const rootBin = join(rootNodeModules, "tls-client-node", "bin");
    const outsideNodeModules = join(outsideDir, "node_modules");
    const outsideBin = join(outsideNodeModules, "tls-client-node", "bin");
    const outsideBinary = join(outsideBin, asset.file);
    mkdirSync(rootBin, { recursive: true });
    mkdirSync(outsideBin, { recursive: true });
    writeFileSync(join(rootBin, asset.file), "tampered-root-binary");
    writeFileSync(outsideBinary, "external-file-must-not-be-removed");

    let swappedAncestor = false;
    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset,
        fetchImpl: async () => new Response(bytes, { status: 200 }),
        strict: true,
        retryDelaysMs: [],
        log(message) {
          if (!swappedAncestor && message.includes("missing or unverified")) {
            renameSync(rootNodeModules, originalNodeModules);
            symlinkSync(outsideNodeModules, rootNodeModules, "dir");
            swappedAncestor = true;
          }
        },
      }),
      /unsafe.*(ancestor|outside)|symlink/i
    );
    assert.equal(swappedAncestor, true);
    assert.equal(readFileSync(outsideBinary, "utf8"), "external-file-must-not-be-removed");
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
    rmSync(outsideDir, { recursive: true, force: true });
  }
});

test("strict mode revalidates root ancestors after recovery before post-verification", async () => {
  const rootDir = makeRoot();
  const outsideDir = makeRoot();
  try {
    const bytes = Buffer.from("verified-native-before-post-recovery-race");
    const asset = {
      file: "tls-client-post-recovery-race-test.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const rootNodeModules = join(rootDir, "node_modules");
    const originalNodeModules = join(rootDir, "node_modules-before-post-recovery-race");
    const outsideNodeModules = join(outsideDir, "node_modules");
    const outsideBin = join(outsideNodeModules, "tls-client-node", "bin");
    mkdirSync(join(rootNodeModules, "tls-client-node", "bin"), { recursive: true });
    mkdirSync(outsideBin, { recursive: true });
    writeFileSync(join(outsideBin, asset.file), bytes);

    const targetArch = process.arch === "arm64" ? "x64" : "arm64";
    let swappedAncestor = false;
    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset,
        platform: process.platform,
        arches: [targetArch],
        fetchImpl: async () => new Response(bytes, { status: 200 }),
        strict: true,
        retryDelaysMs: [],
        log(message) {
          if (message.includes("fetched successfully")) {
            renameSync(rootNodeModules, originalNodeModules);
            symlinkSync(outsideNodeModules, rootNodeModules, "dir");
            swappedAncestor = true;
          }
        },
      }),
      /unsafe.*(ancestor|outside)|symlink/i
    );
    assert.equal(swappedAncestor, true);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
    rmSync(outsideDir, { recursive: true, force: true });
  }
});

test("strict mode revalidates dist ancestors before copying verified bytes", async () => {
  const rootDir = makeRoot();
  const outsideDir = makeRoot();
  try {
    const bytes = Buffer.from("verified-native-before-dist-race");
    const asset = {
      file: "tls-client-dist-race-test.so",
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
    const rootDist = join(rootDir, "dist");
    const originalDist = join(rootDir, "dist-before-race");
    const outsideDist = join(outsideDir, "dist-target");
    const outsideTlsClientDir = join(outsideDist, "node_modules", "tls-client-node");
    const outsideBinary = join(outsideTlsClientDir, "bin", asset.file);
    mkdirSync(rootBin, { recursive: true });
    mkdirSync(join(rootDist, "node_modules", "tls-client-node"), { recursive: true });
    mkdirSync(outsideTlsClientDir, { recursive: true });
    writeFileSync(join(rootBin, asset.file), bytes);

    let swappedAncestor = false;
    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        asset,
        strict: true,
        retryDelaysMs: [],
        afterSourceStat() {
          if (!swappedAncestor) {
            renameSync(rootDist, originalDist);
            symlinkSync(outsideDist, rootDist, "dir");
            swappedAncestor = true;
          }
        },
        log() {},
      }),
      /unsafe.*(ancestor|outside)|symlink/i
    );
    assert.equal(swappedAncestor, true);
    assert.equal(existsSync(outsideBinary), false);
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
    rmSync(outsideDir, { recursive: true, force: true });
  }
});

test("strict mode rejects unmanifested native siblings in every packaged bin root", async () => {
  const locations: Array<{
    label: string;
    binDir: (rootDir: string, standaloneDir: string) => string;
    nextDistDir?: string | null;
  }> = [
    {
      label: "root node_modules",
      binDir: (rootDir: string, _standaloneDir: string) =>
        join(rootDir, "node_modules", "tls-client-node", "bin"),
    },
    {
      label: "dist node_modules",
      binDir: (rootDir: string, _standaloneDir: string) =>
        join(rootDir, "dist", "node_modules", "tls-client-node", "bin"),
    },
    {
      label: "standalone node_modules",
      binDir: (_rootDir: string, standaloneDir: string) =>
        join(standaloneDir, "node_modules", "tls-client-node", "bin"),
    },
    {
      label: "projects OmniRoute nested standalone node_modules",
      binDir: (_rootDir: string, standaloneDir: string) =>
        join(standaloneDir, "projects", "OmniRoute", "node_modules", "tls-client-node", "bin"),
    },
    {
      label: "root-basename nested standalone node_modules",
      binDir: (rootDir: string, standaloneDir: string) =>
        join(standaloneDir, basename(rootDir), "node_modules", "tls-client-node", "bin"),
    },
    {
      label: "standalone runtime assets",
      binDir: (_rootDir: string, standaloneDir: string) =>
        join(standaloneDir, "runtime-assets", "tls-client", "bin"),
    },
    {
      label: "isolated next build node_modules",
      nextDistDir: null,
      binDir: (rootDir: string, _standaloneDir: string) =>
        join(rootDir, ".build", "next", "node_modules", "tls-client-node", "bin"),
    },
    {
      label: "configured isolated next build node_modules",
      nextDistDir: ".custom-next",
      binDir: (rootDir: string, _standaloneDir: string) =>
        join(rootDir, ".custom-next", "node_modules", "tls-client-node", "bin"),
    },
    {
      label: "nested standalone next build node_modules",
      nextDistDir: null,
      binDir: (_rootDir: string, standaloneDir: string) =>
        join(standaloneDir, ".build", "next", "node_modules", "tls-client-node", "bin"),
    },
    {
      label: "configured nested standalone next build node_modules",
      nextDistDir: ".custom-next",
      binDir: (_rootDir: string, standaloneDir: string) =>
        join(standaloneDir, ".custom-next", "node_modules", "tls-client-node", "bin"),
    },
  ];

  for (const location of locations) {
    const rootDir = makeRoot();
    const hadNextDistDir = Object.prototype.hasOwnProperty.call(process.env, "NEXT_DIST_DIR");
    const previousNextDistDir = process.env.NEXT_DIST_DIR;
    try {
      if (location.nextDistDir === null) delete process.env.NEXT_DIST_DIR;
      else if (location.nextDistDir) process.env.NEXT_DIST_DIR = location.nextDistDir;
      const binary = Buffer.from(`verified-target-for-${location.label}`);
      const asset = {
        file: "tls-client-target-test.so",
        sha256: createHash("sha256").update(binary).digest("hex"),
      };
      const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
      const standaloneDir = join(rootDir, ".build", "next", "standalone");
      mkdirSync(rootBin, { recursive: true });
      mkdirSync(standaloneDir, { recursive: true });
      writeFileSync(join(rootBin, asset.file), binary);
      const candidateBin = location.binDir(rootDir, standaloneDir);
      mkdirSync(candidateBin, { recursive: true });
      writeFileSync(join(candidateBin, "unlisted-native.so"), "must-not-ship");

      await assert.rejects(
        fixTlsClientNodeBinary({
          rootDir,
          asset,
          standaloneDir,
          requireStandalone: true,
          strict: true,
          retryDelaysMs: [],
          fetchImpl: async () => {
            throw new Error("verified root target must not trigger recovery");
          },
          log() {},
        }),
        /unlisted|not.*manifest|unexpected native sibling/i,
        location.label
      );
    } finally {
      if (hadNextDistDir) process.env.NEXT_DIST_DIR = previousNextDistDir;
      else delete process.env.NEXT_DIST_DIR;
      rmSync(rootDir, { recursive: true, force: true });
    }
  }
});

test("strict mode rejects a manifest-known non-target sibling with an invalid digest", async () => {
  const rootDir = makeRoot();
  try {
    const targetBytes = Buffer.from("verified-linux-x64-target");
    const siblingBytes = Buffer.from("verified-linux-arm64-sibling");
    const targetAsset = {
      file: "tls-client-linux-x64-test.so",
      sha256: createHash("sha256").update(targetBytes).digest("hex"),
    };
    const siblingAsset = {
      file: "tls-client-linux-arm64-test.so",
      sha256: createHash("sha256").update(siblingBytes).digest("hex"),
    };
    const nativeAssets = {
      "linux-x64": targetAsset,
      "linux-arm64": siblingAsset,
    };
    const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
    mkdirSync(rootBin, { recursive: true });
    writeFileSync(join(rootBin, targetAsset.file), targetBytes);
    writeFileSync(join(rootBin, siblingAsset.file), "tampered-known-sibling");

    await assert.rejects(
      fixTlsClientNodeBinary({
        rootDir,
        platform: "linux",
        arches: ["x64"],
        nativeAssets,
        strict: true,
        retryDelaysMs: [],
        fetchImpl: async () => {
          throw new Error("verified target must not trigger recovery");
        },
        log() {},
      }),
      /unverified|sha-?256|digest/i
    );
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("strict mode allows a verified subset of manifest-known native siblings", async () => {
  const rootDir = makeRoot();
  try {
    const targetBytes = Buffer.from("verified-subset-linux-x64");
    const siblingBytes = Buffer.from("verified-subset-linux-arm64");
    const targetAsset = {
      file: "tls-client-subset-linux-x64.so",
      sha256: createHash("sha256").update(targetBytes).digest("hex"),
    };
    const siblingAsset = {
      file: "tls-client-subset-linux-arm64.so",
      sha256: createHash("sha256").update(siblingBytes).digest("hex"),
    };
    const nativeAssets = {
      "linux-x64": targetAsset,
      "linux-arm64": siblingAsset,
    };
    const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
    const targetPath = join(rootBin, targetAsset.file);
    const siblingPath = join(rootBin, siblingAsset.file);
    mkdirSync(rootBin, { recursive: true });
    writeFileSync(targetPath, targetBytes);
    writeFileSync(siblingPath, siblingBytes);

    let fetchCalls = 0;
    await fixTlsClientNodeBinary({
      rootDir,
      platform: "linux",
      arches: ["x64"],
      nativeAssets,
      strict: true,
      retryDelaysMs: [],
      fetchImpl: async () => {
        fetchCalls += 1;
        throw new Error("verified subset must not trigger recovery");
      },
      log() {},
    });

    assert.equal(fetchCalls, 0);
    assert.deepEqual(readFileSync(targetPath), targetBytes);
    assert.deepEqual(readFileSync(siblingPath), siblingBytes);
    if (process.platform !== "win32") {
      assert.equal(lstatSync(targetPath).mode & 0o777, 0o555);
      assert.equal(lstatSync(siblingPath).mode & 0o777, 0o555);
    }
  } finally {
    rmSync(rootDir, { recursive: true, force: true });
  }
});

test("strict mode rejects manifest-known siblings that are symlinks or non-files", async () => {
  for (const variant of ["symlink", "directory"] as const) {
    const rootDir = makeRoot();
    try {
      const targetBytes = Buffer.from(`verified-target-for-${variant}`);
      const siblingBytes = Buffer.from(`verified-sibling-for-${variant}`);
      const targetAsset = {
        file: `tls-client-target-${variant}.so`,
        sha256: createHash("sha256").update(targetBytes).digest("hex"),
      };
      const siblingAsset = {
        file: `tls-client-sibling-${variant}.so`,
        sha256: createHash("sha256").update(siblingBytes).digest("hex"),
      };
      const nativeAssets = {
        "linux-x64": targetAsset,
        "linux-arm64": siblingAsset,
      };
      const rootBin = join(rootDir, "node_modules", "tls-client-node", "bin");
      const siblingPath = join(rootBin, siblingAsset.file);
      mkdirSync(rootBin, { recursive: true });
      writeFileSync(join(rootBin, targetAsset.file), targetBytes);
      if (variant === "symlink") {
        const outsideFile = join(rootDir, "outside-native.so");
        writeFileSync(outsideFile, siblingBytes);
        symlinkSync(outsideFile, siblingPath);
      } else {
        mkdirSync(siblingPath);
      }

      await assert.rejects(
        fixTlsClientNodeBinary({
          rootDir,
          platform: "linux",
          arches: ["x64"],
          nativeAssets,
          strict: true,
          retryDelaysMs: [],
          log() {},
        }),
        /unsafe.*sibling|symlink|non-regular file/i,
        variant
      );
    } finally {
      rmSync(rootDir, { recursive: true, force: true });
    }
  }
});
