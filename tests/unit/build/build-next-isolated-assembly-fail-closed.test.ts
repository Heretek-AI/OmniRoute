import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

const BUILD_SCRIPT = resolve("scripts/build/build-next-isolated.mjs");

test("isolated build verifies the assembled TLS seed before continuing", async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "omniroute-assembly-tls-gate-"));
  const standaloneDir = join(projectRoot, ".build", "next", "standalone");
  const seedPath = join(
    standaloneDir,
    "runtime-assets",
    "tls-client",
    "bin",
    "tls-client-linux-x64"
  );
  const moduleUrl = `${pathToFileURL(BUILD_SCRIPT).href}?tls-gate=${Date.now()}`;
  const buildModule = (await import(moduleUrl)) as {
    assembleAndVerifyStandalone?: (options: {
      rootDir: string;
      buildDistDir: string;
      standaloneDir: string;
      assembleImpl: (options: Record<string, unknown>) => void;
      verifyImpl: (options: Record<string, unknown>) => Promise<void>;
    }) => Promise<void>;
  };

  try {
    assert.equal(
      typeof buildModule.assembleAndVerifyStandalone,
      "function",
      "build-next-isolated must expose its post-assembly TLS verification composition"
    );

    let assembled = false;
    await assert.rejects(
      buildModule.assembleAndVerifyStandalone?.({
        rootDir: projectRoot,
        buildDistDir: join(projectRoot, ".build", "next"),
        standaloneDir,
        assembleImpl: () => {
          mkdirSync(join(seedPath, ".."), { recursive: true });
          writeFileSync(seedPath, "TAMPERED_AFTER_ASSEMBLY");
          assembled = true;
        },
        verifyImpl: async (options) => {
          assert.equal(assembled, true, "verification must run after standalone assembly");
          assert.equal(options.rootDir, projectRoot);
          assert.equal(options.standaloneDir, standaloneDir);
          assert.equal(options.strict, true);
          assert.equal(options.requireStandalone, true);
          assert.equal(readFileSync(seedPath, "utf8"), "TAMPERED_AFTER_ASSEMBLY");
          throw new Error("TLS seed digest mismatch");
        },
      }),
      /TLS seed digest mismatch/
    );
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("isolated build fails closed when standalone assembly fails", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "omniroute-assembly-fail-closed-"));
  const nextBin = join(projectRoot, "node_modules", "next", "dist", "bin", "next");
  const sentinelPath = join(projectRoot, "build-base-path-sentinel-ran");

  try {
    mkdirSync(join(projectRoot, "node_modules", "next", "dist", "bin"), {
      recursive: true,
    });
    mkdirSync(join(projectRoot, "scripts", "build"), { recursive: true });

    // A successful fake Next build leaves an invalid standalone FILE. The real
    // assembler must throw when it tries to treat that path as a directory.
    writeFileSync(
      nextBin,
      [
        'const fs = require("node:fs");',
        'const path = require("node:path");',
        'const distDir = path.resolve(process.env.NEXT_DIST_DIR || ".build/next");',
        "fs.mkdirSync(distDir, { recursive: true });",
        'fs.writeFileSync(path.join(distDir, "standalone"), "not-a-directory");',
        'console.log("FAKE_NEXT_BUILD_SUCCEEDED");',
      ].join("\n")
    );
    writeFileSync(
      join(projectRoot, "scripts", "build", "write-build-base-path.mjs"),
      [
        'import { writeFileSync } from "node:fs";',
        `writeFileSync(${JSON.stringify(sentinelPath)}, "ran");`,
      ].join("\n")
    );

    const result = spawnSync(process.execPath, [BUILD_SCRIPT], {
      cwd: projectRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        NEXT_DIST_DIR: ".build/next",
        OMNIROUTE_BUILD_BACKEND_ONLY: "0",
        OMNIROUTE_BUILD_PROFILE: "full",
      },
      timeout: 60_000,
    });
    const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;

    assert.equal(result.error, undefined, output);
    assert.match(output, /FAKE_NEXT_BUILD_SUCCEEDED/, output);
    assert.equal(result.signal, null, output);
    assert.equal(result.status, 1, `assembly failure must be fatal\n${output}`);
    assert.match(output, /\[build-next-isolated\] Build failed:/, output);
    assert.doesNotMatch(output, /Non-fatal error assembling standalone/, output);
    assert.equal(
      existsSync(sentinelPath),
      false,
      "post-assembly steps must not run after the assembler throws"
    );
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("isolated build fails closed when Next exits successfully without standalone output", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "omniroute-standalone-missing-"));
  const nextBin = join(projectRoot, "node_modules", "next", "dist", "bin", "next");
  const sentinelPath = join(projectRoot, "build-base-path-sentinel-ran");

  try {
    mkdirSync(join(projectRoot, "node_modules", "next", "dist", "bin"), {
      recursive: true,
    });
    mkdirSync(join(projectRoot, "scripts", "build"), { recursive: true });

    // Next reports success but produces no standalone directory. This is the
    // failure mode seen when a worker aborts after Next has already decided its
    // process exit code; the wrapper must not silently skip assembly/verification.
    writeFileSync(
      nextBin,
      ['console.log("FAKE_NEXT_BUILD_SUCCEEDED_WITHOUT_STANDALONE");'].join("\n")
    );
    writeFileSync(
      join(projectRoot, "scripts", "build", "write-build-base-path.mjs"),
      [
        'import { writeFileSync } from "node:fs";',
        `writeFileSync(${JSON.stringify(sentinelPath)}, "ran");`,
      ].join("\n")
    );

    const result = spawnSync(process.execPath, [BUILD_SCRIPT], {
      cwd: projectRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        NEXT_DIST_DIR: ".build/next",
        OMNIROUTE_BUILD_BACKEND_ONLY: "0",
        OMNIROUTE_BUILD_PROFILE: "full",
      },
      timeout: 60_000,
    });
    const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;

    assert.equal(result.error, undefined, output);
    assert.match(output, /FAKE_NEXT_BUILD_SUCCEEDED_WITHOUT_STANDALONE/, output);
    assert.equal(result.signal, null, output);
    assert.equal(result.status, 1, `missing standalone output must be fatal\n${output}`);
    assert.match(
      output,
      /Next\.js build exited successfully but did not produce a standalone directory/,
      output
    );
    assert.doesNotMatch(output, /Assembling standalone bundle/, output);
    assert.equal(
      existsSync(sentinelPath),
      false,
      "post-assembly steps must not run when Next omits standalone output"
    );
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});
