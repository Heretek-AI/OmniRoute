import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const ROOT = join(import.meta.dirname, "..", "..", "..");
const prepareScript = readFileSync(
  join(ROOT, "scripts", "build", "prepare-electron-standalone.mjs"),
  "utf8"
);
const electronReleaseWorkflow = readFileSync(
  join(ROOT, ".github", "workflows", "electron-release.yml"),
  "utf8"
);
const fixerScript = readFileSync(
  join(ROOT, "scripts", "build", "fixTlsClientNodeBinary.mjs"),
  "utf8"
);
const rootPackage = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as {
  scripts: Record<string, string>;
};
const electronPackage = JSON.parse(
  readFileSync(join(ROOT, "electron", "package.json"), "utf8")
) as {
  scripts: Record<string, string>;
  build: {
    win: { target: Array<{ arch: string[] }> };
    linux: { target: Array<{ arch: string[] }> };
  };
};

function getFixerCalls(source: string): RegExpMatchArray[] {
  return [...source.matchAll(/await\s+fixTlsClientNodeBinary\(\{([\s\S]*?)\}\);/g)];
}

function assertStrictStandaloneCall(call: RegExpMatchArray, standaloneDir: string): void {
  const options = call[1];
  assert.match(options, /\brootDir:\s*ROOT\b/);
  assert.match(options, /\bstrict:\s*true\b/);
  assert.match(options, /\bplatform:\s*ELECTRON_TARGET_PLATFORM\b/);
  assert.match(options, /\barches:\s*ELECTRON_TARGET_ARCHES\b/);
  assert.match(options, new RegExp(`\\bstandaloneDir:\\s*${standaloneDir}\\b`));
  assert.match(options, /\brequireStandalone:\s*true\b/);
}

test("Electron staging verifies the source and final TLS client runtime seeds in release order", () => {
  assert.match(
    prepareScript,
    /import\s*\{\s*fixTlsClientNodeBinary\s*\}\s*from\s*"\.\/fixTlsClientNodeBinary\.mjs";/
  );
  assert.match(prepareScript, /const STANDALONE_DIR = join\(DIST_DIR, "standalone"\);/);
  assert.match(
    prepareScript,
    /const ELECTRON_STANDALONE_DIR = join\(ROOT, "\.build", "electron-standalone"\);/
  );
  assert.match(prepareScript, /process\.env\.OMNIROUTE_ELECTRON_TARGET_PLATFORM/);
  assert.match(prepareScript, /process\.env\.OMNIROUTE_ELECTRON_TARGET_ARCHES/);
  assert.match(
    prepareScript,
    /ELECTRON_TARGET_PLATFORM\s*===\s*"linux"[\s\S]{0,160}\["x64",\s*"arm64"\][\s\S]{0,160}\[process\.arch\]/,
    "Linux packaging must safely default to both electron-builder target arches"
  );
  assert.match(
    fixerScript,
    /for\s*\(const targetArch of targetArches\)/,
    "the fixer must verify every requested target arch"
  );
  assert.match(fixerScript, /readCliOptionValues\(cliArgs, \["--platform"\]\)/);
  assert.match(
    fixerScript,
    /readCliOptionValues\(cliArgs, \["--arch", "--arches"\]\)/,
    "the CLI must accept one or more target arches"
  );

  const fixerCalls = getFixerCalls(prepareScript);
  assert.equal(fixerCalls.length, 2, "Electron staging must verify exactly both bundle boundaries");
  assertStrictStandaloneCall(fixerCalls[0], "STANDALONE_DIR");
  assertStrictStandaloneCall(fixerCalls[1], "ELECTRON_STANDALONE_DIR");

  const sourceFixIndex = fixerCalls[0].index ?? -1;
  const assembleIndex = prepareScript.indexOf("assembleStandalone({");
  const optionalPackIndex = prepareScript.indexOf("await stageOptionalPacks({");
  const finalFixIndex = fixerCalls[1].index ?? -1;
  const successIndex = prepareScript.indexOf("[electron] prepared standalone bundle:");

  assert.ok(sourceFixIndex >= 0 && sourceFixIndex < assembleIndex, "verify source before assembly");
  assert.ok(
    assembleIndex < optionalPackIndex && optionalPackIndex < finalFixIndex,
    "verify the final Electron bundle after all staging mutations"
  );
  assert.ok(
    finalFixIndex < successIndex,
    "verify the final Electron bundle before reporting success"
  );
});

test("shared Electron web build seeds the TLS client binary before packing the artifact", () => {
  const webBuildStart = electronReleaseWorkflow.indexOf("\n  web-build:");
  const buildStart = electronReleaseWorkflow.indexOf("\n  build:", webBuildStart + 1);
  assert.ok(webBuildStart >= 0 && buildStart > webBuildStart, "locate the shared web-build job");

  const webBuildJob = electronReleaseWorkflow.slice(webBuildStart, buildStart);
  const buildIndex = webBuildJob.indexOf("run: npm run build");
  const fixerIndex = webBuildJob.indexOf(
    "run: node scripts/build/fixTlsClientNodeBinary.mjs --strict --standalone-dir .build/next/standalone"
  );
  const packIndex = webBuildJob.indexOf(
    "run: node scripts/build/standaloneBundle.mjs pack --out web-bundle.tar.gz"
  );

  assert.ok(buildIndex >= 0, "shared web-build job must build the Next standalone bundle");
  assert.ok(fixerIndex > buildIndex, "strict TLS client seed verification must follow Next build");
  assert.ok(packIndex > fixerIndex, "strict TLS client seed verification must precede packing");
});

test("Electron matrix passes platform and every packaging arch to bundle preparation via env", () => {
  const buildStepStart = electronReleaseWorkflow.indexOf(
    "- name: Build Electron for ${{ matrix.platform }}"
  );
  const smokeStepStart = electronReleaseWorkflow.indexOf(
    "- name: Smoke packaged Electron app",
    buildStepStart + 1
  );
  assert.ok(buildStepStart >= 0 && smokeStepStart > buildStepStart, "locate Electron build step");

  const buildStep = electronReleaseWorkflow.slice(buildStepStart, smokeStepStart);
  assert.match(buildStep, /OMNIROUTE_ELECTRON_TARGET_PLATFORM:\s*\$\{\{ matrix\.os \}\}/);
  assert.match(buildStep, /OMNIROUTE_ELECTRON_TARGET_ARCHES:\s*\$\{\{ matrix\.arch \}\}/);
  assert.match(
    electronReleaseWorkflow,
    /platform:\s*linux[\s\S]{0,180}os:\s*linux[\s\S]{0,80}arch:\s*x64,arm64/,
    "the Linux matrix must continue declaring both packaged architectures"
  );
});

test("root Electron build scripts pass each packaged platform and arch to bundle preparation", () => {
  assert.deepEqual(
    [...new Set(electronPackage.build.win.target.flatMap((target) => target.arch))],
    ["x64"],
    "Windows packages x64 artifacts"
  );
  assert.deepEqual(
    [...new Set(electronPackage.build.linux.target.flatMap((target) => target.arch))],
    ["x64", "arm64"],
    "Linux packages x64 and arm64 artifacts"
  );
  assert.match(electronPackage.scripts["build:mac-x64"], /electron-builder --mac --x64$/);
  assert.match(electronPackage.scripts["build:mac-arm64"], /electron-builder --mac --arm64$/);

  assert.match(
    rootPackage.scripts["electron:build:win"],
    /cd electron && cross-env OMNIROUTE_ELECTRON_TARGET_PLATFORM=win32 OMNIROUTE_ELECTRON_TARGET_ARCHES=x64 npm run build:win$/,
    "Windows preparation must verify the win32/x64 DLL seed"
  );
  assert.match(
    rootPackage.scripts["electron:build:mac"],
    /cd electron && cross-env OMNIROUTE_ELECTRON_TARGET_PLATFORM=darwin OMNIROUTE_ELECTRON_TARGET_ARCHES=x64 npm run build:mac-x64 && cross-env OMNIROUTE_ELECTRON_TARGET_PLATFORM=darwin OMNIROUTE_ELECTRON_TARGET_ARCHES=arm64 npm run build:mac-arm64$/,
    "macOS preparation must verify the exact Intel and Apple Silicon seeds it packages"
  );
  assert.match(
    rootPackage.scripts["electron:build:linux"],
    /cd electron && cross-env OMNIROUTE_ELECTRON_TARGET_PLATFORM=linux OMNIROUTE_ELECTRON_TARGET_ARCHES=x64,arm64 npm run build:linux$/,
    "Linux preparation must verify both configured electron-builder target arches"
  );
});
