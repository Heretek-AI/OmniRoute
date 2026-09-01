import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..", "..");

function getDockerStage(dockerfile: string, stageName: string): string {
  const stageStartPattern = new RegExp(`^FROM\\s+.+\\s+AS\\s+${stageName}\\s*$`, "m");
  const stageStart = dockerfile.search(stageStartPattern);

  assert.notEqual(stageStart, -1, `Dockerfile.bun must define the ${stageName} stage`);

  const nextStageOffset = dockerfile.slice(stageStart + 1).search(/^FROM\s+/m);
  const stageEnd = nextStageOffset === -1 ? dockerfile.length : stageStart + 1 + nextStageOffset;

  return dockerfile.slice(stageStart, stageEnd);
}

function assertStrictTlsClientBinaryChain(
  dockerfile: string,
  dockerfileName: string,
  buildCommand: string
) {
  assert.doesNotMatch(
    dockerfile,
    /(?:node|bun)\s+node_modules\/tls-client-node\/scripts\/postinstall\.js/,
    `${dockerfileName} must not bypass checksum verification by invoking the upstream downloader directly`
  );

  const rootRepair = dockerfile.indexOf("scripts/build/fixTlsClientNodeBinary.mjs --strict");
  const build = dockerfile.indexOf(buildCommand);
  const standaloneRepair = dockerfile.search(
    /scripts\/build\/fixTlsClientNodeBinary\.mjs --strict\s*\\?\s*--standalone-dir \.build\/next\/standalone/
  );

  assert.notEqual(rootRepair, -1, `${dockerfileName} must strictly repair the root native binary`);
  assert.notEqual(build, -1, `${dockerfileName} must contain its expected build command`);
  assert.notEqual(
    standaloneRepair,
    -1,
    `${dockerfileName} must strictly verify the post-build standalone native binary`
  );
  assert.ok(rootRepair < build, `${dockerfileName} must repair the root binary before build`);
  assert.ok(
    build < standaloneRepair,
    `${dockerfileName} must verify the standalone binary after build`
  );
}

test("Docker images fail closed around tls-client-node's native binary (#7802)", () => {
  const dockerfile = readFileSync(join(ROOT, "Dockerfile"), "utf8");
  const bunDockerfile = readFileSync(join(ROOT, "Dockerfile.bun"), "utf8");
  const postinstall = readFileSync(join(ROOT, "scripts/build/postinstall.mjs"), "utf8");

  assert.match(
    dockerfile,
    // Flag-order tolerant on purpose: the assertion is about the --ignore-scripts
    // PRECONDITION, not the exact flag list. #9185 inserted --include=optional
    // (LLMLingua optional deps) and broke the literal pin without touching intent.
    /npm ci(?: --[\w-]+(?:=[\w-]+)?)* --ignore-scripts/,
    "expected the builder stage to install with --ignore-scripts (precondition of #7802)"
  );

  assert.match(
    dockerfile,
    /better-sqlite3[\s\S]*node-gyp\.js rebuild/,
    "expected an explicit better-sqlite3 rebuild step after --ignore-scripts"
  );

  assert.match(
    postinstall,
    /fixWreqJsBinary/,
    "expected postinstall.mjs to repair wreq-js's native binary"
  );

  assert.match(
    dockerfile,
    /COPY scripts\/build\/fixTlsClientNodeBinary\.mjs \.\/scripts\/build\/fixTlsClientNodeBinary\.mjs/,
    "Docker builder must copy the checksum-verifying repair helper"
  );
  assert.match(
    dockerfile,
    /COPY open-sse\/config\/tlsClientNativeManifest\.json \.\/open-sse\/config\/tlsClientNativeManifest\.json/,
    "Docker builder must copy the pinned version and official SHA-256 manifest"
  );
  assertStrictTlsClientBinaryChain(dockerfile, "Dockerfile", "npm run build");
  assertStrictTlsClientBinaryChain(bunDockerfile, "Dockerfile.bun", "bun run --quiet build");

  const bunStandaloneCopy = bunDockerfile
    .split(/\r?\n/)
    .find((line) => line.includes("/app/.build/next/standalone"));
  assert.ok(bunStandaloneCopy, "Dockerfile.bun must copy the verified standalone runtime");
  assert.match(
    bunStandaloneCopy,
    /\s--chown=bun:bun(?:\s|$)/,
    "Dockerfile.bun must make the verified TLS seed owned by USER bun"
  );
  assert.match(
    bunDockerfile,
    /RUN mkdir -p \/app\/data\s*\\?\s*&& chown -R bun:bun \/app\/data/,
    "Dockerfile.bun must let USER bun materialize the verified seed under DATA_DIR"
  );

  for (const [dockerfileName, contents] of [
    ["Dockerfile", dockerfile],
    ["Dockerfile.bun", bunDockerfile],
  ]) {
    assert.doesNotMatch(
      contents,
      /org\.opencontainers\.image\.licenses\s*=/,
      `${dockerfileName} must not claim a single SPDX license for its multi-license image`
    );
  }

  const dockerfileHandlesIt = /tls-client-node[\s\S]{0,200}(postinstall|rebuild|download)/i.test(
    dockerfile
  );
  const postinstallHandlesIt = /tls-client-node/i.test(postinstall);

  assert.ok(
    dockerfileHandlesIt || postinstallHandlesIt,
    "tls-client-node has no --ignore-scripts compensation in Dockerfile or " +
      "scripts/build/postinstall.mjs (unlike better-sqlite3 and wreq-js) — " +
      "node_modules/tls-client-node/bin/ is never populated in the official " +
      "Docker image, so chatgpt-web/claude-web/grok-web/lmarena/perplexity-web " +
      "all fail with TlsClientUnavailableError at first request (#7802)"
  );
});

test("Dockerfile.bun production stages run the application as USER bun", () => {
  const bunDockerfile = readFileSync(join(ROOT, "Dockerfile.bun"), "utf8");
  const runnerBase = getDockerStage(bunDockerfile, "runner-base");
  const runnerWeb = getDockerStage(bunDockerfile, "runner-web");

  const baseAptInstall = runnerBase.indexOf("RUN apt-get update");
  const baseLastCopy = runnerBase.lastIndexOf("COPY ");
  const baseUserBun = runnerBase.search(/^USER\s+bun\s*$/m);
  const baseHealthcheck = runnerBase.indexOf("HEALTHCHECK");
  const baseEntrypoint = runnerBase.indexOf("ENTRYPOINT");

  assert.notEqual(baseAptInstall, -1, "runner-base must install its runtime packages");
  assert.notEqual(baseLastCopy, -1, "runner-base must copy its runtime artifacts");
  assert.notEqual(baseUserBun, -1, "runner-base must explicitly drop privileges to USER bun");
  assert.notEqual(baseHealthcheck, -1, "runner-base must define its healthcheck");
  assert.notEqual(baseEntrypoint, -1, "runner-base must define its entrypoint");
  assert.ok(baseAptInstall < baseUserBun, "runner-base must drop privileges after apt install");
  assert.ok(baseLastCopy < baseUserBun, "runner-base must drop privileges after artifact copies");
  assert.ok(baseUserBun < baseHealthcheck, "runner-base must be USER bun before HEALTHCHECK");
  assert.ok(baseUserBun < baseEntrypoint, "runner-base must be USER bun before ENTRYPOINT");

  const webAptInstall = runnerWeb.indexOf("RUN apt-get update");
  const webUserBun = runnerWeb.search(/^USER\s+bun\s*$/m);

  assert.notEqual(webAptInstall, -1, "runner-web must install its browser packages");
  assert.notEqual(webUserBun, -1, "runner-web must return to USER bun");
  assert.ok(webAptInstall < webUserBun, "runner-web must return to USER bun after apt install");
});
