import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const FIXTURE = fileURLToPath(
  new URL("../fixtures/codex-response-failed-boundary.fixture.ts", import.meta.url)
);

test("Codex public failure boundaries pass in an isolated process", () => {
  const result = spawnSync(
    process.execPath,
    [
      "--import",
      "tsx/esm",
      "--import",
      "./open-sse/utils/setupPolyfill.ts",
      "--test",
      "--test-force-exit",
      FIXTURE,
    ],
    {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { ...process.env, DISABLE_SQLITE_AUTO_BACKUP: "true" },
      timeout: 60_000,
    }
  );

  assert.ifError(result.error);
  assert.equal(
    result.signal,
    null,
    `isolated Codex boundary fixture terminated by ${result.signal}\n${result.stdout}\n${result.stderr}`
  );
  assert.equal(
    result.status,
    0,
    `isolated Codex boundary fixture failed\n${result.stdout}\n${result.stderr}`
  );
});
