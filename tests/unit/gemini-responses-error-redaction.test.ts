import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-gemini-errors-"));
const originalDataDir = process.env.DATA_DIR;
const originalPluginsDir = process.env.OMNIROUTE_PLUGINS_DIR;
process.env.DATA_DIR = path.join(testRoot, "data");
process.env.OMNIROUTE_PLUGINS_DIR = path.join(testRoot, "plugins");
fs.mkdirSync(process.env.DATA_DIR, { recursive: true });
fs.mkdirSync(process.env.OMNIROUTE_PLUGINS_DIR, { recursive: true });

const core = await import("../../src/lib/db/core.ts");
const { translateResponse, initState } = await import("../../open-sse/translator/index.ts");
const { FORMATS } = await import("../../open-sse/translator/formats.ts");

test.after(() => {
  core.resetDbInstance();
  if (originalDataDir === undefined) delete process.env.DATA_DIR;
  else process.env.DATA_DIR = originalDataDir;
  if (originalPluginsDir === undefined) delete process.env.OMNIROUTE_PLUGINS_DIR;
  else process.env.OMNIROUTE_PLUGINS_DIR = originalPluginsDir;
  fs.rmSync(testRoot, { recursive: true, force: true });
});

test("Gemini keeps raw failure wording internal but projects response.completed.error", () => {
  const state = initState(FORMATS.OPENAI_RESPONSES);
  const hostileMessage =
    "Gemini failed at /srv/omniroute/private-runtime.ts:71:3 token=sk-gemini-secret-123456";

  const translated = translateResponse(
    FORMATS.GEMINI,
    FORMATS.OPENAI_RESPONSES,
    {
      response: {
        error: {
          code: 503,
          status: "UNAVAILABLE",
          message: hostileMessage,
          api_key: "sk-gemini-secret-abcdef",
        },
      },
    },
    state
  );
  assert.equal(translated?.length ?? 0, 0);
  assert.match(state.upstreamError?.message ?? "", /private-runtime\.ts/);

  const flushed = translateResponse(FORMATS.GEMINI, FORMATS.OPENAI_RESPONSES, null, state);
  const completed = flushed.find((event) => event?.data?.type === "response.completed");
  assert.ok(completed);
  assert.equal(completed.data.response.status, "failed");

  const publicError = JSON.stringify(completed.data.response.error);
  assert.doesNotMatch(publicError, /private-runtime\.ts/);
  assert.doesNotMatch(publicError, /sk-gemini-secret/);
  assert.doesNotMatch(publicError, /api_key/);
  assert.equal(completed.data.response.error.code, "503");
});
