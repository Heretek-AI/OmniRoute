// tests/unit/chatcore-stream-error-result.test.ts
// Characterization of isSemaphoreCapacityError / createStreamingErrorResult /
// getUpstreamErrorIdentifier — streaming error-result helpers extracted from handleChatCore
// (chatCore god-file decomposition, #3501). Locks the semaphore code matching, the SSE error
// envelope shape (status, headers, `data: {...}\n\ndata: [DONE]\n\n` body, optional code/type), and
// the string-code extraction.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-stream-error-result-"));
const originalDataDir = process.env.DATA_DIR;
const originalPluginsDir = process.env.OMNIROUTE_PLUGINS_DIR;
process.env.DATA_DIR = path.join(testRoot, "data");
process.env.OMNIROUTE_PLUGINS_DIR = path.join(testRoot, "plugins");
fs.mkdirSync(process.env.DATA_DIR, { recursive: true });
fs.mkdirSync(process.env.OMNIROUTE_PLUGINS_DIR, { recursive: true });

const core = await import("../../src/lib/db/core.ts");
const { isSemaphoreCapacityError, createStreamingErrorResult, getUpstreamErrorIdentifier } =
  await import("../../open-sse/handlers/chatCore/streamErrorResult.ts");

test.after(() => {
  core.resetDbInstance();
  if (originalDataDir === undefined) delete process.env.DATA_DIR;
  else process.env.DATA_DIR = originalDataDir;
  if (originalPluginsDir === undefined) delete process.env.OMNIROUTE_PLUGINS_DIR;
  else process.env.OMNIROUTE_PLUGINS_DIR = originalPluginsDir;
  fs.rmSync(testRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

test("isSemaphoreCapacityError matches the two semaphore codes only", () => {
  assert.equal(isSemaphoreCapacityError({ code: "SEMAPHORE_TIMEOUT" }), true);
  assert.equal(isSemaphoreCapacityError({ code: "SEMAPHORE_QUEUE_FULL" }), true);
  assert.equal(isSemaphoreCapacityError({ code: "OTHER" }), false);
  assert.equal(isSemaphoreCapacityError(null), false);
  assert.equal(isSemaphoreCapacityError("SEMAPHORE_TIMEOUT"), false);
});

test("createStreamingErrorResult builds an SSE error envelope with [DONE] terminator", async () => {
  const result = createStreamingErrorResult(503, "boom");
  assert.equal(result.success, false);
  assert.equal(result.status, 503);
  assert.equal(result.error, "boom");
  assert.equal(result.response.status, 503);
  assert.equal(result.response.headers.get("Content-Type"), "text/event-stream");
  assert.equal(result.response.headers.get("X-Accel-Buffering"), "no");
  const body = await result.response.text();
  assert.ok(body.startsWith("data: "));
  assert.ok(body.endsWith("data: [DONE]\n\n"));
  const json = JSON.parse(body.slice("data: ".length, body.indexOf("\n\n")));
  assert.equal(json.error.message, "boom");
});

test("createStreamingErrorResult attaches optional code and type", async () => {
  const result = createStreamingErrorResult(429, "slow down", "rate_limited", "rate_limit_error");
  const body = await result.response.text();
  const json = JSON.parse(body.slice("data: ".length, body.indexOf("\n\n")));
  assert.equal(json.error.code, "rate_limited");
  assert.equal(json.error.type, "rate_limit_error");
});

test("createStreamingErrorResult sanitizes code and type at the SSE boundary", async () => {
  const result = createStreamingErrorResult(
    502,
    "upstream failed",
    "sk-live-secret-value",
    "server_error\nX-Leak: yes"
  );
  const body = await result.response.text();
  const json = JSON.parse(body.slice("data: ".length, body.indexOf("\n\n"))) as {
    error: { code: string; type: string };
  };

  assert.equal(json.error.code, "bad_gateway");
  assert.equal(json.error.type, "server_error");
  assert.doesNotMatch(body, /sk-live-secret-value|X-Leak/);
});

test("getUpstreamErrorIdentifier returns a non-empty string code or undefined", () => {
  assert.equal(getUpstreamErrorIdentifier({ code: "ECONNRESET" }), "ECONNRESET");
  assert.equal(getUpstreamErrorIdentifier({ code: "" }), undefined);
  assert.equal(getUpstreamErrorIdentifier({ code: 123 }), undefined);
  assert.equal(getUpstreamErrorIdentifier(null), undefined);
  assert.equal(getUpstreamErrorIdentifier("ECONNRESET"), undefined);
});
