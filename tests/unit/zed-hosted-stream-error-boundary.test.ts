import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const TEST_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-zed-stream-data-"));
const TEST_PLUGINS_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-zed-stream-plugins-"));
const originalDataDir = process.env.DATA_DIR;
const originalPluginsDir = process.env.OMNIROUTE_PLUGINS_DIR;
const originalFetch = globalThis.fetch;
let networkCalls = 0;

process.env.DATA_DIR = TEST_DATA_DIR;
process.env.OMNIROUTE_PLUGINS_DIR = TEST_PLUGINS_DIR;
globalThis.fetch = async () => {
  networkCalls += 1;
  throw new Error("Unexpected network access in Zed stream boundary test");
};

const core = await import("../../src/lib/db/core.ts");
const { __test__ } = await import("../../open-sse/executors/zed-hosted.ts");
const { ensureStreamReadiness } = await import("../../open-sse/utils/streamReadiness.ts");
const { wrapZedCompletionStream } = __test__;

const RAW_FAILURE = "Bearer TOP_SECRET /srv/omniroute/zed-handler.ts:42 api_key=zed-secret";

function failedStatusLine(): string {
  return JSON.stringify({ status: { failed: { message: RAW_FAILURE } } });
}

function nestedFailedStatusLine(): string {
  return JSON.stringify({
    status: {
      type: "failed",
      error: { message: `${RAW_FAILURE} ${"x".repeat(2_000)}` },
    },
  });
}

function wrapNdjson(lines: unknown[]): Response {
  const body = lines
    .map((line) => (typeof line === "string" ? line : JSON.stringify(line)))
    .join("\n");
  const response = new Response(`${body}\n`, {
    status: 200,
    headers: { "Content-Type": "application/x-ndjson" },
  });
  return wrapZedCompletionStream(response, "x_ai", "grok-test");
}

function wrapOpenFailedNdjson(): Response {
  const encoder = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode(`${failedStatusLine()}\n`));
      // Deliberately stay open: status.failed is terminal by itself and must not
      // depend on the upstream socket eventually reaching EOF.
    },
    cancel() {},
  });
  return wrapZedCompletionStream(
    new Response(body, {
      status: 200,
      headers: { "Content-Type": "application/x-ndjson" },
    }),
    "x_ai",
    "grok-test"
  );
}

function parseSsePayloads(text: string): Array<Record<string, unknown>> {
  return text
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data: ") && line.slice(6) !== "[DONE]")
    .map((line) => JSON.parse(line.slice(6)) as Record<string, unknown>);
}

function assertNoSensitiveFailureText(text: string): void {
  assert.doesNotMatch(text, /TOP_SECRET|zed-secret|\/srv\/omniroute\/zed-handler\.ts/);
}

test.after(() => {
  core.resetDbInstance();
  globalThis.fetch = originalFetch;
  if (originalDataDir === undefined) delete process.env.DATA_DIR;
  else process.env.DATA_DIR = originalDataDir;
  if (originalPluginsDir === undefined) delete process.env.OMNIROUTE_PLUGINS_DIR;
  else process.env.OMNIROUTE_PLUGINS_DIR = originalPluginsDir;
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  fs.rmSync(TEST_PLUGINS_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

test("zed-hosted pre-content status.failed becomes a sanitized 502 readiness failure", async () => {
  const readiness = await ensureStreamReadiness(wrapOpenFailedNdjson(), {
    timeoutMs: 100,
    provider: "zed-hosted",
    model: "grok-test",
  });

  assert.equal(readiness.ok, false, "the structured error must remain eligible for fallback");
  if (readiness.ok) assert.fail("pre-content Zed failure must not make the stream ready");
  assert.equal(readiness.response.status, 502);
  assert.equal(readiness.code, "STREAM_EARLY_EOF");

  const bodyText = await readiness.response.text();
  const body = JSON.parse(bodyText) as {
    error: { message: string; type: string; code: string };
    upstream_details?: { error?: { message?: string } };
  };
  assert.equal(body.error.type, "stream_early_eof");
  assert.equal(body.error.code, "STREAM_EARLY_EOF");
  assert.match(body.upstream_details?.error?.message ?? "", /Zed stream failed/i);
  assertNoSensitiveFailureText(bodyText);
  assert.equal(networkCalls, 0);
});

test("zed-hosted partial output ends with a safe structured error, not a normal stop", async () => {
  const contentChunk = {
    event: {
      id: "chatcmpl-zed-partial",
      object: "chat.completion.chunk",
      choices: [{ index: 0, delta: { content: "partial answer" }, finish_reason: null }],
    },
  };
  const readiness = await ensureStreamReadiness(
    wrapNdjson([contentChunk, nestedFailedStatusLine(), { event: { ignored: "after failure" } }]),
    {
      timeoutMs: 100,
      provider: "zed-hosted",
      model: "grok-test",
    }
  );

  assert.equal(readiness.ok, true, "partial model output must remain deliverable");
  const text = await readiness.response.text();
  const payloads = parseSsePayloads(text);
  const errorPayload = payloads.find((payload) => "error" in payload) as
    { error: { message: string; type: string; code: string } } | undefined;

  assert.match(text, /partial answer/);
  assert.ok(errorPayload, "the terminal frame must use the canonical error envelope");
  assert.equal(errorPayload.error.type, "upstream_error");
  assert.equal(errorPayload.error.code, "ZED_STREAM_FAILED");
  assert.match(errorPayload.error.message, /Zed stream failed/i);
  assert.ok(errorPayload.error.message.length <= 531, "provider diagnostics must stay bounded");
  assert.doesNotMatch(text, /\[Zed error\]|"finish_reason":"stop"|data: \[DONE\]/);
  assert.doesNotMatch(text, /"ignored":"after failure"/);
  assertNoSensitiveFailureText(text);
  assert.equal(networkCalls, 0);
});
