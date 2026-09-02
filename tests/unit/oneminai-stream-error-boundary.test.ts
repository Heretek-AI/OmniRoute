import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const originalDataDir = process.env.DATA_DIR;
const originalPluginsDir = process.env.OMNIROUTE_PLUGINS_DIR;
const testRoot = mkdtempSync(join(tmpdir(), "omniroute-onemin-stream-error-"));
const testDataDir = join(testRoot, "data");
const testPluginsDir = join(testRoot, "plugins");

mkdirSync(testDataDir, { recursive: true });
mkdirSync(testPluginsDir, { recursive: true });
process.env.DATA_DIR = testDataDir;
process.env.OMNIROUTE_PLUGINS_DIR = testPluginsDir;

const [{ OneMinAiExecutor }, { ensureStreamReadiness }, dbCore] = await Promise.all([
  import("../../open-sse/executors/oneminai.ts"),
  import("../../open-sse/utils/streamReadiness.ts"),
  import("../../src/lib/db/core.ts"),
]);

const originalFetch = globalThis.fetch;
const encoder = new TextEncoder();
const STREAM_URL = "https://api.1min.ai/api/chat-with-ai?isStreaming=true";

function restoreEnv(name: "DATA_DIR" | "OMNIROUTE_PLUGINS_DIR", value: string | undefined) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

function installStreamingFetch(events: string[]): () => number {
  let calls = 0;
  globalThis.fetch = async (input, init = {}) => {
    calls += 1;
    assert.equal(String(input), STREAM_URL, "the test must never permit another network target");
    assert.equal(init.method, "POST");
    assert.equal((init.headers as Record<string, string>)["API-KEY"], "unit-test-key");

    return new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          for (const event of events) controller.enqueue(encoder.encode(event));
          controller.close();
        },
      }),
      { status: 200, headers: { "Content-Type": "text/event-stream" } }
    );
  };
  return () => calls;
}

async function executeStreaming(events: string[]): Promise<Response> {
  const getCalls = installStreamingFetch(events);
  const result = await new OneMinAiExecutor().execute({
    model: "gpt-4o-mini",
    body: { messages: [{ role: "user", content: "hello" }] },
    stream: true,
    credentials: { apiKey: "unit-test-key" },
    signal: AbortSignal.timeout(10_000),
    log: null,
  });
  assert.equal(getCalls(), 1);
  return result.response;
}

test.afterEach(() => {
  globalThis.fetch = originalFetch;
});

test.after(() => {
  globalThis.fetch = originalFetch;
  dbCore.resetDbInstance();
  restoreEnv("DATA_DIR", originalDataDir);
  restoreEnv("OMNIROUTE_PLUGINS_DIR", originalPluginsDir);
  rmSync(testRoot, { recursive: true, force: true });
});

test("1min.ai pre-content stream errors stay errors and permit readiness fallback", async () => {
  const rawMessage =
    "quota lookup failed at /srv/omniroute/open-sse/executors/oneminai.ts:170\n" +
    "    at translateSseStream (/srv/omniroute/open-sse/executors/oneminai.ts:99:5)";
  const response = await executeStreaming([
    `event: error\ndata: ${JSON.stringify({ error: { message: rawMessage } })}\n\n`,
  ]);
  const clientCopy = response.clone();

  const readiness = await ensureStreamReadiness(response, {
    timeoutMs: 100,
    provider: "oneminai",
    model: "gpt-4o-mini",
  });
  assert.equal(readiness.ok, false);
  if (readiness.ok) assert.fail("an error-only stream must not become ready");
  assert.equal(readiness.response.status, 502);
  const fallbackBody = await readiness.response.text();
  assert.match(fallbackBody, /STREAM_EARLY_EOF/);
  assert.doesNotMatch(fallbackBody, /\/srv\/omniroute/);
  assert.doesNotMatch(fallbackBody, /translateSseStream/);

  const clientText = await clientCopy.text();
  assert.match(clientText, /^data: \{"error":/);
  assert.match(clientText, /quota lookup failed at <path>/);
  assert.match(clientText, /data: \[DONE\]/);
  assert.doesNotMatch(clientText, /"role":"assistant"/);
  assert.doesNotMatch(clientText, /"finish_reason":"stop"/);
  assert.doesNotMatch(clientText, /\/srv\/omniroute/);
  assert.doesNotMatch(clientText, /translateSseStream/);
});

test("1min.ai preserves partial content before a sanitized terminal stream error", async () => {
  const response = await executeStreaming([
    'event: content\ndata: {"content":"partial answer"}\n\n',
    `event: error\ndata: ${JSON.stringify({
      message:
        "provider failed at /srv/omniroute/open-sse/executors/oneminai.ts:214 api_key=top-secret\nstack tail",
    })}\n\n`,
    'event: done\ndata: {"message":"must not become a normal stop"}\n\n',
  ]);

  const readiness = await ensureStreamReadiness(response, {
    timeoutMs: 100,
    provider: "oneminai",
    model: "gpt-4o-mini",
  });
  assert.equal(readiness.ok, true);
  if (!readiness.ok) assert.fail("real partial content must make the stream ready");

  const clientText = await readiness.response.text();
  const roleIndex = clientText.indexOf('"role":"assistant"');
  const contentIndex = clientText.indexOf("partial answer");
  const errorIndex = clientText.indexOf('"error":');
  const doneIndex = clientText.indexOf("data: [DONE]");

  assert.ok(roleIndex >= 0 && roleIndex < contentIndex, "the role must precede real content");
  assert.ok(contentIndex < errorIndex, "partial content must remain before the terminal error");
  assert.ok(errorIndex < doneIndex, "the structured error must precede [DONE]");
  assert.equal(clientText.match(/"role":"assistant"/g)?.length, 1);
  assert.match(clientText, /provider failed at <path> api_key=\[REDACTED\]/);
  assert.doesNotMatch(clientText, /"finish_reason":"stop"/);
  assert.doesNotMatch(clientText, /must not become a normal stop/);
  assert.doesNotMatch(clientText, /top-secret/);
  assert.doesNotMatch(clientText, /\/srv\/omniroute/);
  assert.doesNotMatch(clientText, /stack tail/);
});

test("1min.ai accepts the bounded error-string shape without exposing a success chunk", async () => {
  const response = await executeStreaming([
    'event: error\ndata: {"error":"billing temporarily unavailable"}\n\n',
  ]);
  const clientText = await response.text();

  assert.match(clientText, /"error":\{"message":"billing temporarily unavailable"/);
  assert.doesNotMatch(clientText, /"role":"assistant"/);
  assert.doesNotMatch(clientText, /"finish_reason":"stop"/);
});

test("1min.ai replaces oversized stream-error payloads with a fixed public fallback", async () => {
  const oversizedMessage = `private-prefix-${"x".repeat(70 * 1024)}`;
  const response = await executeStreaming([
    `event: error\ndata: ${JSON.stringify({ message: oversizedMessage })}\n\n`,
  ]);
  const clientText = await response.text();

  assert.match(clientText, /1min\.ai upstream stream failed/);
  assert.ok(clientText.length < 1_024, "the oversized upstream payload must not be reflected");
  assert.doesNotMatch(clientText, /private-prefix/);
  assert.doesNotMatch(clientText, /"role":"assistant"/);
  assert.doesNotMatch(clientText, /"finish_reason":"stop"/);
});
