import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const TEST_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-stream-public-error-"));
const TEST_PLUGINS_DIR = fs.mkdtempSync(
  path.join(os.tmpdir(), "omniroute-stream-public-error-plugins-")
);
process.env.DATA_DIR = TEST_DATA_DIR;
process.env.OMNIROUTE_PLUGINS_DIR = TEST_PLUGINS_DIR;

const core = await import("../../src/lib/db/core.ts");
const { createStreamController, pipeWithDisconnect } =
  await import("../../open-sse/utils/streamHandler.ts");
const { FORMATS } = await import("../../open-sse/translator/formats.ts");

const SECRET = "sk-live-streamhandler-secret-123456";
const API_KEY = "provider-key-streamhandler-654321";
const PRIVATE_PATH = "/srv/omniroute/private/provider.ts:42:9";
const RAW_MESSAGE =
  `Upstream failed at ${PRIVATE_PATH} Authorization: Bearer ${SECRET} api_key=${API_KEY}` +
  `\n    at dispatch (/srv/omniroute/private/dispatcher.ts:88:3)`;

test.after(() => {
  core.resetDbInstance();
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  fs.rmSync(TEST_PLUGINS_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

test("OpenAI stream failures keep raw diagnostics internal and sanitize the public wire", async () => {
  const upstreamError = Object.assign(new Error(RAW_MESSAGE), { statusCode: 502 });
  const source = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.error(upstreamError);
    },
  });
  let internalMessage = "";

  const stream = pipeWithDisconnect(
    new Response(source),
    new TransformStream<Uint8Array, Uint8Array>(),
    createStreamController({
      clientResponseFormat: FORMATS.OPENAI,
      onError(event) {
        internalMessage = event.message;
        return true;
      },
    }),
    { stallTimeoutMs: 0 }
  );
  const publicWire = await new Response(stream).text();

  assert.equal(internalMessage, RAW_MESSAGE, "failure classification must retain the raw message");
  assert.match(publicWire, /"finish_reason":"error"/);
  assert.match(publicWire, /"code":"server_error"/);
  assert.match(publicWire, /\[DONE\]/);
  assert.doesNotMatch(publicWire, new RegExp(SECRET));
  assert.doesNotMatch(publicWire, new RegExp(API_KEY));
  assert.doesNotMatch(publicWire, /\/srv\/omniroute\/private/);
  assert.doesNotMatch(publicWire, /dispatcher\.ts/);
  assert.match(publicWire, /Authorization: \[REDACTED\]/);
  assert.match(publicWire, /<path>/);
});

test("Responses stream failures preserve the failure event shape without leaking diagnostics", async () => {
  const upstreamError = Object.assign(new Error(RAW_MESSAGE), { statusCode: 429 });
  const source = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.error(upstreamError);
    },
  });
  let internalError: unknown;

  const stream = pipeWithDisconnect(
    new Response(source),
    new TransformStream<Uint8Array, Uint8Array>(),
    createStreamController({
      clientResponseFormat: FORMATS.OPENAI_RESPONSES,
      onError(event) {
        internalError = event.error;
        return true;
      },
    }),
    { stallTimeoutMs: 0 }
  );
  const publicWire = await new Response(stream).text();

  assert.equal(internalError, upstreamError, "the original error object must reach classification");
  assert.match(publicWire, /event: response\.failed/);
  assert.match(publicWire, /"type":"response\.failed"/);
  assert.match(publicWire, /"type":"rate_limit_error"/);
  assert.match(publicWire, /"code":"rate_limit_exceeded"/);
  assert.doesNotMatch(publicWire, new RegExp(SECRET));
  assert.doesNotMatch(publicWire, new RegExp(API_KEY));
  assert.doesNotMatch(publicWire, /\/srv\/omniroute\/private/);
  assert.doesNotMatch(publicWire, /dispatcher\.ts/);
  assert.match(publicWire, /Authorization: \[REDACTED\]/);
  assert.match(publicWire, /<path>/);
});

test("Claude stream failures preserve error and stop events without leaking diagnostics", async () => {
  const upstreamError = Object.assign(new Error(RAW_MESSAGE), { statusCode: 403 });
  const source = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.error(upstreamError);
    },
  });
  let internalStatusCode = 0;

  const stream = pipeWithDisconnect(
    new Response(source),
    new TransformStream<Uint8Array, Uint8Array>(),
    createStreamController({
      clientResponseFormat: FORMATS.CLAUDE,
      onError(event) {
        internalStatusCode = event.statusCode;
        return true;
      },
    }),
    { stallTimeoutMs: 0 }
  );
  const publicWire = await new Response(stream).text();

  assert.equal(internalStatusCode, 403);
  assert.match(publicWire, /event: error/);
  assert.match(publicWire, /"type":"permission_error"/);
  assert.match(publicWire, /event: message_stop/);
  assert.doesNotMatch(publicWire, new RegExp(SECRET));
  assert.doesNotMatch(publicWire, new RegExp(API_KEY));
  assert.doesNotMatch(publicWire, /\/srv\/omniroute\/private/);
  assert.doesNotMatch(publicWire, /dispatcher\.ts/);
  assert.match(publicWire, /Authorization: \[REDACTED\]/);
  assert.match(publicWire, /<path>/);
});

test("stream diagnostics sanitize logs while callbacks retain the original failure", () => {
  const upstreamError = Object.assign(new Error(RAW_MESSAGE), { statusCode: 502 });
  const originalLog = console.log;
  const logLines: string[] = [];
  let internalError: unknown;
  console.log = (...args: unknown[]) => {
    logLines.push(args.map(String).join(" "));
  };

  try {
    createStreamController({
      provider: "test-provider",
      model: "test-model",
      onError(event) {
        internalError = event.error;
        return true;
      },
    }).handleError(upstreamError);
  } finally {
    console.log = originalLog;
  }

  const logs = logLines.join("\n");
  assert.equal(internalError, upstreamError);
  assert.match(logs, /error: Upstream failed at <path>/);
  assert.match(logs, /Authorization: \[REDACTED\]/);
  assert.doesNotMatch(logs, new RegExp(SECRET));
  assert.doesNotMatch(logs, new RegExp(API_KEY));
  assert.doesNotMatch(logs, /\/srv\/omniroute\/private/);
  assert.doesNotMatch(logs, /dispatcher\.ts/);
});

test("client disconnects stay outside the provider-failure callback", () => {
  let providerFailureRecorded = false;
  const controller = createStreamController({
    onError() {
      providerFailureRecorded = true;
      return true;
    },
  });

  controller.handleError(new DOMException("request_signal_aborted", "AbortError"));

  assert.equal(providerFailureRecorded, false);
  assert.equal(controller.signal.aborted, false);
});
