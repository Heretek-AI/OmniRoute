// tests/unit/video-bridge-log-redaction.test.ts
// P1b of #12150 (Video Bridge transcript retention) — surface 1 (call-log sink).
// Exercises the real persistAttemptLogs serialization (same harness pattern as
// tests/unit/chatcore-attempt-logging.test.ts): a real temp DB, a poll for the
// async saveCallLog write, and assertions on the persisted requestBody.
//
// Proves: when PersistAttemptLogsContext carries a videoBridgeLogRedaction map
// (P1a's per-part structured-redaction shadow), the PERSISTED requestBody has
// the transcript text swapped for the placeholder — while a control call
// WITHOUT the map (the byte-identical non-video path) keeps the original text,
// and the caller's own `body` object is never mutated in the process (the
// model already received the untouched original earlier in the request
// lifecycle; this call must not reach back and change it).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const testDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "omni-video-log-redaction-test-"));
process.env.DATA_DIR = testDataDir;

const coreDb = await import("../../src/lib/db/core.ts");
const { getCallLogById } = await import("../../src/lib/usage/callLogs.ts");
const { persistAttemptLogs } = await import("../../open-sse/handlers/chatCore/attemptLogging.ts");

const SECRET = "secret words";
const PLACEHOLDER_TEXT =
  "[Video 1]: A person talks. transcript[00:00-00:02]: [redacted-video-transcript]";

function videoBody() {
  return {
    model: "openai/gpt-x",
    messages: [
      { role: "system", content: "sys" },
      {
        role: "user",
        content: [
          { type: "text", text: "look at this video" },
          {
            type: "text",
            text: `[Video 1]: A person talks. transcript[00:00-00:02]: ${SECRET}`,
          },
        ],
      },
    ],
  };
}

function baseCtx(overrides: Record<string, unknown> = {}) {
  return {
    provider: "openai",
    connectionId: "conn-1",
    model: "gpt-x",
    skillRequestId: "skill-1",
    detailedLoggingEnabled: false,
    reqLogger: null,
    pendingRequestId: "REPLACE",
    clientRawRequest: { endpoint: "/v1/chat/completions" },
    requestedModel: "gpt-x-requested",
    credentials: { connectionId: "cred-conn" },
    startTime: Date.now(),
    body: videoBody(),
    sourceFormat: "openai",
    targetFormat: "openai",
    comboName: null,
    comboStepId: null,
    comboExecutionKey: null,
    tokensCompressed: 0,
    apiKeyInfo: { id: "key-1", name: "Key One" },
    noLogEnabled: false,
    ...overrides,
  } as Parameters<typeof persistAttemptLogs>[1];
}

async function pollForCallLog(id: string, tries = 120) {
  for (let i = 0; i < tries; i++) {
    const row = await getCallLogById(id);
    if (row) return row as Record<string, unknown>;
    await new Promise((r) => setTimeout(r, 20));
  }
  return null;
}

function persistedPartText(requestBody: unknown): string {
  const record = requestBody as {
    messages?: Array<{ content?: Array<{ text?: string }> }>;
  };
  return record?.messages?.[1]?.content?.[1]?.text ?? "";
}

before(async () => {
  await coreDb.ensureDbInitialized();
});

after(() => {
  coreDb.resetDbInstance();
  fs.rmSync(testDataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

test("persisted requestBody carries the placeholder and never the raw transcript when a redaction map is present", async () => {
  const id = "video-redacted-1";
  persistAttemptLogs(
    { status: 200, tokens: { input: 1, output: 2 } },
    baseCtx({
      pendingRequestId: id,
      videoBridgeLogRedaction: [
        { container: "messages", messageIndex: 1, partIndex: 1, redactedText: PLACEHOLDER_TEXT },
      ],
    })
  );
  const row = await pollForCallLog(id);
  assert.ok(row, "call log row should be persisted");
  const persistedText = persistedPartText(row.requestBody);
  assert.equal(persistedText, PLACEHOLDER_TEXT);
  assert.ok(!persistedText.includes(SECRET), "persisted log must not contain the raw transcript");
  assert.equal(
    JSON.stringify(row.requestBody).includes(SECRET),
    false,
    "raw transcript must not appear anywhere in the persisted requestBody"
  );
});

test("control: without a redaction map the persisted requestBody keeps the original text (model path untouched)", async () => {
  const id = "video-control-1";
  persistAttemptLogs(
    { status: 200, tokens: { input: 1, output: 2 } },
    baseCtx({ pendingRequestId: id })
  );
  const row = await pollForCallLog(id);
  assert.ok(row);
  const persistedText = persistedPartText(row.requestBody);
  assert.ok(
    persistedText.includes(SECRET),
    "control call (no redaction map) must keep the raw transcript text"
  );
});

test("the caller's body object is never mutated by the redaction", async () => {
  const id = "video-nomutate-1";
  const body = videoBody();
  const snapshotBefore = JSON.parse(JSON.stringify(body));
  persistAttemptLogs(
    { status: 200 },
    baseCtx({
      pendingRequestId: id,
      body,
      videoBridgeLogRedaction: [
        { container: "messages", messageIndex: 1, partIndex: 1, redactedText: PLACEHOLDER_TEXT },
      ],
    })
  );
  await pollForCallLog(id);
  assert.deepEqual(
    body,
    snapshotBefore,
    "ctx.body must be byte-identical after persistAttemptLogs runs"
  );
});
