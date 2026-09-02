// tests/unit/video-bridge-memory-suppression.test.ts
// P1b of #12150 (Video Bridge transcript retention) — surface 3 (Memory sink).
//
// chatCore.ts gates its two extractFacts(requestMemoryText, ...) call sites
// (non-streaming ~L5134, streaming ~L5758) on an inline
// `memoryOwnerId && memorySettings?.enabled && memorySettings.maxTokens > 0`
// check. This adds a fourth condition — the request must not be a
// video-bridge-observed one — extracted to a pure, exported decision function
// so it is unit-testable without invoking the handleChatCore monolith (same
// god-file-decomposition convention as chatCore/attemptLogging.ts,
// chatCore/nonStreamingUsageStats.ts, etc.).
//
// Only the REQUEST-derived extractFacts call is gated (per the design doc,
// "surface 3: gate extractFacts on !videoBridgeObserved for request-derived
// text") — the response-derived extractFacts call (the model's own reply) is
// out of scope and untouched.
import test from "node:test";
import assert from "node:assert/strict";

import {
  shouldExtractMemory,
  extractMemoryTextFromRequestBody,
} from "../../open-sse/handlers/chatCore/memoryExtraction.ts";

// ─── shouldExtractMemory: pure decision table ──────────────────────────────

test("shouldExtractMemory: videoBridgeObserved=true skips extraction even when memory is otherwise enabled", () => {
  assert.equal(
    shouldExtractMemory({
      enabled: true,
      maxTokens: 2000,
      memoryOwnerId: "key-1",
      videoBridgeObserved: true,
    }),
    false
  );
});

test("shouldExtractMemory: videoBridgeObserved=false extracts when memory is enabled (unaffected non-video path)", () => {
  assert.equal(
    shouldExtractMemory({
      enabled: true,
      maxTokens: 2000,
      memoryOwnerId: "key-1",
      videoBridgeObserved: false,
    }),
    true
  );
});

test("shouldExtractMemory: videoBridgeObserved omitted (undefined) behaves like false — additive param default", () => {
  assert.equal(
    shouldExtractMemory({
      enabled: true,
      maxTokens: 2000,
      memoryOwnerId: "key-1",
    }),
    true
  );
});

test("shouldExtractMemory: still false when memory disabled, regardless of videoBridgeObserved", () => {
  assert.equal(
    shouldExtractMemory({
      enabled: false,
      maxTokens: 2000,
      memoryOwnerId: "key-1",
      videoBridgeObserved: false,
    }),
    false
  );
});

test("shouldExtractMemory: still false when maxTokens <= 0, regardless of videoBridgeObserved", () => {
  assert.equal(
    shouldExtractMemory({
      enabled: true,
      maxTokens: 0,
      memoryOwnerId: "key-1",
      videoBridgeObserved: false,
    }),
    false
  );
});

test("shouldExtractMemory: still false when memoryOwnerId is null, regardless of videoBridgeObserved", () => {
  assert.equal(
    shouldExtractMemory({
      enabled: true,
      maxTokens: 2000,
      memoryOwnerId: null,
      videoBridgeObserved: false,
    }),
    false
  );
});

// ─── Integration stub: wire the real decision + the real request-text ─────
// extractor together against a stubbed extractFacts, mirroring the exact
// shape of the two chatCore.ts call sites (only the DB-writing extractFacts
// is stubbed — everything else is the real exported implementation).

function runRequestMemoryExtractionStub(params: {
  memoryOwnerId: string | null;
  memorySettings: { enabled: boolean; maxTokens: number };
  videoBridgeObserved: boolean;
  body: Record<string, unknown>;
  pipelineSessionId: string;
  extractFactsSpy: (text: string, ownerId: string, sessionId: string) => void;
}): void {
  const {
    memoryOwnerId,
    memorySettings,
    videoBridgeObserved,
    body,
    pipelineSessionId,
    extractFactsSpy,
  } = params;
  if (memoryOwnerId && memorySettings?.enabled && memorySettings.maxTokens > 0) {
    if (
      shouldExtractMemory({
        enabled: memorySettings.enabled,
        maxTokens: memorySettings.maxTokens,
        memoryOwnerId,
        videoBridgeObserved,
      })
    ) {
      const requestMemoryText = extractMemoryTextFromRequestBody(body);
      if (requestMemoryText) {
        extractFactsSpy(requestMemoryText, memoryOwnerId, pipelineSessionId);
      }
    }
  }
}

const flattenedVideoBody = {
  messages: [
    {
      role: "user",
      content: "[Video 1]: A person talks. transcript[00:00-00:02]: secret words",
    },
  ],
};

test("integration stub: zero extractFacts calls for a video-bridge-observed request", () => {
  const calls: Array<[string, string, string]> = [];
  runRequestMemoryExtractionStub({
    memoryOwnerId: "key-1",
    memorySettings: { enabled: true, maxTokens: 2000 },
    videoBridgeObserved: true,
    body: flattenedVideoBody,
    pipelineSessionId: "session-1",
    extractFactsSpy: (text, ownerId, sessionId) => calls.push([text, ownerId, sessionId]),
  });
  assert.equal(calls.length, 0, "extractFacts must not be called when videoBridgeObserved=true");
});

test("integration stub: extractFacts IS called for the same body when video-bridge was not observed", () => {
  const calls: Array<[string, string, string]> = [];
  runRequestMemoryExtractionStub({
    memoryOwnerId: "key-1",
    memorySettings: { enabled: true, maxTokens: 2000 },
    videoBridgeObserved: false,
    body: flattenedVideoBody,
    pipelineSessionId: "session-1",
    extractFactsSpy: (text, ownerId, sessionId) => calls.push([text, ownerId, sessionId]),
  });
  assert.equal(calls.length, 1, "extractFacts must run on the ordinary (non-video) path");
  assert.match(calls[0][0], /secret words/);
});
