// @ts-nocheck
import test from "node:test";
import assert from "node:assert/strict";

interface PplxChatCompletionJson {
  id: string;
  object: string;
  choices: Array<{
    message: { role: string; content: string };
    finish_reason: string;
  }>;
  usage: { total_tokens: number };
}

interface PplxErrorJson {
  error: { message: string };
}

const { PerplexityWebExecutor, toPublicPerplexityErrorCode } =
  await import("../../open-sse/executors/perplexity-web.ts");
const { getExecutor, hasSpecializedExecutor } = await import("../../open-sse/executors/index.ts");
const { __setTlsFetchOverrideForTesting, TlsClientUnavailableError } =
  await import("../../open-sse/services/perplexityTlsClient.ts");

const PPLX_THINKING_EVENT = {
  blocks: [
    { intended_usage: "plan", plan_block: { goals: [{ description: "preflight thinking" }] } },
  ],
};
// #2459: the executor now routes through tlsFetchPerplexity (Firefox TLS) instead of
// global fetch. Install one persistent bridge so the tests below can keep stubbing
// globalThis.fetch (returning a Response) and have it surface as a TlsFetchResult.
__setTlsFetchOverrideForTesting(async (url, opts) => {
  const res = await (globalThis.fetch as typeof fetch)(url, opts);
  return {
    status: res.status,
    headers: res.headers,
    text: res.status === 200 ? null : await res.text(),
    body: res.status === 200 ? res.body : null,
  };
});

function mockPplxStream(events) {
  const encoder = new TextEncoder();
  const chunks = [];
  for (const evt of events) {
    chunks.push(`event: message\r\ndata: ${JSON.stringify(evt)}\r\n\r\n`);
  }
  chunks.push("event: end_of_stream\r\n\r\n");
  const body = chunks.join("");
  return new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(body));
      controller.close();
    },
  });
}

// The persistent bridge above forwards tlsFetchPerplexity calls to globalThis.fetch,
// so stubbing fetch is still the way to mock Perplexity's upstream response.

function mockFetch(status, events, bodyText) {
  const original = globalThis.fetch;
  globalThis.fetch = async () => {
    if (status === 200) {
      const stream = events instanceof ReadableStream ? events : mockPplxStream(events);
      return new Response(stream, {
        status,
        headers: { "Content-Type": "text/event-stream" },
      });
    }
    return new Response(bodyText ?? `{"error":"http ${status}"}`, {
      status,
      headers: { "Content-Type": "text/html" },
    });
  };
  return () => {
    globalThis.fetch = original;
  };
}

function mockFetchError(error) {
  const original = globalThis.fetch;
  globalThis.fetch = async () => {
    throw error;
  };
  return () => {
    globalThis.fetch = original;
  };
}

function mockFetchLateStreamError(error) {
  const original = globalThis.fetch;
  globalThis.fetch = async () => {
    const encoder = new TextEncoder();
    const firstEvent = {
      blocks: [
        {
          intended_usage: "markdown",
          markdown_block: { chunks: ["partial answer"], progress: "IN_PROGRESS" },
        },
      ],
    };
    let sentFirstEvent = false;

    return new Response(
      new ReadableStream({
        pull(controller) {
          if (!sentFirstEvent) {
            sentFirstEvent = true;
            controller.enqueue(
              encoder.encode(`event: message\r\ndata: ${JSON.stringify(firstEvent)}\r\n\r\n`)
            );
            return;
          }
          controller.error(error);
        },
      }),
      { status: 200, headers: { "Content-Type": "text/event-stream" } }
    );
  };
  return () => {
    globalThis.fetch = original;
  };
}

function executePerplexity(stream, log = null, bodyOverrides = {}) {
  return new PerplexityWebExecutor().execute({
    model: "pplx-auto",
    body: { messages: [{ role: "user", content: "hello" }], stream, ...bodyOverrides },
    stream,
    credentials: { apiKey: "test-cookie" },
    signal: AbortSignal.timeout(10000),
    log,
  });
}

function executePerplexityWithEvents(events, stream = false, bodyOverrides = {}, log = null) {
  const restore = mockFetch(200, events);
  return executePerplexity(stream, log, bodyOverrides).finally(restore);
}

test("PerplexityWebExecutor is registered in executor index", () => {
  assert.ok(hasSpecializedExecutor("perplexity-web"));
  assert.ok(hasSpecializedExecutor("pplx-web"));
  const executor = getExecutor("perplexity-web");
  assert.ok(executor instanceof PerplexityWebExecutor);
});

test("PerplexityWebExecutor alias resolves to same type", () => {
  const a = getExecutor("perplexity-web");
  const b = getExecutor("pplx-web");
  assert.ok(a instanceof PerplexityWebExecutor);
  assert.ok(b instanceof PerplexityWebExecutor);
});

test("PerplexityWebExecutor sets correct provider name", () => {
  const executor = new PerplexityWebExecutor();
  assert.equal(executor.getProvider(), "perplexity-web");
});

test("Non-streaming: simple text response", async () => {
  const opaqueSessionId = "opaque-session-secret-uuid-123456";
  const pplxEvents = [
    {
      backend_uuid: opaqueSessionId,
      blocks: [
        {
          intended_usage: "markdown",
          markdown_block: { chunks: ["Hello, world!"], progress: "DONE" },
        },
      ],
      status: "COMPLETED",
    },
  ];

  const result = await executePerplexityWithEvents(pplxEvents, false, {
    messages: [{ role: "user", content: "hi" }],
  });

  assert.equal(result.response.status, 200);
  const json = (await result.response.json()) as PplxChatCompletionJson;
  assert.equal(json.object, "chat.completion");
  assert.equal(json.choices[0].message.role, "assistant");
  assert.equal(json.choices[0].message.content, "Hello, world!");
  assert.equal(json.choices[0].finish_reason, "stop");
  assert.ok(json.id.startsWith("chatcmpl-pplx-"));
  assert.ok(json.usage.total_tokens > 0);
  const infoLogs: string[] = [];
  const followUp = await executePerplexityWithEvents(
    pplxEvents,
    false,
    {
      messages: [
        { role: "user", content: "hi" },
        { role: "assistant", content: "Hello, world!" },
        { role: "user", content: "follow-up" },
      ],
    },
    { info: (_tag, message) => infoLogs.push(String(message)) }
  );
  assert.equal(followUp.transformedBody.params.last_backend_uuid, opaqueSessionId);
  assert.doesNotMatch(infoLogs.join("\n"), new RegExp(opaqueSessionId.slice(0, 12)));
  assert.match(infoLogs.join("\n"), /Continuing existing session/);
});

test("Non-streaming: strips citations from response", async () => {
  const pplxEvents = [
    {
      blocks: [
        {
          intended_usage: "markdown",
          markdown_block: {
            chunks: ["The answer is 42[1] according to sources[2][3]."],
            progress: "DONE",
          },
        },
      ],
      status: "COMPLETED",
    },
  ];

  const restore = mockFetch(200, pplxEvents);
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-sonar",
      body: { messages: [{ role: "user", content: "meaning of life" }], stream: false },
      stream: false,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    const json = (await result.response.json()) as PplxChatCompletionJson;
    assert.ok(!json.choices[0].message.content.includes("[1]"));
    assert.ok(!json.choices[0].message.content.includes("[2]"));
    assert.ok(!json.choices[0].message.content.includes("[3]"));
    assert.ok(json.choices[0].message.content.includes("The answer is 42"));
  } finally {
    restore();
  }
});

test("Non-streaming: sanitizes upstream event errors and exposes only a safe code", async () => {
  const upstreamError =
    "Perplexity event failed at /srv/private/perplexity-secret.ts:41:9; " +
    "access_token=pplx-upstream-secret\n" +
    "    at SecretUpstreamFrame (/srv/private/perplexity-stack.ts:3:4)";
  const unsafeErrorCode = "UPSTREAM_FAILURE access_token=pplx-code-secret";
  const result = await executePerplexityWithEvents([
    { error_code: unsafeErrorCode, error_message: upstreamError },
  ]);
  assert.equal(result.response.status, 502);
  assert.equal(result.response.headers.get("Retry-After"), null);
  const payloadText = await result.response.text();
  const json = JSON.parse(payloadText);
  assert.equal(json.error?.type, "upstream_error");
  assert.equal(json.error?.code, "PPLX_ERROR");
  assert.match(String(json.error?.message || ""), /Perplexity event failed/);
  const privateDetails =
    /\/srv\/private\/perplexity-(?:secret|stack)\.ts|pplx-upstream-secret|pplx-code-secret|SecretUpstreamFrame/;
  assert.doesNotMatch(payloadText, privateDetails);
  assert.ok(!payloadText.includes(unsafeErrorCode), "must not expose the raw upstream code");
});

test("Non-streaming: preserves bounded upstream codes and rejects untrusted codes", () => {
  assert.equal(toPublicPerplexityErrorCode("RATE_LIMIT", false), "RATE_LIMIT");
  assert.equal(toPublicPerplexityErrorCode("token_expired", false), "token_expired");
  assert.equal(toPublicPerplexityErrorCode("access_token_SECRET", false), "PPLX_ERROR");
  assert.equal(toPublicPerplexityErrorCode("password_hunter2", false), "PPLX_ERROR");
  assert.equal(
    toPublicPerplexityErrorCode("UPSTREAM_FAILURE access_token=pplx-code-secret", false),
    "PPLX_ERROR"
  );
  assert.equal(toPublicPerplexityErrorCode(`X${"A".repeat(64)}`, false), "PPLX_ERROR");
  assert.equal(toPublicPerplexityErrorCode("RATE_LIMIT", true), "quota_exhausted");
});

test("Non-streaming: uses a stable fallback when sanitization removes the whole error", async (t) => {
  const failures = [
    ["stack-only", "\n    at SecretOnlyFrame (/srv/private/perplexity-stack-only.ts:3:4)"],
    ["whitespace-only", " \t  "],
  ];
  for (const [name, message] of failures) {
    await t.test(name, async () => {
      const result = await executePerplexityWithEvents([
        { error_code: "UPSTREAM_FAILURE", error_message: message },
      ]);
      assert.equal(result.response.status, 502);
      const json = JSON.parse(await result.response.text());
      assert.equal(json.error?.message, "Perplexity upstream error");
      assert.equal(json.error?.type, "upstream_error");
      assert.equal(json.error?.code, "UPSTREAM_FAILURE");
    });
  }
});

test("Streaming: produces valid SSE chunks", async () => {
  const pplxEvents = [
    {
      backend_uuid: "stream-uuid-456",
      blocks: [
        {
          intended_usage: "markdown",
          markdown_block: { chunks: ["Hello "], progress: "IN_PROGRESS" },
        },
      ],
    },
    {
      blocks: [
        {
          intended_usage: "markdown",
          markdown_block: { chunks: ["Hello world!"], progress: "DONE" },
        },
      ],
      status: "COMPLETED",
    },
  ];

  const restore = mockFetch(200, pplxEvents);
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-sonnet",
      body: { messages: [{ role: "user", content: "hello" }], stream: true },
      stream: true,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(result.response.status, 200);
    assert.equal(result.response.headers.get("Content-Type"), "text/event-stream");

    // Read all SSE chunks
    const text = await result.response.text();
    const lines = text.split("\n").filter((l) => l.startsWith("data: "));
    assert.ok(lines.length >= 3, `Expected at least 3 SSE data lines, got ${lines.length}`);

    // First chunk should have role
    const first = JSON.parse(lines[0].slice(6));
    assert.equal(first.object, "chat.completion.chunk");
    assert.equal(first.choices[0].delta.role, "assistant");

    // Last data line should be [DONE]
    const lastLine = text.trim().split("\n").filter(Boolean).pop();
    assert.equal(lastLine, "data: [DONE]");

    // Second-to-last should have finish_reason: stop
    const stopLine = lines[lines.length - 1];
    if (stopLine !== "data: [DONE]") {
      const stop = JSON.parse(stopLine.slice(6));
      assert.equal(stop.choices[0].finish_reason, "stop");
    }
  } finally {
    restore();
  }
});

test("Streaming: sanitizes late Error and non-Error failures before emitting SSE", async (t) => {
  const failures = [
    {
      name: "Error rejection",
      reason: new Error(
        "Late read failed at /srv/omniroute/private/perplexity.ts:44:9; " +
          "access token: pplx-secret-error; access_token=pplx-query-error\n" +
          "    at SecretFunction (/srv/omniroute/private/perplexity.ts:44:9)"
      ),
      forbidden:
        /\/srv\/omniroute\/private\/perplexity\.ts|pplx-secret-error|pplx-query-error|SecretFunction/,
    },
    {
      name: "non-Error rejection",
      reason:
        "Late read failed at C:\\Users\\runner\\OmniRoute\\perplexity.ts:8:2; " +
        "access token: pplx-secret-string; access_token=pplx-query-string\n" +
        "    at NonErrorFrame (C:\\Users\\runner\\OmniRoute\\perplexity.ts:8:2)",
      forbidden:
        /C:\\Users\\runner\\OmniRoute\\perplexity\.ts|pplx-secret-string|pplx-query-string|NonErrorFrame/,
    },
    {
      name: "stack-only rejection",
      reason: "\n    at StackOnlyFrame (/srv/private/perplexity-late-stack-only.ts:8:2)",
      forbidden: /\/srv\/private\/perplexity-late-stack-only\.ts|StackOnlyFrame/,
      expectedContent: "[Stream error: Perplexity upstream error]",
    },
    {
      name: "hostile toString rejection",
      reason: {
        toString() {
          throw new Error(
            "access_token=pplx-hostile-secret at /srv/private/perplexity-hostile.ts:1:1"
          );
        },
      },
      forbidden: /pplx-hostile-secret|perplexity-hostile/,
      expectedContent: "[Stream error: Perplexity upstream error]",
    },
  ];
  for (const failure of failures) {
    await t.test(failure.name, async () => {
      const restore = mockFetchLateStreamError(failure.reason);
      try {
        const result = await executePerplexity(true);
        assert.equal(result.response.status, 200);
        assert.equal(result.response.headers.get("Content-Type"), "text/event-stream");
        const text = await result.response.text();
        const dataLines = text.split("\n").filter((line) => line.startsWith("data: "));
        const payloads = dataLines
          .filter((line) => line !== "data: [DONE]")
          .map((line) => JSON.parse(line.slice(6)));
        const errorChunk = payloads.find((payload) =>
          String(payload.choices?.[0]?.delta?.content || "").startsWith("[Stream error:")
        );
        assert.ok(errorChunk, "must emit a structured stream-error delta");
        assert.equal(errorChunk.choices[0].finish_reason, "stop");
        if (failure.expectedContent) {
          assert.equal(errorChunk.choices[0].delta.content, failure.expectedContent);
        }
        assert.equal(dataLines.at(-1), "data: [DONE]");
        assert.doesNotMatch(text, failure.forbidden);
      } finally {
        restore();
      }
    });
  }
});

test("Streaming: sanitizes upstream event errors before emitting SSE", async () => {
  const upstreamError =
    "Perplexity event failed at /srv/private/perplexity-secret.ts:41:9; " +
    "access_token=pplx-upstream-secret\n" +
    "    at SecretUpstreamFrame (/srv/private/perplexity-stack.ts:3:4)";
  const upstream = mockPplxStream([
    { error_code: "UPSTREAM_FAILURE", error_message: upstreamError },
  ]);
  const result = await executePerplexityWithEvents(upstream, true);
  assert.equal(result.response.status, 200);
  const text = await result.response.text();
  assert.match(text, /\[Error:/);
  assert.match(text, /data: \[DONE\]/);
  assert.doesNotMatch(
    text,
    /\/srv\/private\/perplexity-(?:secret|stack)\.ts|pplx-upstream-secret|SecretUpstreamFrame/
  );
  assert.equal(upstream.locked, false);
});

test("Streaming: cancellation releases a pending upstream reader", async () => {
  let cancelled = false;
  const upstream = new ReadableStream({
    start: (controller) =>
      controller.enqueue(
        new TextEncoder().encode(`data: ${JSON.stringify(PPLX_THINKING_EVENT)}\n\n`)
      ),
    cancel() {
      cancelled = true;
    },
  });
  const result = await executePerplexityWithEvents(upstream, true);
  await result.response.body.getReader().cancel();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(cancelled, true);
  assert.equal(upstream.locked, false);
});

test("Tools + streaming preserves a sanitized upstream error response", async () => {
  const result = await executePerplexityWithEvents(
    [
      {
        error_code: "UPSTREAM_FAILURE",
        error_message:
          "Tool error at /srv/private/pplx-tool.ts:4:2; access_token=pplx-tool-secret\n" +
          "    at SecretToolFrame (/srv/private/pplx-tool-stack.ts:5:6)",
      },
    ],
    true,
    { tools: [{ type: "function", function: { name: "lookup", parameters: { type: "object" } } }] }
  );
  assert.equal(result.response.status, 502);
  const payloadText = await result.response.text();
  const json = JSON.parse(payloadText);
  assert.equal(json.error?.type, "upstream_error");
  assert.equal(json.error?.code, "UPSTREAM_FAILURE");
  assert.doesNotMatch(payloadText, /pplx-tool-secret|SecretToolFrame|\/srv\/private/);
});

test("Tools + streaming preserves sanitized quota metadata", async () => {
  const result = await executePerplexityWithEvents(
    [
      {
        upsell_information: {
          name: "advanced_models_quota_low",
          title: "No uses at /srv/private/pplx-quota.ts:4:2; access_token=pplx-quota-secret",
          description:
            "Upgrade now\n    at SecretQuotaFrame (/srv/private/pplx-quota-stack.ts:5:6)",
        },
      },
      { final: true, text_completed: true },
    ],
    true,
    { tools: [{ type: "function", function: { name: "lookup", parameters: { type: "object" } } }] }
  );
  assert.equal(result.response.status, 429);
  const payloadText = await result.response.text();
  const json = JSON.parse(payloadText);
  assert.equal(json.error?.code, "quota_exhausted");
  assert.ok(json.error?.reset_seconds >= 3600);
  assert.equal(result.response.headers.get("Retry-After"), String(json.error.reset_seconds));
  assert.doesNotMatch(payloadText, /pplx-quota-secret|SecretQuotaFrame|\/srv\/private/);
});

test("Streaming: uses a stable fallback when sanitization removes the whole error", async (t) => {
  const failures = [
    ["stack-only", "\n    at SecretOnlyFrame (/srv/private/perplexity-stack-only.ts:3:4)"],
    ["whitespace-only", " \t  "],
  ];
  for (const [name, message] of failures) {
    await t.test(name, async () => {
      const result = await executePerplexityWithEvents(
        [{ error_code: "UPSTREAM_FAILURE", error_message: message }],
        true
      );
      assert.equal(result.response.status, 200);
      const text = await result.response.text();
      assert.match(text, /\[Error: Perplexity upstream error\]/);
      assert.match(text, /data: \[DONE\]/);
      assert.doesNotMatch(text, /SecretOnlyFrame|perplexity-stack-only/);
    });
  }
});

// ─── Test: Schematized diff_block streaming (use_schematized_api) ───────────

test("Schematized API: diff_block chunks reconstruct answer (non-streaming)", async () => {
  // Mirrors the live www.perplexity.ai schematized API: the answer streams as
  // RFC-6902 JSON-patch frames against markdown_block, a `final:true` flag
  // arrives on a still-PENDING frame, then a COMPLETED frame materializes the
  // full markdown_block. The parser must NOT stop on `final` and must apply
  // the diff patches.
  const pplxEvents = [
    {
      backend_uuid: "diff-uuid-1",
      status: "PENDING",
      blocks: [
        {
          intended_usage: "ask_text_0_markdown",
          diff_block: {
            field: "markdown_block",
            patches: [
              { op: "replace", path: "", value: { progress: "IN_PROGRESS", chunks: ["The "] } },
            ],
          },
        },
      ],
    },
    {
      status: "PENDING",
      blocks: [
        {
          intended_usage: "ask_text_0_markdown",
          diff_block: {
            field: "markdown_block",
            patches: [{ op: "add", path: "/chunks/1", value: "answer " }],
          },
        },
      ],
    },
    {
      status: "PENDING",
      final: true,
      blocks: [
        {
          intended_usage: "ask_text_0_markdown",
          diff_block: {
            field: "markdown_block",
            patches: [{ op: "add", path: "/chunks/2", value: "is 42." }],
          },
        },
      ],
    },
    {
      status: "COMPLETED",
      final: true,
      blocks: [
        {
          intended_usage: "ask_text_0_markdown",
          markdown_block: {
            progress: "DONE",
            chunks: ["The answer is 42."],
            answer: "The answer is 42.",
          },
        },
      ],
    },
  ];

  const restore = mockFetch(200, pplxEvents);
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-auto",
      body: { messages: [{ role: "user", content: "what is the answer?" }], stream: false },
      stream: false,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(result.response.status, 200);
    const json = JSON.parse(await result.response.text());
    assert.equal(json.choices[0].message.content, "The answer is 42.");
  } finally {
    restore();
  }
});

test("Schematized API: diff_block streams incremental deltas", async () => {
  const pplxEvents = [
    {
      backend_uuid: "diff-uuid-2",
      status: "PENDING",
      blocks: [
        {
          intended_usage: "ask_text_0_markdown",
          diff_block: {
            field: "markdown_block",
            patches: [
              { op: "replace", path: "", value: { progress: "IN_PROGRESS", chunks: ["one, "] } },
            ],
          },
        },
      ],
    },
    {
      status: "PENDING",
      blocks: [
        {
          intended_usage: "ask_text_0_markdown",
          diff_block: {
            field: "markdown_block",
            patches: [{ op: "add", path: "/chunks/1", value: "two, " }],
          },
        },
      ],
    },
    {
      status: "COMPLETED",
      final: true,
      blocks: [
        {
          intended_usage: "ask_text_0_markdown",
          markdown_block: {
            progress: "DONE",
            chunks: ["one, two, three"],
            answer: "one, two, three",
          },
        },
      ],
    },
  ];

  const restore = mockFetch(200, pplxEvents);
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-auto",
      body: { messages: [{ role: "user", content: "count" }], stream: true },
      stream: true,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(result.response.status, 200);
    const text = await result.response.text();
    let assembled = "";
    for (const line of text.split("\n")) {
      if (!line.startsWith("data: ")) continue;
      const d = line.slice(6).trim();
      if (d === "[DONE]") continue;
      const o = JSON.parse(d);
      const c = o.choices?.[0]?.delta?.content;
      if (c) assembled += c;
    }
    assert.equal(assembled, "one, two, three");
  } finally {
    restore();
  }
});

test("Streaming: thinking content emitted as reasoning_content", async () => {
  const pplxEvents = [
    PPLX_THINKING_EVENT,
    {
      blocks: [
        {
          intended_usage: "markdown",
          markdown_block: { chunks: ["The answer."], progress: "DONE" },
        },
      ],
      status: "COMPLETED",
    },
  ];

  const restore = mockFetch(200, pplxEvents);
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-sonnet",
      body: { messages: [{ role: "user", content: "search test" }], stream: true },
      stream: true,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    const text = await result.response.text();
    const deltas = text
      .split("\n")
      .filter((line) => line.startsWith("data: ") && line !== "data: [DONE]")
      .map((line) => JSON.parse(line.slice(6)).choices?.[0]?.delta ?? {});
    assert.deepEqual(
      deltas.flatMap((delta) => (delta.reasoning_content ? [delta.reasoning_content] : [])),
      ["preflight thinking\n"]
    );
    assert.equal(deltas.map((delta) => delta.content || "").join(""), "The answer.");
  } finally {
    restore();
  }
});

test("Error: 401 returns auth error message", async () => {
  const restore = mockFetch(401, []);
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-auto",
      body: { messages: [{ role: "user", content: "hi" }] },
      stream: false,
      credentials: { apiKey: "expired-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(result.response.status, 401);
    const json = (await result.response.json()) as PplxErrorJson;
    assert.ok(json.error.message.includes("auth failed"));
    assert.ok(json.error.message.includes("session-token"));
  } finally {
    restore();
  }
});

test("Error: 429 returns rate limit message", async () => {
  const restore = mockFetch(429, []);
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-sonar",
      body: { messages: [{ role: "user", content: "hi" }] },
      stream: false,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(result.response.status, 429);
    const json = (await result.response.json()) as PplxErrorJson;
    assert.ok(json.error.message.includes("rate limited"));
  } finally {
    restore();
  }
});

test("Error: fetch failure returns 502", async () => {
  const restore = mockFetchError(new Error("ECONNREFUSED"));
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-auto",
      body: { messages: [{ role: "user", content: "hi" }] },
      stream: false,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(result.response.status, 502);
    const json = (await result.response.json()) as PplxErrorJson;
    assert.ok(json.error.message.includes("ECONNREFUSED"));
  } finally {
    restore();
  }
});

test("Error: fetch failure sanitizes sensitive details in logs", async () => {
  const upstreamError = new Proxy(
    new Error("access_token=pplx-fetch-secret\n at SecretFetchFrame (/srv/pplx.ts:2:3)"),
    { getPrototypeOf: () => 42 }
  );
  const errorLogs: string[] = [];
  const restore = mockFetchError(upstreamError);
  try {
    const result = await executePerplexity(false, {
      error: (_tag, message) => errorLogs.push(String(message)),
    });
    assert.equal(result.response.status, 502);
    assert.equal(errorLogs.length, 1);
    const publicOutput = `${errorLogs.join("\n")}\n${await result.response.text()}`;
    assert.match(publicOutput, /Fetch failed/);
    assert.doesNotMatch(publicOutput, /pplx-fetch-secret|SecretFetchFrame|\/srv\/pplx\.ts/);
  } finally {
    restore();
  }
});

test("Error: fetch stack-only failure uses a stable fallback in logs and response", async () => {
  const errorLogs: string[] = [];
  const restore = mockFetchError(
    new Error("\n    at SecretOnlyFrame (/srv/private/perplexity-fetch-stack-only.ts:2:3)")
  );
  try {
    const result = await executePerplexity(false, {
      error: (_tag, message) => errorLogs.push(String(message)),
    });
    assert.equal(result.response.status, 502);
    assert.deepEqual(errorLogs, ["Fetch failed: Perplexity upstream error"]);
    const json = JSON.parse(await result.response.text());
    assert.equal(json.error?.message, "Perplexity connection failed: Perplexity upstream error");
  } finally {
    restore();
  }
});

test("Error: whitespace-only fetch failures use the stable fallback", async () => {
  const errorLogs: string[] = [];
  const restore = mockFetchError(new Error(" \t  "));
  try {
    const result = await executePerplexity(false, {
      error: (_tag, message) => errorLogs.push(String(message)),
    });
    assert.equal(result.response.status, 502);
    assert.deepEqual(errorLogs, ["Fetch failed: Perplexity upstream error"]);
    const json = JSON.parse(await result.response.text());
    assert.equal(json.error?.message, "Perplexity connection failed: Perplexity upstream error");
  } finally {
    restore();
  }
});

test("Error: refreshed-cookie persistence failure sanitizes sensitive details in logs", async () => {
  const original = globalThis.fetch;
  const warningLogs: string[] = [];
  globalThis.fetch = async () =>
    new Response(
      mockPplxStream([
        {
          blocks: [
            {
              intended_usage: "markdown",
              markdown_block: { chunks: ["ok"], progress: "DONE" },
            },
          ],
          status: "COMPLETED",
        },
      ]),
      {
        status: 200,
        headers: {
          "Content-Type": "text/event-stream",
          "set-cookie": "__Secure-next-auth.session-token=ROTATED-VALUE; Path=/; HttpOnly; Secure",
        },
      }
    );
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-auto",
      body: { messages: [{ role: "user", content: "hi" }] },
      stream: false,
      credentials: { apiKey: "old-cookie-value" },
      signal: AbortSignal.timeout(10000),
      log: {
        warn: (_tag, message) => warningLogs.push(String(message)),
      },
      onCredentialsRefreshed: async () => {
        throw new Error(
          "Persistence failed at /srv/private/perplexity-cookie.ts:23:7; " +
            "access_token=pplx-cookie-secret\n" +
            "    at SecretCookieFrame (/srv/private/perplexity-cookie-stack.ts:4:5)"
        );
      },
    });

    assert.equal(result.response.status, 200, "persistence failure remains non-fatal");
    assert.equal(warningLogs.length, 1);
    const publicLog = warningLogs.join("\n");
    assert.match(publicLog, /Failed to persist refreshed cookie/);
    assert.doesNotMatch(publicLog, /\/srv\/private\/perplexity-cookie(?:-stack)?\.ts/);
    assert.doesNotMatch(publicLog, /pplx-cookie-secret|SecretCookieFrame/);
  } finally {
    globalThis.fetch = original;
  }
});

test("Error: empty messages returns 400", async () => {
  const executor = new PerplexityWebExecutor();
  const result = await executor.execute({
    model: "pplx-auto",
    body: { messages: [] },
    stream: false,
    credentials: { apiKey: "test-cookie" },
    signal: AbortSignal.timeout(10000),
    log: null,
  });

  assert.equal(result.response.status, 400);
  const json = (await result.response.json()) as PplxErrorJson;
  assert.ok(json.error.message.includes("Missing or empty messages"));
});

test("Error: missing messages returns 400", async () => {
  const executor = new PerplexityWebExecutor();
  const result = await executor.execute({
    model: "pplx-auto",
    body: {},
    stream: false,
    credentials: { apiKey: "test-cookie" },
    signal: AbortSignal.timeout(10000),
    log: null,
  });

  assert.equal(result.response.status, 400);
});

test("Non-streaming: Perplexity stream error returns 502", async () => {
  const pplxEvents = [{ error_code: "RATE_LIMIT", error_message: "Too many requests" }];

  const restore = mockFetch(200, pplxEvents);
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-auto",
      body: { messages: [{ role: "user", content: "test" }], stream: false },
      stream: false,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(result.response.status, 502);
    const json = (await result.response.json()) as PplxErrorJson;
    assert.equal(json.error.code, "RATE_LIMIT");
  } finally {
    restore();
  }
});

// ─── Test: Message parsing ──────────────────────────────────────────────────

test("Streaming and non-streaming preserve a quota wire error code", async () => {
  const events = [PPLX_THINKING_EVENT, { error_code: "quota_exhausted", error_message: "limit" }];
  for (const stream of [false, true]) {
    const upstream = mockPplxStream(events);
    const result = await executePerplexityWithEvents(upstream, stream);
    const json = await result.response.json();
    assert.equal(result.response.status, 429);
    assert.equal(json.error.code, "quota_exhausted");
    assert.equal(json.error.reset_seconds, 6 * 60 * 60);
    assert.equal(result.response.headers.get("Retry-After"), String(6 * 60 * 60));
    assert.equal(upstream.locked, false);
  }
});
test("Message parsing: system + user + assistant history", async () => {
  let capturedBody = null;
  const original = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    capturedBody = JSON.parse(opts.body);
    return new Response(
      mockPplxStream([
        {
          blocks: [
            {
              intended_usage: "markdown",
              markdown_block: { chunks: ["response"], progress: "DONE" },
            },
          ],
          status: "COMPLETED",
        },
      ]),
      { status: 200, headers: { "Content-Type": "text/event-stream" } }
    );
  };

  try {
    const executor = new PerplexityWebExecutor();
    await executor.execute({
      model: "pplx-auto",
      body: {
        messages: [
          { role: "system", content: "You are helpful" },
          { role: "user", content: "First question" },
          { role: "assistant", content: "First answer" },
          { role: "user", content: "Follow up" },
        ],
        stream: false,
      },
      stream: false,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    // The query should contain the current message
    const query = capturedBody.query_str;
    assert.ok(query.includes("Follow up"), "Query should contain current user message");
    assert.ok(query.includes("You are helpful"), "Query should contain system message");
    assert.equal(capturedBody.params.search_focus, "internet");
    assert.equal(capturedBody.params.use_schematized_api, true);
  } finally {
    globalThis.fetch = original;
  }
});

test("Message parsing: developer role treated as system", async () => {
  let capturedBody = null;
  const original = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    capturedBody = JSON.parse(opts.body);
    return new Response(
      mockPplxStream([
        {
          blocks: [
            {
              intended_usage: "markdown",
              markdown_block: { chunks: ["ok"], progress: "DONE" },
            },
          ],
          status: "COMPLETED",
        },
      ]),
      { status: 200, headers: { "Content-Type": "text/event-stream" } }
    );
  };

  try {
    const executor = new PerplexityWebExecutor();
    await executor.execute({
      model: "pplx-sonnet",
      body: {
        messages: [
          { role: "developer", content: "Be concise" },
          { role: "user", content: "hello" },
        ],
        stream: false,
      },
      stream: false,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    const query = capturedBody.query_str;
    assert.ok(query.includes("Be concise"), "Developer message should be treated as system");
  } finally {
    globalThis.fetch = original;
  }
});

// ─── Test: Auth header construction ─────────────────────────────────────────

test("Auth: cookie-based auth sends Cookie header", async () => {
  let capturedHeaders = null;
  const original = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    capturedHeaders = opts.headers;
    return new Response(
      mockPplxStream([
        {
          blocks: [
            {
              intended_usage: "markdown",
              markdown_block: { chunks: ["ok"], progress: "DONE" },
            },
          ],
          status: "COMPLETED",
        },
      ]),
      { status: 200, headers: { "Content-Type": "text/event-stream" } }
    );
  };

  try {
    const executor = new PerplexityWebExecutor();
    await executor.execute({
      model: "pplx-auto",
      body: { messages: [{ role: "user", content: "test" }], stream: false },
      stream: false,
      credentials: { apiKey: "my-session-token-value" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(
      capturedHeaders["Cookie"],
      "__Secure-next-auth.session-token=my-session-token-value"
    );
    assert.ok(
      !capturedHeaders["Authorization"],
      "Should not have Authorization header for cookie auth"
    );
  } finally {
    globalThis.fetch = original;
  }
});

test("Auth: JWT auth sends Authorization Bearer header", async () => {
  let capturedHeaders = null;
  const original = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    capturedHeaders = opts.headers;
    return new Response(
      mockPplxStream([
        {
          blocks: [
            {
              intended_usage: "markdown",
              markdown_block: { chunks: ["ok"], progress: "DONE" },
            },
          ],
          status: "COMPLETED",
        },
      ]),
      { status: 200, headers: { "Content-Type": "text/event-stream" } }
    );
  };

  try {
    const executor = new PerplexityWebExecutor();
    await executor.execute({
      model: "pplx-auto",
      body: { messages: [{ role: "user", content: "test" }], stream: false },
      stream: false,
      credentials: { accessToken: "jwt-token-value" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(capturedHeaders["Authorization"], "Bearer jwt-token-value");
    assert.ok(!capturedHeaders["Cookie"], "Should not have Cookie header for JWT auth");
  } finally {
    globalThis.fetch = original;
  }
});

// ─── Test: Model mapping ────────────────────────────────────────────────────

test("Model mapping: GPT-5.6 Terra sends its current internal preference", async () => {
  let capturedBody = null;
  const original = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    capturedBody = JSON.parse(opts.body);
    return new Response(
      mockPplxStream([
        {
          blocks: [
            {
              intended_usage: "markdown",
              markdown_block: { chunks: ["ok"], progress: "DONE" },
            },
          ],
          status: "COMPLETED",
        },
      ]),
      { status: 200, headers: { "Content-Type": "text/event-stream" } }
    );
  };

  try {
    const executor = new PerplexityWebExecutor();
    await executor.execute({
      model: "pplx-gpt-5.6-terra",
      body: { messages: [{ role: "user", content: "test" }], stream: false },
      stream: false,
      credentials: { apiKey: "test" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(capturedBody.params.model_preference, "gpt56_terra");
    assert.equal(capturedBody.params.mode, "copilot");
  } finally {
    globalThis.fetch = original;
  }
});

test("Model mapping: pplx-sonar maps to turbo/copilot (live browser default)", async () => {
  let capturedBody = null;
  const original = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    capturedBody = JSON.parse(opts.body);
    return new Response(
      mockPplxStream([
        {
          blocks: [
            {
              intended_usage: "markdown",
              markdown_block: { chunks: ["ok"], progress: "DONE" },
            },
          ],
          status: "COMPLETED",
        },
      ]),
      { status: 200, headers: { "Content-Type": "text/event-stream" } }
    );
  };

  try {
    const executor = new PerplexityWebExecutor();
    await executor.execute({
      model: "pplx-sonar",
      body: { messages: [{ role: "user", content: "hello" }], stream: false },
      stream: false,
      credentials: { apiKey: "test" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(capturedBody.params.model_preference, "turbo");
    assert.equal(capturedBody.params.mode, "copilot");
    assert.equal(capturedBody.params.supports_tool_approval_modal, true);
    assert.ok(
      capturedBody.params.supported_block_use_cases.includes("workflow_widgets"),
      "payload must advertise workflow_widgets like the live browser"
    );
    assert.ok(
      capturedBody.params.supported_block_use_cases.includes("navigation_results"),
      "payload must advertise navigation_results like the live browser"
    );
  } finally {
    globalThis.fetch = original;
  }
});

test("Model mapping: thinking mode uses thinking variant", async () => {
  let capturedBody = null;
  const original = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    capturedBody = JSON.parse(opts.body);
    return new Response(
      mockPplxStream([
        {
          blocks: [
            {
              intended_usage: "markdown",
              markdown_block: { chunks: ["ok"], progress: "DONE" },
            },
          ],
          status: "COMPLETED",
        },
      ]),
      { status: 200, headers: { "Content-Type": "text/event-stream" } }
    );
  };

  try {
    const executor = new PerplexityWebExecutor();
    await executor.execute({
      model: "pplx-sonnet",
      body: {
        messages: [{ role: "user", content: "test" }],
        stream: false,
        thinking: true,
      },
      stream: false,
      credentials: { apiKey: "test" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(capturedBody.params.model_preference, "claude50sonnetthinking");
    // THINKING_MAP path posts "copilot" too ("search" is downgraded to CONCISE).
    assert.equal(capturedBody.params.mode, "copilot");
  } finally {
    globalThis.fetch = original;
  }
});

// ─── The search hint is opt-in ──────────────────────────────────────────────
// It used to be appended to every system message and leaked into answers as
// meta-commentary, which is noise for coding clients.

test("buildQuery: search hint is off by default and opt-in via env", async () => {
  const { buildQuery } = await import("../../open-sse/executors/perplexity-web/protocol.ts");
  const parsed = { systemMsg: "You are terse.", history: [], currentMsg: "hi" };
  const HINT = "built-in web search";
  const prev = process.env.OMNIROUTE_PPLX_SEARCH_HINT;

  try {
    delete process.env.OMNIROUTE_PPLX_SEARCH_HINT;
    const off = JSON.parse(buildQuery(parsed, null));
    assert.deepEqual(off.instructions, ["You are terse."]);
    assert.equal(off.query, "hi");

    process.env.OMNIROUTE_PPLX_SEARCH_HINT = "1";
    const on = JSON.parse(buildQuery(parsed, null));
    assert.equal(on.instructions.length, 2);
    assert.ok(on.instructions[1].includes(HINT));

    process.env.OMNIROUTE_PPLX_SEARCH_HINT = "0";
    assert.equal(JSON.parse(buildQuery(parsed, null)).instructions.length, 1);
  } finally {
    if (prev === undefined) delete process.env.OMNIROUTE_PPLX_SEARCH_HINT;
    else process.env.OMNIROUTE_PPLX_SEARCH_HINT = prev;
  }
});

// ─── Test: Live multi-step stream (no COMPLETED; text_completed + diffs) ────

test("Live multi-step: reconstructs answer without status COMPLETED", async () => {
  // Mirrors Chrome 150 / copilot multi-step capture: PENDING frames with
  // ask_text + ask_text_0_markdown diff_block chunks, text_completed:true,
  // never status COMPLETED. Parser must still return the answer, and plan
  // goals delivered as RFC-6902 diff patches (not a materialized plan_block)
  // must still surface as reasoning_content.
  const pplxEvents = [
    {
      status: "PENDING",
      blocks: [
        {
          intended_usage: "plan",
          diff_block: {
            field: "plan_block",
            patches: [
              {
                op: "replace",
                path: "",
                value: {
                  progress: "IN_PROGRESS",
                  goals: [{ id: "0", description: "Greeting the user", final: false }],
                },
              },
            ],
          },
        },
      ],
    },
    {
      status: "PENDING",
      blocks: [
        {
          intended_usage: "ask_text_0_markdown",
          diff_block: {
            field: "markdown_block",
            patches: [
              { op: "replace", path: "", value: { progress: "IN_PROGRESS", chunks: ["Hello "] } },
            ],
          },
        },
        {
          intended_usage: "ask_text",
          diff_block: {
            field: "markdown_block",
            patches: [
              { op: "replace", path: "", value: { progress: "IN_PROGRESS", chunks: ["Hello "] } },
            ],
          },
        },
      ],
    },
    {
      status: "PENDING",
      text_completed: true,
      blocks: [
        {
          intended_usage: "ask_text_0_markdown",
          diff_block: {
            field: "markdown_block",
            patches: [{ op: "add", path: "/chunks/1", value: "there." }],
          },
        },
        {
          intended_usage: "ask_text",
          diff_block: {
            field: "markdown_block",
            patches: [{ op: "add", path: "/chunks/1", value: "there." }],
          },
        },
      ],
    },
    {
      status: "PENDING",
      final: true,
      text: '[{"step_type":"INITIAL_QUERY","content":{"query":"hello"}}]',
    },
  ];

  const restore = mockFetch(200, pplxEvents);
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-opus",
      body: { messages: [{ role: "user", content: "hello" }], stream: false },
      stream: false,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(result.response.status, 200);
    const json = JSON.parse(await result.response.text());
    assert.equal(json.choices[0].message.content, "Hello there.");
    // Plan goals via diff_block should surface as reasoning_content
    assert.ok(
      String(json.choices[0].message.reasoning_content || "").includes("Greeting the user")
    );
  } finally {
    restore();
  }
});

test("Advanced-model quota upsell with empty answer surfaces clear error", async () => {
  const pplxEvents = [
    {
      status: "PENDING",
      upsell_information: {
        name: "advanced_models_quota_low",
        upsell_type: "UPGRADE_TO_PRO",
        title: "No advanced model uses left this week",
        description: "Upgrade to Perplexity Max",
      },
      blocks: [
        {
          intended_usage: "plan",
          diff_block: {
            field: "plan_block",
            patches: [
              {
                op: "replace",
                path: "",
                value: { goals: [{ description: "Hello, how can I assist you?" }] },
              },
            ],
          },
        },
      ],
    },
    { status: "PENDING", final: true, text_completed: true },
  ];

  const restore = mockFetch(200, pplxEvents);
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-opus",
      body: { messages: [{ role: "user", content: "hello" }], stream: false },
      stream: false,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(result.response.status, 429);
    const json = JSON.parse(await result.response.text());
    assert.match(String(json.error?.message || ""), /quota exhausted/i);
    assert.match(String(json.error?.message || ""), /No advanced model uses left/i);
    assert.match(String(json.error?.message || ""), /reset after/i);
    assert.equal(json.error?.code, "quota_exhausted");
    assert.equal(json.error?.type, "quota_exhausted");
    assert.ok(
      typeof json.error?.reset_seconds === "number" && json.error.reset_seconds >= 3600,
      "reset_seconds should be a multi-hour weekly-quota cooldown"
    );
    assert.equal(result.response.headers.get("Retry-After"), String(json.error.reset_seconds));
  } finally {
    restore();
  }
});

// ─── Test: Fallback text field ──────────────────────────────────────────────

test("Non-streaming: falls back to text field when no blocks", async () => {
  const pplxEvents = [{ text: "Fallback answer text", status: "COMPLETED", final: true }];

  const restore = mockFetch(200, pplxEvents);
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-auto",
      body: { messages: [{ role: "user", content: "test" }], stream: false },
      stream: false,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    const json = (await result.response.json()) as PplxChatCompletionJson;
    assert.ok(json.choices[0].message.content.includes("Fallback answer text"));
  } finally {
    restore();
  }
});

// Live COMPLETED frame carries the answer only in a double-encoded FINAL step
// blob (no markdown_block / diff_block). Without this fallback the executor
// returns empty content → chatCore 502 "Provider returned empty content".
test("Non-streaming: recovers answer from COMPLETED FINAL text step-blob", async () => {
  const answerObj = {
    answer: "Hi Bilal — nice to meet you! How can I help today?",
    chunks: ["Hi Bilal — ", "nice to meet ", "you! How can I ", "help to", "day?"],
    web_results: [],
  };
  const pplxEvents = [
    {
      status: "COMPLETED",
      final: true,
      final_sse_message: true,
      blocks: [],
      text: JSON.stringify([
        { step_type: "INITIAL_QUERY", content: { query: "hello" } },
        { step_type: "FINAL", content: { answer: JSON.stringify(answerObj) } },
      ]),
    },
  ];

  const restore = mockFetch(200, pplxEvents);
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-sonar",
      body: { messages: [{ role: "user", content: "hello" }], stream: false },
      stream: false,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(result.response.status, 200);
    const json = (await result.response.json()) as {
      choices: Array<{ message: { content: string } }>;
    };
    assert.equal(
      json.choices[0].message.content,
      "Hi Bilal — nice to meet you! How can I help today?"
    );
  } finally {
    restore();
  }
});

// Mirrors the Jul 2026 browser capture: dual ask_text + ask_text_0_markdown
// tracks stream the same chunks via diff_block; parser must not double-count
// and must assemble the full answer.
test("Schematized API: dual ask_text tracks do not double-count", async () => {
  const pplxEvents = [
    {
      status: "PENDING",
      blocks: [
        {
          intended_usage: "ask_text_0_markdown",
          diff_block: {
            field: "markdown_block",
            patches: [
              {
                op: "replace",
                path: "",
                value: { progress: "IN_PROGRESS", chunks: ["Hi Bilal — "] },
              },
            ],
          },
        },
        {
          intended_usage: "ask_text",
          diff_block: {
            field: "markdown_block",
            patches: [
              {
                op: "replace",
                path: "",
                value: { progress: "IN_PROGRESS", chunks: ["Hi Bilal — "] },
              },
            ],
          },
        },
      ],
    },
    {
      status: "PENDING",
      blocks: [
        {
          intended_usage: "ask_text_0_markdown",
          diff_block: {
            field: "markdown_block",
            patches: [{ op: "add", path: "/chunks/1", value: "nice to meet you!" }],
          },
        },
        {
          intended_usage: "ask_text",
          diff_block: {
            field: "markdown_block",
            patches: [{ op: "add", path: "/chunks/1", value: "nice to meet you!" }],
          },
        },
      ],
    },
    {
      status: "COMPLETED",
      final: true,
      blocks: [
        {
          intended_usage: "ask_text_0_markdown",
          markdown_block: {
            progress: "DONE",
            answer: "Hi Bilal — nice to meet you!",
            chunks: ["Hi Bilal — nice to meet you!"],
          },
        },
      ],
    },
  ];

  const restore = mockFetch(200, pplxEvents);
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-sonar",
      body: { messages: [{ role: "user", content: "hello" }], stream: false },
      stream: false,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(result.response.status, 200);
    const json = (await result.response.json()) as {
      choices: Array<{ message: { content: string } }>;
    };
    assert.equal(json.choices[0].message.content, "Hi Bilal — nice to meet you!");
  } finally {
    restore();
  }
});

// Unit: extractAnswerFromFinalText pure helper
test("extractAnswerFromFinalText: double-encoded FINAL step blob", async () => {
  const { extractAnswerFromFinalText } =
    await import("../../open-sse/executors/perplexity-web/protocol.ts");
  const text = JSON.stringify([
    { step_type: "INITIAL_QUERY", content: { query: "hello" } },
    {
      step_type: "FINAL",
      content: {
        answer: JSON.stringify({
          answer: "Recovered from blob",
          chunks: ["Recovered ", "from blob"],
        }),
      },
    },
  ]);
  assert.equal(extractAnswerFromFinalText(text), "Recovered from blob");
  assert.equal(extractAnswerFromFinalText("plain text answer"), "plain text answer");
  assert.equal(extractAnswerFromFinalText(null), null);
  assert.equal(extractAnswerFromFinalText(""), null);
});

// ─── Test: Request URL and headers ──────────────────────────────────────────

test("Request: posts to correct Perplexity SSE endpoint", async () => {
  let capturedUrl = null;
  let capturedHeaders = null;
  const original = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    capturedUrl = url;
    capturedHeaders = opts.headers;
    return new Response(
      mockPplxStream([
        {
          blocks: [
            { intended_usage: "markdown", markdown_block: { chunks: ["ok"], progress: "DONE" } },
          ],
          status: "COMPLETED",
        },
      ]),
      { status: 200, headers: { "Content-Type": "text/event-stream" } }
    );
  };

  try {
    const executor = new PerplexityWebExecutor();
    await executor.execute({
      model: "pplx-auto",
      body: { messages: [{ role: "user", content: "test" }], stream: false },
      stream: false,
      credentials: { apiKey: "test" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(capturedUrl, "https://www.perplexity.ai/rest/sse/perplexity_ask");
    assert.equal(capturedHeaders["Origin"], "https://www.perplexity.ai");
    assert.equal(
      capturedHeaders["x-perplexity-request-endpoint"],
      "https://www.perplexity.ai/rest/sse/perplexity_ask"
    );
    assert.equal(capturedHeaders["x-perplexity-request-reason"], "ask-query-state-provider");
    assert.ok(capturedHeaders["x-request-id"], "x-request-id header should be set");
    assert.equal(capturedHeaders["Accept"], "text/event-stream");
  } finally {
    globalThis.fetch = original;
  }
});

// ─── #2459: Cloudflare challenge vs genuine auth failure ─────────────────────

test("Error: Cloudflare 403 challenge returns a distinct (non-cookie) error", async () => {
  const restore = mockFetch(403, [], "<html><title>Just a moment...</title></html>");
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-auto",
      body: { messages: [{ role: "user", content: "hi" }] },
      stream: false,
      credentials: { apiKey: "valid-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(result.response.status, 403);
    const json = (await result.response.json()) as PplxErrorJson;
    assert.match(json.error.message, /Cloudflare/i);
    assert.ok(!/session-token/i.test(json.error.message), "must not blame the cookie");
  } finally {
    restore();
  }
});

test("Error: TlsClientUnavailableError returns 502 with install hint", async () => {
  const restore = mockFetchError(new TlsClientUnavailableError("native binary missing"));
  try {
    const executor = new PerplexityWebExecutor();
    const result = await executor.execute({
      model: "pplx-auto",
      body: { messages: [{ role: "user", content: "hi" }] },
      stream: false,
      credentials: { apiKey: "test-cookie" },
      signal: AbortSignal.timeout(10000),
      log: null,
    });

    assert.equal(result.response.status, 502);
    const json = (await result.response.json()) as PplxErrorJson;
    assert.match(json.error.message, /TLS client unavailable/i);
  } finally {
    restore();
  }
});
