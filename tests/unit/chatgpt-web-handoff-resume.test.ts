import assert from "node:assert/strict";
import test from "node:test";

import type { TlsFetchOptions } from "../../open-sse/services/chatgptTlsClient.ts";

const { ChatGptWebExecutor, __resetChatGptWebCachesForTesting } =
  await import("../../open-sse/executors/chatgpt-web.ts");
const { resumeChatGptHandoff } = await import("../../open-sse/executors/chatgpt-web/handoff.ts");
const { __setTlsFetchOverrideForTesting } =
  await import("../../open-sse/services/chatgptTlsClient.ts");

function makeHeaders(values: Record<string, string> = {}): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(values)) headers.set(name, value);
  return headers;
}

function sseText(events: unknown[]): string {
  return `${events.map((event) => `data: ${JSON.stringify(event)}\r\n\r\n`).join("")}data: [DONE]\r\n\r\n`;
}

type ResumeRequest = {
  body: { conversation_id?: string; offset?: number };
  headers: Record<string, string>;
};

function installHandoffMock(
  finalText: string,
  options: { firstResumeStatus?: number } = {}
): {
  calls: { conversationDetail: number; resume: ResumeRequest[] };
  restore: () => void;
} {
  const calls = {
    conversationDetail: 0,
    resume: [] as ResumeRequest[],
  };

  __setTlsFetchOverrideForTesting(async (url: string, request: TlsFetchOptions = {}) => {
    const target = String(url);
    const json = (body: unknown, status = 200) => ({
      status,
      headers: makeHeaders({ "Content-Type": "application/json" }),
      text: JSON.stringify(body),
      body: null,
    });

    if (
      (target === "https://chatgpt.com/" || target === "https://chatgpt.com") &&
      (request.method ?? "GET") === "GET"
    ) {
      return {
        status: 200,
        headers: makeHeaders({ "Content-Type": "text/html" }),
        text: '<html data-build="prod-test"><script src="/_next/static/chunks/main.js"></script></html>',
        body: null,
      };
    }

    if (target.includes("/api/auth/session")) {
      return json({
        accessToken: "jwt-test",
        expires: new Date(Date.now() + 3_600_000).toISOString(),
        user: { id: "account-test" },
      });
    }

    if (target.includes("/sentinel/chat-requirements")) {
      return json({ token: "requirements-token", proofofwork: { required: false } });
    }

    if (target.endsWith("/backend-api/f/conversation/resume")) {
      const body = JSON.parse(request.body ?? "{}") as ResumeRequest["body"];
      calls.resume.push({ body, headers: request.headers ?? {} });
      if (options.firstResumeStatus && calls.resume.length === 1) {
        return {
          status: options.firstResumeStatus,
          headers: makeHeaders({ "Content-Type": "text/plain" }),
          text: "not ready",
          body: null,
        };
      }
      return {
        status: 200,
        headers: makeHeaders({ "Content-Type": "text/event-stream" }),
        text: sseText([
          {
            conversation_id: "conversation-handoff",
            message: {
              id: "assistant-final",
              author: { role: "assistant" },
              content: { content_type: "text", parts: [finalText] },
              status: "in_progress",
            },
          },
          {
            conversation_id: "conversation-handoff",
            message: {
              id: "assistant-final",
              author: { role: "assistant" },
              content: { content_type: "text", parts: [finalText] },
              status: "finished_successfully",
              end_turn: true,
            },
          },
        ]),
        body: null,
      };
    }

    if (target.endsWith("/backend-api/f/conversation")) {
      return {
        status: 200,
        headers: makeHeaders({ "Content-Type": "text/event-stream" }),
        text: sseText([
          {
            type: "resume_conversation_token",
            token: "resume-token",
            conversation_id: "conversation-handoff",
          },
          {
            type: "stream_handoff",
            conversation_id: "conversation-handoff",
            turn_exchange_id: "turn-handoff",
            options: [
              { type: "resume_sse_endpoint", topic_id: "conversation-turn-handoff" },
              { type: "subscribe_ws_topic", topic_id: "conversation-turn-handoff" },
            ],
          },
        ]),
        body: null,
      };
    }

    if (/\/backend-api\/conversation\/[^/?#]+$/.test(target)) {
      calls.conversationDetail++;
      return json(
        {
          detail: {
            message: "You do not have access to this temporary conversation.",
            code: "conversation_not_found",
          },
        },
        404
      );
    }

    // Browser warmup requests are non-fatal, but returning 200 keeps test logs quiet.
    if (
      target.includes("/backend-api/me") ||
      target.includes("/backend-api/conversations?") ||
      target.includes("/backend-api/models?")
    ) {
      return json({});
    }

    return { status: 404, headers: makeHeaders(), text: "not mocked", body: null };
  });

  return {
    calls,
    restore() {
      __setTlsFetchOverrideForTesting(null);
    },
  };
}

test("ChatGPT Web GPT-5.6 Sol Pro resumes Temporary Chat handoffs through native SSE", async (t) => {
  for (const model of ["gpt-5.6-sol-pro"]) {
    await t.test(model, async () => {
      __resetChatGptWebCachesForTesting();
      const expected = `RESUMED_${model}`;
      const mock = installHandoffMock(expected);
      try {
        const executor = new ChatGptWebExecutor();
        const result = await executor.execute({
          model,
          body: { messages: [{ role: "user", content: "hard problem" }] },
          stream: false,
          credentials: { apiKey: `cookie-${model}` },
          signal: AbortSignal.timeout(20_000),
          log: null,
        });

        assert.equal(result.response.status, 200);
        const response = await result.response.json();
        assert.equal(response.choices[0].message.content, expected);
        assert.equal(mock.calls.resume.length, 1);
        assert.deepEqual(mock.calls.resume[0].body, {
          conversation_id: "conversation-handoff",
          offset: 0,
        });
        assert.equal(mock.calls.resume[0].headers["x-conduit-token"], "resume-token");
        assert.equal(mock.calls.conversationDetail, 0);
      } finally {
        mock.restore();
      }
    });
  }
});

test("ChatGPT Web handoff retries the next resume offset after a 404", async () => {
  __resetChatGptWebCachesForTesting();
  const mock = installHandoffMock("OFFSET_ONE_OK", { firstResumeStatus: 404 });
  try {
    const executor = new ChatGptWebExecutor();
    const result = await executor.execute({
      model: "gpt-5.6-sol-pro",
      body: { messages: [{ role: "user", content: "hard problem" }] },
      stream: false,
      credentials: { apiKey: "cookie-offset" },
      signal: AbortSignal.timeout(20_000),
      log: null,
    });

    assert.equal(result.response.status, 200);
    const response = await result.response.json();
    assert.equal(response.choices[0].message.content, "OFFSET_ONE_OK");
    assert.deepEqual(
      mock.calls.resume.map((call) => call.body.offset),
      [0, 1]
    );
    assert.equal(mock.calls.conversationDetail, 0);
  } finally {
    mock.restore();
  }
});

test("ChatGPT Web streaming appends the native resumed Pro answer", async () => {
  __resetChatGptWebCachesForTesting();
  const mock = installHandoffMock("STREAM_RESUME_OK");
  try {
    const executor = new ChatGptWebExecutor();
    const result = await executor.execute({
      model: "gpt-5.6-sol-pro",
      body: { messages: [{ role: "user", content: "hard problem" }], stream: true },
      stream: true,
      credentials: { apiKey: "cookie-stream" },
      signal: AbortSignal.timeout(20_000),
      log: null,
    });

    assert.equal(result.response.status, 200);
    const responseText = await result.response.text();
    const content = responseText
      .split("\n")
      .filter((line) => line.startsWith("data: ") && line !== "data: [DONE]")
      .map((line) => JSON.parse(line.slice(6)) as Record<string, unknown>)
      .map((event) => {
        const choices = event.choices as Array<{ delta?: { content?: string } }> | undefined;
        return choices?.[0]?.delta?.content ?? "";
      })
      .join("");

    assert.equal(content, "STREAM_RESUME_OK");
    assert.equal(mock.calls.resume.length, 1);
    assert.equal(mock.calls.conversationDetail, 0);
  } finally {
    mock.restore();
  }
});

test("ChatGPT Web handoff logs sanitize upstream response and transport details", async () => {
  const cases = [
    {
      label: "response body",
      run: async () => ({
        status: 502,
        headers: makeHeaders({ "Content-Type": "text/plain" }),
        text:
          "Cannot read download_url_https://files.oaiusercontent.com/private?sig=OPAQUE-HANDOFF-URL " +
          "and '/srv/private/handoff.pem' access_token=sk-handoff-body\n" +
          "    at /srv/private/handoff.ts:1",
        body: null,
      }),
      expected:
        "conversation resume 502: Cannot read download_url_<url> and '<path>' access_token=[REDACTED]",
    },
    {
      label: "transport error",
      run: async () => {
        throw new Error(
          "Cannot open '/srv/private/handoff.sock' access_token=sk-handoff-error\n" +
            "    at /srv/private/handoff.ts:2"
        );
      },
      expected: "conversation resume failed: Cannot open '<path>' access_token=[REDACTED]",
    },
    {
      label: "stack-only transport error",
      run: async () => {
        throw new Error("\n    at /srv/private/handoff.ts:3");
      },
      expected: "conversation resume failed: upstream error unavailable",
    },
    {
      label: "hostile prototype transport error",
      run: async () => {
        throw new Proxy(
          {},
          {
            getPrototypeOf() {
              throw new Error(
                "access_token=handoff-prototype-secret at /srv/private/handoff-prototype.ts:1:2"
              );
            },
            get(_target, property) {
              if (property === "toString") {
                return () => {
                  throw new Error(
                    "access_token=handoff-coercion-secret at /srv/private/handoff-coercion.ts:1:2"
                  );
                };
              }
              return undefined;
            },
          }
        );
      },
      expected: "conversation resume failed: upstream error unavailable",
    },
    {
      label: "conversation id",
      conversationId: "conversation-opaque-01J9YQ8Z4K7M6N5P3R2T",
      run: async () => ({
        status: 404,
        headers: makeHeaders({ "Content-Type": "text/plain" }),
        text: "not ready",
        body: null,
      }),
      expected: "conversation resume returned no assistant text for <id>",
    },
  ];

  for (const { label, conversationId, run, expected } of cases) {
    const warnings: string[] = [];
    __setTlsFetchOverrideForTesting(run);
    try {
      const answer = await resumeChatGptHandoff({
        conversationId: conversationId ?? `conversation-${label}`,
        resumeToken: "resume-token",
        headers: {},
        timeoutMs: 1_000,
        log: { warn: (_tag, message) => warnings.push(message) },
        readContent: async function* () {},
      });

      assert.equal(answer, null);
      assert.deepEqual(warnings, [expected]);
      assert.doesNotMatch(
        warnings.join("\n"),
        /\/srv\/private|sk-handoff|handoff(?:-prototype|-coercion)?\.ts|handoff-(?:prototype|coercion)-secret|conversation-opaque|files\.oaiusercontent|OPAQUE-HANDOFF/,
        `${label} must not expose upstream paths, tokens, or stack frames`
      );
    } finally {
      __setTlsFetchOverrideForTesting(null);
    }
  }
});
