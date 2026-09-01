import test from "node:test";
import assert from "node:assert/strict";

const { handleModeration } = await import("../../open-sse/handlers/moderations.ts");
const { MODERATION_PROVIDERS, getModerationProvider, parseModerationModel } =
  await import("../../open-sse/config/moderationRegistry.ts");

const originalFetch = globalThis.fetch;

test.afterEach(() => {
  globalThis.fetch = originalFetch;
});

test("MODERATION_PROVIDERS registers mistral with the Mistral moderations base URL", () => {
  const provider = getModerationProvider("mistral");
  assert.ok(provider);
  assert.equal(provider.baseUrl, "https://api.mistral.ai/v1/moderations");
  assert.ok(provider.models.some((m: { id: string }) => m.id === "mistral-moderation-latest"));
  assert.ok(MODERATION_PROVIDERS.mistral);
});

test("parseModerationModel routes mistral moderation models to the mistral provider", () => {
  assert.deepEqual(parseModerationModel("mistral/mistral-moderation-latest"), {
    provider: "mistral",
    model: "mistral-moderation-latest",
  });
  assert.deepEqual(parseModerationModel("mistral-moderation-latest"), {
    provider: "mistral",
    model: "mistral-moderation-latest",
  });
});

test("handleModeration proxies mistral moderation requests to the mistral endpoint", async () => {
  let captured: any;
  globalThis.fetch = async (url: any, options: any = {}) => {
    captured = { url: String(url), headers: options.headers };
    return Response.json({ id: "modr-mistral", results: [{ flagged: false }] });
  };

  const response = await handleModeration({
    body: { model: "mistral/mistral-moderation-latest", input: "check this" },
    credentials: { apiKey: "sk-mistral" },
  });

  assert.equal(captured.url, "https://api.mistral.ai/v1/moderations");
  assert.equal(captured.headers.Authorization, "Bearer sk-mistral");
  assert.equal(response.status, 200);
});

test("handleModeration requires input", async () => {
  const response = await handleModeration({
    body: { model: "openai/omni-moderation-latest" },
    credentials: { apiKey: "sk-test" },
  });
  const payload = (await response.json()) as any;

  assert.equal(response.status, 400);
  assert.equal(payload.error.message, "input is required");
});

test("handleModeration rejects unknown moderation models", async () => {
  const response = await handleModeration({
    body: { model: "mystery/moderation", input: "hello" },
    credentials: { apiKey: "sk-test" },
  });
  const payload = (await response.json()) as any;

  assert.equal(response.status, 400);
  assert.match(payload.error.message, /No moderation provider found/);
});

test("handleModeration requires credentials for the resolved provider", async () => {
  const response = await handleModeration({
    body: { input: "hello" },
    credentials: null,
  });
  const payload = (await response.json()) as any;

  assert.equal(response.status, 401);
  assert.equal(payload.error.message, "No credentials for moderation provider: openai");
});

test("handleModeration proxies successful requests with default model and accessToken fallback", async () => {
  let captured;

  globalThis.fetch = async (url, options = {}) => {
    captured = {
      url: String(url),
      headers: options.headers,
      body: JSON.parse(String(options.body || "{}")),
    };

    return Response.json({
      id: "modr-1",
      results: [{ flagged: false }],
    });
  };

  const response = await handleModeration({
    body: { input: "all clear" },
    credentials: { accessToken: "oauth-token" },
  });

  assert.equal(captured.url, "https://api.openai.com/v1/moderations");
  assert.equal(captured.headers.Authorization, "Bearer oauth-token");
  assert.deepEqual(captured.body, {
    model: "omni-moderation-latest",
    input: "all clear",
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("access-control-allow-origin"), null);
  assert.match(response.headers.get("access-control-allow-methods") || "", /OPTIONS/);
  assert.deepEqual(await response.json(), {
    id: "modr-1",
    results: [{ flagged: false }],
  });
});

test("handleModeration returns upstream error payloads with CORS headers", async () => {
  globalThis.fetch = async () =>
    new Response('{"error":"busy"}', {
      status: 429,
      headers: { "content-type": "application/json" },
    });

  const response = await handleModeration({
    body: { model: "openai/text-moderation-latest", input: "check this" },
    credentials: { apiKey: "sk-test" },
  });

  assert.equal(response.status, 429);
  assert.equal(await response.text(), '{"error":"busy"}');
  assert.equal(response.headers.get("content-type"), "application/json");
  assert.equal(response.headers.get("access-control-allow-origin"), null);
  assert.match(response.headers.get("access-control-allow-methods") || "", /OPTIONS/);
});

test("handleModeration removes Unicode-escaped credential fields while preserving safe fields", async () => {
  const upstreamBody = String.raw`{"\u0061pi_key":"credential-value-12345","message":"quota busy"}`;
  globalThis.fetch = async () =>
    new Response(upstreamBody, {
      status: 429,
      headers: { "content-type": "application/json" },
    });

  const response = await handleModeration({
    body: { model: "openai/text-moderation-latest", input: "check this" },
    credentials: { apiKey: "sk-test" },
  });
  const text = await response.text();
  const payload = JSON.parse(text) as { api_key?: string; message: string };

  assert.equal(response.status, 429);
  assert.equal(response.headers.get("content-type"), "application/json");
  assert.equal(payload.api_key, undefined);
  assert.equal(payload.message, "quota busy");
  assert.doesNotMatch(text, /credential-value-12345|\\u0061pi_key/i);
});

test("handleModeration preserves valid pretty-printed JSON while sanitizing its fields", async () => {
  const upstreamBody = JSON.stringify(
    {
      error: {
        message: "quota metadata at /srv/provider/moderations.ts:12:3",
        api_key: "credential-value-12345",
      },
    },
    null,
    2
  );
  globalThis.fetch = async () =>
    new Response(upstreamBody, {
      status: 429,
      headers: { "content-type": "application/json" },
    });

  const response = await handleModeration({
    body: { model: "openai/text-moderation-latest", input: "check this" },
    credentials: { apiKey: "sk-test" },
  });
  const text = await response.text();
  const payload = JSON.parse(text) as {
    error: { message: string; api_key?: string };
  };

  assert.equal(response.status, 429);
  assert.equal(payload.error.api_key, undefined);
  assert.equal(payload.error.message, "quota metadata at <path>");
  assert.doesNotMatch(text, /credential-value-12345|\/srv\/provider/i);
});

test("handleModeration removes paths and stacks and falls back for stack-only or blank errors", async () => {
  const cases = [
    {
      name: "POSIX and Windows paths",
      upstreamBody: String.raw`failed reading /home/service/private/moderations.ts and C:\Users\alice\private\moderations.ts; retry later`,
      expectedBody: /^failed reading <path>$/i,
    },
    {
      name: "physical stack",
      upstreamBody:
        "Moderation upstream busy\n    at handler (/home/service/private/moderations.ts:12:3)",
      expectedBody: /^Moderation upstream busy$/,
    },
    {
      name: "serialized stack",
      upstreamBody: String.raw`Moderation upstream busy\n    at handler (C:\Users\alice\private\moderations.ts:12:3)`,
      expectedBody: /^Moderation upstream busy$/,
    },
    {
      name: "stack only",
      upstreamBody: "    at handler (/home/service/private/moderations.ts:12:3)",
      expectedBody: /^Moderation provider returned HTTP 503$/,
    },
    {
      name: "whitespace only",
      upstreamBody: " \n\t ",
      expectedBody: /^Moderation provider returned HTTP 503$/,
    },
  ];

  for (const fixture of cases) {
    globalThis.fetch = async () =>
      new Response(fixture.upstreamBody, {
        status: 503,
        headers: { "content-type": "application/json" },
      });

    const response = await handleModeration({
      body: { model: "openai/text-moderation-latest", input: "check this" },
      credentials: { apiKey: "sk-test" },
    });
    const text = await response.text();
    const payload = JSON.parse(text) as { error: { message: string } };

    assert.equal(response.status, 503, fixture.name);
    assert.equal(response.headers.get("content-type"), "application/json", fixture.name);
    assert.match(payload.error.message, fixture.expectedBody, fixture.name);
    assert.doesNotMatch(text, /\/home\/service\/private|C:\\Users\\alice/i, fixture.name);
    assert.doesNotMatch(text, /(?:^|\\n)\s*at\s/i, fixture.name);
  }
});

test("handleModeration returns a 500 when the upstream request throws", async () => {
  globalThis.fetch = async () => {
    throw new Error("socket closed");
  };

  const response = await handleModeration({
    body: { model: "openai/text-moderation-latest", input: "check this" },
    credentials: { apiKey: "sk-test" },
  });
  const payload = (await response.json()) as any;

  assert.equal(response.status, 500);
  assert.match(payload.error.message, /Moderation request failed: socket closed/);
});

test("handleModeration fails closed when a thrown value rejects string coercion", async () => {
  globalThis.fetch = async () => {
    throw {
      get message() {
        throw new Error("access_token=hostile-secret at /srv/private/moderation.ts:1:2");
      },
      toString() {
        throw new Error("access_token=hostile-secret at /srv/private/moderation.ts:1:2");
      },
    };
  };

  const response = await handleModeration({
    body: { model: "openai/text-moderation-latest", input: "check this" },
    credentials: { apiKey: "sk-test" },
  });
  const payload = (await response.json()) as { error: { message: string } };

  assert.equal(response.status, 500);
  assert.equal(payload.error.message, "Moderation request failed: unknown upstream failure");
  assert.doesNotMatch(payload.error.message, /hostile-secret|srv\/private/i);
});
