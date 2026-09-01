import { test } from "node:test";
import assert from "node:assert/strict";
import { handleOcr } from "../../open-sse/handlers/ocr.ts";

function fetchStub(
  script: Array<{ status: number; headers?: Record<string, string>; json?: unknown }>
) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl = async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const step = script.shift()!;
    return new Response(step.json !== undefined ? JSON.stringify(step.json) : null, {
      status: step.status,
      headers: { "Content-Type": "application/json", ...(step.headers ?? {}) },
    });
  };
  return { impl, calls };
}

const noSleep = async () => {};

test("mistral path posts once and returns the upstream body", async () => {
  const { impl, calls } = fetchStub([
    { status: 200, json: { pages: [{ index: 0, markdown: "ok" }], model: "mistral-ocr-latest" } },
  ]);
  const res = await handleOcr({
    body: {
      model: "mistral/mistral-ocr-latest",
      document: { type: "image_url", image_url: "https://x/y.png" },
    },
    credentials: { apiKey: "sk" },
    fetchImpl: impl,
    sleepImpl: noSleep,
  });
  assert.equal(res.status, 200);
  assert.equal(calls.length, 1);
  const data = await res.json();
  assert.equal(data.pages[0].markdown, "ok");
});

test("OCR removes Unicode-escaped credential fields while preserving safe fields", async () => {
  const upstreamBody = String.raw`{"\u0061pi_key":"credential-value-12345","message":"quota busy"}`;
  const res = await handleOcr({
    body: {
      model: "mistral/mistral-ocr-latest",
      document: { type: "image_url", image_url: "https://x/y.png" },
    },
    credentials: { apiKey: "sk" },
    fetchImpl: async () =>
      new Response(upstreamBody, {
        status: 429,
        headers: { "Content-Type": "application/json" },
      }),
    sleepImpl: noSleep,
  });
  const text = await res.text();
  const payload = JSON.parse(text) as { api_key?: string; message: string };

  assert.equal(res.status, 429);
  assert.equal(res.headers.get("content-type"), "application/json");
  assert.equal(payload.api_key, undefined);
  assert.equal(payload.message, "quota busy");
  assert.doesNotMatch(text, /credential-value-12345|\\u0061pi_key/i);
});

test("OCR preserves valid pretty-printed JSON while sanitizing its fields", async () => {
  const upstreamBody = JSON.stringify(
    {
      error: {
        message: "quota metadata at /srv/provider/ocr.ts:12:3",
        api_key: "credential-value-12345",
      },
    },
    null,
    2
  );
  const res = await handleOcr({
    body: {
      model: "mistral/mistral-ocr-latest",
      document: { type: "image_url", image_url: "https://x/y.png" },
    },
    credentials: { apiKey: "sk" },
    fetchImpl: async () =>
      new Response(upstreamBody, {
        status: 429,
        headers: { "Content-Type": "application/json" },
      }),
    sleepImpl: noSleep,
  });
  const text = await res.text();
  const payload = JSON.parse(text) as {
    error: { message: string; api_key?: string };
  };

  assert.equal(res.status, 429);
  assert.equal(payload.error.api_key, undefined);
  assert.equal(payload.error.message, "quota metadata at <path>");
  assert.doesNotMatch(text, /credential-value-12345|\/srv\/provider/i);
});

test("OCR removes paths and stacks and falls back for stack-only or blank errors", async () => {
  const cases = [
    {
      name: "POSIX and Windows paths",
      upstreamBody: String.raw`failed reading /home/service/private/ocr.ts and C:\Users\alice\private\ocr.ts; retry later`,
      expectedBody: /^failed reading <path>$/i,
    },
    {
      name: "physical stack",
      upstreamBody: "OCR upstream busy\n    at handler (/home/service/private/ocr.ts:12:3)",
      expectedBody: /^OCR upstream busy$/,
    },
    {
      name: "serialized stack",
      upstreamBody: String.raw`OCR upstream busy\n    at handler (C:\Users\alice\private\ocr.ts:12:3)`,
      expectedBody: /^OCR upstream busy$/,
    },
    {
      name: "stack only",
      upstreamBody: "    at handler (/home/service/private/ocr.ts:12:3)",
      expectedBody: /^OCR provider returned HTTP 503$/,
    },
    {
      name: "whitespace only",
      upstreamBody: " \n\t ",
      expectedBody: /^OCR provider returned HTTP 503$/,
    },
  ];

  for (const fixture of cases) {
    const res = await handleOcr({
      body: {
        model: "mistral/mistral-ocr-latest",
        document: { type: "image_url", image_url: "https://x/y.png" },
      },
      credentials: { apiKey: "sk" },
      fetchImpl: async () =>
        new Response(fixture.upstreamBody, {
          status: 503,
          headers: { "Content-Type": "application/json" },
        }),
      sleepImpl: noSleep,
    });
    const text = await res.text();
    const payload = JSON.parse(text) as { error: { message: string } };

    assert.equal(res.status, 503, fixture.name);
    assert.equal(res.headers.get("content-type"), "application/json", fixture.name);
    assert.match(payload.error.message, fixture.expectedBody, fixture.name);
    assert.doesNotMatch(text, /\/home\/service\/private|C:\\Users\\alice/i, fixture.name);
    assert.doesNotMatch(text, /(?:^|\\n)\s*at\s/i, fixture.name);
  }
});

test("OCR catch logs only a canonical-sanitized message and keeps the public 500 static", async () => {
  const originalConsoleError = console.error;
  const logged: unknown[][] = [];
  console.error = (...args: unknown[]) => {
    logged.push(args);
  };
  const upstreamError = new Error(
    String.raw`OCR transport failed; \u0061pi_key\u003dcredential-value-12345; path /home/service/private/ocr.ts`
  );
  upstreamError.stack = String.raw`Error: credential-value-12345\n    at handler (C:\Users\alice\private\ocr.ts:12:3)`;

  try {
    const res = await handleOcr({
      body: {
        model: "mistral/mistral-ocr-latest",
        document: { type: "image_url", image_url: "https://x/y.png" },
      },
      credentials: { apiKey: "sk" },
      fetchImpl: async () => {
        throw upstreamError;
      },
      sleepImpl: noSleep,
    });
    const body = await res.json();

    assert.equal(res.status, 500);
    assert.equal(body.error.message, "OCR request failed");
    assert.equal(logged.length, 1);
    assert.equal(logged[0][0], "[OCR]");
    assert.equal(typeof logged[0][1], "string");
    const publicLog = logged.flat().join(" ");
    assert.match(publicLog, /OCR transport failed/i);
    assert.match(publicLog, /\[REDACTED\]/);
    assert.doesNotMatch(
      publicLog,
      /credential-value-12345|\/home\/service\/private|C:\\Users\\alice|(?:^|\\n)\s*at\s/i
    );
  } finally {
    console.error = originalConsoleError;
  }
});

test("OCR catch fails closed when a thrown value rejects string coercion", async () => {
  const originalConsoleError = console.error;
  const logged: unknown[][] = [];
  console.error = (...args: unknown[]) => {
    logged.push(args);
  };

  try {
    const res = await handleOcr({
      body: {
        model: "mistral/mistral-ocr-latest",
        document: { type: "image_url", image_url: "https://x/y.png" },
      },
      credentials: { apiKey: "sk" },
      fetchImpl: async () => {
        throw {
          toString() {
            throw new Error("access_token=hostile-secret at /srv/private/ocr.ts:1:2");
          },
        };
      },
      sleepImpl: noSleep,
    });
    const body = await res.json();

    assert.equal(res.status, 500);
    assert.equal(body.error.message, "OCR request failed");
    assert.deepEqual(logged, [["[OCR]", "OCR request failed"]]);
  } finally {
    console.error = originalConsoleError;
  }
});

test("azure DI path polls Operation-Location until succeeded", async () => {
  const { impl, calls } = fetchStub([
    { status: 202, headers: { "Operation-Location": "https://poll/op/1" } },
    { status: 200, json: { status: "running" } },
    { status: 200, json: { status: "succeeded", analyzeResult: { content: "# md", pages: [{}] } } },
  ]);
  const res = await handleOcr({
    body: {
      model: "azure-document-intelligence/prebuilt-read",
      document: { type: "document_url", document_url: "https://x/d.pdf" },
    },
    credentials: { apiKey: "azkey", baseUrl: "https://r.cognitiveservices.azure.com" },
    fetchImpl: impl,
    sleepImpl: noSleep,
  });
  assert.equal(res.status, 200);
  assert.ok(calls.length >= 3);
  const data = await res.json();
  assert.equal(data.pages[0].markdown, "# md");
});

test("unknown model lists available providers dynamically and errors do not leak internals", async () => {
  const res = await handleOcr({
    body: { model: "nope/none", document: { type: "image_url", image_url: "https://x" } },
    credentials: { apiKey: "k" },
    fetchImpl: async () => new Response("{}", { status: 200 }),
    sleepImpl: noSleep,
  });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.ok(body.error.message.includes("azure-document-intelligence"));
  assert.ok(!body.error.message.includes("at /"));
});

test("azure DI poll returns failed status maps to 502", async () => {
  const { impl } = fetchStub([
    { status: 202, headers: { "Operation-Location": "https://poll/op/1" } },
    { status: 200, json: { status: "failed" } },
  ]);
  const res = await handleOcr({
    body: {
      model: "azure-document-intelligence/prebuilt-read",
      document: { type: "document_url", document_url: "https://x/d.pdf" },
    },
    credentials: { apiKey: "azkey", baseUrl: "https://r.cognitiveservices.azure.com" },
    fetchImpl: impl,
    sleepImpl: noSleep,
  });
  assert.equal(res.status, 502);
  const body = await res.json();
  assert.ok(!body.error.message.includes("at /"));
});

test("azure DI poll returns a non-ok response (401) and fails fast without exhausting the loop", async () => {
  const { impl, calls } = fetchStub([
    { status: 202, headers: { "Operation-Location": "https://poll/op/1" } },
    { status: 401, json: { error: "unauthorized" } },
  ]);
  const res = await handleOcr({
    body: {
      model: "azure-document-intelligence/prebuilt-read",
      document: { type: "document_url", document_url: "https://x/d.pdf" },
    },
    credentials: { apiKey: "azkey", baseUrl: "https://r.cognitiveservices.azure.com" },
    fetchImpl: impl,
    sleepImpl: noSleep,
  });
  assert.equal(res.status, 502);
  // 1 initial POST + 1 poll: the loop stopped immediately, it did not run all 30 attempts.
  assert.equal(calls.length, 2);
  const body = await res.json();
  assert.ok(!body.error.message.includes("at /"));
});

test("azure DI poll never resolves and times out after 30 attempts with a 504", async () => {
  const script = [{ status: 202, headers: { "Operation-Location": "https://poll/op/1" } }];
  for (let i = 0; i < 30; i++) {
    script.push({ status: 200, json: { status: "running" } });
  }
  const { impl, calls } = fetchStub(script);
  const res = await handleOcr({
    body: {
      model: "azure-document-intelligence/prebuilt-read",
      document: { type: "document_url", document_url: "https://x/d.pdf" },
    },
    credentials: { apiKey: "azkey", baseUrl: "https://r.cognitiveservices.azure.com" },
    fetchImpl: impl,
    sleepImpl: noSleep,
  });
  assert.equal(res.status, 504);
  // 1 initial POST + 30 poll attempts (the max cap), no more.
  assert.equal(calls.length, 31);
});
