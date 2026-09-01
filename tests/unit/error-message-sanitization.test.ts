/**
 * Verifies that API routes sanitize error messages (CodeQL js/stack-trace-exposure)
 * and that security-critical helpers behave correctly.
 */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const TEST_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-err-sanitize-"));
process.env.DATA_DIR = TEST_DATA_DIR;
process.env.API_KEY_SECRET = "test-api-key-secret-32chars-long!!";

const core = await import("../../src/lib/db/core.ts");
const combosDb = await import("../../src/lib/db/combos.ts");
const mappingsRoute = await import("../../src/app/api/model-combo-mappings/route.ts");
const mappingsIdRoute = await import("../../src/app/api/model-combo-mappings/[id]/route.ts");
const syncTokens = await import("../../src/lib/sync/tokens.ts");

const repoRoot = path.resolve(import.meta.dirname, "../..");
const read = (relPath: string) => fs.readFileSync(path.join(repoRoot, relPath), "utf8");

function makeRequest(url: string, options: { method?: string; body?: unknown } = {}) {
  const { method = "GET", body } = options;
  return new Request(url, {
    method,
    headers: body !== undefined ? { "content-type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

async function resetStorage() {
  core.resetDbInstance();
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  fs.mkdirSync(TEST_DATA_DIR, { recursive: true });
}

test.beforeEach(async () => {
  await resetStorage();
});

test.after(() => {
  core.resetDbInstance();
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
});

async function createCombo(name: string, model: string) {
  return combosDb.createCombo({
    name,
    models: [{ provider: "openai", model }],
    strategy: "priority",
    config: {},
  });
}

// ── model-combo-mappings routes ──────────────────────────────────────────────

test("GET /model-combo-mappings returns empty list on fresh DB", async () => {
  const res = await mappingsRoute.GET(makeRequest("http://localhost/api/model-combo-mappings"));
  assert.equal(res.status, 200);
  const body = (await res.json()) as any;
  assert.ok(Array.isArray(body.mappings), "body.mappings must be an array");
  assert.equal(body.mappings.length, 0);
  assert.ok(!("error" in body), "success response must not contain error field");
});

test("GET /model-combo-mappings error response never leaks raw error.message", async () => {
  const res = await mappingsRoute.GET(makeRequest("http://localhost/api/model-combo-mappings"));
  // In the success case, there is no error field at all
  const body = (await res.json()) as any;
  if (res.status >= 500) {
    assert.equal(body.error, "Failed to list model-combo mappings");
    assert.ok(!("stack" in body), "stack trace must not be present in response");
  }
});

test("POST /model-combo-mappings returns 400 for empty pattern", async () => {
  const res = await mappingsRoute.POST(
    makeRequest("http://localhost/api/model-combo-mappings", {
      method: "POST",
      body: { pattern: "", comboId: "combo-1" },
    })
  );
  assert.equal(res.status, 400);
  const body = (await res.json()) as any;
  assert.ok("error" in body);
  assert.ok(!("stack" in body), "400 response must not contain stack trace");
});

test("POST /model-combo-mappings returns 400 for missing comboId", async () => {
  const res = await mappingsRoute.POST(
    makeRequest("http://localhost/api/model-combo-mappings", {
      method: "POST",
      body: { pattern: "gpt-*" },
    })
  );
  assert.equal(res.status, 400);
});

test("POST /model-combo-mappings creates a mapping and response has no error field", async () => {
  const combo = await createCombo("test-combo", "gpt-4o");
  const res = await mappingsRoute.POST(
    makeRequest("http://localhost/api/model-combo-mappings", {
      method: "POST",
      body: { pattern: "gpt-*", comboId: combo.id },
    })
  );
  assert.equal(res.status, 201);
  const body = (await res.json()) as any;
  assert.ok("mapping" in body, "response must have mapping field");
  assert.ok(!("error" in body), "success response must not contain error field");
  assert.ok(!("stack" in body));
  assert.equal(body.mapping.pattern, "gpt-*");
});

test("GET /model-combo-mappings/[id] returns 404 for non-existent id", async () => {
  const res = await mappingsIdRoute.GET(
    makeRequest("http://localhost/api/model-combo-mappings/nonexistent"),
    { params: Promise.resolve({ id: "nonexistent" }) }
  );
  assert.equal(res.status, 404);
  const body = (await res.json()) as any;
  assert.equal(body.error, "Mapping not found");
  assert.ok(!("stack" in body), "404 response must not contain stack trace");
});

test("GET /model-combo-mappings/[id] error response never leaks internal details", async () => {
  const res = await mappingsIdRoute.GET(
    makeRequest("http://localhost/api/model-combo-mappings/some-id"),
    { params: Promise.resolve({ id: "some-id" }) }
  );
  const body = (await res.json()) as any;
  if (res.status >= 500) {
    assert.equal(body.error, "Failed to get mapping");
    assert.ok(!body.error.includes("SQLITE"), "SQLite internals must not be exposed");
    assert.ok(!("stack" in body));
  }
});

test("DELETE /model-combo-mappings/[id] returns 404 for non-existent mapping", async () => {
  const res = await mappingsIdRoute.DELETE(
    makeRequest("http://localhost/api/model-combo-mappings/nonexistent", { method: "DELETE" }),
    { params: Promise.resolve({ id: "nonexistent" }) }
  );
  assert.equal(res.status, 404);
  const body = (await res.json()) as any;
  assert.equal(body.error, "Mapping not found");
  assert.ok(!("stack" in body));
});

test("PUT /model-combo-mappings/[id] returns 404 for non-existent mapping", async () => {
  const res = await mappingsIdRoute.PUT(
    makeRequest("http://localhost/api/model-combo-mappings/nonexistent", {
      method: "PUT",
      body: { pattern: "new-*" },
    }),
    { params: Promise.resolve({ id: "nonexistent" }) }
  );
  assert.equal(res.status, 404);
  const body = (await res.json()) as any;
  assert.equal(body.error, "Mapping not found");
  assert.ok(!("stack" in body));
});

// ── sync token hashing (src/lib/sync/tokens.ts) ──────────────────────────────

test("hashSyncToken returns a 64-character hex string (SHA-256 output)", () => {
  const token = syncTokens.generatePlaintextSyncToken();
  const hash = syncTokens.hashSyncToken(token);
  assert.match(hash, /^[0-9a-f]{64}$/, "hash must be 64 lowercase hex chars");
});

test("hashSyncToken is deterministic — same input always produces same output", () => {
  const token = syncTokens.generatePlaintextSyncToken();
  assert.equal(
    syncTokens.hashSyncToken(token),
    syncTokens.hashSyncToken(token),
    "hashing the same token twice must yield the same result"
  );
});

test("hashSyncToken produces different hashes for different tokens", () => {
  const a = syncTokens.generatePlaintextSyncToken();
  const b = syncTokens.generatePlaintextSyncToken();
  assert.notEqual(
    syncTokens.hashSyncToken(a),
    syncTokens.hashSyncToken(b),
    "different tokens must produce different hashes"
  );
});

test("generatePlaintextSyncToken starts with osync_ prefix", () => {
  const token = syncTokens.generatePlaintextSyncToken();
  assert.ok(
    token.startsWith("osync_"),
    `token must start with 'osync_', got: ${token.slice(0, 10)}`
  );
});

test("hashSyncToken output is never the plain token (not stored in clear text)", () => {
  const token = syncTokens.generatePlaintextSyncToken();
  const hash = syncTokens.hashSyncToken(token);
  assert.notEqual(hash, token, "hash must differ from plaintext token");
  assert.ok(!hash.startsWith("osync_"), "hash must not start with the token prefix");
});

test("sanitizeErrorMessage strips multi-line stack traces", async () => {
  const { sanitizeErrorMessage } = await import("../../open-sse/utils/error.ts");
  const input =
    "Cannot read property 'foo' of undefined\n    at handler (/srv/app/src/lib/x.ts:42:11)\n    at next (internal)";
  const out = sanitizeErrorMessage(input);
  assert.equal(out, "Cannot read property 'foo' of undefined");
  assert.ok(!out.includes("at handler"));
});

test("sanitizeErrorMessage replaces absolute paths with <path>", async () => {
  const { sanitizeErrorMessage } = await import("../../open-sse/utils/error.ts");
  const out1 = sanitizeErrorMessage("Failed to open /home/user/secret-project/src/config.ts:10");
  assert.ok(!out1.includes("/home/user/secret-project"));
  assert.ok(out1.includes("<path>"));

  const out2 = sanitizeErrorMessage("Module not found: C:\\Users\\admin\\app\\index.js:1:1");
  assert.ok(!out2.includes("C:\\Users\\admin"));
  assert.ok(out2.includes("<path>"));

  const out3 = sanitizeErrorMessage("Native binary missing at /srv/private/tls-client");
  assert.ok(!out3.includes("/srv/private/tls-client"));
  assert.ok(out3.includes("<path>"));
});

test("sanitizeErrorMessage redacts wrapped filesystem paths without stripping punctuation", async () => {
  const { sanitizeErrorMessage } = await import("../../open-sse/utils/error.ts");
  const cases = [
    {
      input: "Cannot load '/home/alice/omniroute/index.js:12:7'.",
      expected: "Cannot load '<path>'.",
    },
    {
      input: 'Cannot load "C:\\Users\\alice\\omniroute\\index.js:12:7",',
      expected: 'Cannot load "<path>",',
    },
    {
      input: "Loader failed (/opt/omniroute/native/tls-client.node:42:9).",
      expected: "Loader failed (<path>).",
    },
    {
      input: "Loader failed (C:\\Users\\alice\\omniroute\\tls-client.node:42:9);",
      expected: "Loader failed (<path>);",
    },
    {
      input: "Import failed for file:///home/alice/omniroute/index.mjs:8:3;",
      expected: "Import failed for <path>;",
    },
    {
      input: "Import failed for file:///C:/Users/alice/omniroute/index.cjs:8:3!",
      expected: "Import failed for <path>!",
    },
    {
      input: "Cannot import file://server/share/private/secret.js",
      expected: "Cannot import <path>",
    },
    {
      input: "Cannot import 'file://localhost/home/alice/private/secret.js'",
      expected: "Cannot import '<path>'",
    },
    {
      input: "Cannot load //server/share/My Project/private/secret.js",
      expected: "Cannot load <path>",
    },
    {
      input: "dlopen failed at /Users/alice/private/native.dylib:12:4",
      expected: "dlopen failed at <path>",
    },
    {
      input: "open '/Users/alice/private/native.dylib'",
      expected: "open '<path>'",
    },
    {
      input: "dlopen failed at /nix/store/abc/private/native.so",
      expected: "dlopen failed at <path>",
    },
    {
      input: "open '/nix/store/abc/private/native.so'",
      expected: "open '<path>'",
    },
    {
      input: "dlopen failed at /custom/private/native.dll",
      expected: "dlopen failed at <path>",
    },
    {
      input: "Failed at /proc/self/fd/17",
      expected: "Failed at <path>",
    },
    {
      input: "Failed at /dev/shm/private-token",
      expected: "Failed at <path>",
    },
    {
      input: "Failed at /sys/kernel/private /boot/private /media/alice/private",
      expected: "Failed at <path> <path> <path>",
    },
    {
      input: "open '/custom/private/no-extension'",
      expected: "open '<path>'",
    },
    {
      input: "Couldn't open '/home/alice/My Project/tls-client/bin/native.so'",
      expected: "Couldn't open '<path>'",
    },
    {
      input: "dlopen failed at /home/alice/My Project/native.so: denied",
      expected: "dlopen failed at <path>: denied",
    },
    {
      input: "dlopen failed at /custom/alice/My Project/native.so: denied",
      expected: "dlopen failed at <path>: denied",
    },
    {
      input: "dlopen failed at /home/alice/My Project/native.so. Retry",
      expected: "dlopen failed at <path>. Retry",
    },
    {
      input: "Cannot read /home/alice/My Project/config.json: denied",
      expected: "Cannot read <path>: denied",
    },
    {
      input: "Cannot read /custom/alice/My Project/secret.pem: denied",
      expected: "Cannot read <path>: denied",
    },
    {
      input: "Cannot import file:///home/alice/My Project/native.so: denied",
      expected: "Cannot import <path>: denied",
    },
    {
      input: 'EACCES: open "C:\\Users\\Alice Smith\\tls-client\\bin\\native.dll": denied',
      expected: 'EACCES: open "<path>": denied',
    },
    {
      input: "dlopen failed at \\\\server\\share\\secret\\native.dll",
      expected: "dlopen failed at <path>",
    },
    {
      input: 'dlopen failed at "\\\\server\\share\\secret folder\\native.dll"',
      expected: 'dlopen failed at "<path>"',
    },
    {
      input: "dlopen failed at \\\\?\\C:\\secret\\native.dll",
      expected: "dlopen failed at <path>",
    },
    {
      input: "dlopen failed at C:\\Users\\John Smith\\private\\native.dll",
      expected: "dlopen failed at <path>",
    },
    {
      input: "Route ('C:\\Users\\alice\\private\\native.dll') failed",
      expected: "Route ('<path>') failed",
    },
    {
      input: "Cannot open '/v1/private/secret'",
      expected: "Cannot open '<path>'",
    },
    {
      input: "Cannot open '/v1/private/secret.js'",
      expected: "Cannot open '<path>'",
    },
    {
      input: "Cannot open /home/alice/My Project/archive.tar.gz: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open file:///home/alice/My Project/file.js.map: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open /home/alice/My Project/archive.tar.gz/child: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open /archive.tar.gz/secret",
      expected: "Cannot open <path>",
    },
    {
      input: "Cannot open file:///home/alice/My Project/archive.tar.gz/child: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open C:\\Users\\alice\\My Project\\archive.tar.gz\\child: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot get '/home/alice/private/secret.pem'",
      expected: "Cannot get '<path>'",
    },
    {
      input: "Please delete '/Users/alice/private/token.txt'",
      expected: "Please delete '<path>'",
    },
    {
      input: "GET '/home/alice/private/secret.pem'",
      expected: "GET '<path>'",
    },
    {
      input: "Route: /Users/alice/private/token.txt",
      expected: "Route: <path>",
    },
    {
      input: "Cannot route '/custom/alice/private/secret.pem'",
      expected: "Cannot route '<path>'",
    },
    {
      input: "Cannot load '/home/alice/O'Connor/private/secret.js'",
      expected: "Cannot load '<path>'",
    },
    {
      input: "Cannot load '/home/alice/John' Doe/private/secret.js'",
      expected: "Cannot load '<path>'",
    },
    {
      input: "Cannot load '/home/alice/O'.config/private/secret.js'",
      expected: "Cannot load '<path>'",
    },
    {
      input: "Route ('/app/status') failed at '/home/alice/private/secret.pem'",
      expected: "Route ('/app/status') failed at '<path>'",
    },
    {
      input: "Cannot load /home/alice/My.Project Files/native.so",
      expected: "Cannot load <path>",
    },
    {
      input: "Cannot load file:///home/alice/My.Project Files/native.so",
      expected: "Cannot load <path>",
    },
    {
      input: "Cannot load file://server/share/My.Project Files/native.so",
      expected: "Cannot load <path>",
    },
    {
      input: "Cannot load C:\\Users\\alice\\My.Project Files\\native.dll",
      expected: "Cannot load <path>",
    },
    {
      input: "Cannot load \\\\server\\share\\My.Project Files\\native.dll",
      expected: "Cannot load <path>",
    },
    {
      input: "Cannot load \\\\?\\C:\\My.Project Files\\native.dll",
      expected: "Cannot load <path>",
    },
    {
      input: "Cannot load C:\\My, Project\\native.dll",
      expected: "Cannot load <path>",
    },
    {
      input: "Cannot load file:///home/My, Project/native.so",
      expected: "Cannot load <path>",
    },
    {
      input: "Cannot open /v1/private/My very secret.js: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open /v1/private/My very secret.js because permission failed",
      expected: "Cannot open <path> because permission failed",
    },
    {
      input: "Cannot open /custom/file.js because https://api.example.com/v1 failed",
      expected: "Cannot open <path> because https://api.example.com/v1 failed",
    },
    {
      input: "Cannot open /home/alice/file.js because https://api.example.com/v1 failed",
      expected: "Cannot open <path> because https://api.example.com/v1 failed",
    },
    {
      input: "Cannot open C:\\Users\\alice\\file.js because https://api.example.com/v1 failed",
      expected: "Cannot open <path> because https://api.example.com/v1 failed",
    },
    {
      input: "Cannot open file:///home/alice/file.js because https://api.example.com/v1 failed",
      expected: "Cannot open <path> because https://api.example.com/v1 failed",
    },
    {
      input: "Cannot open /custom/file.js because Route /v1/config.js failed",
      expected: "Cannot open <path> because Route /v1/config.js failed",
    },
    {
      input: "Cannot open /home/alice/file.js because Route ('/v1/config.js') failed",
      expected: "Cannot open <path> because Route ('/v1/config.js') failed",
    },
    {
      input: "Cannot open /home/alice/file.js because Route('/v1/config.js') failed",
      expected: "Cannot open <path> because Route('/v1/config.js') failed",
    },
    {
      input: "Cannot open C:\\Users\\alice\\file.js because GET /v1/config.js failed",
      expected: "Cannot open <path> because GET /v1/config.js failed",
    },
    {
      input: "Cannot open file:///home/alice/file.js because TRACE ('/v1/config.js') failed",
      expected: "Cannot open <path> because TRACE ('/v1/config.js') failed",
    },
    {
      input: "Cannot open /home/alice/My Project.js Files/private: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open /custom/My Project.js Files/private: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open file:///home/alice/My Project.js Files/private: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open C:\\Users\\alice\\My Project.dll Files\\private: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open /home/alice/My archive.tar.gz Child/private: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open /home/alice/My Project.js Secret Files/private: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open file:///home/alice/My Project.js Secret Files/private: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open C:\\Users\\alice\\My Project.dll Secret Files\\private: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open /home/alice/My Folder/Another Deep secret.pem: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open file:///home/alice/My Folder/Another Deep secret.pem: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open C:\\Users\\alice\\My Folder\\Another Deep secret.pem: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open /home/alice/My Folder/Another because Secret/private: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open file:///home/alice/My Folder/Another because Secret/private: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open C:\\Users\\alice\\My Folder\\Another because Secret\\private: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Cannot open \\\\server\\share\\My Folder\\Another because Secret\\private: denied",
      expected: "Cannot open <path>: denied",
    },
    {
      input: "Route ('//server/share/private/secret.pem') failed",
      expected: "Route ('<path>') failed",
    },
    {
      input: "GET '//server/share/private/secret.pem' failed",
      expected: "GET '<path>' failed",
    },
    {
      input: "Route ('//?/C:/private/secret.pem') failed",
      expected: "Route ('<path>') failed",
    },
    {
      input: "Failure path:/home/alice/private/secret.ts",
      expected: "Failure path:<path>",
    },
    {
      input: "Failure path:/Users/alice/My Project/secret.js",
      expected: "Failure path:<path>",
    },
    {
      input: "Failure path=>/home/alice/private/secret.pem",
      expected: "Failure path=><path>",
    },
    {
      input: "Failure path->/home/alice/private/secret.pem",
      expected: "Failure path-><path>",
    },
    {
      input: "Failure path|/home/alice/private/secret.pem",
      expected: "Failure path|<path>",
    },
    {
      input: "Failure path=>C:\\Users\\alice\\private\\secret.pem",
      expected: "Failure path=><path>",
    },
    {
      input: "Failure path=>file:///home/alice/private/secret.pem",
      expected: "Failure path=><path>",
    },
    {
      input: "Failure://server/share/LeakBoundary.pem tail",
      expected: "Failure:<path>",
    },
    {
      input: "Error,/home/alice/private/a.ts",
      expected: "Error,<path>",
    },
    {
      input: "Error;/home/alice/private/a.ts",
      expected: "Error;<path>",
    },
    {
      input: "Error./home/alice/private/a.ts",
      expected: "Error.<path>",
    },
    {
      input: "Error,C:\\Users\\alice\\secret.js",
      expected: "Error,<path>",
    },
    {
      input: "Error;file:///home/alice/secret.js",
      expected: "Error;<path>",
    },
    {
      input: "Error /home,denied",
      expected: "Error <path>",
    },
    {
      input: "Error /home:denied",
      expected: "Error <path>",
    },
    {
      input: "Cannot read /secret.pem",
      expected: "Cannot read <path>",
    },
    {
      input: "Cannot read /config.json",
      expected: "Cannot read <path>",
    },
    {
      input: "Cannot open /home/alice/My Project",
      expected: "Cannot open <path>",
    },
    {
      input: "Cannot open /home/alice/My project",
      expected: "Cannot open <path>",
    },
    {
      input: "Cannot open file:///home/alice/My Project",
      expected: "Cannot open <path>",
    },
    {
      input: "Cannot open file://server/share/My Project",
      expected: "Cannot open <path>",
    },
    {
      input: "Cannot open '/home/alice/a.pem' then '/home/bob/b.pem' failed",
      expected: "Cannot open '<path>' then '<path>' failed",
    },
    {
      input: "Cannot open '/home/alice/a.pem' because token 'abc' expired",
      expected: "Cannot open '<path>' expired",
    },
    {
      input: "Cannot open /v1/private/My secret.js: denied",
      expected: "Cannot open <path>: denied",
    },
  ];

  for (const { input, expected } of cases) {
    assert.equal(sanitizeErrorMessage(input), expected, input);
  }

  for (const boundary of [
    "after",
    "because",
    "before",
    "but",
    "crashed",
    "denied",
    "eacces",
    "enoent",
    "expired",
    "failed",
    "rejected",
    "retry",
    "then",
    "when",
    "while",
  ]) {
    const input = "/home/alice/My Folder/Another " + boundary + " Secret/private: denied";
    assert.equal(sanitizeErrorMessage(input), "<path>: denied", input);
  }
});

test("sanitizeErrorMessage preserves HTTPS URLs and ordinary slash text", async () => {
  const { sanitizeErrorMessage } = await import("../../open-sse/utils/error.ts");
  const cases = [
    "Request to https://api.example.com/path failed",
    "Request url=>https://api.example.com/path failed",
    "Route /v1/chat/completions rejected input/output text",
    "Route ('/v1/chat/completions') rejected input/output text",
    "Route('/v1/chat/completions') rejected input/output text",
    "Route ('/health') rejected input/output text",
    "Route ('/api/models') rejected input/output text",
    "Route ('/v1/chat/completions') reported native.node",
    "Route ('/health') reported native.so",
    "Route ('/api/models') reported native.dll",
    "Route ('/app/status') rejected input/output text",
    "Route('/app/status') rejected input/output text",
    "Route ('/v1/config.js') rejected input/output text",
    "GET /app/status",
    "Message /health, try again",
    "Endpoint /v1/chat/completions, rejected",
    "Request /foo and then input/output text",
    "Route: ('/app/config.js')",
    "Route: /app/config.js",
    "GET: ('/app/config.js')",
    "GET: /app/config.js",
    "TRACE ('/v1/config.js') failed",
    "TRACE /v1/config.js failed",
    "CONNECT ('/app/status') failed",
    "CONNECT /app/status failed",
    "Endpoint /v1/chat/completions rejected input/output text",
    "Message /api/models rejected input/output text",
  ];

  for (const input of cases) {
    assert.equal(sanitizeErrorMessage(input), input);
  }
});

test("sanitizeErrorMessage stops path spans before unrelated slash prose", async () => {
  const { sanitizeErrorMessage } = await import("../../open-sse/utils/error.ts");
  const cases = [
    {
      input: "Failed at /home/alice because input/output validation failed",
      expected: "Failed at <path>",
    },
    {
      input: "Failed at /proc/self/fd/17 then input/output validation failed",
      expected: "Failed at <path>",
    },
  ];

  for (const { input, expected } of cases) {
    assert.equal(sanitizeErrorMessage(input), expected, input);
  }
});

test("sanitizeErrorMessage preserves context after ambiguous unquoted paths", async () => {
  const { sanitizeErrorMessage } = await import("../../open-sse/utils/error.ts");
  const determinable = sanitizeErrorMessage(
    "Failed at C:\\Program Files\\tls-client because loader.js crashed"
  );
  const ambiguous = sanitizeErrorMessage(
    "Failed at C:\\Program Files because native loader failed"
  );

  assert.equal(determinable, "Failed at <path> because loader.js crashed");
  assert.equal(ambiguous, "Failed at <path>");
});

test("sanitizeErrorMessage handles non-string inputs safely", async () => {
  const { sanitizeErrorMessage } = await import("../../open-sse/utils/error.ts");
  assert.equal(sanitizeErrorMessage(undefined), "");
  assert.equal(sanitizeErrorMessage(null), "");
  assert.equal(sanitizeErrorMessage(42), "42");
  assert.equal(sanitizeErrorMessage(new Error("boom")), "Error: boom");
});

test("buildErrorBody never exposes stack traces in its message", async () => {
  const { buildErrorBody } = await import("../../open-sse/utils/error.ts");
  const body = buildErrorBody(
    500,
    "Internal error\n    at /opt/app/src/server.ts:99:7\n    at next (internal)"
  );
  assert.equal(body.error.message, "Internal error");
  assert.ok(!body.error.message.includes("at /opt"));
});

test("buildErrorBody(499) yields client_disconnected for type and code", async () => {
  const { buildErrorBody } = await import("../../open-sse/utils/error.ts");
  const body = buildErrorBody(499, "Client disconnected: request_signal_aborted");
  assert.equal(body.error.type, "client_disconnected");
  assert.equal(body.error.code, "client_disconnected");
  assert.equal(body.error.message, "Client disconnected: request_signal_aborted");
});

test("buildErrorBody preserves caller-supplied type/code overrides", async () => {
  const { buildErrorBody } = await import("../../open-sse/utils/error.ts");
  const body = buildErrorBody(502, "Upstream stream error", undefined, {
    type: "stream_error",
    code: "stream_pipeline_error",
  });
  assert.equal(body.error.type, "stream_error");
  assert.equal(body.error.code, "stream_pipeline_error");
  assert.notEqual(body.error.type, "server_error");
  assert.notEqual(body.error.code, "bad_gateway");
});

test("types barrel keeps the model cooldown payload export only", async () => {
  const src = await read("src/types/index.ts");
  assert.match(src, /ModelCooldownErrorPayload/);
  assert.doesNotMatch(src, /ProviderConnection/);
  assert.doesNotMatch(src, /ProviderNode/);
});

// ── sanitizeUpstreamDetails ──────────────────────────────────────────────────

test("sanitizeUpstreamDetails — basic pass-through for safe fields", async () => {
  const { sanitizeUpstreamDetails } = await import("../../open-sse/utils/error.ts");
  const input = { error: { message: "context_length_exceeded", type: "invalid_request_error" } };
  const out = sanitizeUpstreamDetails(input) as any;
  assert.equal(out.error.message, "context_length_exceeded");
  assert.equal(out.error.type, "invalid_request_error");
});

test("sanitizeUpstreamDetails — sanitizes string values (absolute path)", async () => {
  const { sanitizeUpstreamDetails } = await import("../../open-sse/utils/error.ts");
  const input = { error: { message: "bad input at /srv/app/src/lib/db.ts:42" } };
  const out = sanitizeUpstreamDetails(input) as any;
  assert.ok(
    !out.error.message.includes("/srv/app/src/lib/db.ts"),
    "absolute path must be stripped"
  );
  assert.ok(out.error.message.includes("<path>"), "path placeholder must be present");
});

test("sanitizeUpstreamDetails — removes blocked keys (stack, apiKey)", async () => {
  const { sanitizeUpstreamDetails } = await import("../../open-sse/utils/error.ts");
  const input = {
    error: { message: "oops" },
    stack: "Error\n    at foo.ts:1",
    apiKey: "sk-secret",
  };
  const out = sanitizeUpstreamDetails(input) as any;
  assert.ok(!("stack" in out), "stack key must be removed");
  assert.ok(!("apiKey" in out), "apiKey key must be removed");
  assert.equal(out.error.message, "oops");
});

test("sanitizeUpstreamDetails — depth cap replaces nested value at depth > 4", async () => {
  const { sanitizeUpstreamDetails } = await import("../../open-sse/utils/error.ts");
  // Build depth-6 nesting: a.b.c.d.e.f = "leaf"
  const input = { a: { b: { c: { d: { e: { f: "leaf" } } } } } };
  const out = sanitizeUpstreamDetails(input) as any;
  // depth 0:a, 1:b, 2:c, 3:d, 4:e → e is at depth 4, f would be depth 5 → truncated
  assert.equal(out.a.b.c.d.e, "[truncated]");
});

// ── buildErrorBody with upstreamDetails ──────────────────────────────────────

test("buildErrorBody — without upstream details omits upstream_details field", async () => {
  const { buildErrorBody } = await import("../../open-sse/utils/error.ts");
  const body = buildErrorBody(400, "bad request");
  assert.ok(!("upstream_details" in body), "upstream_details must be absent when not provided");
});

test("buildErrorBody — with safe upstream details embeds upstream_details", async () => {
  const { buildErrorBody } = await import("../../open-sse/utils/error.ts");
  const body = buildErrorBody(400, "bad request", {
    error: { message: "context_length_exceeded" },
  });
  assert.ok("upstream_details" in body, "upstream_details must be present");
  assert.equal((body.upstream_details as any).error.message, "context_length_exceeded");
});

test("buildErrorBody — upstream details with stack key are stripped", async () => {
  const { buildErrorBody } = await import("../../open-sse/utils/error.ts");
  const body = buildErrorBody(500, "err", { stack: "Error\n    at foo.ts:1", code: "internal" });
  assert.ok("upstream_details" in body, "upstream_details must be present");
  assert.ok(
    !("stack" in (body.upstream_details as any)),
    "stack must be stripped from upstream_details"
  );
  assert.equal((body.upstream_details as any).code, "internal");
});

// ── createErrorResult with upstreamDetails ───────────────────────────────────

test("createErrorResult — response body includes upstream_details when provided", async () => {
  const { createErrorResult } = await import("../../open-sse/utils/error.ts");
  const result = createErrorResult(
    400,
    "context too long",
    null,
    "context_length_exceeded",
    "invalid_request_error",
    { error: { message: "context_length_exceeded" } }
  );
  const body = (await result.response.clone().json()) as any;
  assert.ok("upstream_details" in body, "upstream_details must be in response body");
  assert.equal(body.upstream_details.error.message, "context_length_exceeded");
});

test("createErrorResult — response body excludes upstream_details when not provided", async () => {
  const { createErrorResult } = await import("../../open-sse/utils/error.ts");
  const result = createErrorResult(400, "bad request", null, "bad_request");
  const body = (await result.response.clone().json()) as any;
  assert.ok(!("upstream_details" in body), "upstream_details must be absent when not provided");
});

test("createErrorResult — exposes error code/type on the result object", async () => {
  const { createErrorResult } = await import("../../open-sse/utils/error.ts");
  const result = createErrorResult(504, "upstream timeout", null, "UPSTREAM_TIMEOUT", "timeout");
  assert.equal(result.errorCode, "UPSTREAM_TIMEOUT");
  assert.equal(result.errorType, "timeout");
});

// ── createErrorResult.rawMessage (#7360) ──────────────────────────────────────
//
// `error` is sanitized to its first line (sanitizeErrorMessage) for the
// client-facing response body — correct per Hard Rule #12. But internal
// classification (checkFallbackError / Gemini TPM-vs-RPD metric detection)
// needs the FULL multi-line upstream text, since Google's metric name and
// retry hint live on lines 2-3. `rawMessage` carries the untruncated text on
// the returned object only — it must never leak into the HTTP response body.

test("createErrorResult — rawMessage preserves the full multi-line message untruncated", async () => {
  const { createErrorResult } = await import("../../open-sse/utils/error.ts");
  const fullMessage =
    "You exceeded your current quota, please check your plan and billing details.\n" +
    "* Quota exceeded for metric: generativelanguage.googleapis.com/generate_content_free_tier_input_token_count, limit: 16000, model: gemma-4-31b\n" +
    "Please retry in 8.093498133s.";
  const result = createErrorResult(429, fullMessage);

  assert.equal(result.rawMessage, fullMessage, "rawMessage must be the complete, untruncated text");
  assert.ok(
    result.error.length < fullMessage.length,
    "error (client-facing) must still be truncated to the first line"
  );
  assert.ok(
    !result.error.includes("generativelanguage.googleapis.com"),
    "sanitized error must not include the metric name (line 2)"
  );
});

test("createErrorResult — rawMessage never appears in the serialized response body", async () => {
  const { createErrorResult } = await import("../../open-sse/utils/error.ts");
  const fullMessage =
    "You exceeded your current quota, please check your plan and billing details.\n" +
    "* Quota exceeded for metric: generativelanguage.googleapis.com/generate_content_free_tier_input_token_count, limit: 16000, model: gemma-4-31b";
  const result = createErrorResult(429, fullMessage);
  const bodyText = await result.response.clone().text();

  assert.ok(
    !bodyText.includes("generativelanguage.googleapis.com"),
    "the raw multi-line metric text must never reach the HTTP response body"
  );
});

test("buildModelCooldownBody returns the public cooldown error payload shape", async () => {
  const { buildModelCooldownBody } = await import("../../open-sse/utils/error.ts");
  const body = buildModelCooldownBody({ model: "gpt-4o", retryAfterSec: 1.2 });

  assert.deepEqual(body, {
    error: {
      message: "All credentials for model gpt-4o are cooling down",
      type: "rate_limit_error",
      code: "model_cooldown",
      model: "gpt-4o",
      reset_seconds: 2,
    },
  });
});

test("regression: upstream_details never contains stack trace text", async () => {
  const { createErrorResult } = await import("../../open-sse/utils/error.ts");
  const upstream = { error: { message: "err" }, stack: "Error\n    at /abs/path.ts:1:2" };
  const result = createErrorResult(500, "upstream err", null, undefined, undefined, upstream);
  const body = (await result.response.clone().json()) as any;
  const serialized = JSON.stringify(body);
  assert.ok(
    !serialized.includes("at /abs/path.ts"),
    "stack trace path must not appear in response body"
  );
  assert.ok(!("stack" in (body.upstream_details || {})), "stack key must not be present");
});

// ── existing tests continue ──────────────────────────────────────────────────

test("GET /token-health response never leaks stack frames or absolute paths", async () => {
  const tokenHealthRoute = await import("../../src/app/api/token-health/route.ts");
  const res = await tokenHealthRoute.GET();
  const body = (await res.json()) as any;
  assert.ok(!("stack" in body), "response must not contain stack trace");
  if (typeof body.error === "string") {
    assert.ok(!body.error.includes("    at "), "stack frame must not leak in error");
    assert.ok(!/^\//.test(body.error), "absolute POSIX path must not leak");
    assert.ok(!/^[A-Za-z]:[\\/]/.test(body.error), "absolute Windows path must not leak");
  }
});
