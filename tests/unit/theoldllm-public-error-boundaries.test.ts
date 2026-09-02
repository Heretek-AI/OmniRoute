import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-theoldllm-errors-"));
const originalDataDir = process.env.DATA_DIR;
const originalPluginsDir = process.env.OMNIROUTE_PLUGINS_DIR;
process.env.DATA_DIR = path.join(testRoot, "data");
process.env.OMNIROUTE_PLUGINS_DIR = path.join(testRoot, "plugins");
fs.mkdirSync(process.env.DATA_DIR, { recursive: true });
fs.mkdirSync(process.env.OMNIROUTE_PLUGINS_DIR, { recursive: true });

const core = await import("../../src/lib/db/core.ts");

test.after(() => {
  core.resetDbInstance();
  if (originalDataDir === undefined) delete process.env.DATA_DIR;
  else process.env.DATA_DIR = originalDataDir;
  if (originalPluginsDir === undefined) delete process.env.OMNIROUTE_PLUGINS_DIR;
  else process.env.OMNIROUTE_PLUGINS_DIR = originalPluginsDir;
  fs.rmSync(testRoot, { recursive: true, force: true });
});

async function executeWithFetch(fetchImpl: typeof fetch, logged: string[]): Promise<Response> {
  const { TheOldLlmExecutor } = await import("../../open-sse/executors/theoldllm.ts");
  const executor = new TheOldLlmExecutor({
    resolveProxy: async () => null,
    runWithProxy: async <T>(_proxy: null, request: () => Promise<T>) => request(),
    fetch: fetchImpl,
  });
  const result = await executor.execute({
    model: "gpt-5.4",
    body: { messages: [{ role: "user", content: "hi" }] },
    stream: false,
    credentials: {} as never,
    signal: null,
    log: {
      error: (_scope: string, message: string) => logged.push(message),
    } as never,
  });
  return result.response;
}

test("theoldllm does not echo hostile non-2xx upstream errors", async () => {
  const secretPath = "/srv/omniroute/private/provider-config.ts:91:4";
  const secretToken = "sk-theoldllm-secret-token-123456789";
  const response = await executeWithFetch(
    (async () =>
      new Response(
        JSON.stringify({
          error: {
            message: `upstream failed at ${secretPath}`,
            api_key: secretToken,
          },
        }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      )) as typeof fetch,
    []
  );

  const body = await response.text();
  assert.equal(response.status, 500);
  assert.doesNotMatch(body, /provider-config\.ts/);
  assert.doesNotMatch(body, /sk-theoldllm-secret-token/);
  assert.doesNotMatch(body, /api_key/);
});

test("theoldllm sanitizes thrown failures in both the response and process log", async () => {
  const logged: string[] = [];
  const response = await executeWithFetch(
    (async () => {
      throw new Error(
        "socket failed at /srv/omniroute/private/runtime.ts:17:2 token=sk-log-secret-123456789"
      );
    }) as typeof fetch,
    logged
  );

  const body = await response.text();
  assert.equal(response.status, 502);
  assert.doesNotMatch(body, /runtime\.ts/);
  assert.doesNotMatch(body, /sk-log-secret/);
  assert.doesNotMatch(logged.join("\n"), /runtime\.ts/);
  assert.doesNotMatch(logged.join("\n"), /sk-log-secret/);
});
