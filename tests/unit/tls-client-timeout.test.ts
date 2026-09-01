import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";

import { raceWithTimeout, TlsClientHangError } from "../../open-sse/services/tlsClientTimeout.ts";

const TIMEOUT_MODULE_URL = pathToFileURL(
  resolve(process.cwd(), "open-sse/services/tlsClientTimeout.ts")
).href;

function runExitProbe(body: string) {
  return spawnSync(
    process.execPath,
    [
      "--import",
      "tsx/esm",
      "--input-type=module",
      "--eval",
      `const { raceWithTimeout } = await import(${JSON.stringify(TIMEOUT_MODULE_URL)}); ${body}`,
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      timeout: 10_000,
    }
  );
}

test("raceWithTimeout clears its timer after a no-signal promise settles", () => {
  const result = runExitProbe(
    'await raceWithTimeout(Promise.resolve("ok"), 30_000, null); console.log("settled");'
  );

  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /settled/);
});

test("raceWithTimeout clears its timer when passed an already-aborted signal", () => {
  const result = runExitProbe(
    [
      "const controller = new AbortController();",
      'controller.abort(new Error("stop"));',
      "await raceWithTimeout(new Promise(() => {}), 30_000, controller.signal).catch(() => {});",
      'console.log("aborted");',
    ].join(" ")
  );

  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /aborted/);
});

test("raceWithTimeout returns a safe actionable timeout error", async () => {
  await assert.rejects(raceWithTimeout(new Promise<never>(() => {}), 1, null), (error: unknown) => {
    assert.ok(error instanceof TlsClientHangError);
    assert.match(error.message, /timed out/i);
    return true;
  });
});

test("raceWithTimeout rejects safely when abort reason prototype inspection throws", async () => {
  const controller = new AbortController();
  const hostileReason = new Proxy(new Error("access_token=abort-secret at /srv/abort.ts"), {
    getPrototypeOf() {
      throw new Error("abort-prototype-secret");
    },
  });
  const raced = raceWithTimeout(new Promise<never>(() => {}), 30_000, controller.signal);
  controller.abort(hostileReason);
  await assert.rejects(
    Promise.race([
      raced,
      new Promise<never>((_resolve, reject) =>
        setTimeout(() => reject(new Error("abort did not settle")), 250)
      ),
    ]),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.equal(error.name, "AbortError");
      assert.equal(error.message, "The operation was aborted");
      assert.doesNotMatch(error.stack ?? "", /abort-(?:secret|prototype)|srv\/abort/);
      return true;
    }
  );
});
