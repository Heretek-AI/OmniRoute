import test from "node:test";
import assert from "node:assert/strict";
import {
  shouldPassthroughUpstreamError,
  buildPassthroughErrorResponse,
} from "../../open-sse/utils/upstreamErrorPassthrough.ts";

test("upstream error passthrough", async (t) => {
  await t.test("4xx com corpo JSON de erro do provider é elegível", () => {
    const body = {
      type: "error",
      error: { type: "invalid_request_error", message: "thinking.type: adaptive is not supported" },
    };
    assert.equal(shouldPassthroughUpstreamError(400, body), true);
  });
  await t.test("5xx NÃO é elegível (segue sanitizado)", () => {
    assert.equal(shouldPassthroughUpstreamError(500, { error: { message: "x" } }), false);
  });
  await t.test("corpo com cara de vazamento interno (stack trace) NÃO é elegível", () => {
    assert.equal(
      shouldPassthroughUpstreamError(400, {
        error: { message: "Error\n    at /usr/lib/node_modules/omniroute/x.js:1" },
      }),
      false
    );
  });
  await t.test(
    "401/407 NÃO são elegíveis (credencial nossa pode vazar em www-authenticate)",
    () => {
      assert.equal(shouldPassthroughUpstreamError(401, { error: { message: "bad key" } }), false);
    }
  );
  await t.test(
    "corpo que ecoa uma credencial (Bearer/api_key/sk-) NÃO é elegível (#secret-leak hardening)",
    () => {
      // Some providers echo the offending request inside a 400/422 validation
      // body. Passthrough must refuse so the key is not relayed to the client.
      assert.equal(
        shouldPassthroughUpstreamError(400, {
          error: { message: "invalid request: Authorization: Bearer sk-live-abc123def456ghi" },
        }),
        false
      );
      assert.equal(
        shouldPassthroughUpstreamError(422, {
          error: { message: "bad field", received: { api_key: "sk-abc123def456" } },
        }),
        false
      );
      assert.equal(
        shouldPassthroughUpstreamError(429, {
          error: { message: 'rejected: {"api-key":"xyzabc123secret"}' },
        }),
        false
      );
    }
  );
  await t.test(
    "corpo de capacidade/quota sem segredo continua elegível (contrato Claude Code preservado)",
    () => {
      // Safe wording/shape must survive canonical sanitization so Claude Code
      // can still match the response and auto-disable capabilities.
      assert.equal(
        shouldPassthroughUpstreamError(400, {
          error: { message: "thinking.type: adaptive is not supported" },
        }),
        true
      );
      assert.equal(
        shouldPassthroughUpstreamError(429, {
          error: { type: "rate_limit_error", message: "slow down, retry after 60s" },
        }),
        true
      );
    }
  );
  await t.test("buildPassthroughErrorResponse preserva wording e shape seguros", async () => {
    const body = {
      type: "error",
      error: { type: "invalid_request_error", message: "thinking.type: nope" },
    };
    const res = buildPassthroughErrorResponse(400, body);
    assert.ok(res);
    assert.equal(res.status, 400);
    assert.deepEqual(await res.json(), body);
  });
  await t.test(
    "buildPassthroughErrorResponse sanitiza recursivamente corpo elegível e preserva metadados",
    async () => {
      const body = {
        type: "error",
        error: {
          type: "invalid_request_error",
          message: "password=hunter2",
          details: [
            "failed opening /home/alice/private.ts:1:2",
            {
              trace: "Error\r\n    at C:\\Users\\alice\\private.ts:1:2",
              credential: "PASSTHROUGH_CREDENTIAL_SECRET",
              sessionId: "PASSTHROUGH_SESSION_SECRET",
              session_count: 2,
            },
          ],
        },
      };

      assert.equal(shouldPassthroughUpstreamError(422, body), true);
      const res = buildPassthroughErrorResponse(422, body, { "X-Test": "preserved" });
      assert.ok(res, "eligible safe-shape body remains passthrough-capable");
      assert.equal(res.status, 422);
      assert.equal(res.headers.get("X-Test"), "preserved");
      const sanitized = await res.json();
      const serialized = JSON.stringify(sanitized);
      assert.equal(sanitized.type, "error");
      assert.equal(sanitized.error.type, "invalid_request_error");
      assert.ok(!serialized.includes("hunter2"));
      assert.ok(!serialized.includes("/home/alice"));
      assert.ok(!serialized.includes("C:\\Users\\alice"));
      assert.ok(!serialized.includes("    at "));
      assert.ok(!serialized.includes("PASSTHROUGH_CREDENTIAL_SECRET"));
      assert.ok(!serialized.includes("PASSTHROUGH_SESSION_SECRET"));
      assert.ok(serialized.includes('"session_count":2'));
    }
  );
  await t.test("retorna null quando inelegível", () => {
    assert.equal(buildPassthroughErrorResponse(500, {}), null);
  });
  await t.test("corpos não serializáveis falham fechados sem lançar", () => {
    const cyclic: Record<string, unknown> = { error: { message: "safe" } };
    cyclic.self = cyclic;
    const throwing = {
      toJSON(): never {
        throw new Error("hostile toJSON");
      },
    };

    for (const body of [cyclic, { value: 1n }, throwing]) {
      assert.equal(shouldPassthroughUpstreamError(400, body), false);
      assert.equal(buildPassthroughErrorResponse(400, body), null);
    }
  });
});

test("createErrorResult opt-in passthrough (opts.passthrough)", async (t) => {
  await t.test(
    "com opts.passthrough, wording e shape seguros sobrevivem à sanitização",
    async () => {
      const { createErrorResult } = await import("../../open-sse/utils/error.ts");
      const upstreamBody = {
        type: "error",
        error: {
          type: "invalid_request_error",
          message: "thinking.type: adaptive is not supported",
        },
      };
      const result = createErrorResult(400, "msg", null, "code", "type", upstreamBody, {
        passthrough: true,
      });
      assert.deepEqual(await result.response.json(), upstreamBody);
      assert.equal(result.status, 400);
      // Internal classification fields must never be affected by passthrough.
      assert.equal(typeof result.error, "string");
      assert.notEqual(result.error, JSON.stringify(upstreamBody));
    }
  );

  await t.test("sem opts, comportamento atual (corpo sanitizado) é preservado", async () => {
    const { createErrorResult } = await import("../../open-sse/utils/error.ts");
    const upstreamBody = {
      type: "error",
      error: { type: "invalid_request_error", message: "thinking.type: adaptive is not supported" },
    };
    const result = createErrorResult(400, "msg", null, "code", "type", upstreamBody);
    const body = (await result.response.json()) as { error?: { message?: string } };
    assert.ok(body.error?.message, "sanitized body keeps the wrapped error.message shape");
    assert.ok(
      !JSON.stringify(body).includes("    at /"),
      "sanitized body never leaks stack-trace-like text"
    );
  });

  await t.test("com retryAfterMs e passthrough elegível, header Retry-After é setado", async () => {
    const { createErrorResult } = await import("../../open-sse/utils/error.ts");
    const upstreamBody = {
      type: "error",
      error: { type: "rate_limit_error", message: "slow down" },
    };
    const result = createErrorResult(429, "msg", 5000, "code", "type", upstreamBody, {
      passthrough: true,
    });
    assert.equal(result.response.headers.get("Retry-After"), "5");
    assert.deepEqual(await result.response.json(), upstreamBody);
  });

  await t.test(
    "opts.passthrough true mas corpo inelegível (401) cai no corpo sanitizado atual",
    async () => {
      const { createErrorResult } = await import("../../open-sse/utils/error.ts");
      const upstreamBody = { error: { message: "bad key" } };
      const result = createErrorResult(401, "unauthorized", null, "code", "type", upstreamBody, {
        passthrough: true,
      });
      const body = (await result.response.json()) as { error?: { message?: string } };
      assert.notDeepEqual(body, upstreamBody);
      assert.ok(body.error?.message, "sanitized body keeps the wrapped error.message shape");
    }
  );
});
