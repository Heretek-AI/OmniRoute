/**
 * QA P0 — sanitized auto-combo diagnostic trace.
 * Guards the new `errorResponseWithComboDiagnostics` / `sanitizeComboDiagnostics`
 * helpers: they must surface pool size + attempt order + exclusion reasons as
 * both `x-omniroute-combo-*` headers and a `diagnostics` body field, while the
 * sanitizer is the secret-containment boundary (only provider/model/reason ids +
 * counts may ever escape — never keys/tokens/credentials).
 */
import test from "node:test";
import assert from "node:assert/strict";

const { errorResponseWithComboDiagnostics, sanitizeComboDiagnostics } =
  await import("../../open-sse/utils/error.ts");

test("combo diagnostics: headers + body carry the sanitized trace (code override preserved)", async () => {
  const res = errorResponseWithComboDiagnostics(
    503,
    "all upstream accounts inactive",
    {
      poolSize: 3,
      attempted: 2,
      excluded: [{ provider: "openai", model: "gpt-x", reason: "exhausted" }],
      attemptOrder: [{ provider: "openai", model: "gpt-x" }],
      terminalReason: "all_accounts_inactive",
    },
    { code: "ALL_ACCOUNTS_INACTIVE", type: "service_unavailable" }
  );

  assert.equal(res.status, 503);
  assert.equal(res.headers.get("x-omniroute-combo-pool-size"), "3");
  assert.equal(res.headers.get("x-omniroute-combo-attempted"), "2");
  assert.match(res.headers.get("x-omniroute-combo-excluded") || "", /openai\/gpt-x:exhausted/);
  assert.equal(res.headers.get("x-omniroute-combo-terminal-reason"), "all_accounts_inactive");

  const body = await res.json();
  assert.equal(body.error.code, "ALL_ACCOUNTS_INACTIVE");
  assert.equal(body.error.type, "service_unavailable");
  assert.ok(body.diagnostics, "diagnostics field present in body");
  assert.equal(body.diagnostics.poolSize, 3);
  assert.equal(body.diagnostics.attempted, 2);
  assert.equal(body.diagnostics.terminalReason, "all_accounts_inactive");
  assert.equal(body.diagnostics.attemptOrder[0].provider, "openai");
});

test("combo diagnostics: sanitizer caps sizes + keeps only the whitelist keys", () => {
  const dirty = {
    poolSize: 1,
    attempted: 1,
    excluded: Array.from({ length: 200 }, (_, i) => ({
      provider: "p" + i,
      reason: "r".repeat(500),
    })),
    attemptOrder: Array.from({ length: 200 }, () => ({ provider: "p", model: "m" })),
    terminalReason: "x".repeat(1000),
  };
  const safe = sanitizeComboDiagnostics(dirty as never);
  assert.ok(safe.excluded.length <= 64, "excluded capped at 64");
  assert.ok(safe.attemptOrder.length <= 64, "attemptOrder capped at 64");
  assert.ok(safe.excluded[0].reason.length <= 64, "reason length clamped");
  assert.ok(safe.terminalReason.length <= 200, "terminalReason length clamped");
  assert.deepEqual(Object.keys(safe.excluded[0]).sort(), ["provider", "reason"]);
});

test("combo diagnostics: secret containment — non-whitelisted fields never survive", () => {
  const leaky = {
    poolSize: 1,
    attempted: 1,
    excluded: [
      { provider: "openai", reason: "exhausted", apiKey: "sk-SECRET-KEY", token: "SECRET-TOK" },
    ],
    attemptOrder: [{ provider: "openai", model: "m", accessToken: "SECRET-OAUTH" }],
    terminalReason: "t",
  };
  const safe = sanitizeComboDiagnostics(leaky as never);
  const serialized = JSON.stringify(safe);
  assert.ok(!serialized.includes("SECRET"), "no secret VALUES survive the projection");
  assert.ok(!serialized.includes("apiKey"), "no apiKey KEY survives");
  assert.ok(!serialized.includes("accessToken"), "no accessToken KEY survives");
  assert.ok(!serialized.includes("token"), "no token KEY survives");
});

test("combo diagnostics: canonical sanitizer protects every public string and header", async () => {
  const res = errorResponseWithComboDiagnostics(502, "combo failed", {
    poolSize: 2,
    attempted: 1,
    excluded: [
      {
        provider: "provider access_token=DIAG_SECRET /home/alice/provider.ts",
        model: "C:\\Users\\alice\\private-model.ts:1:2",
        reason: "reason password=REASON_SECRET",
      },
    ],
    attemptOrder: [
      {
        provider: "provider secret=ORDER_SECRET",
        model: "model\n    at /home/alice/model.ts:1:2",
      },
    ],
    terminalReason: "terminal secret=TERM_SECRET /home/alice/terminal.ts",
    recovery: {
      action: "retry",
      next_step: "next password=NEXT_SECRET /home/alice/next.ts",
    },
  });
  const body = await res.json();
  const publicText = [
    JSON.stringify(body),
    res.headers.get("x-omniroute-combo-excluded") || "",
    res.headers.get("x-omniroute-combo-terminal-reason") || "",
    res.headers.get("x-omniroute-recovery-next-step") || "",
  ].join("\n");

  for (const leak of [
    "DIAG_SECRET",
    "REASON_SECRET",
    "ORDER_SECRET",
    "TERM_SECRET",
    "NEXT_SECRET",
    "/home/alice",
    "C:\\Users\\alice",
  ]) {
    assert.ok(!publicText.includes(leak), leak);
  }
});

test("combo diagnostics: terminalReason with a non-Latin1 char (em dash) must not crash Response construction (#6612)", () => {
  const terminalReason = "reasoning consumed 5/5 tokens — no content output";
  assert.doesNotThrow(() => {
    const res = errorResponseWithComboDiagnostics(
      502,
      `Upstream response failed quality validation: ${terminalReason}`,
      {
        poolSize: 4,
        attempted: 1,
        excluded: [
          { provider: "deepseek", model: "deepseek-v4-flash-free", reason: "quality — bad" },
        ],
        attemptOrder: [{ provider: "deepseek", model: "deepseek-v4-flash-free" }],
        terminalReason,
      }
    );
    assert.equal(res.status, 502);
  });
});

test("combo diagnostics: JSON body keeps the original non-Latin1 text even though headers are ASCII-sanitized (#6612)", async () => {
  const terminalReason = "reasoning consumed 5/5 tokens — no content output";
  const res = errorResponseWithComboDiagnostics(
    502,
    `Upstream response failed quality validation: ${terminalReason}`,
    {
      poolSize: 1,
      attempted: 1,
      excluded: [],
      attemptOrder: [{ provider: "deepseek", model: "deepseek-v4-flash-free" }],
      terminalReason,
    }
  );
  // Header value must be a valid Latin1 ByteString — em dash (U+2014) replaced.
  assert.equal(
    res.headers.get("x-omniroute-combo-terminal-reason"),
    terminalReason.replace("—", "?")
  );
  const body = await res.json();
  // JSON body keeps the original, safe em dash after canonical sanitization.
  assert.equal(body.diagnostics.terminalReason, terminalReason);
});

test("combo diagnostics: every C0/DEL byte is printable in headers without corrupting JSON", async () => {
  for (const code of [0x00, 0x01, 0x08, 0x09, 0x0b, 0x0c, 0x1f, 0x7f]) {
    const control = String.fromCharCode(code);
    const diagnostic = `safe${control}tail`;
    const res = errorResponseWithComboDiagnostics(503, "combo failed", {
      poolSize: 1,
      attempted: 0,
      excluded: [{ provider: diagnostic, reason: diagnostic }],
      attemptOrder: [{ provider: diagnostic, model: diagnostic }],
      terminalReason: diagnostic,
      recovery: { action: "retry", next_step: diagnostic },
    });

    assert.equal(res.status, 503, `control 0x${code.toString(16)}`);
    for (const header of [
      "x-omniroute-combo-excluded",
      "x-omniroute-combo-terminal-reason",
      "x-omniroute-recovery-next-step",
    ]) {
      assert.doesNotMatch(res.headers.get(header) || "", /[\x00-\x1f\x7f]/);
    }
    const body = await res.json();
    assert.equal(body.diagnostics.terminalReason, diagnostic);
    assert.equal(body.recovery_hint.next_step, diagnostic);
  }
});
