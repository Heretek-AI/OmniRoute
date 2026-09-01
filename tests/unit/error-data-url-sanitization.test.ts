import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import test from "node:test";

import { redactSensitiveErrorText } from "../../open-sse/utils/errorSanitization.ts";

test("redacts base64 data URLs without changing their surrounding text", () => {
  const input =
    "before DATA:image/svg+xml;charset=utf-8;BaSe64,PHN2Zz48L3N2Zz4= after " +
    "data:text/plain;base64,SGVsbG8! and data:;base64,U0VDUkVU.";

  assert.equal(
    redactSensitiveErrorText(input),
    "before [REDACTED_DATA_URL] after [REDACTED_DATA_URL]! and [REDACTED_DATA_URL]."
  );
});

test(
  "bounds work for adversarial repeated data prefixes while preserving an incomplete URL",
  { timeout: 20_000 },
  () => {
    const input = `${"data:".repeat(30_000)}image/png;base64`;
    const startedAt = performance.now();

    const output = redactSensitiveErrorText(input);
    const elapsedMs = performance.now() - startedAt;

    assert.equal(output, input, "an incomplete data URL must remain unchanged");
    assert.ok(
      elapsedMs < 6_000,
      `repeated data prefixes must be processed in bounded time (took ${elapsedMs.toFixed(1)}ms)`
    );
  }
);
