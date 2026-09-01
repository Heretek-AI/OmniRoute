import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const TEST_DATA_DIR = fs.mkdtempSync(
  path.join(os.tmpdir(), "omniroute-provider-validation-errors-")
);
const ORIGINAL_DATA_DIR = process.env.DATA_DIR;

process.env.DATA_DIR = TEST_DATA_DIR;

const { isSecurityBlockError, readProxyFallbackErrorState, toValidationErrorResult } =
  await import("../../src/lib/providers/validation/transport.ts");
const { SafeOutboundFetchError } = await import("../../src/shared/network/safeOutboundFetch.ts");

test.after(() => {
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  if (ORIGINAL_DATA_DIR === undefined) delete process.env.DATA_DIR;
  else process.env.DATA_DIR = ORIGINAL_DATA_DIR;
});

test("provider validation sanitizes generic thrown error details", () => {
  const result = toValidationErrorResult(
    new Error(
      "Provider probe failed at /srv/private/provider-key.json access_token=provider-secret\n" +
        "    at validate (/srv/private/validator.ts:42:7)"
    )
  );

  assert.equal(result.valid, false);
  assert.match(result.error, /Provider probe failed/i);
  assert.doesNotMatch(result.error, /srv\/private|provider-secret|validator\.ts/);
  assert.doesNotMatch(result.error, /[\r\n]|\bat validate\b/i);
  assert.equal(result.unsupported, false);
});

test("provider validation sanitizes non-Error string failures", () => {
  const result = toValidationErrorResult(
    "String probe failed at /srv/private/string-secret.pem access_token=string-secret\n" +
      "    at stringProbe (/srv/private/probe.ts:1:1)"
  );

  assert.equal(result.valid, false);
  assert.match(result.error, /String probe failed/i);
  assert.doesNotMatch(result.error, /srv\/private|string-secret|probe\.ts/);
  assert.doesNotMatch(result.error, /[\r\n]|\bat stringProbe\b/i);
  assert.equal(result.unsupported, false);
});

test("provider validation fails closed when a thrown value rejects string coercion", () => {
  const hostile = {
    toString() {
      throw new Error("access_token=hostile-secret at /srv/private/hostile.ts:1:2");
    },
  };

  const result = toValidationErrorResult(hostile);

  assert.deepEqual(result, {
    valid: false,
    error: "Validation failed",
    unsupported: false,
  });
});

test("provider validation fails closed when prototype inspection throws", () => {
  const hostile = new Proxy(
    {},
    {
      getPrototypeOf() {
        throw new Error("access_token=proxy-secret at /srv/private/proxy.ts:1:2");
      },
      get(_target, property) {
        if (property === "code" || property === "isRetryable") {
          throw new Error("access_token=metadata-secret at /srv/private/metadata.ts:1:2");
        }
        if (property === "toString") {
          return () => {
            throw new Error("access_token=coercion-secret at /srv/private/coercion.ts:1:2");
          };
        }
        return undefined;
      },
    }
  );

  assert.deepEqual(toValidationErrorResult(hostile), {
    valid: false,
    error: "Validation failed",
    unsupported: false,
  });
  assert.equal(isSecurityBlockError(hostile), false);
  assert.deepEqual(readProxyFallbackErrorState(hostile), {
    isNetworkIssue: false,
    isRetryable: false,
  });
});

test("provider validation preserves safe generic messages", () => {
  const result = toValidationErrorResult(new Error("Provider temporarily unavailable"));

  assert.equal(result.error, "Provider temporarily unavailable");
  assert.equal(result.statusCode, undefined);
  assert.equal(result.timeout, undefined);
  assert.equal(result.securityBlocked, undefined);
});

test("provider validation preserves timeout and security classifications", () => {
  const timeout = toValidationErrorResult(
    new SafeOutboundFetchError(
      "Timed out at /srv/private/provider.json access_token=timeout-secret",
      {
        code: "TIMEOUT",
        url: "https://api.example.com/models",
        method: "GET",
        attempts: 1,
        isRetryable: true,
        timeoutMs: 1000,
      }
    )
  );
  const securityBlock = toValidationErrorResult(
    new SafeOutboundFetchError("Blocked private host", {
      code: "URL_GUARD_BLOCKED",
      url: "http://169.254.169.254/latest/meta-data/",
      method: "GET",
      attempts: 1,
      isRetryable: false,
    })
  );

  assert.equal(timeout.statusCode, 504);
  assert.equal(timeout.timeout, true);
  assert.equal(timeout.securityBlocked, undefined);
  assert.doesNotMatch(timeout.error, /srv\/private|timeout-secret/);

  assert.equal(securityBlock.statusCode, 503);
  assert.equal(securityBlock.timeout, undefined);
  assert.equal(securityBlock.securityBlocked, true);
  assert.equal(securityBlock.error, "Blocked private host");
});

test("provider validation route sanitizes unexpected failures before logging", () => {
  const routeSource = fs.readFileSync(
    new URL("../../src/app/api/providers/validate/route.ts", import.meta.url),
    "utf8"
  );

  assert.match(
    routeSource,
    /console\.log\(\s*"Error validating API key:",\s*sanitizeErrorMessage\(error\) \|\| "Validation failed"\s*\)/
  );
  assert.doesNotMatch(routeSource, /console\.log\(\s*"Error validating API key:",\s*error\s*\)/);
});
