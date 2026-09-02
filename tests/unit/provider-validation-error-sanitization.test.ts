import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const TEST_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-provider-validation-errors-"));
const TEST_DATA_DIR = path.join(TEST_ROOT, "data");
const TEST_PLUGINS_DIR = path.join(TEST_ROOT, "plugins");
const ORIGINAL_DATA_DIR = process.env.DATA_DIR;
const ORIGINAL_PLUGINS_DIR = process.env.OMNIROUTE_PLUGINS_DIR;

fs.mkdirSync(TEST_DATA_DIR, { recursive: true });
fs.mkdirSync(TEST_PLUGINS_DIR, { recursive: true });
process.env.DATA_DIR = TEST_DATA_DIR;
process.env.OMNIROUTE_PLUGINS_DIR = TEST_PLUGINS_DIR;

const core = await import("../../src/lib/db/core.ts");
const { projectProviderValidationResultForPublicResponse, toValidationErrorResult } =
  await import("../../src/lib/providers/validation/transport.ts");

test.after(() => {
  core.resetDbInstance();
  if (ORIGINAL_DATA_DIR === undefined) delete process.env.DATA_DIR;
  else process.env.DATA_DIR = ORIGINAL_DATA_DIR;
  if (ORIGINAL_PLUGINS_DIR === undefined) delete process.env.OMNIROUTE_PLUGINS_DIR;
  else process.env.OMNIROUTE_PLUGINS_DIR = ORIGINAL_PLUGINS_DIR;
  fs.rmSync(TEST_ROOT, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

test("provider validation sanitizes thrown error details", () => {
  const result = toValidationErrorResult(
    new Error(
      "Provider probe failed at /srv/private/provider-key.json " +
        "access_token=provider-secret\n    at validate (/srv/private/validator.ts:42:7)"
    )
  );

  assert.equal(result.valid, false);
  assert.match(result.error, /Provider probe failed/i);
  assert.doesNotMatch(result.error, /srv\/private|provider-secret|validator\.ts|\bat validate\b/i);
  assert.equal(result.unsupported, false);
});

test("provider validation fails closed for hostile thrown values", () => {
  const hostile = new Proxy(
    {},
    {
      getPrototypeOf(): never {
        throw new Error("access_token=prototype-secret at /srv/private/prototype.ts:1:2");
      },
      get(_target, property): unknown {
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
});

test("provider validation route sanitizes unexpected failures before persistent logging", () => {
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

test("provider validation final response projection sanitizes validator errors and warnings", () => {
  const projected = projectProviderValidationResultForPublicResponse({
    valid: false,
    error:
      "Provider echoed access_token=response-secret at /srv/private/provider.json\n" +
      "    at validate (/srv/private/validator.ts:42:7)",
    warning: "Retry after reading C:\\Users\\admin\\private\\warning.json",
    method: "probe",
  });
  const serialized = JSON.stringify(projected);

  assert.equal(projected.valid, false);
  assert.equal(projected.method, "probe");
  assert.doesNotMatch(
    serialized,
    /response-secret|srv\/private|validator\.ts|C:\\Users|warning\.json/i
  );
});

test("provider validation projection preserves intentionally empty fields without synthetic text", () => {
  const projected = projectProviderValidationResultForPublicResponse({
    valid: false,
    error: "",
    warning: "",
  });

  assert.equal(projected.error, "");
  assert.equal(projected.warning, "");
});

test("provider validation route applies the final response projection", () => {
  const routeSource = fs.readFileSync(
    new URL("../../src/app/api/providers/validate/route.ts", import.meta.url),
    "utf8"
  );

  assert.match(routeSource, /projectProviderValidationResultForPublicResponse\(/);
});
