---
title: "Error Message Sanitization"
version: 3.8.50
lastUpdated: 2026-09-01
---

# Error Message Sanitization

> **Source of truth:** `open-sse/utils/errorSanitization.ts`, which composes `errorPathRedaction.ts` and is re-exported by `open-sse/utils/error.ts`
> **Tests:** `tests/unit/error-message-sanitization.test.ts` and `error-message-sanitization-credentials.test.ts`
> **Last updated:** 2026-09-01 — v3.8.50
> **Audience:** Any engineer touching error responses or error log sinks (HTTP routes, SSE streams, executors, MCP handlers).
> **Status:** **MANDATORY** for every client-visible error and every untrusted or upstream-derived error value sent to a log sink.

## Why this exists

CodeQL rule `js/stack-trace-exposure` (CWE-209) flags any code path where an error message originating from a runtime exception reaches an HTTP / SSE response without being sanitized. Stack traces and absolute file paths in production responses give attackers:

- Internal directory layout (`/srv/app/src/lib/...`) → reconnaissance for further attacks.
- Library / framework versions inferred from stack frames → targeted exploit selection.
- Sensitive runtime values that may be string-interpolated into errors (DB queries, config values).

The `sanitizeErrorMessage` helper implemented in `open-sse/utils/errorSanitization.ts` and
re-exported by `open-sse/utils/error.ts` strips both classes of leakage:

1. Multi-line stack traces — only the first line (the actual error message) is kept.
2. Absolute paths (`/...*.{ts,js,tsx,jsx,mjs,cjs}[:line[:col]]` and `C:\...`) — replaced with `<path>`.

## The mandatory pattern

### 1. Building an error response (HTTP / API routes)

Use `buildErrorBody()` — sanitization is built-in:

```ts
import { buildErrorBody, sanitizeErrorMessage } from "@omniroute/open-sse/utils/error.ts";

export async function POST(req: Request) {
  try {
    // ... handler logic ...
  } catch (err) {
    const safeMessage = sanitizeErrorMessage(err) || "Internal server error";
    return new Response(JSON.stringify(buildErrorBody(500, safeMessage)), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}
```

Or, for the convenience wrappers in the same module:

```ts
import {
  errorResponse, // one-shot Response object
  writeStreamError, // SSE writer
  createErrorResult, // { success: false, status, response, ... } shape
  unavailableResponse, // adds Retry-After
  providerCircuitOpenResponse,
  modelCooldownResponse,
} from "@omniroute/open-sse/utils/error.ts";
```

All of these enforce the canonical sanitization/projection boundary. Helpers backed by
`buildErrorBody` sanitize automatically; helpers with protocol-specific envelopes apply equivalent
safe projections. Pass an already typed string directly. At a `catch (err)` boundary where the
value is `unknown`, normalize it with `sanitizeErrorMessage(err)` as in the example above; never
pre-coerce an unknown value with `String(err)` because a hostile coercion hook can throw.

### 2. Custom error envelopes (rare)

When you can't use the helpers above (e.g. the response shape is dictated by an upstream protocol like Connect-RPC), import `sanitizeErrorMessage` directly:

```ts
import { sanitizeErrorMessage } from "@omniroute/open-sse/utils/error.ts";

const body = JSON.stringify({
  error: {
    message: sanitizeErrorMessage(rawMessage),
    type: "invalid_request_error",
    code: "",
  },
});
```

This is the only sanctioned way to assemble a custom error body. See `open-sse/executors/cursor.ts::buildErrorResponse` for the reference implementation.

When a provider error must retain its upstream JSON shape, use
`buildSanitizedUpstreamErrorResponse()` from `open-sse/utils/upstreamErrorResponse.ts`. It parses
and recursively sanitizes valid JSON; mislabeled text or HTML becomes OmniRoute's canonical JSON
error envelope, so the response bytes always match `Content-Type: application/json`.

### 3. Logging vs. responding

Responses and logs are separate boundaries, but neither may receive untrusted upstream material
verbatim:

- **Responses:** every dynamic message or detail goes through `buildErrorBody`, one of its wrappers,
  or `sanitizeErrorMessage`. A response never receives a raw exception message, stack, or upstream
  body.
- **Logs:** trusted local fields such as a provider identifier, numeric HTTP status, enumerated
  classification, request ID, or validated domain identifier may be logged directly. Any error
  message, error detail, or classification text derived from an upstream response, external
  exception, request, plugin, or other untrusted source must go through `sanitizeErrorMessage`
  (with a safe fallback) before reaching `pino`, `console`, or another sink. Request transcripts
  and other non-error observability fields follow their own data-minimization policy; this error
  sanitizer is not a universal transcript encoder. Do not pass a raw upstream `Error` object to the
  logger: serializers may include its message and stack.
- **Classification:** code may inspect raw material in memory to classify the failure. Log only the
  trusted classification and sanitized projection; do not attach the raw input as structured
  context.

A locally generated `Error` may retain its stack in access-controlled internal observability when
the application proves that neither its message nor stack contains upstream or otherwise untrusted
data. This policy does not claim that every locally generated internal stack is removed.

Pattern for an upstream-derived failure:

```ts
const upstreamStatus = response.status;
const rawUpstreamText = await response.text();
const classification = upstreamStatus === 429 ? "rate_limited" : "upstream_error";
const safeDetail =
  sanitizeErrorMessage(rawUpstreamText.trim()) || `Provider returned HTTP ${upstreamStatus}`;

log.warn(
  { providerId, status: upstreamStatus, classification, detail: safeDetail },
  "upstream request failed"
);
return errorResponse(upstreamStatus, safeDetail);
```

### 4. Forbidden patterns

❌ **Never** put raw exception output in a Response body:

```ts
// BAD: stack trace + file paths reach the client
return new Response(JSON.stringify({ error: { message: err.stack || err.message } }), {
  status: 500,
});
```

❌ **Never** roll your own first-line splitter:

```ts
// BAD: forgets to strip absolute paths, may drift from the canonical helper
const safe = String(err).split("\n")[0];
```

❌ **Never** sanitize in the route and forget the SSE path. Anything that writes to a stream goes through `writeStreamError` (or its underlying `buildErrorBody`).

❌ **Never** include `process.cwd()`, `__filename`, `__dirname`, or env-derived paths in error
messages. Path detection is deliberately bounded defense in depth; callers must not rely on the
redactor to make an avoidable disclosure safe.

## Coverage in CI

`tests/unit/error-message-sanitization.test.ts` and
`tests/unit/error-message-sanitization-credentials.test.ts` enforce:

- Every route under `/api/model-combo-mappings/*` returns sanitized bodies on 4xx/5xx.
- `sanitizeErrorMessage` strips multi-line stack traces.
- `sanitizeErrorMessage` replaces POSIX and Windows absolute paths with `<path>`.
- `sanitizeErrorMessage` handles `null`/`undefined`/`Error` instance inputs safely.
- `buildErrorBody` never exposes stack traces in its `message` field.

When adding a new route or executor, copy the assertion pattern from this file. The coverage gate (`npm run test:coverage`) enforces ≥60% statements/lines/functions/branches — error paths must be covered.

## Related controls

- `js/stack-trace-exposure` CodeQL alerts in `.github/security` should always be **either** fixed via these helpers **or** dismissed with a comment citing this doc.
- The `pino` redaction config (`src/shared/utils/logRedaction.ts`) is defense in depth for known
  structured fields. It does not make arbitrary upstream strings or raw `Error` objects safe to
  log, and it does not replace the untrusted-to-log boundary documented above.
- Upstream-header denylist (`src/shared/constants/upstreamHeaders.ts`) covers header leakage — keep both files aligned when adding a new exfiltration concern.

## Upstream details passthrough

`buildErrorBody` accepts an optional third argument `upstreamDetails` (raw
parsed body from the upstream provider). When provided, it is sanitized by
`sanitizeUpstreamDetails` before inclusion in the response as `upstream_details`.

An optional fourth argument `classification` (`{ type?: string; code?: string }`) accepts a
caller's explicit error type/code and projects it onto the public identifier policy. Runtime guards
also reject non-string values received from untyped JavaScript or upstream parsing. Unsafe,
non-string, or empty values fall back to the status-code table rather than being reflected
verbatim — for example, HTTP 499 falls back to `client_disconnected` unless the supplied identifier
is safe.

Sanitization rules applied to `upstreamDetails`:

1. String leaves: run through `sanitizeErrorMessage` (strips stacks, absolute paths, labeled or
   strongly identifiable credentials, and JWT-shaped secrets).
2. Key blocklist: stack/path/file/directory fields, credential/key material, authorization/cookie
   fields, and opaque credential or session identifiers are removed. Explicit aggregate fields
   such as `session_count` and `session_status` remain eligible after normal sanitization.
3. Depth cap: nesting beyond 4 levels is replaced with the string `"[truncated]"`.
4. Arrays are capped at 32 elements.

Only the seven upstream-error `createErrorResult` call sites in `chatCore.ts` pass
`upstreamErrorBody`. Internal OmniRoute errors (SSE parse failures, empty content,
guardrail blocks) do not include `upstream_details`.

Those call sites may also opt into `createErrorResult(..., { passthrough: true })`. Passthrough is
limited to eligible upstream 4xx object bodies and excludes authentication-adjacent 401, 403, and
407 responses. The selected body keeps its upstream JSON shape only after recursive sanitization;
otherwise the normal OmniRoute envelope remains in place. The option replaces only the public
`Response`: internal classification fields and retry logic continue using their original values.
The tests prove this response-shape contract with synthetic payloads; they do not by themselves
prove a client's end-to-end recovery behavior.

Do NOT pass raw `err.stack`, `err.message`, or any string from a runtime exception to
`upstreamDetails`. Those must still go through `errorResponse` / `buildErrorBody(code, msg)`
without an upstream body.

## Known CodeQL limitation: custom sanitizers not recognized

The CodeQL query [`js/stack-trace-exposure`](https://codeql.github.com/codeql-query-help/javascript/js-stack-trace-exposure/) uses a fixed allowlist of sanitizer patterns (e.g. inline `.split("\n")[0]`, `String#replace` with specific regex shapes, access to `.message` on `Error`). It does **not** recognize indirection through a custom helper like our `sanitizeErrorMessage()`.

This means callsites that demonstrably sanitize via this module — for example `open-sse/utils/error.ts::errorResponse` and `open-sse/executors/cursor.ts::buildErrorResponse` — may continue to raise the alert even though the code is functionally safe. Precedent dismissals: `#224`, `#231` (May 2026), both marked `false positive` with technical justification.

**How to handle a new occurrence:**

1. Confirm the callsite actually routes the message through `sanitizeErrorMessage` / `buildErrorBody` / one of the wrappers documented above (read the call chain end-to-end — don't trust a comment).
2. Confirm `tests/unit/error-message-sanitization.test.ts` exercises the path (or add coverage).
3. Dismiss the alert via `gh api ... -X PATCH state=dismissed -f 'dismissed_reason=false positive'` referencing this doc.
4. Do **not** "fix" by inlining `.split("\n")[0]` everywhere — the helper is the single source of truth; duplicating the pattern weakens the sanitizer (loses path scrubbing, length cap, type coercion) for the appearance of placating the scanner.

Adopting opt-in features like CodeQL's [`@codeql/javascript-models` custom sanitizer config](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-javascript/) is the long-term fix; it lives outside this doc.

## References

- [CWE-209: Information Exposure Through an Error Message](https://cwe.mitre.org/data/definitions/209.html)
- [CodeQL `js/stack-trace-exposure`](https://codeql.github.com/codeql-query-help/javascript/js-stack-trace-exposure/)
- [OWASP: Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- Commit centralizing the helper: `1a39c31f` — _fix(security): mask public upstream creds + centralize error sanitization_
