import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const TEST_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-err-boundaries-"));
process.env.DATA_DIR = TEST_DATA_DIR;

const {
  buildErrorBody,
  createErrorResult,
  projectPublicErrorIdentifier,
  providerCircuitOpenResponse,
  sanitizeErrorMessage,
  sanitizeUpstreamDetails,
  unavailableResponse,
} = await import("../../open-sse/utils/error.ts");

test.after(() => {
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
});

test("sanitizeErrorMessage redacts the reported credential forms", () => {
  const cases = [
    ["auth failed access token: sk-raw-secret", "auth failed access token: [REDACTED]"],
    ["auth failed token sk-raw-secret", "auth failed token [REDACTED]"],
    ["refresh_token=rt-private-value", "refresh_token=[REDACTED]"],
    ["token=sk-private-value", "token=[REDACTED]"],
    ["password=hunter2", "password=[REDACTED]"],
  ] as const;

  for (const [input, expected] of cases) {
    assert.equal(sanitizeErrorMessage(input), expected, input);
  }
});

test("sanitizeErrorMessage redacts labeled credential syntax across delimiters and quotes", () => {
  const labels = [
    "api_key",
    "api-key",
    "api key",
    "access_token",
    "access-token",
    "access token",
    "refresh_token",
    "refresh-token",
    "refresh token",
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
  ];
  const delimiters = [": ", "="];
  const quotePairs = [
    ["", ""],
    ["'", "'"],
    ['"', '"'],
  ] as const;

  for (const label of labels) {
    for (const delimiter of delimiters) {
      for (const [openQuote, closeQuote] of quotePairs) {
        const input = `${label}${delimiter}${openQuote}sk-private.value_123/+${closeQuote}`;
        const output = sanitizeErrorMessage(input);
        assert.ok(!output.includes("sk-private"), input);
        assert.ok(output.includes("[REDACTED]"), input);
      }
    }
  }
});

test("sanitizeErrorMessage preserves token metrics, status codes, and ordinary numbers", () => {
  const safeCases = [
    "token budget is 16384",
    "input token count: 16000",
    "status code 401; retry in 30 seconds",
    "request failed at status 503",
    "retry at 12:30 UTC",
  ];

  for (const input of safeCases) {
    assert.equal(sanitizeErrorMessage(input), input, input);
  }
});

test("sanitizeErrorMessage redacts assignment-shaped numeric tokens", () => {
  const cases = [
    ["token: 16000", "token: [REDACTED]"],
    ["token=401", "token=[REDACTED]"],
    ['"token": "16000"', '"token": "[REDACTED]"'],
    ["authToken=123456", "authToken=[REDACTED]"],
  ] as const;

  for (const [input, expected] of cases) {
    assert.equal(sanitizeErrorMessage(input), expected, input);
  }
});

test("sanitizeErrorMessage redacts bare service keys without matching ordinary sk words", () => {
  assert.equal(
    sanitizeErrorMessage("upstream rejected sk-SUPERSECRET123"),
    "upstream rejected [REDACTED]"
  );
  assert.equal(
    sanitizeErrorMessage("upstream rejected sk_SUPERSECRET123"),
    "upstream rejected [REDACTED]"
  );
  for (const safe of ["sk-ui", "sk-learn", "sk-board", "ask-SUPERSECRET123"]) {
    assert.equal(sanitizeErrorMessage(safe), safe, safe);
  }
});

test("sanitizeErrorMessage redacts strong bare GitHub personal access tokens", () => {
  const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
  for (const input of [token, `upstream rejected ${token}`]) {
    const output = sanitizeErrorMessage(input);
    assert.ok(!output.includes(token), input);
    assert.ok(output.includes("[REDACTED]"), input);
    assert.ok(!JSON.stringify(buildErrorBody(500, input)).includes(token), input);
  }

  for (const safe of ["ghp_status", "paragraphp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"]) {
    assert.equal(sanitizeErrorMessage(safe), safe, safe);
  }
});

test("sanitizeErrorMessage redacts strong bare JWTs without matching ordinary dotted codes", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signatureSECRET123";
  for (const input of [jwt, `upstream rejected ${jwt}`]) {
    const output = sanitizeErrorMessage(input);
    assert.ok(!output.includes(jwt), input);
    assert.ok(output.includes("[REDACTED]"), input);
    assert.ok(!JSON.stringify(buildErrorBody(500, input)).includes(jwt), input);
  }

  for (const safe of ["com.example.error", "eyJshort.payload.signature"]) {
    assert.equal(sanitizeErrorMessage(safe), safe, safe);
  }
});

test("sanitizeErrorMessage fails closed over unquoted high-risk credential values", () => {
  const cases = [
    ["password: correct horse battery staple", "password: [REDACTED]"],
    ["secret: multi word private value", "secret: [REDACTED]"],
    ["cookie=foo=abc; bar=SUPERSECRET", "cookie=[REDACTED]"],
    ["authorization: Basic first second", "authorization: [REDACTED]"],
  ] as const;

  for (const [input, expected] of cases) {
    assert.equal(sanitizeErrorMessage(input), expected, input);
    assert.equal(buildErrorBody(500, input).error.message, expected, input);
  }
});

test("sanitizeErrorMessage redacts credential labels embedded in composite keys", () => {
  const cases = [
    ["client_secret=SUPERSECRET", "client_secret=[REDACTED]"],
    ['{"clientSecret":"SUPERSECRET"}', '{"clientSecret":"[REDACTED]"}'],
    ["db_password=correct horse battery staple", "db_password=[REDACTED]"],
    ["sessionCookie=foo=abc; bar=SUPERSECRET", "sessionCookie=[REDACTED]"],
    ["authToken=sk-private-value", "authToken=[REDACTED]"],
  ] as const;

  for (const [input, expected] of cases) {
    assert.equal(sanitizeErrorMessage(input), expected, input);
  }
});

test("sanitizeErrorMessage redacts explicit high-risk credential labels", () => {
  const cases = [
    [
      "private_key=-----BEGIN PRIVATE KEY-----\nPEM_PRIVATE_SECRET\n-----END PRIVATE KEY-----",
      "private_key=[REDACTED]",
    ],
    ["private-key='PRIVATE_SECRET'", "private-key='[REDACTED]'"],
    ["private key=PRIVATE_SECRET", "private key=[REDACTED]"],
    ['{"privateKey":"PRIVATE_SECRET"}', '{"privateKey":"[REDACTED]"}'],
    ["session_key=multi word SESSION_SECRET", "session_key=[REDACTED]"],
    ['{"session-key":"SESSION_SECRET"}', '{"session-key":"[REDACTED]"}'],
    ["session key=SESSION_SECRET", "session key=[REDACTED]"],
    ["sessionKey: SESSION_SECRET", "sessionKey: [REDACTED]"],
    ["encryption key: multi word ENCRYPTION_SECRET", "encryption key: [REDACTED]"],
    ["encryption-key=ENCRYPTION_SECRET", "encryption-key=[REDACTED]"],
    ["encryption_key=ENCRYPTION_SECRET", "encryption_key=[REDACTED]"],
    ['{"encryptionKey":"ENCRYPTION_SECRET"}', '{"encryptionKey":"[REDACTED]"}'],
    ["secret_key=multi word SECRET_KEY_VALUE", "secret_key=[REDACTED]"],
    ["secret-key='SECRET_KEY_VALUE'", "secret-key='[REDACTED]'"],
    ['{"secret key":"SECRET_KEY_VALUE"}', '{"secret key":"[REDACTED]"}'],
    ["secretKey: SECRET_KEY_VALUE", "secretKey: [REDACTED]"],
    ["signing_key=multi word SIGNING_KEY_VALUE", "signing_key=[REDACTED]"],
    ["signing-key='SIGNING_KEY_VALUE'", "signing-key='[REDACTED]'"],
    ['{"signing key":"SIGNING_KEY_VALUE"}', '{"signing key":"[REDACTED]"}'],
    ["signingKey: SIGNING_KEY_VALUE", "signingKey: [REDACTED]"],
    ["credential=OPAQUE_CREDENTIAL", "credential=[REDACTED]"],
    ["credentials: multi word private value", "credentials: [REDACTED]"],
    ["session=OPAQUE_SESSION", "session=[REDACTED]"],
    ["session_id=OPAQUE_SESSION_ID", "session_id=[REDACTED]"],
    ['{"sessionId":"OPAQUE_SESSION_ID"}', '{"sessionId":"[REDACTED]"}'],
  ] as const;

  for (const [input, expected] of cases) {
    assert.equal(sanitizeErrorMessage(input), expected, input);
    assert.equal(buildErrorBody(500, input).error.message, expected, input);
  }

  for (const safe of [
    "private key rotation is scheduled",
    "session key count: 2",
    "encryption key status: active",
    "private_key_id=kid",
    "sessionKeyCount: 2",
    "encryption_key_version=v1",
    "secret_key_name=webhook",
    "signing_key_id=kid",
    "signing key rotation is scheduled",
    "credentials are missing",
    "credential validation failed",
    "session count: 3",
    "session_count=2",
    "sessionStatus=active",
    "public_key=PUBLIC",
    "key=value",
  ]) {
    assert.equal(sanitizeErrorMessage(safe), safe, safe);
  }
});

test("sanitizeErrorMessage redacts repository credential aliases", () => {
  const cases = [
    ["token_v2=NOTION_TOKEN_SECRET", "token_v2=[REDACTED]"],
    ["tokenV2=NOTION_CAMEL_TOKEN_SECRET", "tokenV2=[REDACTED]"],
    ['{"access_token_v2":"ACCESS_TOKEN_SECRET"}', '{"access_token_v2":"[REDACTED]"}'],
    ["sso=GROK_SESSION_SECRET", "sso=[REDACTED]"],
    ["sso-rw='COOKIE_SECRET'", "sso-rw='[REDACTED]'"],
    ['{"cf_clearance":"CLOUDFLARE_COOKIE_SECRET"}', '{"cf_clearance":"[REDACTED]"}'],
    ["__cf_bm=CLOUDFLARE_BOT_SECRET", "__cf_bm=[REDACTED]"],
    ['{"_cfuvid":"CLOUDFLARE_VISITOR_SECRET"}', '{"_cfuvid":"[REDACTED]"}'],
    ["_puid=CHATGPT_COOKIE_SECRET", "_puid=[REDACTED]"],
    [
      "__Secure-next-auth.session-token.0=CHUNKED_SESSION_SECRET",
      "__Secure-next-auth.session-token.0=[REDACTED]",
    ],
    ["arena-auth-prod-v1=ARENA_COOKIE_SECRET", "arena-auth-prod-v1=[REDACTED]"],
    ['{"arena-auth-prod-v1.1":"ARENA_CHUNK_SECRET"}', '{"arena-auth-prod-v1.1":"[REDACTED]"}'],
  ] as const;

  for (const [input, expected] of cases) {
    assert.equal(sanitizeErrorMessage(input), expected, input);
    assert.equal(buildErrorBody(500, input).error.message, expected, input);
  }

  for (const safe of [
    "token budget: 4096",
    "token_count=3",
    "access token version is v2",
    "sso status: unavailable",
    "key_id=kid",
  ]) {
    assert.equal(sanitizeErrorMessage(safe), safe, safe);
  }
});

test("sanitizeErrorMessage fails closed when string coercion throws", () => {
  const hostile = {
    toString(): string {
      throw new Error("coercion must not cross the public boundary");
    },
  };

  assert.equal(sanitizeErrorMessage(hostile), "");
  assert.equal(
    buildErrorBody(500, hostile as unknown as string).error.message,
    "Internal server error"
  );
});

test("sanitizer and public identifiers reject strong provider token formats", () => {
  const strongTokens = [
    "github_pat_SYNTHETICVALUE1234567890",
    "glpat-SYNTHETICVALUE1234567890",
    "xoxb-SYNTHETICVALUE1234567890",
    "AKIAABCDEFGHIJKLMNOP",
  ];

  for (const token of strongTokens) {
    const input = `provider rejected ${token}`;
    assert.equal(sanitizeErrorMessage(input), "provider rejected [REDACTED]", token);
    assert.equal(
      projectPublicErrorIdentifier(`prefix_${token}_suffix`, "bad_gateway"),
      "bad_gateway"
    );
    assert.ok(!JSON.stringify(buildErrorBody(500, input)).includes(token), token);
  }

  for (const safe of ["github_path_error", "glpat_status", "xoxo_error", "AKIA_STATUS"]) {
    assert.equal(sanitizeErrorMessage(safe), safe, safe);
    assert.equal(projectPublicErrorIdentifier(safe, "error"), safe, safe);
  }
});

test("sanitizeErrorMessage redacts bare private-key PEM blocks", () => {
  const cases = [
    [
      "upstream returned -----BEGIN PRIVATE KEY-----\nMII_BARE_PRIVATE_SECRET\n-----END PRIVATE KEY----- after",
      "upstream returned [REDACTED] after",
    ],
    ["-----BEGIN RSA PRIVATE KEY-----\nMII_UNCLOSED_PRIVATE_SECRET", "[REDACTED]"],
    [
      "ß -----BEGIN PRIVATE KEY-----\nMII_UNICODE_PREFIX_SECRET\n-----END PRIVATE KEY----- after",
      "ß [REDACTED] after",
    ],
    [
      "ﬃ -----BEGIN EC PRIVATE KEY-----\nMII_UNICODE_BODY_ﬃ_SECRET\n-----END EC PRIVATE KEY----- after",
      "ﬃ [REDACTED] after",
    ],
  ] as const;

  for (const [input, expected] of cases) {
    assert.equal(sanitizeErrorMessage(input), expected, input);
    assert.equal(buildErrorBody(500, input).error.message, expected, input);
  }

  const safeCases = [
    [
      "-----BEGIN PUBLIC KEY-----\nPUBLIC_MATERIAL\n-----END PUBLIC KEY-----",
      "-----BEGIN PUBLIC KEY-----",
    ],
    [
      "-----BEGIN CERTIFICATE-----\nPUBLIC_CERTIFICATE\n-----END CERTIFICATE-----",
      "-----BEGIN CERTIFICATE-----",
    ],
    ["private key rotation is scheduled", "private key rotation is scheduled"],
  ] as const;
  for (const [input, expected] of safeCases) {
    assert.equal(sanitizeErrorMessage(input), expected, input);
  }
});

test("sanitizeErrorMessage consumes escaped quotes inside quoted credentials", () => {
  const cases = [
    [String.raw`password="first\"SECOND_SECRET"`, 'password="[REDACTED]"'],
    [String.raw`secret='first\'SECOND_SECRET'`, "secret='[REDACTED]'"],
    [String.raw`{"access_token":"first\"SECOND_SECRET"}`, '{"access_token":"[REDACTED]"}'],
  ] as const;

  for (const [input, expected] of cases) {
    assert.equal(sanitizeErrorMessage(input), expected, input);
  }
});

test("sanitizeErrorMessage fails closed when a quoted credential is truncated", () => {
  const cases = [
    ['password="SUPERSECRET', 'password="[REDACTED]'],
    ["secret='SUPERSECRET", "secret='[REDACTED]"],
    ['{"access_token":"SUPERSECRET', '{"access_token":"[REDACTED]'],
    ['cookie="session=SUPERSECRET', 'cookie="[REDACTED]'],
  ] as const;

  for (const [input, expected] of cases) {
    assert.equal(sanitizeErrorMessage(input), expected, input);
  }
});

test("sanitizeErrorMessage preserves non-assignment credential prose", () => {
  const cases = [
    "password policy requires 12 characters",
    "secret count: 2",
    "cookie count: 3",
    "authorization status: missing",
  ];

  for (const input of cases) {
    assert.equal(sanitizeErrorMessage(input), input, input);
  }
});

test("sanitizeErrorMessage decodes bounded ASCII escapes before credential scanning", () => {
  const cases = [
    [String.raw`api\u005fkey=SUPERSECRET`, "api_key=[REDACTED]"],
    [String.raw`password\u003dSUPERSECRET`, "password=[REDACTED]"],
    [String.raw`\u0061\U0070\u0069\u005F\u006B\u0065\u0079=SUPERSECRET`, "api_key=[REDACTED]"],
    [String.raw`api\\u005fkey=SUPERSECRET`, "api_key=[REDACTED]"],
    [
      String.raw`\\u0061\\u0070\\u0069\\u005f\\u006b\\u0065\\u0079=SUPERSECRET`,
      "api_key=[REDACTED]",
    ],
    [String.raw`{"api\\u005fkey":"SUPERSECRET"}`, '{"api_key":"[REDACTED]"}'],
    [String.raw`api_key=\"SUPERSECRET\"`, "api_key=[REDACTED]"],
  ] as const;

  for (const [input, expected] of cases) {
    assert.equal(sanitizeErrorMessage(input), expected, input);
    assert.equal(buildErrorBody(500, input).error.message, expected, input);
  }
});

test("encoded labels cannot erase quoted-credential escape provenance", () => {
  const cases = [
    [String.raw`p\u0061ssword="first\"SECOND_SECRET"`, 'password="[REDACTED]"'],
    [String.raw`p\u0061ssword="first\u0022SECOND_SECRET"`, 'password="[REDACTED]"'],
    [String.raw`api\u005fkey="first\"SECOND_SECRET"`, 'api_key="[REDACTED]"'],
    [String.raw`api\u005fkey="first\u0022SECOND_SECRET"`, 'api_key="[REDACTED]"'],
  ] as const;

  for (const [input, expected] of cases) {
    assert.equal(sanitizeErrorMessage(input), expected, input);
    assert.equal(buildErrorBody(500, input).error.message, expected, input);
  }
});

test("deeply serialized credential-label escapes fail closed without a depth bypass", () => {
  for (const slashCount of [3, 5, 6, 7, 8, 9, 16]) {
    const input = `api${"\\".repeat(slashCount)}u005fkey=DEPTH_SECRET`;
    const output = sanitizeErrorMessage(input);

    assert.ok(!output.includes("DEPTH_SECRET"), input);
    assert.ok(output.includes("[REDACTED]"), input);
    assert.ok(!JSON.stringify(buildErrorBody(500, input)).includes("DEPTH_SECRET"), input);
  }
});

test("sanitizeErrorMessage decodes bounded ASCII escapes before path scanning", () => {
  const cases = [
    String.raw`failed at \u002fhome\u002falice\u002fsecret.ts:1:2`,
    String.raw`failed at \\u002fhome\\u002falice\\u002fsecret.ts:1:2`,
    String.raw`failed at C\u003a\u005cUsers\u005calice\u005csecret.ts:1:2`,
    String.raw`failed at C:\\Users\\alice\\secret.ts:1:2`,
  ];

  for (const input of cases) {
    assert.equal(sanitizeErrorMessage(input), "failed at <path>", input);
    assert.equal(buildErrorBody(500, input).error.message, "failed at <path>", input);
  }
});

test("ASCII escape normalization preserves and redacts UNC path evidence", () => {
  const cases = [
    String.raw`failed at \\node\share\TOP_SECRET.ts:1:2`,
    String.raw`failed at \\router\share\TOP_SECRET.ts:1:2`,
    String.raw`failed at \\u005fserver\share\TOP_SECRET.ts:1:2`,
    String.raw`failed at \\u0061\u0070\TOP_SECRET.ts:1:2`,
  ];

  for (const input of cases) {
    assert.equal(sanitizeErrorMessage(input), "failed at <path>", input);
    assert.equal(buildErrorBody(500, input).error.message, "failed at <path>", input);
  }
  assert.equal(
    sanitizeErrorMessage("network node and router remain healthy"),
    "network node and router remain healthy"
  );
});

test("ASCII escape normalization preserves safe URLs, prose, and non-ASCII escapes", () => {
  const safeCases = [
    [
      String.raw`request GET https:\u002f\u002fapi.example.com\u002fv1\u002fstatus`,
      "request GET https://api.example.com/v1/status",
    ],
    [String.raw`\u0074\u006f\u006b\u0065\u006e budget is 16384`, "token budget is 16384"],
    [String.raw`provider returned \u263a`, String.raw`provider returned \u263a`],
    [String.raw`control \u001f and delete \u007f`, String.raw`control \u001f and delete \u007f`],
  ] as const;

  for (const [input, expected] of safeCases) {
    assert.equal(sanitizeErrorMessage(input), expected, input);
  }

  const pathological = String.raw`\u0061`.repeat(4096);
  assert.ok(sanitizeErrorMessage(pathological).length <= 4096);
});

test("upstream details reject escaped unsafe keys and sanitize escaped values", () => {
  const input = Object.create(null) as Record<string, unknown>;
  input[String.raw`p\u0061ssword`] = "SINGLE_ESCAPED_KEY_SECRET";
  input[String.raw`\u0061\u0070\u0069\u005f\u006b\u0065\u0079`] = "FULLY_ESCAPED_KEY_SECRET";
  input[String.raw`__pr\u006fto__`] = "PROTO_CONTROL_SECRET";
  input[String.raw`constr\u0075ctor`] = "CONSTRUCTOR_CONTROL_SECRET";
  input[String.raw`prot\u006ftype`] = "PROTOTYPE_CONTROL_SECRET";
  input.safeCollision = "SAFE_KEEP";
  input[String.raw`s\u0061feCollision`] = "COLLISION_SECRET";
  input.safe = String.raw`password\u003dVALUE_SECRET`;
  input.nested = {
    [String.raw`\u002f\u0068\u006f\u006d\u0065\u002f\u0061\u006c\u0069\u0063\u0065\u002f\u006e\u006f\u0074\u0065\u002e\u0074\u0073`]:
      "PATH_KEY_SECRET",
    message: String.raw`failed at \u002fhome\u002falice\u002fsecret.ts:1:2`,
  };

  const sanitized = sanitizeUpstreamDetails(input) as Record<string, unknown>;
  const serialized = JSON.stringify(sanitized);

  assert.equal(sanitized.safe, "password=[REDACTED]");
  assert.equal(sanitized.safeCollision, "SAFE_KEEP");
  assert.equal((sanitized.nested as Record<string, unknown>).message, "failed at <path>");
  for (const secret of [
    "SINGLE_ESCAPED_KEY_SECRET",
    "FULLY_ESCAPED_KEY_SECRET",
    "PROTO_CONTROL_SECRET",
    "CONSTRUCTOR_CONTROL_SECRET",
    "PROTOTYPE_CONTROL_SECRET",
    "COLLISION_SECRET",
    "PATH_KEY_SECRET",
    "VALUE_SECRET",
    "/home/alice",
  ]) {
    assert.ok(!serialized.includes(secret), secret);
  }
});

test("upstream details drop unsafe keys recursively without key collisions", () => {
  const input = {
    "/home/alice/private.ts": "POSIX_KEY_SECRET",
    "C:\\Users\\alice\\private.ts": "WINDOWS_KEY_SECRET",
    credential: "OPAQUE_CREDENTIAL_SECRET",
    credentials: "OPAQUE_CREDENTIALS_SECRET",
    session: "OPAQUE_SESSION_SECRET",
    sessionId: "OPAQUE_SESSION_ID_SECRET",
    session_id: "OPAQUE_SESSION_SNAKE_SECRET",
    session_count: 2,
    session_status: "ready",
    sessionStatus: "active",
    token_v2: "NOTION_ALIAS_SECRET",
    cf_clearance: "CLEARANCE_ALIAS_SECRET",
    __cf_bm: "BOT_ALIAS_SECRET",
    _cfuvid: "VISITOR_ALIAS_SECRET",
    _puid: "PUID_ALIAS_SECRET",
    sso: "SSO_ALIAS_SECRET",
    "sso-rw": "SSO_RW_ALIAS_SECRET",
    "arena-auth-prod-v1": "ARENA_ALIAS_SECRET",
    "arena-auth-prod-v1.3": "ARENA_CHUNK_ALIAS_SECRET",
    safe: {
      ok: "kept",
      token_v2: "NESTED_NOTION_ALIAS_SECRET",
      cf_clearance: "NESTED_CLEARANCE_ALIAS_SECRET",
      credential: "NESTED_CREDENTIAL_SECRET",
      sessionId: "NESTED_SESSION_SECRET",
      "/srv/private/location.ts": "NESTED_KEY_SECRET",
      "at handler (/home/alice/private.ts:1:2)": "STACK_SHAPED_KEY_SECRET",
      "authorization=Bearer SUPERSECRET": "CREDENTIAL_KEY_SECRET",
      stack: "STACK_SECRET",
      password: "PASSWORD_SECRET",
    },
  };
  const body = buildErrorBody(500, "upstream failed", input);
  const details = body.upstream_details as Record<string, unknown>;
  const serialized = JSON.stringify(details);

  assert.equal((details.safe as Record<string, unknown>).ok, "kept");
  assert.equal(details.session_count, 2);
  assert.equal(details.session_status, "ready");
  assert.equal(details.sessionStatus, "active");
  for (const secret of [
    "/home/alice/private.ts",
    "C:\\Users\\alice\\private.ts",
    "/srv/private/location.ts",
    "POSIX_KEY_SECRET",
    "WINDOWS_KEY_SECRET",
    "NESTED_KEY_SECRET",
    "STACK_SHAPED_KEY_SECRET",
    "CREDENTIAL_KEY_SECRET",
    "STACK_SECRET",
    "PASSWORD_SECRET",
    "OPAQUE_CREDENTIAL_SECRET",
    "OPAQUE_CREDENTIALS_SECRET",
    "OPAQUE_SESSION_SECRET",
    "OPAQUE_SESSION_ID_SECRET",
    "OPAQUE_SESSION_SNAKE_SECRET",
    "NESTED_CREDENTIAL_SECRET",
    "NESTED_SESSION_SECRET",
    "NOTION_ALIAS_SECRET",
    "CLEARANCE_ALIAS_SECRET",
    "BOT_ALIAS_SECRET",
    "VISITOR_ALIAS_SECRET",
    "PUID_ALIAS_SECRET",
    "SSO_ALIAS_SECRET",
    "SSO_RW_ALIAS_SECRET",
    "ARENA_ALIAS_SECRET",
    "ARENA_CHUNK_ALIAS_SECRET",
    "NESTED_NOTION_ALIAS_SECRET",
    "NESTED_CLEARANCE_ALIAS_SECRET",
  ]) {
    assert.ok(!serialized.includes(secret), secret);
  }
});

test("upstream details reject prototype-control keys from null-prototype input", () => {
  const hostile = Object.create(null) as Record<string, unknown>;
  hostile.safe = "kept";
  hostile.__proto__ = { polluted: "PROTO_SECRET" };
  hostile.constructor = "CONSTRUCTOR_SECRET";
  hostile.prototype = "PROTOTYPE_SECRET";

  const sanitized = sanitizeUpstreamDetails(hostile) as Record<string, unknown>;
  const serialized = JSON.stringify(sanitized);

  assert.equal(sanitized.safe, "kept");
  assert.equal(({} as { polluted?: string }).polluted, undefined);
  assert.ok(!serialized.includes("PROTO_SECRET"));
  assert.ok(!serialized.includes("CONSTRUCTOR_SECRET"));
  assert.ok(!serialized.includes("PROTOTYPE_SECRET"));
});

test("public error classification rejects unsafe identifiers with status fallbacks", async () => {
  const unsafeCode = "bad access_token=TOP_SECRET /home/alice/code.ts";
  const unsafeType = "bad_type\n    at /home/alice/type.ts:1:2";
  const body = buildErrorBody(502, "upstream failed", undefined, {
    code: unsafeCode,
    type: unsafeType,
  });
  const result = createErrorResult(502, "upstream failed", null, unsafeCode, unsafeType);
  const responseBody = (await result.response.json()) as {
    error: { code?: string; type?: string };
  };

  assert.equal(body.error.code, "bad_gateway");
  assert.equal(body.error.type, "server_error");
  assert.equal(responseBody.error.code, "bad_gateway");
  assert.equal(responseBody.error.type, "server_error");
  assert.equal(result.errorCode, unsafeCode, "internal classification stays available");
  assert.equal(result.errorType, unsafeType, "internal classification stays available");
  assert.ok(!JSON.stringify(responseBody).includes("TOP_SECRET"));
  assert.ok(!JSON.stringify(responseBody).includes("/home/alice"));
});

test("public error classification preserves bounded identifiers", () => {
  const body = buildErrorBody(429, "rate limited", undefined, {
    code: "usage_limit_reached",
    type: "rate_limit_error",
  });

  assert.equal(body.error.code, "usage_limit_reached");
  assert.equal(body.error.type, "rate_limit_error");
});

test("public error classification rejects bare service keys that look like identifiers", () => {
  const body = buildErrorBody(502, "upstream failed", undefined, {
    code: "sk-SUPERSECRET123",
    type: "server_error",
  });

  assert.equal(body.error.code, "bad_gateway");
  assert.equal(body.error.type, "server_error");
  assert.ok(!JSON.stringify(body).includes("SUPERSECRET123"));
});

test("public error classification rejects credential-shaped identifier payloads", () => {
  for (const unsafe of [
    "access_token_SECRET123",
    "password_hunter2",
    "authorization_BearerSecret",
    "UPSTREAM_access_token_SECRET123",
    "provider-password-hunter2",
    "X.authorization_BearerSecret",
    "bearer_SUPERSECRET123",
    "provider_bearer_SUPERSECRET123",
    "hunter2_password",
    "passwordhunter2",
    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
    "UPSTREAM_ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
    "UPSTREAM_sk-SUPERSECRET123",
  ]) {
    const body = buildErrorBody(502, "upstream failed", undefined, {
      code: unsafe,
      type: unsafe,
    });
    assert.equal(body.error.code, "bad_gateway", unsafe);
    assert.equal(body.error.type, "server_error", unsafe);
    assert.ok(!JSON.stringify(body).includes(unsafe), unsafe);
  }

  for (const safe of [
    "invalid_api_key",
    "invalid_token",
    "token_expired",
    "provider_token_expired",
    "bearer_invalid",
    "bearer_required",
    "bearer_expired",
    "provider_bearer_error",
    "invalid_password",
    "password_required",
    "passwordless",
    "passwordless_error",
    "unsupported_feature",
    "RATE_LIMIT",
  ]) {
    const body = buildErrorBody(502, "upstream failed", undefined, { code: safe, type: safe });
    assert.equal(body.error.code, safe, safe);
    assert.equal(body.error.type, safe, safe);
  }
});

test("public error classification rejects credentials masked by safe-looking segments", () => {
  const unsafeIdentifiers = [
    "hunter2_password_expired",
    "SECRET123_access_token_missing",
    "hunter2_token_expired",
    "SECRET123_bearer_invalid",
    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456_expired",
    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456_token_expired",
    "letmein_password",
    "qwerty_password",
    "passwordsecret",
    "secretSECRET123",
    "authorizationBearerSecret",
    "bearerSecret123",
    "api_keySECRET123",
    "access_tokenSECRET123",
    "access_token_SECRET",
    "password_provider",
    "password_secret",
    "secret_token",
    "token_secret",
    "access_token_github",
    "SECRET_access_token_missing",
    "provider_secret_token",
    "github_bearer_token",
    "client_password_session",
    "authorization_bearer_secret",
    "prefixAccessTokenSUPERSECRET123",
    "prefixPasswordSUPERSECRET123",
    "prefixPrivateKeySUPERSECRET123",
    "prefixSessionKeySUPERSECRET123",
    "prefixEncryptionKeySUPERSECRET123",
    "prefixSigningKeySUPERSECRET123",
    "prefixSecretKeySUPERSECRET123",
    "prefixCredentialSUPERSECRET123",
    "prefixSessionIdSUPERSECRET123",
    "session_SUPERSECRET123",
    "prefixghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
    "prefixsk-SUPERSECRET123",
    "prefixeyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signatureSECRET123",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signatureSECRET123",
    "access_token",
    "refresh_token",
    "api_key",
    "accesstoken",
    "refreshtoken",
    "apikey",
    "authorization",
    "bearer",
    "cookie",
    "password",
    "secret",
    "token",
  ];

  for (const unsafe of unsafeIdentifiers) {
    const body = buildErrorBody(502, "upstream failed", undefined, {
      code: unsafe,
      type: unsafe,
    });
    assert.equal(body.error.code, "bad_gateway", unsafe);
    assert.equal(body.error.type, "server_error", unsafe);
    assert.ok(!JSON.stringify(body).includes(unsafe), unsafe);
  }

  for (const safe of [
    "authorization_code",
    "authorization_code_pkce",
    "authorization_endpoint",
    "authorization_failed",
    "authorization_pending",
    "client_secret_missing",
    "codex_access_token_missing",
    "codex_oauth_token_missing",
    "access_token_required",
    "access_token_missing",
    "expired_token",
    "github_access_token_invalid",
    "invalid_token",
    "invalid_token_response",
    "LEASE_API_KEY_INVALID",
    "LEASE_AUTHORIZATION_MISMATCH",
    "missing_access_token",
    "missing_api_key",
    "missing_authorization",
    "missing_cookie",
    "missing_id_token",
    "missing_refresh_token",
    "no_refresh_token",
    "no_access_token",
    "oauth_invalid_token",
    "PASSWORD_MISMATCH",
    "PASSWORD_REQUIRED",
    "refresh_token_invalid",
    "refresh_token_invalidated",
    "refresh_token_reused",
    "TOKEN_LIMIT_EXCEEDED",
    "token_required",
    "token_limit_exceeded",
    "token_health_check",
    "token_refresh_failed",
    "token_refresh_transient",
    "token_type",
    "token_usage",
    "github_token_expired",
    "no_credentials",
    "passwordless_auth_required",
    "tokenizer_error",
    "tokenization_error",
    "SESSION_EXPIRED",
    "missing_session_id",
    "TLS_SESSION_CAPACITY",
  ]) {
    assert.equal(projectPublicErrorIdentifier(safe, "error"), safe, safe);
  }
});

test("public error identifier rejects non-string candidates without throwing", () => {
  for (const candidate of [401, true, null, { code: "safe_code" }, ["safe_code"]]) {
    assert.equal(projectPublicErrorIdentifier(candidate, "bad_gateway"), "bad_gateway");
  }
});

test("public error identifier applies the same policy to hostile fallbacks", () => {
  assert.equal(projectPublicErrorIdentifier(undefined, "access_token_SECRET123"), "error");
  assert.equal(projectPublicErrorIdentifier("bad value", "password_hunter2"), "error");
  assert.equal(projectPublicErrorIdentifier("bad value", "sk-SUPERSECRET123"), "error");
  assert.equal(
    projectPublicErrorIdentifier("bad value", {
      toString(): string {
        throw new Error("hostile fallback coercion");
      },
    } as unknown as string),
    "error"
  );
  assert.equal(projectPublicErrorIdentifier(undefined, "bad_gateway"), "bad_gateway");
});

test("unavailableResponse sanitizes the message and retry hint", async () => {
  const response = unavailableResponse(
    429,
    "failed at /home/alice/private.ts:1:2",
    null,
    "reset after 30s password=SUPERSECRET"
  );
  const body = (await response.json()) as { error: { message: string } };

  assert.equal(body.error.message, "failed at <path> (reset after 30s password=[REDACTED])");
  assert.ok(!JSON.stringify(body).includes("SUPERSECRET"));
  assert.ok(!JSON.stringify(body).includes("/home/alice"));
});

test("provider circuit responses project hostile provider labels", async () => {
  const provider = "provider access_token=CIRCUIT_SECRET /home/alice/provider.ts";
  const response = providerCircuitOpenResponse(provider, 30);
  const body = await response.json();
  const serialized = JSON.stringify(body);

  assert.equal(response.status, 503);
  assert.equal(response.headers.get("Retry-After"), "30");
  assert.equal(response.headers.get("X-OmniRoute-Provider-Breaker"), "open");
  assert.equal(body.error.provider, "unknown");
  assert.equal(body.error.message, "Provider unknown circuit breaker is open");
  assert.ok(!serialized.includes("CIRCUIT_SECRET"));
  assert.ok(!serialized.includes("/home/alice"));

  const safe = await providerCircuitOpenResponse("openai", 5).json();
  assert.equal(safe.error.provider, "openai");
});

test("sanitizeErrorMessage removes physical and serialized stack-frame tails", () => {
  const physicalSeparators = ["\n", "\r", "\r\n", "\u2028", "\u2029"];
  const serializedSeparators = ["\\n", "\\r", "\\r\\n", "\\u2028", "\\u2029"];
  const frameLabels = [
    "handler",
    "async handler",
    "Object.handler",
    "Object.handler [as run]",
    "new Handler",
    "<anonymous>",
  ];
  const framePaths = [
    "/srv/private/file.ts:1:2",
    "C:\\private\\file.ts:1:2",
    "file:///srv/private/file.mjs:1:2",
    "/custom/private/file.ts:1:2",
  ];

  for (const separator of [...physicalSeparators, ...serializedSeparators]) {
    for (const label of frameLabels) {
      for (const filePath of framePaths) {
        const input = `boom${separator}    at ${label} (${filePath})`;
        assert.equal(sanitizeErrorMessage(input), "boom", input);
      }
    }
  }
});

test("serialized Unicode control escapes never expose stack frames", () => {
  const cases = [
    "boom\\u000a    at /home/alice/secret.ts:10:2",
    "boom\\U000A    at handler (src/private/secret.ts:10:2)",
    "boom\\u000d    at /home/alice/secret.ts:10:2",
    "boom\\u000D    at handler (src/private/secret.ts:10:2)",
  ];

  for (const input of cases) {
    assert.equal(sanitizeErrorMessage(input), "boom", input);
    assert.equal(buildErrorBody(500, input).error.message, "boom", input);
  }
});

test("serialized stack separators remove every escape prefix and preserve fallback", () => {
  for (const slashCount of [1, 2, 3, 4, 8]) {
    const separator = `${"\\".repeat(slashCount)}n`;
    const framed = `failed${separator}    at Secret (/home/alice/secret.ts:1:2)`;
    const stackOnly = `${separator}    at Secret (/home/alice/secret.ts:1:2)`;

    assert.equal(sanitizeErrorMessage(framed), "failed", framed);
    assert.equal(sanitizeErrorMessage(stackOnly), "", stackOnly);
    assert.equal(buildErrorBody(500, stackOnly).error.message, "Internal server error", stackOnly);
  }
});

test("serialized stack tails remove async, Node, eval, and aggregate frames", () => {
  const cases = [
    "boom\n    at async /home/alice/app.ts:1:2",
    "boom\n    at processTicksAndRejections (node:internal/process/task_queues:95:5)",
    "boom\\u000a    at async /home/alice/app.ts:1:2",
    "boom\\u000d    at async src/app.ts:1:2",
    "boom\\n    at async Promise.all (index 0)",
    "boom\\u000A    at [eval]:1:1",
    "boom\\u000a    at processTicksAndRejections (node:internal/process/task_queues:95:5)",
    "boom\\u000d    at node:events:1:2",
    "boom at processTicksAndRejections (node:internal/process/task_queues:95:5)",
  ];

  for (const input of cases) {
    assert.equal(sanitizeErrorMessage(input), "boom", input);
    assert.equal(buildErrorBody(500, input).error.message, "boom", input);
  }
});

test("stack-tail detection preserves URLs, routes, and stack-like prose", () => {
  const cases = [
    "request stopped at handler (https://api.example.com/status)",
    "request stopped at handler (/v1/status)",
    "Retry at processTicksAndRejections (node:internal/process/task_queues)",
    "retry at handler (node:internal/process/task_queues:soon:later)",
    "completed at async Promise.all (index zero)",
    "boom\\u000a    at handler (https://api.example.com/status)",
    "boom\\u000a    at handler (/v1/status)",
    "boom\\u000a    at async https://api.example.com/status",
    "boom\\u000a    at Promise.all (index many)",
  ];

  for (const input of cases) {
    assert.equal(sanitizeErrorMessage(input), input, input);
  }
});

test("sanitizeErrorMessage removes an unambiguous inline named stack frame", () => {
  const input = "single-line stack at SecretFunction (/srv/private/file.ts:1:2)";
  assert.equal(sanitizeErrorMessage(input), "single-line stack");
});

test("sanitizeErrorMessage keeps useful prose and the documented unknown-root limitation", () => {
  const safeCases = [
    "Failed at /srv/private/file.ts:1:2",
    "Cannot open /custom/private/token",
    "message at handler (/v1/status)",
    "request stopped at handler (https://api.example.com/status)",
  ];
  const expected = [
    "Failed at <path>",
    "Cannot open /custom/private/token",
    "message at handler (/v1/status)",
    "request stopped at handler (https://api.example.com/status)",
  ];

  for (let index = 0; index < safeCases.length; index++) {
    assert.equal(sanitizeErrorMessage(safeCases[index]), expected[index], safeCases[index]);
  }
});

test("buildErrorBody applies credential and inline-stack sanitization", () => {
  const credentialBody = buildErrorBody(500, "upstream token=sk-private-value");
  const stackBody = buildErrorBody(
    500,
    "upstream failed at SecretFunction (/srv/private/file.ts:1:2)"
  );

  assert.equal(credentialBody.error.message, "upstream token=[REDACTED]");
  assert.equal(stackBody.error.message, "upstream failed");
});
