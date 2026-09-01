import { redactErrorPaths, stripErrorStackTail } from "./errorPathRedaction.ts";

// Length cap protects against pathological inputs even before tokenization.
const MAX_ERROR_LEN = 4096;
const MAX_SECURITY_ESCAPE_LAYERS = 3;
const STRONG_CREDENTIAL_TOKEN_SOURCE =
  "(?:eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}|" +
  "github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}|" +
  "xox[a-z]-[A-Za-z0-9-]{10,}|(?:AKIA|ASIA)[A-Z0-9]{16}|" +
  "(?<![A-Za-z0-9])sk[-_][A-Za-z0-9._~+/=-]{8,}|" +
  "[A-Za-z0-9]{3,}sk[-_][A-Za-z0-9._~+/=-]{8,})";
const STRONG_CREDENTIAL_TOKEN = new RegExp(STRONG_CREDENTIAL_TOKEN_SOURCE, "i");
const STRONG_CREDENTIAL_TOKEN_GLOBAL = new RegExp(STRONG_CREDENTIAL_TOKEN_SOURCE, "gi");

export function containsStrongCredentialToken(value: string): boolean {
  return STRONG_CREDENTIAL_TOKEN.test(value);
}

const CREDENTIAL_LABELS = [
  ["__secure-next-auth.session-token", true],
  ["arena-auth-prod-v1", true],
  ["__cf_bm", true],
  ["_cfuvid", true],
  ["_puid", true],
  ["access_token_v2", true],
  ["token_v2", true],
  ["tokenv2", true],
  ["cf_clearance", true],
  ["credentials", true],
  ["credential", true],
  ["session id", true],
  ["session-id", true],
  ["session_id", true],
  ["sessionid", true],
  ["encryption key", true],
  ["encryption-key", true],
  ["encryption_key", true],
  ["encryptionkey", true],
  ["private key", true],
  ["private-key", true],
  ["private_key", true],
  ["privatekey", true],
  ["session key", true],
  ["session-key", true],
  ["session_key", true],
  ["sessionkey", true],
  ["secret key", true],
  ["secret-key", true],
  ["secret_key", true],
  ["secretkey", true],
  ["signing key", true],
  ["signing-key", true],
  ["signing_key", true],
  ["signingkey", true],
  ["refresh token", false],
  ["refresh-token", false],
  ["refresh_token", false],
  ["refreshtoken", false],
  ["access token", false],
  ["access-token", false],
  ["access_token", false],
  ["accesstoken", false],
  ["authorization", true],
  ["sso-rw", true],
  ["session", true],
  ["sso", true],
  ["api key", false],
  ["api-key", false],
  ["api_key", false],
  ["apikey", false],
  ["password", true],
  ["cookie", true],
  ["secret", true],
  ["token", false],
] as const;

type CredentialAssignment = {
  valueStart: number;
  failClosed: boolean;
};

function isAsciiAlphaNumericCode(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a)
  );
}

function asciiHexValue(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  return -1;
}

function unicodeEscapeCodeAt(value: string, start: number): number | null {
  if (
    value.charCodeAt(start) !== 0x5c ||
    (value[start + 1] !== "u" && value[start + 1] !== "U") ||
    start + 5 >= value.length
  ) {
    return null;
  }

  let decoded = 0;
  for (let digit = start + 2; digit <= start + 5; digit++) {
    const nibble = asciiHexValue(value.charCodeAt(digit));
    if (nibble < 0) return null;
    decoded = decoded * 16 + nibble;
  }
  return decoded;
}

function isPrintableAscii(code: number | null): code is number {
  return code !== null && code >= 0x20 && code <= 0x7e;
}

function isEscapeTokenBoundary(code: number): boolean {
  return !isAsciiAlphaNumericCode(code) && code !== 0x2e && code !== 0x5f && code !== 0x2d;
}

function shouldPreserveUnicodeUncEvidence(
  value: string,
  runStart: number,
  runEnd: number,
  decoded: number
): boolean {
  if (
    runEnd - runStart < 2 ||
    decoded === 0x2f ||
    decoded === 0x5c ||
    decoded === 0x3a ||
    (runStart > 0 && !isEscapeTokenBoundary(value.charCodeAt(runStart - 1)))
  ) {
    return false;
  }

  const afterEscape = runEnd + 5;
  let tokenEnd = afterEscape;
  while (tokenEnd < value.length && !/\s/.test(value[tokenEnd])) tokenEnd++;
  if (value.slice(afterEscape, tokenEnd).includes("=")) return false;
  return afterEscape < tokenEnd;
}

function decodeSecurityEscapesOnce(value: string, decodeQuotes: boolean): string {
  const output: string[] = [];
  let changed = false;

  for (let index = 0; index < value.length; index++) {
    if (value.charCodeAt(index) !== 0x5c) {
      output.push(value[index]);
      continue;
    }

    const runStart = index;
    while (index < value.length && value.charCodeAt(index) === 0x5c) index++;
    const runEnd = index;
    if (runEnd >= value.length) {
      output.push(value.slice(runStart));
      break;
    }

    const escaped = value[runEnd];
    if (escaped === "u" || escaped === "U") {
      const decoded = unicodeEscapeCodeAt(value, runEnd - 1);
      const isQuote = decoded === 0x22 || decoded === 0x27;
      if (
        isPrintableAscii(decoded) &&
        (decodeQuotes || !isQuote) &&
        !shouldPreserveUnicodeUncEvidence(value, runStart, runEnd, decoded)
      ) {
        output.push(String.fromCharCode(decoded));
        index = runEnd + 4;
        changed = true;
        continue;
      }
      output.push(value.slice(runStart, runEnd + 5));
      index = runEnd + 4;
      continue;
    }

    if (escaped === "/" || (decodeQuotes && (escaped === '"' || escaped === "'"))) {
      output.push(escaped);
      index = runEnd;
      changed = true;
      continue;
    }

    output.push(value.slice(runStart, runEnd));
    index = runEnd - 1;
  }

  return changed ? output.join("").slice(0, MAX_ERROR_LEN) : value;
}

function hasResidualSecurityEscape(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    if (value.charCodeAt(index) !== 0x5c) continue;
    while (index < value.length && value.charCodeAt(index) === 0x5c) index++;
    if (index >= value.length) return false;
    const escaped = value[index];
    if (escaped === "/" || escaped === '"' || escaped === "'") return true;
    if (escaped === "u" || escaped === "U") {
      const decoded = unicodeEscapeCodeAt(value, index - 1);
      if (isPrintableAscii(decoded)) return true;
    }
  }
  return false;
}

/** Decode bounded security ASCII/JSON escapes while never materializing arbitrary Unicode. */
function normalizeSecurityEscapes(value: string, decodeQuotes: boolean): string {
  let normalized = value.slice(0, MAX_ERROR_LEN);
  for (let layer = 0; layer < MAX_SECURITY_ESCAPE_LAYERS; layer++) {
    const decoded = decodeSecurityEscapesOnce(normalized, decodeQuotes);
    if (decoded === normalized) break;
    normalized = decoded.slice(0, MAX_ERROR_LEN);
  }
  return normalized;
}

function isCredentialLabelBoundary(code: number): boolean {
  return !isAsciiAlphaNumericCode(code) && code !== 0x5f && code !== 0x2d;
}

function matchCredentialAssignmentAt(value: string, start: number): CredentialAssignment | null {
  const keyQuote = value[start] === '"' || value[start] === "'" ? value[start] : "";
  const labelStart = start + (keyQuote ? 1 : 0);

  for (const [label, failClosed] of CREDENTIAL_LABELS) {
    const labelEnd = labelStart + label.length;
    if (value.slice(labelStart, labelEnd).toLowerCase() !== label) continue;
    let index = labelEnd;
    if (
      (label === "arena-auth-prod-v1" || label === "__secure-next-auth.session-token") &&
      value[index] === "."
    ) {
      const chunkStart = ++index;
      while (index < value.length && /\d/.test(value[index])) index++;
      if (index === chunkStart) continue;
    }
    if (keyQuote) {
      if (value[index] !== keyQuote) continue;
      index++;
    } else if (!isCredentialLabelBoundary(value.charCodeAt(index))) {
      continue;
    } else if (value[index] === '"' || value[index] === "'") {
      index++;
    }
    while (/\s/.test(value[index])) index++;
    if (value[index] !== ":" && value[index] !== "=") continue;
    index++;
    while (/\s/.test(value[index])) index++;
    return { valueStart: index, failClosed };
  }
  return null;
}

function findQuotedCredentialEnd(value: string, start: number, quote: string): number {
  let index = start + 1;
  while (index < value.length) {
    if (value.charCodeAt(index) === 0x5c) {
      index += 2;
      continue;
    }
    if (value[index] === quote) return index;
    index++;
  }
  return -1;
}

function findUnquotedCredentialEnd(value: string, start: number): number {
  let end = start;
  while (end < value.length) {
    const char = value[end];
    if (/\s/.test(char) || char === '"' || char === "'" || char === "," || char === "}") break;
    end++;
  }
  return end;
}

function redactLabeledCredentialAssignments(value: string): string {
  const parts: string[] = [];
  let copyStart = 0;
  let index = 0;

  while (index < value.length) {
    const assignment = matchCredentialAssignmentAt(value, index);
    if (!assignment) {
      index++;
      continue;
    }

    const { valueStart, failClosed } = assignment;
    const quote = value[valueStart] === '"' || value[valueStart] === "'" ? value[valueStart] : "";
    if (quote) {
      const closingQuote = findQuotedCredentialEnd(value, valueStart, quote);
      parts.push(value.slice(copyStart, valueStart + 1), "[REDACTED]");
      if (closingQuote < 0) {
        copyStart = value.length;
        index = value.length;
      } else {
        parts.push(quote);
        copyStart = closingQuote + 1;
        index = copyStart;
      }
      continue;
    }

    // A leading backslash may be a serialized quote or another encoded
    // delimiter. Do not redact only that prefix and leave the value behind.
    const valueEnd =
      failClosed || value.charCodeAt(valueStart) === 0x5c
        ? value.length
        : findUnquotedCredentialEnd(value, valueStart);
    parts.push(value.slice(copyStart, valueStart), "[REDACTED]");
    copyStart = valueEnd;
    index = Math.max(valueEnd, valueStart + 1);
  }

  if (parts.length === 0) return value;
  parts.push(value.slice(copyStart));
  return parts.join("");
}

function redactPrivateKeyPemBlocks(value: string): string {
  // ASCII-only fold keeps offsets aligned even when the surrounding message
  // contains Unicode characters whose full uppercase form expands in length.
  const upperValue = value.replace(/[a-z]/g, (char) => char.toUpperCase());
  const beginPrefix = "-----BEGIN ";
  const parts: string[] = [];
  let copyStart = 0;
  let searchStart = 0;

  while (searchStart < value.length) {
    const blockStart = upperValue.indexOf(beginPrefix, searchStart);
    if (blockStart < 0) break;
    const labelStart = blockStart + beginPrefix.length;
    const headerEnd = upperValue.indexOf("-----", labelStart);
    if (headerEnd < 0) break;
    const label = upperValue.slice(labelStart, headerEnd).trim();
    if (!/^(?:[A-Z0-9]+ )*PRIVATE KEY$/.test(label)) {
      searchStart = headerEnd + 5;
      continue;
    }

    const endMarker = `-----END ${label}-----`;
    const closingStart = upperValue.indexOf(endMarker, headerEnd + 5);
    const blockEnd = closingStart < 0 ? value.length : closingStart + endMarker.length;
    parts.push(value.slice(copyStart, blockStart), "[REDACTED]");
    copyStart = blockEnd;
    searchStart = blockEnd;
  }

  if (parts.length === 0) return value;
  parts.push(value.slice(copyStart));
  return parts.join("");
}

export function redactSensitiveErrorText(value: string): string {
  const commonCredentialsRedacted = redactPrivateKeyPemBlocks(value)
    .replace(/data:[^,\s]+;base64,[A-Za-z0-9+/=_-]+/gi, "[REDACTED_DATA_URL]")
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [REDACTED]")
    .replace(STRONG_CREDENTIAL_TOKEN_GLOBAL, "[REDACTED]");
  return redactLabeledCredentialAssignments(commonCredentialsRedacted);
}

function coerceErrorText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "";
  try {
    return String(value);
  } catch {
    // Fail closed when an attacker-controlled toString/valueOf accessor throws.
    return "";
  }
}

/**
 * Strip stack-trace tails, credentials, and absolute source paths from a
 * client-visible error message.
 */
export function sanitizeErrorMessage(message: unknown): string {
  let str = coerceErrorText(message);
  if (str.length > MAX_ERROR_LEN) str = str.slice(0, MAX_ERROR_LEN);
  // Preserve quote provenance until hidden labels/delimiters have been
  // exposed and redacted, then decode safe quote escapes in the clean text.
  str = redactSensitiveErrorText(str);
  str = normalizeSecurityEscapes(str, false);
  str = redactSensitiveErrorText(redactErrorPaths(stripErrorStackTail(str)));
  str = normalizeSecurityEscapes(str, true);
  str = redactSensitiveErrorText(redactErrorPaths(stripErrorStackTail(str)));
  return hasResidualSecurityEscape(str) ? "[REDACTED]" : str;
}

const BLOCKED_KEYS =
  /stack|trace|path|file|cwd|dir|password|secret|token|key|authorization|cookie|credential|session(?!_?(?:count|status)$)/i;
const BLOCKED_CREDENTIAL_ALIAS_KEYS =
  /^(?:cf_clearance|__cf_bm|_cfuvid|_puid|sso|sso-rw|arena-auth-prod-v1(?:\.\d+)?)$/i;
const PROTOTYPE_CONTROL_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const MAX_DEPTH = 4;
const MAX_UPSTREAM_KEY_LEN = 256;

function isSafeUpstreamDetailKey(key: string): boolean {
  if (
    key.length === 0 ||
    key.length > MAX_UPSTREAM_KEY_LEN ||
    BLOCKED_KEYS.test(key) ||
    BLOCKED_CREDENTIAL_ALIAS_KEYS.test(key) ||
    PROTOTYPE_CONTROL_KEYS.has(key.toLowerCase())
  ) {
    return false;
  }
  return sanitizeErrorMessage(key) === key;
}

/**
 * Recursively sanitize an arbitrary JSON value from an upstream provider body.
 * Unsafe keys are dropped rather than renamed so sanitized-key collisions
 * cannot restore a secret under a public placeholder.
 */
export function sanitizeUpstreamDetails(value: unknown, depth = 0): unknown {
  if (depth > MAX_DEPTH) return "[truncated]";
  if (value === null || value === undefined) return null;
  if (typeof value === "string") return sanitizeErrorMessage(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) {
    return value.slice(0, 32).map((v) => sanitizeUpstreamDetails(v, depth + 1));
  }
  if (typeof value === "object") {
    const out = Object.create(null) as Record<string, unknown>;
    for (const [key, entryValue] of Object.entries(value as Record<string, unknown>)) {
      if (!isSafeUpstreamDetailKey(key)) continue;
      out[key] = sanitizeUpstreamDetails(entryValue, depth + 1);
    }
    return out;
  }
  return null;
}
