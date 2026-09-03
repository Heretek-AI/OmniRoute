// scripts/check/routeGuardConstants.mjs
// Shared reader for the compile-time constants in src/server/authz/routeGuard.ts.
//
// The security-tier gate cannot import the module itself (routeGuard pulls the
// server runtime — runtimeSettings → localDb → ioredis — and the gate runs on
// plain `node`), so it re-reads the constants from source. That text parse has
// to mirror `isLocalOnlyPath()` exactly, which means BOTH halves of the
// predicate:
//
//   LOCAL_ONLY_API_PREFIXES.some(...) || LOCAL_ONLY_API_PATTERNS.some(...)
//
// Reading only the prefix array made every route that is gated by a regex
// (e.g. /api/providers/volcengine-plan/connect/*) or by an imported constant
// (VNC_ROUTE_PREFIX) look unprotected, and the gate then demanded the removal
// of a CORRECT `x-loopback-only` annotation — a false positive that pushes the
// fix in the unsafe direction. Unresolvable tokens now throw instead of
// silently degrading into a literal.

import fs from "node:fs";
import path from "node:path";

/**
 * Strip `//` line comments without eating regex literals: a `//` preceded by a
 * backslash (`\/\/`) or a colon (`https://`) is content, not a comment.
 */
export function stripLineComments(text) {
  return text
    .split("\n")
    .map((line) => {
      for (let i = 0; i < line.length - 1; i++) {
        if (line[i] !== "/" || line[i + 1] !== "/") continue;
        const prev = i > 0 ? line[i - 1] : "";
        if (prev === "\\" || prev === ":") continue;
        return line.slice(0, i);
      }
      return line;
    })
    .join("\n");
}

/**
 * Entries of the array literal assigned to `constName`.
 *
 * Hand-rolled instead of a `\[([^\]]+)\]` capture because the pattern arrays
 * hold regex literals whose character classes (`[^/]`) contain the very
 * brackets and commas a naive capture/split would break on.
 */
export function parseArrayTokens(src, constName) {
  const decl = src.search(new RegExp(`export const ${constName}\\b`));
  if (decl < 0) return [];
  const open = src.indexOf("[", decl);
  if (open < 0) return [];

  let depth = 0;
  let end = -1;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (c === "[") depth++;
    else if (c === "]") {
      depth--;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  if (end < 0) return [];

  const body = stripLineComments(src.slice(open + 1, end));
  const tokens = [];
  let current = "";
  let nesting = 0;
  for (const c of body) {
    if (c === "," && nesting === 0) {
      tokens.push(current);
      current = "";
      continue;
    }
    if (c === "[" || c === "(" || c === "{") nesting++;
    else if (c === "]" || c === ")" || c === "}") nesting--;
    current += c;
  }
  tokens.push(current);
  return tokens.map((t) => t.trim()).filter(Boolean);
}

/** True for a token that is already a quoted string literal. */
function isStringLiteral(token) {
  return /^["'`]/.test(token);
}

function unquote(token) {
  return token.replace(/^["'`]|["'`]$/g, "");
}

/**
 * Resolve a bare identifier used inside a routeGuard array (e.g. VNC_ROUTE_PREFIX)
 * to its string value, following a local `const` or a named import. Returns null
 * when it cannot be resolved — callers must treat that as fatal.
 */
export function resolveIdentifier(name, { guardSrc, root, readFile = readFileIfExists } = {}) {
  const localDef = guardSrc.match(
    new RegExp(`(?:export\\s+)?const\\s+${name}\\b[^=]*=\\s*["'\`]([^"'\`]+)["'\`]`)
  );
  if (localDef) return localDef[1];

  const imported = guardSrc.match(
    new RegExp(`import\\s*\\{[^}]*\\b${name}\\b[^}]*\\}\\s*from\\s*["']([^"']+)["']`, "s")
  );
  if (!imported) return null;

  for (const candidate of moduleCandidates(imported[1], root)) {
    const src = readFile(candidate);
    if (!src) continue;
    const def = src.match(
      new RegExp(`export\\s+const\\s+${name}\\b[^=]*=\\s*["'\`]([^"'\`]+)["'\`]`)
    );
    if (def) return def[1];
  }
  return null;
}

/** Candidate on-disk paths for an import specifier (`@/x` → src/x, plus relatives). */
export function moduleCandidates(spec, root) {
  const base = spec.startsWith("@/")
    ? path.join(root, "src", spec.slice(2))
    : spec.startsWith(".")
      ? path.join(root, "src", "server", "authz", spec)
      : null;
  if (!base) return [];
  return [`${base}.ts`, `${base}.tsx`, path.join(base, "index.ts")];
}

function readFileIfExists(p) {
  try {
    return fs.readFileSync(p, "utf-8");
  } catch {
    return null;
  }
}

/** String entries of a prefix array, with identifiers resolved. Throws if any cannot be. */
export function readStringArray(src, constName, opts = {}) {
  const tokens = parseArrayTokens(src, constName);
  return tokens.map((token) => {
    if (isStringLiteral(token)) return unquote(token);
    const resolved = resolveIdentifier(token, { guardSrc: src, ...opts });
    if (resolved === null) {
      throw new Error(
        `[routeGuardConstants] could not resolve \`${token}\` used in ${constName}. ` +
          `Add a resolvable \`export const ${token} = "…"\` or inline the literal — ` +
          `leaving it unresolved would make the gate report protected routes as open.`
      );
    }
    return resolved;
  });
}

/** RegExp entries of a pattern array (regex literals only). */
export function readRegexArray(src, constName) {
  return parseArrayTokens(src, constName)
    .filter((token) => token.startsWith("/"))
    .map((token) => {
      const body = token.match(/^\/(.*)\/([a-z]*)$/s);
      if (!body)
        throw new Error(`[routeGuardConstants] unparsable regex in ${constName}: ${token}`);
      return new RegExp(body[1], body[2]);
    });
}

/**
 * OpenAPI templates use `{param}`; the runtime sees a concrete segment. Swap the
 * placeholders for a segment without slashes so `[^/]+`-style patterns match.
 */
export function concreteFromTemplate(pathStr) {
  return pathStr.replace(/\{[^}]*\}/g, "_param_");
}

/** Mirror of routeGuard.isLocalOnlyPath() for a documented (templated) path. */
export function isLocalOnlyDocPath(pathStr, { prefixes = [], patterns = [] } = {}) {
  const concrete = concreteFromTemplate(pathStr);
  const underPrefix = prefixes.some((prefix) => {
    const norm = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
    return pathStr === norm || pathStr.startsWith(`${norm}/`);
  });
  return underPrefix || patterns.some((re) => re.test(concrete) || re.test(pathStr));
}
