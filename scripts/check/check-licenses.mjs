#!/usr/bin/env node
// scripts/check/check-licenses.mjs
// Gate de license compliance — PLANO-QUALITY-GATES-FASE7.md, Task 20.
//
// Política: OmniRoute é MIT. Dependências de PRODUÇÃO com licença fora da allowlist SPDX
// e sem exceção registrada em .license-allowlist.json => FALHA (policy violation).
// devDependencies com licença não-padrão => advisory (impressas, não falham).
//
// Ferramenta: license-checker-rseidelsohn v4+ (node_modules/.bin/license-checker-rseidelsohn).
//
// Uso:
//   node scripts/check/check-licenses.mjs            # modo normal
//   node scripts/check/check-licenses.mjs --verbose  # lista todos os pacotes classificados
//   node scripts/check/check-licenses.mjs --json     # emite o raw JSON do license-checker
//
// Sair com código 0 = tudo OK (ou apenas advisory).
// Sair com código 1 = violação de política em dep de produção.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = process.cwd();
const ALLOWLIST_PATH = path.join(ROOT, "config/quality/.license-allowlist.json");
const CHECKER_BIN = path.join(ROOT, "node_modules", ".bin", "license-checker-rseidelsohn");

const VERBOSE = process.argv.includes("--verbose");
const PRINT_JSON = process.argv.includes("--json");

// ---------------------------------------------------------------------------
// Allowlist loading
// ---------------------------------------------------------------------------

/**
 * Loads and returns the license allowlist from .license-allowlist.json.
 *
 * @returns {{ allowed: string[], allowedExpressions: string[], exceptions: Record<string, {license:string, version?:string, justification:string, risk:string}> }}
 */
export function loadAllowlist() {
  if (!fs.existsSync(ALLOWLIST_PATH)) {
    throw new Error(
      `Allowlist not found: ${ALLOWLIST_PATH}. Create .license-allowlist.json first.`
    );
  }
  const raw = fs.readFileSync(ALLOWLIST_PATH, "utf-8");
  const parsed = JSON.parse(raw);
  return {
    allowed: parsed.allowed ?? [],
    allowedExpressions: parsed.allowedExpressions ?? [],
    exceptions: parsed.exceptions ?? {},
  };
}

// ---------------------------------------------------------------------------
// Classification logic (pure, testable)
// ---------------------------------------------------------------------------

/**
 * Classifies a package+license against the allowlist.
 *
 * @param {string} packageName - Package key including version when available, e.g. "tls-client-node@0.2.0"
 * @param {string} license     - License string from license-checker, e.g. "MPL-2.0"
 * @param {{ allowed: string[], allowedExpressions: string[], exceptions: Record<string,any> }} allowlist
 * @param {{ now?: Date }} [options]
 * @returns {{ status: "allowed" | "exception" | "denied", reason: string }}
 */
export function classifyLicense(packageName, license, allowlist, { now = new Date() } = {}) {
  const { allowed, allowedExpressions, exceptions } = allowlist;
  const baseName = stripVersion(packageName);

  // 1. A package-specific exception is an overlay on the global policy. It
  // must be evaluated first so a newly detected globally allowed SPDX id
  // cannot bypass the exception's exact-license, ownership, or expiry gates.
  if (exceptions[baseName]) {
    const exc = exceptions[baseName];
    if (typeof exc.license !== "string" || !exc.license.trim()) {
      return {
        status: "denied",
        reason: `invalid exception license for '${baseName}': expected a non-empty string`,
      };
    }
    if (license !== exc.license) {
      return {
        status: "denied",
        reason: `license '${license}' does not match exception license '${exc.license}' for '${baseName}'`,
      };
    }
    if (Object.prototype.hasOwnProperty.call(exc, "version")) {
      if (
        typeof exc.version !== "string" ||
        !exc.version.trim() ||
        exc.version !== exc.version.trim() ||
        /[@\s]/.test(exc.version)
      ) {
        return {
          status: "denied",
          reason: `invalid exception version for '${baseName}': expected an exact non-empty package version`,
        };
      }

      const versionSuffix = packageName.slice(baseName.length);
      if (!versionSuffix) {
        return {
          status: "denied",
          reason: `version-pinned exception for '${baseName}' requires package key '${baseName}@${exc.version}', but '${packageName}' has no version`,
        };
      }
      const detectedVersion = versionSuffix.startsWith("@") ? versionSuffix.slice(1) : "";
      if (!detectedVersion || /[@\s]/.test(detectedVersion)) {
        return {
          status: "denied",
          reason: `version-pinned exception for '${baseName}' cannot evaluate malformed package key '${packageName}'`,
        };
      }
      if (detectedVersion !== exc.version) {
        return {
          status: "denied",
          reason: `package version '${detectedVersion}' does not match exception version '${exc.version}' for '${baseName}'`,
        };
      }
    }
    if (exc.temporary === true) {
      if (typeof exc.owner !== "string" || !exc.owner.trim()) {
        return {
          status: "denied",
          reason: `temporary exception for '${baseName}' has no owner`,
        };
      }
      const reviewBy = exc.reviewBy;
      const isDateOnly = typeof reviewBy === "string" && /^\d{4}-\d{2}-\d{2}$/.test(reviewBy);
      const deadline = isDateOnly ? new Date(`${reviewBy}T23:59:59.999Z`) : new Date(NaN);
      const isRealCalendarDate =
        isDateOnly &&
        !Number.isNaN(deadline.getTime()) &&
        deadline.toISOString().slice(0, 10) === reviewBy;
      if (!isRealCalendarDate) {
        return {
          status: "denied",
          reason: `temporary exception for '${baseName}' has invalid reviewBy metadata`,
        };
      }
      if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
        return {
          status: "denied",
          reason: `temporary exception for '${baseName}' cannot be evaluated with an invalid clock`,
        };
      }
      if (now.getTime() > deadline.getTime()) {
        return {
          status: "denied",
          reason: `temporary exception for '${baseName}' expired at reviewBy=${reviewBy}`,
        };
      }
    }
    return {
      status: "exception",
      reason: `exception: ${exc.justification} [risk=${exc.risk}]`,
    };
  }

  // 2. Direct SPDX match
  if (allowed.includes(license)) {
    return { status: "allowed", reason: `SPDX match: ${license}` };
  }

  // 3. Expression match (e.g. "(MIT OR Apache-2.0)")
  if (allowedExpressions.includes(license)) {
    return { status: "allowed", reason: `allowed expression: ${license}` };
  }

  // 4. Denied
  return {
    status: "denied",
    reason: `license '${license}' not in allowlist and no exception registered for '${baseName}'`,
  };
}

/**
 * Strips the @version suffix from a package key returned by license-checker.
 * e.g. "lightningcss@1.32.0" => "lightningcss"
 *      "@img/sharp-libvips-linux-x64@1.2.4" => "@img/sharp-libvips-linux-x64"
 *
 * @param {string} pkgKey - Package key as returned by license-checker
 * @returns {string}
 */
export function stripVersion(pkgKey) {
  // Handle scoped packages: @scope/name@version
  const scopedMatch = pkgKey.match(/^(@[^/]+\/[^@]+)(?:@.*)?$/);
  if (scopedMatch) return scopedMatch[1];
  // Regular: name@version
  const regularMatch = pkgKey.match(/^([^@]+)(?:@.*)?$/);
  if (regularMatch) return regularMatch[1];
  return pkgKey;
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/**
 * Runs license-checker-rseidelsohn --production and returns parsed JSON.
 *
 * @returns {Record<string, { licenses: string, path: string }>}
 */
function runLicenseChecker() {
  if (!fs.existsSync(CHECKER_BIN)) {
    throw new Error(
      `license-checker-rseidelsohn not found at ${CHECKER_BIN}.\n` +
        `Install it: npm install --save-dev license-checker-rseidelsohn`
    );
  }

  const output = execFileSync(CHECKER_BIN, ["--production", "--json"], {
    cwd: ROOT,
    encoding: "utf-8",
    maxBuffer: 32 * 1024 * 1024, // 32 MB
  });

  return JSON.parse(output);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  /** @type {Record<string, { licenses: string, path: string }>} */
  let licenseData;
  try {
    licenseData = runLicenseChecker();
  } catch (err) {
    console.error("[check-licenses] Falha ao rodar license-checker-rseidelsohn:");
    console.error(err.message ?? err);
    process.exitCode = 1;
    return;
  }

  if (PRINT_JSON) {
    console.log(JSON.stringify(licenseData, null, 2));
    return;
  }

  /** @type {{ allowed: string[], allowedExpressions: string[], exceptions: Record<string,any> }} */
  let allowlist;
  try {
    allowlist = loadAllowlist();
  } catch (err) {
    console.error("[check-licenses]", err.message);
    process.exitCode = 1;
    return;
  }

  const violations = [];
  const exceptions = [];
  const advisory = [];
  let allowedCount = 0;

  for (const [pkgKey, info] of Object.entries(licenseData)) {
    const license = info.licenses ?? "UNKNOWN";
    const result = classifyLicense(pkgKey, license, allowlist);

    if (result.status === "allowed") {
      allowedCount++;
      if (VERBOSE) {
        console.log(`  ✓ ${pkgKey}: ${license}`);
      }
    } else if (result.status === "exception") {
      exceptions.push({ pkgKey, license, reason: result.reason });
    } else {
      violations.push({ pkgKey, license, reason: result.reason });
    }
  }

  const total = Object.keys(licenseData).length;

  // Print summary
  console.log(`[check-licenses] Escaneados ${total} pacotes de produção.`);
  console.log(`  Permitidos: ${allowedCount}`);
  console.log(`  Exceções registradas: ${exceptions.length}`);
  console.log(`  Violações de política: ${violations.length}`);

  // Print exceptions (informational)
  if (exceptions.length > 0) {
    console.log(
      "\n[check-licenses] Exceções registradas (não bloqueantes, revisar periodicamente):"
    );
    for (const { pkgKey, license } of exceptions) {
      const baseName = stripVersion(pkgKey);
      const exc = allowlist.exceptions[baseName];
      const riskTag = exc?.risk === "medium" ? " ⚠️  RISK=medium" : "";
      console.log(`  ⚑  ${pkgKey}: ${license}${riskTag}`);
      if (exc?.risk === "medium") {
        console.log(`       → ${exc.justification}`);
      }
    }
  }

  // Print advisory (devDep non-standard — empty here since we run --production)
  if (advisory.length > 0) {
    console.log("\n[check-licenses] Advisory (devDeps com licença não-padrão):");
    for (const { pkgKey, license } of advisory) {
      console.log(`  ℹ  ${pkgKey}: ${license}`);
    }
  }

  // Print violations and fail
  if (violations.length > 0) {
    console.error(
      "\n[check-licenses] ❌ VIOLAÇÕES DE POLÍTICA — deps de produção com licença não permitida:"
    );
    for (const { pkgKey, license, reason } of violations) {
      console.error(`  ✗ ${pkgKey}: ${license}`);
      console.error(`    → ${reason}`);
    }
    console.error(
      "\nAdicione a licença à allowlist 'allowed' em .license-allowlist.json (se SPDX-permissiva)\n" +
        "ou registre uma exceção por-pacote em 'exceptions' com justificativa e 'reviewAt'.\n" +
        "NÃO mascare copyleft forte sem registrar a justificativa. Ver PLANO-QUALITY-GATES-FASE7.md § Task 20."
    );
    process.exitCode = 1;
    return;
  }

  console.log(
    "\n[check-licenses] ✅ Todos os pacotes de produção estão em conformidade com a política de licenças."
  );
}

// Run only when invoked directly (not when imported by tests)
const isMain =
  process.argv[1] === pathToFileURL(import.meta.url).pathname ||
  process.argv[1]?.endsWith("check-licenses.mjs");

if (isMain) {
  main();
}
