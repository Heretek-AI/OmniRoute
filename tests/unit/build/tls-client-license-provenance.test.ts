import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  syncStandaloneExtraModules,
  syncStandaloneNativeAssets,
} from "../../../scripts/build/assembleStandalone.mjs";
import { PACK_ARTIFACT_REQUIRED_PATHS } from "../../../scripts/build/pack-artifact-policy.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

const PRIMARY_SOURCE_HASHES = {
  "tls-client-node@0.2.0 LICENSE":
    "086c687026ff693ad76589dda1af12304a3ff33fc5f15030035ed62ef6a6d6eb",
  "tls-client-node@0.2.0 NOTICE":
    "80e5a526273788f2ace0164ec131daac697c54084add90855afdd03f5fadd3d3",
  "bogdanfinn/tls-client@v1.15.1 LICENSE":
    "7dab9a4dd66987fbe576d53c1ee047c193725df6f4fac67de315a127417fd151",
} as const;

function extractVerbatimBlock(document: string, label: keyof typeof PRIMARY_SOURCE_HASHES): string {
  const beginMarker = `<!-- BEGIN VERBATIM: ${label} -->`;
  const endMarker = `<!-- END VERBATIM: ${label} -->`;
  const markerStart = document.indexOf(beginMarker);
  assert.notEqual(markerStart, -1, `missing begin marker for ${label}`);
  const fenceStart = document.indexOf("```text\n", markerStart + beginMarker.length);
  assert.notEqual(fenceStart, -1, `missing text fence for ${label}`);
  const contentStart = fenceStart + "```text\n".length;
  const finish = document.indexOf("\n```", contentStart);
  assert.notEqual(finish, -1, `missing closing fence for ${label}`);
  assert.notEqual(document.indexOf(endMarker, finish), -1, `missing end marker for ${label}`);
  return document.slice(contentStart, finish);
}

test("distributed tls-client notices reproduce every primary license and NOTICE verbatim", () => {
  const notices = readFileSync(join(ROOT, "THIRD_PARTY_NOTICES.md"), "utf8");

  assert.match(notices, /not OSI-approved/i);

  for (const [label, expectedHash] of Object.entries(PRIMARY_SOURCE_HASHES)) {
    const text = extractVerbatimBlock(notices, label as keyof typeof PRIMARY_SOURCE_HASHES);
    assert.equal(
      createHash("sha256").update(text).digest("hex"),
      expectedHash,
      `${label} must remain byte-for-byte identical to its tagged primary source`
    );
  }
});

test("public comparison qualifies MIT as the project's own code license", () => {
  const comparison = readFileSync(join(ROOT, "docs", "diagrams", "comparison-table.svg"), "utf8");
  assert.doesNotMatch(comparison, /100% MIT/i);
  assert.match(comparison, /own code license/i);
  assert.match(comparison, /optional (?:third-party )?dependencies retain their licenses/i);
});

test("localized public comparisons use the canonical provider count", () => {
  const comparison = readFileSync(join(ROOT, "docs", "diagrams", "comparison-table.svg"), "utf8");
  const italian = readFileSync(join(ROOT, "docs", "i18n", "it", "README.md"), "utf8");
  const turkish = readFileSync(join(ROOT, "docs", "i18n", "tr", "README.md"), "utf8");
  const canonicalCount = comparison.match(/full set: (\d+) providers/i)?.[1];

  assert.ok(canonicalCount, "comparison SVG must expose the docs-counts-verified provider count");
  assert.match(italian, new RegExp(`OmniRoute: ${canonicalCount} provider\\b`));
  assert.match(turkish, new RegExp(`OmniRoute: ${canonicalCount} providers\\b`));
});

test("public privacy claims qualify MIT as the project's own code license", () => {
  const privacyDiagram = readFileSync(join(ROOT, "docs", "diagrams", "privacy-local.svg"), "utf8");
  const localizedReadmes = [
    readFileSync(join(ROOT, "docs", "i18n", "it", "README.md"), "utf8"),
    readFileSync(join(ROOT, "docs", "i18n", "tr", "README.md"), "utf8"),
    readFileSync(join(ROOT, "docs", "i18n", "ru", "README.md"), "utf8"),
  ].join("\n");

  assert.doesNotMatch(privacyDiagram, /MIT licensed (?:and|&amp;) fully open-source/i);
  assert.doesNotMatch(privacyDiagram, /never leak stack traces, paths or internals/i);
  assert.doesNotMatch(localizedReadmes, /MIT-licensed fully open-source/i);
  assert.doesNotMatch(localizedReadmes, /codice completamente open source con licenza MIT/i);
  assert.doesNotMatch(localizedReadmes, /MIT, fully open-source/i);
  assert.doesNotMatch(localizedReadmes, /sanitized errors that never leak internals/i);
  assert.doesNotMatch(localizedReadmes, /errori sanitizzati che non espongono dettagli interni/i);
  assert.match(privacyDiagram, /own code.*MIT/i);
  assert.match(privacyDiagram, /third-party components retain their own licenses/i);
  assert.match(privacyDiagram, /recognized filesystem paths/i);
  assert.match(localizedReadmes, /third-party components retain their own licenses/i);
  assert.match(localizedReadmes, /codice proprio di OmniRoute.*licenza MIT/i);
  assert.match(localizedReadmes, /сторонние компоненты.*лицензии/i);
  assert.match(localizedReadmes, /recognized filesystem paths/i);
  assert.match(localizedReadmes, /percorsi filesystem riconosciuti/i);
});

test("public privacy copy avoids absolute no-network and no-cloud promises", () => {
  const privacyDiagram = readFileSync(join(ROOT, "docs", "diagrams", "privacy-local.svg"), "utf8");
  const italian = readFileSync(join(ROOT, "docs", "i18n", "it", "README.md"), "utf8");
  const turkish = readFileSync(join(ROOT, "docs", "i18n", "tr", "README.md"), "utf8");
  const russian = readFileSync(join(ROOT, "docs", "i18n", "ru", "README.md"), "utf8");

  assert.doesNotMatch(privacyDiagram, /never phones home/i);
  assert.doesNotMatch(privacyDiagram, /\b0 cloud hops\b/i);
  assert.doesNotMatch(privacyDiagram, /no OmniRoute cloud in the request path/i);
  assert.doesNotMatch(privacyDiagram, /prompts go only to the providers you choose, nowhere else/i);
  assert.doesNotMatch(italian, /non comunica autonomamente con servizi cloud/i);
  assert.doesNotMatch(italian, /\b0 passaggi cloud\b/i);
  assert.doesNotMatch(turkish, /never phones home/i);
  assert.doesNotMatch(turkish, /\b0 cloud hops\b/i);
  assert.doesNotMatch(russian, /без «звонков домой»/i);
  assert.doesNotMatch(russian, /100% на вашем железе/i);
  assert.doesNotMatch(russian, /Нет cloud-hop OmniRoute/i);
  assert.doesNotMatch(russian, /промпты уходят только выбранным провайдерам/i);

  assert.match(privacyDiagram, /adds no OmniRoute-hosted prompt-processing hop/i);
  assert.match(privacyDiagram, /telemetry is disabled by default/i);
  assert.match(
    italian,
    /non aggiunge un passaggio di elaborazione dei prompt ospitato da OmniRoute/i
  );
  assert.match(italian, /telemetria (?:è )?disattivata per impostazione predefinita/i);
  assert.match(turkish, /adds no OmniRoute-hosted prompt-processing hop/i);
  assert.match(turkish, /telemetry is disabled by default/i);
  assert.match(
    russian,
    /не добавляет этап обработки промптов, размещённый на инфраструктуре OmniRoute/i
  );
  assert.match(russian, /телеметрия по умолчанию отключена/i);
  assert.match(
    russian,
    /Роутинг выполняется локально.*провайдеры остаются внешними upstream-сервисами/i
  );
});

test("public privacy copy qualifies dashboard identity and opt-in redactions", () => {
  const privacyDiagram = readFileSync(join(ROOT, "docs", "diagrams", "privacy-local.svg"), "utf8");

  assert.doesNotMatch(privacyDiagram, /No account(?: and|,) no sign-up/i);
  assert.doesNotMatch(privacyDiagram, /OmniRoute never asks who you are/i);
  assert.doesNotMatch(privacyDiagram, /payloads are never mutated by default/i);
  assert.match(privacyDiagram, /No OmniRoute-hosted account service/i);
  assert.match(
    privacyDiagram,
    /operator controls dashboard identity.*local password.*optional OIDC/i
  );
  assert.match(privacyDiagram, /These redactions run only when enabled/i);
  assert.match(
    privacyDiagram,
    /MCP tool calls &amp; admin actions logged in your SQLite, not ours/i
  );
});

test("localized privacy copy qualifies dashboard identity", () => {
  const italian = readFileSync(join(ROOT, "docs", "i18n", "it", "README.md"), "utf8");
  const turkish = readFileSync(join(ROOT, "docs", "i18n", "tr", "README.md"), "utf8");

  assert.doesNotMatch(italian, /nessun account o registrazione/i);
  assert.doesNotMatch(turkish, /no account or sign-up/i);
  assert.match(
    italian,
    /nessun servizio di account ospitato da OmniRoute.*l'operatore controlla l'identità della dashboard.*password locale.*OIDC opzionale/i
  );
  assert.match(
    turkish,
    /OmniRoute tarafından barındırılan bir hesap hizmeti yoktur.*operatör pano kimliğini.*yerel parola.*isteğe bağlı OIDC/i
  );
});

test("root README does not present third-party components as MIT-licensed", () => {
  const readme = readFileSync(join(ROOT, "README.md"), "utf8");

  assert.doesNotMatch(readme, /OmniRoute is MIT-licensed and self-hostable/i);
  assert.doesNotMatch(readme, /OmniRoute is MIT-licensed and maintained in the open/i);
  assert.match(readme, /OmniRoute's own code is MIT-licensed/i);
  assert.match(readme, /third-party (?:components|dependencies) retain their own licenses/i);
});

test("localized support copy qualifies MIT as the project's own code license", () => {
  const italian = readFileSync(join(ROOT, "docs", "i18n", "it", "README.md"), "utf8");
  const turkish = readFileSync(join(ROOT, "docs", "i18n", "tr", "README.md"), "utf8");

  assert.doesNotMatch(italian, /(?:^|\n)OmniRoute è distribuito con licenza MIT/i);
  assert.match(italian, /codice proprio di OmniRoute.*licenza MIT/i);
  assert.match(italian, /componenti di terze parti.*rispettive licenze/i);

  assert.doesNotMatch(turkish, /OmniRoute, MIT lisanslıdır/i);
  assert.match(turkish, /OmniRoute'un kendi kodu.*MIT lisanslıdır/i);
  assert.match(turkish, /üçüncü taraf bileşenler.*kendi lisanslarını korur/i);
});

test("TLS seed documentation distinguishes fallback from unsafe-entry failure", () => {
  const environmentReference = readFileSync(
    join(ROOT, "docs", "reference", "ENVIRONMENT.md"),
    "utf8"
  );

  assert.match(environmentReference, /absent file or SHA-256 mismatch falls through/i);
  assert.match(environmentReference, /symlink, non-regular file, or file above 64 MiB/i);
  assert.match(environmentReference, /unsafe entry and aborts resolution/i);
});

test("the distributed wrapper is pinned to the exact audited tls-client-node release", () => {
  const packageJson = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  const packageLock = JSON.parse(readFileSync(join(ROOT, "package-lock.json"), "utf8"));

  assert.equal(packageJson.optionalDependencies["tls-client-node"], "0.2.0");
  assert.equal(packageLock.packages[""].optionalDependencies["tls-client-node"], "0.2.0");
  assert.equal(packageLock.packages["node_modules/tls-client-node"].version, "0.2.0");
});

test("npm pack, standalone, and Docker transport notices, manifest, and the runtime seed", async () => {
  const packageJson = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  assert.ok(packageJson.files.includes("LICENSE"));
  assert.ok(packageJson.files.includes("THIRD_PARTY_NOTICES.md"));
  assert.ok(
    PACK_ARTIFACT_REQUIRED_PATHS.includes("dist/LICENSE"),
    "check:pack-artifact must require the project license inside standalone artifacts"
  );
  assert.ok(
    PACK_ARTIFACT_REQUIRED_PATHS.includes("THIRD_PARTY_NOTICES.md"),
    "check:pack-artifact must fail when the distributed notices are absent"
  );

  const projectRoot = mkdtempSync(join(tmpdir(), "tls-client-notices-project-"));
  const outDir = mkdtempSync(join(tmpdir(), "tls-client-notices-standalone-"));
  try {
    const expected = "legal-notice-sentinel\n";
    const projectLicense = "omniroute-license-sentinel\n";
    const manifest = readFileSync(
      join(ROOT, "open-sse", "config", "tlsClientNativeManifest.json"),
      "utf8"
    );
    const parsedManifest = JSON.parse(manifest) as {
      assets: Record<string, { file: string }>;
    };
    const nativeAsset = Object.values(parsedManifest.assets)[0];
    assert.ok(nativeAsset, "the pinned TLS manifest must contain at least one asset");
    const nativeBinary = "verified-native-seed-sentinel";
    writeFileSync(join(projectRoot, "THIRD_PARTY_NOTICES.md"), expected);
    writeFileSync(join(projectRoot, "LICENSE"), projectLicense);
    mkdirSync(join(projectRoot, "open-sse", "config"), { recursive: true });
    writeFileSync(
      join(projectRoot, "open-sse", "config", "tlsClientNativeManifest.json"),
      manifest
    );
    mkdirSync(join(projectRoot, "node_modules", "tls-client-node", "bin"), {
      recursive: true,
    });
    writeFileSync(
      join(projectRoot, "node_modules", "tls-client-node", "bin", nativeAsset.file),
      nativeBinary
    );
    writeFileSync(
      join(projectRoot, "node_modules", "tls-client-node", "bin", "untracked-extra.so"),
      "must-not-be-distributed"
    );
    await syncStandaloneExtraModules(projectRoot, undefined, { log() {} }, outDir);
    await syncStandaloneNativeAssets(projectRoot, undefined, { log() {} }, outDir, {
      tlsClientNativeAssets: {
        "provenance-fixture": {
          file: nativeAsset.file,
          sha256: "5637d0a3bf3174ac2be169c507151090fb0a4b6acc9917df8d4d2f904d5b6e81",
        },
      },
    });
    assert.equal(readFileSync(join(outDir, "THIRD_PARTY_NOTICES.md"), "utf8"), expected);
    assert.equal(readFileSync(join(outDir, "LICENSE"), "utf8"), projectLicense);
    assert.equal(
      readFileSync(join(outDir, "open-sse", "config", "tlsClientNativeManifest.json"), "utf8"),
      manifest
    );
    assert.equal(
      readFileSync(join(outDir, "runtime-assets", "tls-client", "bin", nativeAsset.file), "utf8"),
      nativeBinary
    );
    assert.throws(
      () =>
        readFileSync(
          join(outDir, "runtime-assets", "tls-client", "bin", "untracked-extra.so"),
          "utf8"
        ),
      /ENOENT/,
      "standalone assembly must not distribute non-manifest TLS native siblings"
    );
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
    rmSync(outDir, { recursive: true, force: true });
  }

  const dockerfile = readFileSync(join(ROOT, "Dockerfile"), "utf8");
  const bunDockerfile = readFileSync(join(ROOT, "Dockerfile.bun"), "utf8");
  assert.match(
    dockerfile,
    /COPY --from=builder \/app\/\.build\/next\/standalone \.\//,
    "Docker runner must consume the standalone tree that carries THIRD_PARTY_NOTICES.md"
  );
  assert.match(
    bunDockerfile,
    /COPY --from=builder(?: --chown=bun:bun)? \/app\/\.build\/next\/standalone \.\//,
    "Bun runner must consume the standalone tree that carries LICENSE and notices"
  );
});
