/**
 * Shared TLS client infrastructure — a factory-style base that consolidates
 * 6 nearly-identical per-provider TLS client files into one source of truth.
 *
 * Each provider file calls `createTlsClientModule(config)` to obtain its
 * provider-specific `tlsFetch` and `__setTlsFetchOverrideForTesting` exports.
 *
 * TailFile variants:
 *   A  — Uint8Array enqueue, includes EOF symbol, substring-based cleanup
 *        ChatGPT, Claude, Perplexity, Notion
 *   B1 — Buffer.from enqueue, excludes EOF symbol, inline drainRemaining loop
 *        Grok
 *   B2 — Buffer.from enqueue, excludes EOF symbol, extracted helpers
 *        LMArena
 *
 * Response validation:
 *   sse — checks `looksLikeSse(peek)`, falls back to buffered
 *         ChatGPT, Claude, Perplexity, Notion
 *   cf  — checks `isCloudflareChallenge(peek)` → 403, HTML → 502
 *         Grok, LMArena
 */

// ---------------------------------------------------------------------------
// Node imports
// ---------------------------------------------------------------------------
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { open, readFile, mkdtemp, stat } from "node:fs/promises";

// ---------------------------------------------------------------------------
// Proxy resolution — every provider file imports both of these
// ---------------------------------------------------------------------------
import { resolveProxyForRequest } from "../utils/proxyFetch.ts";
import { sanitizeErrorMessage } from "../utils/error.ts";
import { logger } from "../utils/logger.ts";
import { resolveTlsClientProxyUrl } from "./tlsClientProxy.ts";
import {
  buildNativeTlsClientOptions,
  resolveVerifiedTlsClientNativeLibrary,
} from "./tlsClientDownloadDir.ts";
import {
  acquireNativeTlsClientLease,
  activateNativeTlsClientLease,
  installNativeTlsClientExitHook,
  releaseNativeTlsClientLease,
  type NativeTlsClientLease,
} from "./tlsClientLifecycleRegistry.ts";
import {
  cleanupTlsClientStreamPath,
  createSanitizedTlsStreamError,
  createTlsClientTailStream,
  sanitizeTlsClientErrorMessage,
  type TlsClientTailVariant,
} from "./tlsClientStream.ts";
import { makeAbortError, raceWithTimeout, TlsClientHangError } from "./tlsClientTimeout.ts";

export { makeAbortError, raceWithTimeout, TlsClientHangError };

const tlsClientLogger = logger("TLSClient");
const DEFAULT_CLIENT_START_TIMEOUT_MS = 30_000;
const DEFAULT_PARTIAL_CLIENT_CLEANUP_TIMEOUT_MS = 5_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TlsResponseLike {
  status: number;
  headers: Record<string, string[]>;
  body: string;
}

export interface TlsFetchResult {
  status: number;
  headers: Headers;
  text: string | null;
  body: ReadableStream<Uint8Array> | null;
}

export interface TlsFetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
  timeoutMs?: number;
  stream?: boolean;
  streamEofSymbol?: string;
  byteResponse?: boolean;
  proxyUrl?: string;
}

// ---------------------------------------------------------------------------
// Factory config (one instance per provider stub)
// ---------------------------------------------------------------------------

export interface TlsClientConfig {
  /** Human-readable provider name for logs and error messages. */
  providerName: string;
  /** TLS profile identifier (e.g. "chrome_146") */
  tlsProfile: string;
  /** Default upstream domain for proxy resolution (e.g. "https://chatgpt.com") */
  domain: string;
  /** Temp directory prefix (e.g. "cgpt-stream-") */
  tempDirPrefix: string;
  /** EOF symbol for streaming (default "[DONE]") */
  streamEofSymbol?: string;
  /** Default timeout in ms (default 60_000) */
  defaultTimeoutMs?: number;
  /** Hard timeout grace period in ms (default 10_000) */
  hardTimeoutGraceMs?: number;
  /** First-byte timeout for waitForContent (default 5_000; ChatGPT uses 30_000) */
  firstByteTimeoutMs?: number;
  /**
   * TailFile variant:
   *   "A"  — Uint8Array enqueue, includes EOF, substring cleanup
   *   "B1" — Buffer.from enqueue, excludes EOF, inline drainRemaining
   *   "B2" — Buffer.from enqueue, excludes EOF, extracted helpers
   */
  tailFileVariant: TlsClientTailVariant;
  /**
   * Response validation mode:
   *   "sse" — check looksLikeSse → fall back to buffered
   *   "cf"  — check isCloudflareChallenge → 403, HTML → 502, else stream
   */
  responseValidation: "sse" | "cf";
  /**
   * Optional override for proxy resolution domain (e.g., LMArena uses
   * "https://arena.ai" hardcoded instead of the config domain).
   */
  proxyDomainOverride?: string;
  /**
   * Whether to export `isCloudflareChallenge` from the provider stub.
   * Grok, LMArena, Perplexity, Notion all export it.
   */
  exportCloudflareCheck: boolean;
  /**
   * Whether to expose `__tlsFetchStreamingForTesting` (ChatGPT only).
   */
  exposeStreamingForTesting?: boolean;
}

// ---------------------------------------------------------------------------
// Error classes
// ---------------------------------------------------------------------------

export class TlsClientUnavailableError extends Error {
  override name = "TlsClientUnavailableError";
}

function isTlsClientHangError(error: unknown): error is TlsClientHangError {
  try {
    return error instanceof TlsClientHangError;
  } catch {
    // A rejected Proxy may throw while instanceof walks its prototype chain.
    return false;
  }
}

// ---------------------------------------------------------------------------
// Shared helpers (identical across all 6 providers)
// ---------------------------------------------------------------------------

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function toHeaders(raw: Record<string, string[]> | null | undefined): Headers {
  const h = new Headers();
  for (const [k, vs] of Object.entries(raw || {})) {
    for (const v of vs) h.append(k, v);
  }
  return h;
}

/** Read up to N bytes from a file, returning the utf-8 decoded text. */
export async function readFirstBytes(path: string, n: number): Promise<string> {
  const fd = await open(path, "r");
  try {
    const buf = Buffer.alloc(n);
    const { bytesRead } = await fd.read(buf, 0, n, 0);
    return buf.subarray(0, bytesRead).toString("utf8");
  } finally {
    await fd.close().catch(() => {});
  }
}

/**
 * Wait for the streaming output file to exist AND contain at least one byte.
 * Returns false if the request settles before any bytes arrive (so the caller
 * can drain `requestPromise` and surface the real upstream status). Returns
 * true as soon as the file has data.
 */
export async function waitForContent(
  path: string,
  timeoutMs: number,
  requestPromise: Promise<TlsResponseLike>
): Promise<boolean> {
  let requestSettled = false;
  requestPromise.then(
    () => {
      requestSettled = true;
    },
    () => {
      requestSettled = true;
    }
  );
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const s = await stat(path);
      if (s.size > 0) return true;
    } catch {
      // file doesn't exist yet
    }
    if (requestSettled) return false;
    await sleep(25);
  }
  return false;
}

/**
 * Returns true if the peeked response body looks like an SSE stream — i.e.,
 * begins (after any leading whitespace) with one of the SSE field markers
 * (`data:`, `event:`, `id:`, `retry:`) or a comment line (`:`).
 */
export function looksLikeSse(text: string): boolean {
  const trimmed = text.replace(/^[\s\r\n]+/, "");
  if (!trimmed) return false;
  if (trimmed.startsWith(":")) return true;
  return /^(data|event|id|retry):/i.test(trimmed);
}

/**
 * Returns true if the response body is a Cloudflare challenge/interstitial page.
 */
export function isCloudflareChallenge(text: string | null | undefined): boolean {
  if (!text) return false;
  return /just a moment|window\._cf_chl_opt|challenges\.cloudflare\.com|attention required|cf-chl/i.test(
    text
  );
}

async function readTextFileIfExists(path: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch {
    return "";
  }
}

function sanitizeTlsFetchRejection(error: unknown): TlsResponseLike {
  return {
    status: 502,
    headers: {},
    body: sanitizeTlsClientErrorMessage(error),
  };
}

// ---------------------------------------------------------------------------
// Client lifecycle — TLS client singleton per provider
// ---------------------------------------------------------------------------

/**
 * Create a getClient function for a provider stub.
 * Uses dynamic `import("tls-client-node")` with `{ runtimeMode: "native" }`
 * and `client.start()`, matching the original per-provider lifecycle.
 */
type TlsClientConstructor = new (config: Record<string, unknown>) => {
  start: () => Promise<void>;
  request: (url: string, opts: Record<string, unknown>) => Promise<TlsResponseLike>;
  stop: () => Promise<void>;
};

type TlsClientInstance = InstanceType<TlsClientConstructor>;
type TlsClientRequestClient = Pick<TlsClientInstance, "request">;
type ManagedTlsClientGetter = {
  (): Promise<TlsClientInstance>;
  invalidate: (expectedClient: TlsClientRequestClient) => Promise<void>;
};

export function createGetClient(
  config: {
    providerName: string;
    tlsProfile?: string;
  },
  dependencies: {
    loadTlsClient?: () => Promise<{ TLSClient: TlsClientConstructor }>;
    resolveNativeLibrary?: () => Promise<string>;
    startTimeoutMs?: number;
    cleanupTimeoutMs?: number;
    installExitHook?: (hook: () => void) => void;
  } = {}
): ManagedTlsClientGetter {
  let clientPromise: Promise<TlsClientInstance> | null = null;
  let activeClient: TlsClientInstance | null = null;
  let invalidationPromise: Promise<void> | null = null;
  let invalidatingClient: TlsClientRequestClient | null = null;
  const clientLeases = new WeakMap<TlsClientInstance, NativeTlsClientLease>();
  const cleanupTimeoutMs =
    dependencies.cleanupTimeoutMs ?? DEFAULT_PARTIAL_CLIENT_CLEANUP_TIMEOUT_MS;

  const releaseClientLeaseBounded = async (
    lease: NativeTlsClientLease,
    warning: string
  ): Promise<void> => {
    try {
      await releaseNativeTlsClientLease(lease, cleanupTimeoutMs);
    } catch (stopErr) {
      tlsClientLogger.warn(warning, {
        provider: config.providerName,
        error: sanitizeErrorMessage(stopErr),
      });
    }
  };

  const getClient = async function getClient(): Promise<TlsClientInstance> {
    if (invalidationPromise) await invalidationPromise;
    if (!clientPromise) {
      clientPromise = (async () => {
        let TLSClientCtor: TlsClientConstructor;
        try {
          // tls-client-node uses a native binary loaded at runtime.
          // The dynamic import delays the binary load until first use — no
          // point crashing startup on machines where it's not installed.
          const mod = dependencies.loadTlsClient
            ? await dependencies.loadTlsClient()
            : ((await import("tls-client-node")) as { TLSClient: TlsClientConstructor });
          TLSClientCtor = mod.TLSClient;
        } catch {
          throw new TlsClientUnavailableError(
            `tls-client-node is not installed — cannot start TLS client for ${config.providerName}`
          );
        }
        let nativeLibraryPath: string;
        try {
          nativeLibraryPath = await (
            dependencies.resolveNativeLibrary ?? resolveVerifiedTlsClientNativeLibrary
          )();
        } catch (err) {
          tlsClientLogger.warn("Native binary verification failed", {
            provider: config.providerName,
            error: sanitizeErrorMessage(err),
          });
          throw new TlsClientUnavailableError(
            `tls-client native binary verification failed for ${config.providerName}`
          );
        }
        const tlsOptions: Record<string, unknown> = {
          ...buildNativeTlsClientOptions(nativeLibraryPath),
        };
        if (config.tlsProfile) {
          tlsOptions.clientIdentifier = config.tlsProfile;
        }
        let client: InstanceType<TlsClientConstructor> | undefined;
        let clientLease: NativeTlsClientLease | null = null;
        let rawStartPromise: Promise<void> | null = null;
        try {
          client = new TLSClientCtor(tlsOptions);
          const constructedClient = client;
          clientLease = await acquireNativeTlsClientLease(
            nativeLibraryPath,
            () => constructedClient.stop(),
            cleanupTimeoutMs
          );
          clientLeases.set(client, clientLease);
          // Start the native TLS client binding.
          rawStartPromise = client.start();
          await raceWithTimeout(
            rawStartPromise,
            dependencies.startTimeoutMs ?? DEFAULT_CLIENT_START_TIMEOUT_MS,
            null
          );
          activateNativeTlsClientLease(clientLease);
        } catch (err) {
          tlsClientLogger.warn("Native TLS client initialization failed", {
            provider: config.providerName,
            error: sanitizeErrorMessage(err),
          });
          if (client && clientLease) {
            if (rawStartPromise && isTlsClientHangError(err)) {
              const discardedLease = clientLease;
              const settledLateStart = rawStartPromise.then(
                () => {
                  activateNativeTlsClientLease(discardedLease);
                },
                (lateStartErr: unknown) => {
                  tlsClientLogger.warn("Timed-out native TLS client start later rejected", {
                    provider: config.providerName,
                    error: sanitizeErrorMessage(lateStartErr),
                  });
                }
              );
              void settledLateStart.then(() =>
                releaseClientLeaseBounded(
                  discardedLease,
                  "Late native TLS client initialization cleanup failed"
                )
              );
            } else {
              await releaseClientLeaseBounded(
                clientLease,
                "Partial native TLS client cleanup failed"
              );
            }
          }
          throw new TlsClientUnavailableError(
            `tls-client native initialization failed for ${config.providerName}`
          );
        }
        activeClient = client;
        installNativeTlsClientExitHook(dependencies.installExitHook);

        return client;
      })();
    }
    const pending = clientPromise;
    try {
      return await pending;
    } catch (err) {
      // A transient download/start failure must not poison this provider until
      // process restart. Concurrent callers still share the same pending attempt;
      // the next call creates a fresh one only after that attempt rejects.
      if (clientPromise === pending) clientPromise = null;
      throw err;
    }
  };

  getClient.invalidate = async (expectedClient: TlsClientRequestClient): Promise<void> => {
    if (invalidationPromise && invalidatingClient === expectedClient) {
      await invalidationPromise;
      return;
    }
    if (activeClient !== expectedClient) return;

    const pendingClient = clientPromise;
    activeClient = null;
    clientPromise = null;
    invalidatingClient = expectedClient;

    const cleanupPromise = (async () => {
      let client: TlsClientInstance | null = null;
      try {
        client = pendingClient ? await pendingClient : null;
      } catch {
        // A rejected pending client never became active, so no client lease exists to release here.
        return;
      }
      if (client !== expectedClient) return;
      const lease = clientLeases.get(client);
      if (!lease) return;

      await releaseClientLeaseBounded(lease, "Native TLS client invalidation cleanup failed");
    })();

    invalidationPromise = cleanupPromise.finally(() => {
      invalidationPromise = null;
      invalidatingClient = null;
    });
    await invalidationPromise;
  };

  return getClient;
}

/**
 * Resolve the proxy URL for a tls-client request. Per-call value wins;
 * falls back to the provider-specific env var and the dashboard proxy config.
 */
export function resolveProxyUrl(domain: string, perCall: string | undefined): string | undefined {
  return resolveTlsClientProxyUrl(domain, perCall, resolveProxyForRequest);
}

// ---------------------------------------------------------------------------
// Factory — creates provider-specific tlsFetch + helpers
// ---------------------------------------------------------------------------

export interface TlsClientModule {
  tlsFetch: (url: string, options: TlsFetchOptions) => Promise<TlsFetchResult>;
  __setTlsFetchOverrideForTesting: (
    fn: ((url: string, options: TlsFetchOptions) => Promise<TlsFetchResult>) | null
  ) => void;
  isCloudflareChallenge?: (text: string | null | undefined) => boolean;
  __tlsFetchStreamingForTesting?: (
    client: { request: (url: string, opts: Record<string, unknown>) => Promise<TlsResponseLike> },
    url: string,
    requestOptions: Record<string, unknown>,
    eofSymbol?: string,
    signal?: AbortSignal | null,
    hardTimeoutMs?: number,
    firstByteTimeoutMs?: number
  ) => Promise<TlsFetchResult>;
  __tlsFetchNonStreamingForTesting?: (
    client: { request: (url: string, opts: Record<string, unknown>) => Promise<TlsResponseLike> },
    url: string,
    requestOptions: Record<string, unknown>,
    signal?: AbortSignal | null,
    hardTimeoutMs?: number
  ) => Promise<TlsFetchResult>;
}

/**
 * Create a provider-specific TLS client module.
 *
 * Each provider file calls this once at module level and re-exports
 * the returned `tlsFetch` (as e.g. `tlsFetchChatGpt`) and
 * `__setTlsFetchOverrideForTesting`.
 */
export function createTlsClientModule(config: TlsClientConfig): TlsClientModule {
  const {
    providerName,
    tlsProfile,
    domain,
    tempDirPrefix,
    streamEofSymbol = "[DONE]",
    defaultTimeoutMs = 60_000,
    hardTimeoutGraceMs = 10_000,
    firstByteTimeoutMs = 5_000,
    tailFileVariant,
    responseValidation,
    proxyDomainOverride,
    exportCloudflareCheck,
  } = config;

  const getClient = createGetClient({ providerName, tlsProfile });

  async function resetClientCache(client: TlsClientRequestClient): Promise<void> {
    await getClient.invalidate(client);
  }

  let testOverride: ((url: string, options: TlsFetchOptions) => Promise<TlsFetchResult>) | null =
    null;

  const cleanupFn = (path: string): Promise<void> =>
    cleanupTlsClientStreamPath(tailFileVariant, path);

  async function tlsFetchStreaming(
    client: { request: (url: string, opts: Record<string, unknown>) => Promise<TlsResponseLike> },
    url: string,
    requestOptions: Record<string, unknown>,
    eofSymbol: string,
    signal: AbortSignal | null,
    hardTimeoutMs: number,
    firstByteMs: number = firstByteTimeoutMs
  ): Promise<TlsFetchResult> {
    const dir = await mkdtemp(join(tmpdir(), tempDirPrefix));
    const path = join(dir, `${randomUUID()}.sse`);

    const streamOpts: Record<string, unknown> = {
      ...requestOptions,
      streamOutputPath: path,
      streamOutputBlockSize: 1024,
      streamOutputEOFSymbol: eofSymbol,
    };

    let nativeRequest: Promise<TlsResponseLike>;
    try {
      nativeRequest = client.request(url, streamOpts);
    } catch (err) {
      await cleanupFn(path);
      throw createSanitizedTlsStreamError(err);
    }

    let resetOnHang = true;
    const requestPromise = raceWithTimeout(nativeRequest, hardTimeoutMs, signal).catch(
      async (err: unknown) => {
        if (resetOnHang && isTlsClientHangError(err)) {
          resetOnHang = false;
          await resetClientCache(client);
        }
        throw err;
      }
    );

    // Wait for the file to exist AND have at least one byte.
    const ready = await waitForContent(path, firstByteMs, requestPromise);
    if (!ready) {
      const r = await requestPromise.catch(sanitizeTlsFetchRejection);
      const fileText = await readTextFileIfExists(path);
      await cleanupFn(path);
      return {
        status: r.status,
        headers: toHeaders(r.headers),
        text: r.body || fileText,
        body: null,
      };
    }

    let peek: string;
    try {
      peek = await readFirstBytes(path, 256);
    } catch (err) {
      await cleanupFn(path);
      throw createSanitizedTlsStreamError(err);
    }

    if (responseValidation === "cf") {
      // Cloudflare challenge check
      if (isCloudflareChallenge(peek)) {
        await cleanupFn(path);
        return {
          status: 403,
          headers: new Headers({ "Content-Type": "text/html" }),
          text: peek,
          body: null,
        };
      }
      // HTML error page check
      if (peek.trimStart().startsWith("<")) {
        await cleanupFn(path);
        return {
          status: 502,
          headers: new Headers({ "Content-Type": "text/html" }),
          text: peek,
          body: null,
        };
      }
    } else {
      // SSE validation — if it doesn't look like SSE, return buffered
      if (!looksLikeSse(peek)) {
        const r = await requestPromise.catch(sanitizeTlsFetchRejection);
        const fileText = await readTextFileIfExists(path);
        await cleanupFn(path);
        return {
          status: r.status,
          headers: toHeaders(r.headers),
          text: r.body || fileText,
          body: null,
        };
      }
    }

    // Looks valid — create streaming response.
    const stream = createTlsClientTailStream({
      variant: tailFileVariant,
      path,
      eofSymbol,
      done: requestPromise,
      signal,
    });

    const contentType = responseValidation === "cf" ? "application/x-ndjson" : "text/event-stream";

    const headers = new Headers({
      "Content-Type": contentType,
      "Cache-Control": "no-cache",
    });
    return { status: 200, headers, text: null, body: stream };
  }

  async function tlsFetchNonStreaming(
    client: { request: (url: string, opts: Record<string, unknown>) => Promise<TlsResponseLike> },
    url: string,
    requestOptions: Record<string, unknown>,
    signal: AbortSignal | null,
    hardTimeoutMs: number
  ): Promise<TlsFetchResult> {
    let tlsResponse: TlsResponseLike;
    try {
      tlsResponse = await raceWithTimeout(
        client.request(url, requestOptions),
        hardTimeoutMs,
        signal
      );
    } catch (err) {
      if (isTlsClientHangError(err)) {
        await resetClientCache(client);
      }
      throw err;
    }
    if (signal?.aborted) throw makeAbortError(signal);
    return {
      status: tlsResponse.status,
      headers: toHeaders(tlsResponse.headers),
      text: tlsResponse.body,
      body: null,
    };
  }

  async function tlsFetch(url: string, options: TlsFetchOptions = {}): Promise<TlsFetchResult> {
    // Resolve proxyUrl early so test overrides and the real path both see it.
    const resolvedProxyUrl = resolveProxyUrl(proxyDomainOverride ?? domain, options.proxyUrl);
    if (testOverride) return testOverride(url, { ...options, proxyUrl: resolvedProxyUrl });

    if (options.signal?.aborted) {
      throw makeAbortError(options.signal);
    }
    const client = await getClient();
    if (options.signal?.aborted) {
      throw makeAbortError(options.signal);
    }

    const requestOptions: Record<string, unknown> = {
      method: options.method || "GET",
      headers: options.headers || {},
      body: options.body,
      tlsClientIdentifier: tlsProfile,
      timeoutMilliseconds: options.timeoutMs ?? defaultTimeoutMs,
      followRedirects: true,
      withRandomTLSExtensionOrder: true,
      proxyUrl: resolvedProxyUrl,
    };

    requestOptions.isByteResponse = options.byteResponse === true;

    if (options.stream) {
      return await tlsFetchStreaming(
        client,
        url,
        requestOptions,
        options.streamEofSymbol || streamEofSymbol,
        options.signal ?? null,
        (options.timeoutMs ?? defaultTimeoutMs) + hardTimeoutGraceMs,
        firstByteTimeoutMs
      );
    }

    return await tlsFetchNonStreaming(
      client,
      url,
      requestOptions,
      options.signal ?? null,
      (options.timeoutMs ?? defaultTimeoutMs) + hardTimeoutGraceMs
    );
  }

  const module: TlsClientModule = {
    tlsFetch,
    __setTlsFetchOverrideForTesting(fn) {
      testOverride = fn;
    },
  };

  if (exportCloudflareCheck) {
    module.isCloudflareChallenge = isCloudflareChallenge;
  }

  if (config.exposeStreamingForTesting) {
    module.__tlsFetchStreamingForTesting = (
      client,
      url,
      requestOptions,
      eofSymbol = "[DONE]",
      signal = null,
      hardTimeoutMs = defaultTimeoutMs + hardTimeoutGraceMs,
      firstByteMs = firstByteTimeoutMs
    ): Promise<TlsFetchResult> => {
      return tlsFetchStreaming(
        client,
        url,
        requestOptions,
        eofSymbol,
        signal,
        hardTimeoutMs,
        firstByteMs
      );
    };
    module.__tlsFetchNonStreamingForTesting = (
      client,
      url,
      requestOptions,
      signal = null,
      hardTimeoutMs = defaultTimeoutMs + hardTimeoutGraceMs
    ): Promise<TlsFetchResult> => {
      return tlsFetchNonStreaming(client, url, requestOptions, signal, hardTimeoutMs);
    };
  }

  return module;
}
