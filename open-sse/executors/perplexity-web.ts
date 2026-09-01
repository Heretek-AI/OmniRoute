/**
 * PerplexityWebExecutor — Perplexity Web Session Provider
 *
 * Routes requests through Perplexity's internal SSE API using a Pro/Max
 * subscription session cookie or JWT, translating between OpenAI chat
 * completions format and Perplexity's internal protocol.
 */

import { BaseExecutor, type ExecuteInput, type ProviderCredentials } from "./base.ts";
import {
  tlsFetchPerplexity,
  isCloudflareChallenge,
  TlsClientUnavailableError,
  type TlsFetchResult,
} from "../services/perplexityTlsClient.ts";
import { prepareToolMessages } from "../translator/webTools.ts";
import { buildToolModeResponse } from "./chatgptWebTools.ts";
import { projectPublicErrorIdentifier, sanitizeErrorMessage } from "../utils/error.ts";
import { buildSessionCookieHeader, mergeRefreshedCookie } from "../utils/nextAuthCookie.ts";
import {
  PPLX_SSE_ENDPOINT,
  PPLX_USER_AGENT,
  PPLX_STREAM_EOF_SYMBOL,
  MODEL_MAP,
  THINKING_MAP,
  cleanResponse,
  parseOpenAIMessages,
  buildPplxRequestBody,
  buildQuery,
  extractContent,
  PPLX_ADVANCED_QUOTA_DEFAULT_RESET_SECONDS,
  sseChunk,
  type ContentChunk,
} from "./perplexity-web/protocol.ts";

// ─── Session continuity ─────────────────────────────────────────────────────

const SESSION_MAX_AGE_MS = 3600_000;
const SESSION_MAX_ENTRIES = 200;
const PPLX_PUBLIC_UPSTREAM_ERROR = "Perplexity upstream error";

function sanitizePerplexityUpstreamError(message: unknown): string {
  const sanitized = sanitizeErrorMessage(message);
  return sanitized.trim() && !/^(?:[A-Za-z_$][\w$]*)?Error:\s*$/.test(sanitized)
    ? sanitized
    : PPLX_PUBLIC_UPSTREAM_ERROR;
}

function isTlsClientUnavailableError(error: unknown): error is TlsClientUnavailableError {
  try {
    return error instanceof TlsClientUnavailableError;
  } catch {
    // A rejected Proxy may throw while instanceof walks its prototype chain.
    return false;
  }
}

export function toPublicPerplexityErrorCode(errorCode: unknown, isQuota: boolean): string {
  if (isQuota) return "quota_exhausted";
  if (typeof errorCode !== "string" || errorCode.length > 64) return "PPLX_ERROR";
  return projectPublicErrorIdentifier(errorCode, "PPLX_ERROR");
}

interface SessionEntry {
  backendUuid: string;
  ts: number;
}

const sessionCache = new Map<string, SessionEntry>();

function sessionKey(history: Array<{ role: string; content: string }>): string {
  const parts = history.map((h) => `${h.role}:${h.content}`).join("\n");
  let hash = 0x811c9dc5;
  for (let i = 0; i < parts.length; i++) {
    hash ^= parts.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

function sessionLookup(history: Array<{ role: string; content: string }>): string | null {
  if (history.length === 0) return null;
  const key = sessionKey(history);
  const entry = sessionCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > SESSION_MAX_AGE_MS) {
    sessionCache.delete(key);
    return null;
  }
  return entry.backendUuid;
}

function sessionStore(
  history: Array<{ role: string; content: string }>,
  currentMsg: string,
  responseText: string,
  backendUuid: string | null
): void {
  if (!backendUuid) return;
  const full = [
    ...history,
    { role: "user", content: currentMsg },
    { role: "assistant", content: responseText },
  ];
  const key = sessionKey(full);
  sessionCache.set(key, { backendUuid, ts: Date.now() });
  if (sessionCache.size > SESSION_MAX_ENTRIES) {
    let oldestKey: string | null = null;
    let oldestTs = Infinity;
    for (const [k, v] of sessionCache) {
      if (v.ts < oldestTs) {
        oldestTs = v.ts;
        oldestKey = k;
      }
    }
    if (oldestKey) sessionCache.delete(oldestKey);
  }
}

const PPLX_STREAM_PREFLIGHT_MAX_CHUNKS = 32;
const PPLX_STREAM_PREFLIGHT_TIMEOUT_MS = 250;
const PPLX_STREAM_PREFLIGHT_TIMED_OUT = Symbol("pplx-stream-preflight-timeout");

async function waitForPreflightChunk(
  pending: Promise<IteratorResult<ContentChunk>>,
  timeoutMs: number
): Promise<IteratorResult<ContentChunk> | typeof PPLX_STREAM_PREFLIGHT_TIMED_OUT> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      pending,
      new Promise<typeof PPLX_STREAM_PREFLIGHT_TIMED_OUT>((resolve) => {
        timer = setTimeout(() => resolve(PPLX_STREAM_PREFLIGHT_TIMED_OUT), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function* replayContentChunks(
  buffered: ContentChunk[],
  pending: Promise<IteratorResult<ContentChunk>> | null,
  remaining: AsyncGenerator<ContentChunk>
): AsyncGenerator<ContentChunk> {
  try {
    yield* buffered;
    if (pending) {
      const nextChunk = await pending;
      if (!nextChunk.done) yield nextChunk.value;
    }
    yield* remaining;
  } finally {
    // Releasing the iterator unlocks the upstream reader; cleanup cannot replace the SSE outcome.
    await remaining.return(undefined).catch(() => {});
  }
}

interface ContentPreflightResult {
  quotaError: ContentChunk | null;
  contentChunks: AsyncIterable<ContentChunk> | null;
}

async function preflightContentChunks(
  source: AsyncGenerator<ContentChunk>
): Promise<ContentPreflightResult> {
  const buffered: ContentChunk[] = [];
  const deadline = Date.now() + PPLX_STREAM_PREFLIGHT_TIMEOUT_MS;

  for (let index = 0; index < PPLX_STREAM_PREFLIGHT_MAX_CHUNKS; index += 1) {
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) {
      return { quotaError: null, contentChunks: replayContentChunks(buffered, null, source) };
    }

    const pending = source.next();
    const nextChunk = await waitForPreflightChunk(pending, remainingMs);
    if (nextChunk === PPLX_STREAM_PREFLIGHT_TIMED_OUT) {
      return { quotaError: null, contentChunks: replayContentChunks(buffered, pending, source) };
    }
    if (nextChunk.done) {
      return { quotaError: null, contentChunks: replayContentChunks(buffered, null, source) };
    }

    const chunk = nextChunk.value;
    buffered.push(chunk);
    if (chunk.error && isPerplexityQuotaError(chunk)) {
      // Closing the primed generator releases its reader; cleanup must not mask the quota response.
      await source.return(undefined).catch(() => {});
      return { quotaError: chunk, contentChunks: null };
    }
    if (chunk.error || chunk.delta || chunk.answer || chunk.done) {
      return { quotaError: null, contentChunks: replayContentChunks(buffered, null, source) };
    }
  }

  // Once either bound is exhausted, preserve the original SSE 200 behavior for later errors.
  return { quotaError: null, contentChunks: replayContentChunks(buffered, null, source) };
}

async function* throwContentError(error: unknown): AsyncGenerator<ContentChunk> {
  throw error;
}

function buildStreamingResponse(
  contentChunks: AsyncIterable<ContentChunk>,
  model: string,
  cid: string,
  created: number,
  history: Array<{ role: string; content: string }>,
  currentMsg: string,
  onCancel?: (reason: unknown) => void
): Response {
  const encoder = new TextEncoder();
  const contentIterator = contentChunks[Symbol.asyncIterator]();
  const ownedChunks = { [Symbol.asyncIterator]: () => contentIterator };
  let cancelled = false;

  const pump = async (controller: ReadableStreamDefaultController<Uint8Array>) => {
    try {
      // Initial role chunk
      controller.enqueue(
        encoder.encode(
          sseChunk({
            id: cid,
            object: "chat.completion.chunk",
            created,
            model,
            system_fingerprint: null,
            choices: [
              { index: 0, delta: { role: "assistant" }, finish_reason: null, logprobs: null },
            ],
          })
        )
      );

      let fullAnswer = "";
      let respBackendUuid: string | null = null;

      for await (const chunk of ownedChunks) {
        if (chunk.backendUuid) respBackendUuid = chunk.backendUuid;

        if (chunk.error) {
          const publicError = sanitizePerplexityUpstreamError(chunk.error);
          controller.enqueue(
            encoder.encode(
              sseChunk({
                id: cid,
                object: "chat.completion.chunk",
                created,
                model,
                system_fingerprint: null,
                choices: [
                  {
                    index: 0,
                    delta: { content: `[Error: ${publicError}]` },
                    finish_reason: null,
                    logprobs: null,
                  },
                ],
              })
            )
          );
          break;
        }

        if (chunk.thinking) {
          controller.enqueue(
            encoder.encode(
              sseChunk({
                id: cid,
                object: "chat.completion.chunk",
                created,
                model,
                system_fingerprint: null,
                choices: [
                  {
                    index: 0,
                    delta: { reasoning_content: chunk.thinking + "\n" },
                    finish_reason: null,
                    logprobs: null,
                  },
                ],
              })
            )
          );
          continue;
        }

        if (chunk.done) {
          fullAnswer = chunk.answer || fullAnswer;
          break;
        }

        let dt = chunk.delta || "";
        if (dt) {
          dt = cleanResponse(dt, false);
          if (dt) {
            controller.enqueue(
              encoder.encode(
                sseChunk({
                  id: cid,
                  object: "chat.completion.chunk",
                  created,
                  model,
                  system_fingerprint: null,
                  choices: [
                    { index: 0, delta: { content: dt }, finish_reason: null, logprobs: null },
                  ],
                })
              )
            );
          }
        }
        if (chunk.answer) fullAnswer = chunk.answer;
      }
      if (cancelled) return;

      // Stop chunk
      controller.enqueue(
        encoder.encode(
          sseChunk({
            id: cid,
            object: "chat.completion.chunk",
            created,
            model,
            system_fingerprint: null,
            choices: [{ index: 0, delta: {}, finish_reason: "stop", logprobs: null }],
          })
        )
      );
      controller.enqueue(encoder.encode("data: [DONE]\n\n"));

      sessionStore(history, currentMsg, cleanResponse(fullAnswer), respBackendUuid);
    } catch (err) {
      if (cancelled) return;
      controller.enqueue(
        encoder.encode(
          sseChunk({
            id: cid,
            object: "chat.completion.chunk",
            created,
            model,
            system_fingerprint: null,
            choices: [
              {
                index: 0,
                delta: {
                  content: `[Stream error: ${sanitizePerplexityUpstreamError(err)}]`,
                },
                finish_reason: "stop",
                logprobs: null,
              },
            ],
          })
        )
      );
      controller.enqueue(encoder.encode("data: [DONE]\n\n"));
    } finally {
      try {
        controller.close();
      } catch {
        // Consumer cancellation or an already-closed stream must not replace the terminal outcome.
      }
    }
  };

  const stream = new ReadableStream(
    {
      start(controller) {
        // The pump must not own start(): cancellation is unavailable until start() settles.
        void pump(controller);
      },
      async cancel(reason) {
        cancelled = true;
        onCancel?.(reason);
        try {
          await contentIterator.return?.(undefined);
        } catch {
          // Upstream cleanup cannot replace the caller's already-selected cancellation outcome.
        }
      },
    },
    { highWaterMark: 16384 }
  );
  return new Response(stream, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "X-Accel-Buffering": "no",
    },
  });
}

function buildUpstreamErrorResponse(chunk: ContentChunk): Response {
  // Quota exhaustion → 429 + reset_seconds so OmniRoute marks rate_limited_until
  // and VibeProxy limit badges / rotation skip parse the same shape as model_cooldown.
  const isQuota = isPerplexityQuotaError(chunk);
  const resetSeconds =
    typeof chunk.resetSeconds === "number" && chunk.resetSeconds > 0
      ? chunk.resetSeconds
      : isQuota
        ? PPLX_ADVANCED_QUOTA_DEFAULT_RESET_SECONDS
        : undefined;
  const error: Record<string, unknown> = {
    message: sanitizePerplexityUpstreamError(chunk.error),
    type: isQuota ? "quota_exhausted" : "upstream_error",
    code: toPublicPerplexityErrorCode(chunk.errorCode, isQuota),
  };
  if (resetSeconds !== undefined) error.reset_seconds = resetSeconds;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (resetSeconds !== undefined) headers["Retry-After"] = String(resetSeconds);
  return new Response(JSON.stringify({ error }), { status: isQuota ? 429 : 502, headers });
}

function isPerplexityQuotaError(chunk: ContentChunk): boolean {
  return (
    chunk.errorCode === "quota_exhausted" ||
    /quota exhausted/i.test(chunk.error || "") ||
    (typeof chunk.resetSeconds === "number" && chunk.resetSeconds > 0)
  );
}

async function buildNonStreamingResponse(
  eventStream: ReadableStream<Uint8Array>,
  model: string,
  cid: string,
  created: number,
  history: Array<{ role: string; content: string }>,
  currentMsg: string,
  signal?: AbortSignal | null
): Promise<Response> {
  let fullAnswer = "";
  let respBackendUuid: string | null = null;
  const thinkingParts: string[] = [];

  for await (const chunk of extractContent(eventStream, signal)) {
    if (chunk.backendUuid) respBackendUuid = chunk.backendUuid;
    if (chunk.error) {
      return buildUpstreamErrorResponse(chunk);
    }
    if (chunk.thinking) {
      thinkingParts.push(chunk.thinking);
      continue;
    }
    if (chunk.done) {
      fullAnswer = chunk.answer || fullAnswer;
      break;
    }
    if (chunk.answer) fullAnswer = chunk.answer;
  }

  fullAnswer = cleanResponse(fullAnswer);
  sessionStore(history, currentMsg, fullAnswer, respBackendUuid);

  const reasoningContent = thinkingParts.length > 0 ? thinkingParts.join("\n") : undefined;
  const msg: Record<string, unknown> = { role: "assistant", content: fullAnswer };
  if (reasoningContent) msg.reasoning_content = reasoningContent;

  const promptTokens = Math.ceil(currentMsg.length / 4);
  const completionTokens = Math.ceil(fullAnswer.length / 4);

  return new Response(
    JSON.stringify({
      id: cid,
      object: "chat.completion",
      created,
      model,
      system_fingerprint: null,
      choices: [{ index: 0, message: msg, finish_reason: "stop", logprobs: null }],
      usage: {
        prompt_tokens: promptTokens,
        completion_tokens: completionTokens,
        total_tokens: promptTokens + completionTokens,
      },
    }),
    { status: 200, headers: { "Content-Type": "application/json" } }
  );
}

async function persistRotatedSessionCookie(
  cookie: string,
  setCookieHeader: string | null,
  credentials: ProviderCredentials,
  onCredentialsRefreshed: ExecuteInput["onCredentialsRefreshed"],
  log: ExecuteInput["log"]
): Promise<void> {
  if (!onCredentialsRefreshed) return;
  try {
    const refreshed = mergeRefreshedCookie(cookie, setCookieHeader);
    if (refreshed && refreshed !== cookie) {
      await onCredentialsRefreshed({ ...credentials, apiKey: refreshed });
    }
  } catch (err) {
    const publicError = sanitizePerplexityUpstreamError(err);
    log?.warn?.("PPLX-WEB", `Failed to persist refreshed cookie: ${publicError}`);
  }
}

// ─── Executor ───────────────────────────────────────────────────────────────

export class PerplexityWebExecutor extends BaseExecutor {
  constructor() {
    super("perplexity-web", { id: "perplexity-web", baseUrl: PPLX_SSE_ENDPOINT });
  }

  async execute({
    model,
    body,
    stream,
    credentials,
    signal,
    log,
    onCredentialsRefreshed,
  }: ExecuteInput) {
    const bodyObj = (body || {}) as Record<string, unknown>;
    const rawMessages = bodyObj.messages as Array<Record<string, unknown>> | undefined;
    if (!rawMessages || !Array.isArray(rawMessages) || rawMessages.length === 0) {
      const errResp = new Response(
        JSON.stringify({
          error: { message: "Missing or empty messages array", type: "invalid_request" },
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
      return { response: errResp, url: PPLX_SSE_ENDPOINT, headers: {}, transformedBody: body };
    }

    const { hasTools, requestedTools, effectiveMessages } = prepareToolMessages(
      bodyObj,
      rawMessages as Array<{ role: string; content: unknown }>
    );

    // Resolve thinking mode
    const thinking =
      bodyObj.thinking === true ||
      (bodyObj.reasoning_effort != null && bodyObj.reasoning_effort !== "none");

    let pplxMode: string;
    let modelPref: string;
    if (thinking && THINKING_MAP[model]) {
      // "copilot", not "search": the backend downgrades "search" to CONCISE and drops
      // model_preference, so the thinking variant would fail the same way the catalog
      // models do (see the note above MODEL_MAP).
      pplxMode = "copilot";
      modelPref = THINKING_MAP[model];
      log?.info?.("PPLX-WEB", `Thinking mode → ${model} using ${modelPref}`);
    } else if (MODEL_MAP[model]) {
      [pplxMode, modelPref] = MODEL_MAP[model];
    } else {
      pplxMode = "copilot";
      modelPref = model;
      log?.info?.("PPLX-WEB", `Unmapped model ${model}, using as raw preference`);
    }

    // Parse messages and check session continuity
    const parsed = parseOpenAIMessages(effectiveMessages);
    const followUpUuid = sessionLookup(parsed.history);
    if (followUpUuid) {
      log?.info?.("PPLX-WEB", "Continuing existing session");
    }

    const query = buildQuery(parsed, followUpUuid);
    if (!query.trim()) {
      const errResp = new Response(
        JSON.stringify({
          error: { message: "Empty query after processing", type: "invalid_request" },
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
      return { response: errResp, url: PPLX_SSE_ENDPOINT, headers: {}, transformedBody: body };
    }

    // Build Perplexity request
    const requestId = crypto.randomUUID();
    const pplxBody = buildPplxRequestBody(
      query,
      parsed.currentMsg,
      pplxMode,
      modelPref,
      followUpUuid,
      requestId
    );

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "text/event-stream",
      Origin: "https://www.perplexity.ai",
      Referer: "https://www.perplexity.ai/",
      "User-Agent": PPLX_USER_AGENT,
      // Current app request headers (replaced the stale X-App-ApiVersion/X-App-ApiClient pair,
      // which the new endpoint no longer expects and which contributed to HTTP 400).
      "x-perplexity-request-endpoint": PPLX_SSE_ENDPOINT,
      "x-perplexity-request-reason": "ask-query-state-provider",
      "x-perplexity-request-try-number": "1",
      "x-request-id": requestId,
    };

    const cookieBlob = credentials.apiKey ?? "";
    if (credentials.accessToken) {
      headers["Authorization"] = `Bearer ${credentials.accessToken}`;
    } else if (cookieBlob) {
      headers["Cookie"] = buildSessionCookieHeader(cookieBlob);
    }

    log?.info?.(
      "PPLX-WEB",
      `Query to ${model} (pref=${modelPref}, mode=${pplxMode}), len=${query.length}`
    );

    // Fetch from Perplexity through the Firefox-fingerprinted TLS client.
    // Perplexity sits behind Cloudflare Enterprise which pins JA3/JA4 to a real
    // browser handshake; Node's fetch() is challenged with a 403 page from
    // VPS/datacenter IPs even with a valid cookie (issue #2459).
    let response: TlsFetchResult;
    try {
      response = await tlsFetchPerplexity(PPLX_SSE_ENDPOINT, {
        method: "POST",
        headers,
        body: JSON.stringify(pplxBody),
        signal: signal ?? null,
        stream: true,
        // Live wire terminator is `event: end_of_stream` (not OpenAI `[DONE]`).
        streamEofSymbol: PPLX_STREAM_EOF_SYMBOL,
      });
    } catch (err) {
      const isTlsUnavail = isTlsClientUnavailableError(err);
      const publicError = sanitizePerplexityUpstreamError(err);
      log?.error?.("PPLX-WEB", `Fetch failed: ${publicError}`);
      const errResp = new Response(
        JSON.stringify({
          error: {
            message: isTlsUnavail
              ? `Perplexity TLS client unavailable: ${publicError}`
              : `Perplexity connection failed: ${publicError}`,
            type: "upstream_error",
          },
        }),
        { status: 502, headers: { "Content-Type": "application/json" } }
      );
      return { response: errResp, url: PPLX_SSE_ENDPOINT, headers, transformedBody: pplxBody };
    }

    if (response.status !== 200 || (!response.body && !response.text)) {
      const status = response.status;
      let errMsg = `Perplexity returned HTTP ${status}`;
      if (status === 401 || status === 403) {
        if (isCloudflareChallenge(response.text)) {
          errMsg =
            "Cloudflare blocked the request — Perplexity's edge rejected this server's TLS fingerprint " +
            "(common on VPS/datacenter IPs). Ensure tls-client-node is installed with its native binary, " +
            "or route perplexity-web through a residential proxy.";
          log?.error?.("PPLX-WEB", "Cloudflare challenge detected — TLS bypass failed");
        } else {
          errMsg =
            "Perplexity auth failed — session cookie may be expired. Re-paste your __Secure-next-auth.session-token.";
        }
      } else if (status === 429) {
        errMsg = "Perplexity rate limited. Wait a moment and retry.";
      }
      log?.warn?.("PPLX-WEB", errMsg);
      const errResp = new Response(
        JSON.stringify({
          error: { message: errMsg, type: "upstream_error", code: `HTTP_${status}` },
        }),
        { status, headers: { "Content-Type": "application/json" } }
      );
      return { response: errResp, url: PPLX_SSE_ENDPOINT, headers, transformedBody: pplxBody };
    }

    // If the TLS client buffered the body (looksLikeSse false-negative, or a
    // non-streaming error page), promote a text body that still looks like SSE
    // into a ReadableStream so extractContent can recover the answer.
    if (!response.body && response.text) {
      const buffered = response.text;
      if (/^(?:\s*)(?:data|event|id|retry):/im.test(buffered) || buffered.includes("\ndata:")) {
        const encoder = new TextEncoder();
        response = {
          ...response,
          body: new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(encoder.encode(buffered));
              controller.close();
            },
          }),
          text: null,
        };
      } else {
        const errResp = new Response(
          JSON.stringify({
            error: {
              message: `Perplexity returned non-SSE body: ${sanitizeErrorMessage(buffered.slice(0, 240))}`,
              type: "upstream_error",
            },
          }),
          { status: 502, headers: { "Content-Type": "application/json" } }
        );
        return { response: errResp, url: PPLX_SSE_ENDPOINT, headers, transformedBody: pplxBody };
      }
    }

    if (!response.body) {
      const errResp = new Response(
        JSON.stringify({
          error: { message: "Perplexity returned empty response body", type: "upstream_error" },
        }),
        { status: 502, headers: { "Content-Type": "application/json" } }
      );
      return { response: errResp, url: PPLX_SSE_ENDPOINT, headers, transformedBody: pplxBody };
    }

    // Surface any rotated session-token back to the caller so the DB credential
    // is refreshed — mirrors chatgpt-web.ts exchangeSession + onCredentialsRefreshed.
    if (cookieBlob) {
      await persistRotatedSessionCookie(
        cookieBlob,
        response.headers.get("set-cookie"),
        credentials,
        onCredentialsRefreshed,
        log
      );
    }

    // Build OpenAI-compatible response
    const cid = `chatcmpl-pplx-${crypto.randomUUID().slice(0, 12)}`;
    const created = Math.floor(Date.now() / 1000);

    // Tool mode buffers the full completion (no live token streaming) and
    // converts <tool> text into real tool_calls — even when the caller asked
    // for a streaming response — mirroring chatgpt-web's toolMode (#5240,
    // #5927). Without this, streaming requests (the default for agentic
    // coding clients) never emitted a tool_calls SSE delta.
    let finalResponse: Response;
    if (hasTools) {
      const bufferedJson = await buildNonStreamingResponse(
        response.body,
        model,
        cid,
        created,
        parsed.history,
        parsed.currentMsg,
        signal
      );
      finalResponse = await buildToolModeResponse(bufferedJson, requestedTools, stream, {
        cid,
        created,
        model,
        idSeed: "pplx",
      });
    } else if (stream) {
      const contentAbortController = new AbortController();
      const contentSignal = signal
        ? AbortSignal.any([signal, contentAbortController.signal])
        : contentAbortController.signal;
      const contentChunks = extractContent(response.body, contentSignal);
      try {
        const preflight = await preflightContentChunks(contentChunks);
        if (preflight.quotaError) {
          finalResponse = buildUpstreamErrorResponse(preflight.quotaError);
        } else {
          finalResponse = buildStreamingResponse(
            preflight.contentChunks as AsyncIterable<ContentChunk>,
            model,
            cid,
            created,
            parsed.history,
            parsed.currentMsg,
            (reason) => contentAbortController.abort(reason)
          );
        }
      } catch (err) {
        finalResponse = buildStreamingResponse(
          throwContentError(err),
          model,
          cid,
          created,
          parsed.history,
          parsed.currentMsg
        );
      }
    } else {
      finalResponse = await buildNonStreamingResponse(
        response.body,
        model,
        cid,
        created,
        parsed.history,
        parsed.currentMsg,
        signal
      );
    }

    return {
      response: finalResponse,
      url: PPLX_SSE_ENDPOINT,
      headers,
      transformedBody: pplxBody,
    };
  }
}
