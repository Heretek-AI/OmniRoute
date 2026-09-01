/**
 * File-backed stream adapter shared by the native TLS client wrappers.
 *
 * The native binding writes response bytes to a temporary file. This module
 * tails that file, applies each provider family's EOF convention, owns cleanup,
 * and guarantees that every terminal stream error is safe for public sinks.
 */

import { open, rm, rmdir } from "node:fs/promises";
import { dirname } from "node:path";

import { sanitizeErrorMessage } from "../utils/error.ts";

export type TlsClientTailVariant = "A" | "B1" | "B2";

type FileHandle = Awaited<ReturnType<typeof open>>;

const TLS_CLIENT_REQUEST_FAILED = "TLS client request failed";
const SAFE_TLS_ERROR_NAMES = new Set([
  "Error",
  "AbortError",
  "TimeoutError",
  "BodyTimeoutError",
  "TlsClientHangError",
  "NativeTlsError",
]);

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function cleanupTempPathSubstring(path: string): Promise<void> {
  // This request-owned scratch path is never reused; cleanup cannot replace the stream outcome.
  await rm(path, { force: true, recursive: true }).catch(() => {});
  const dir = path.substring(0, path.lastIndexOf("/"));
  // This request-owned directory is never reused; removal failure cannot alter response semantics.
  await rmdir(dir).catch(() => {});
}

async function cleanupTempPathDirname(path: string): Promise<void> {
  // This request-owned scratch path is never reused; cleanup cannot replace the stream outcome.
  await rm(path, { force: true, recursive: true }).catch(() => {});
  // This request-owned directory is never reused; removal failure cannot alter response semantics.
  await rmdir(dirname(path)).catch(() => {});
}

export async function cleanupTlsClientStreamPath(
  variant: TlsClientTailVariant,
  path: string
): Promise<void> {
  if (variant === "A") await cleanupTempPathSubstring(path);
  else await cleanupTempPathDirname(path);
}

function projectTlsClientError(error: unknown): { message: string; name: string } {
  let rawMessage: unknown = error;
  let name = "Error";
  try {
    if (error instanceof Error) {
      try {
        rawMessage = error.message;
      } catch {
        rawMessage = undefined;
      }
      try {
        const rawName: unknown = error.name;
        if (typeof rawName === "string" && SAFE_TLS_ERROR_NAMES.has(rawName)) {
          name = rawName;
        }
      } catch {
        name = "Error";
      }
    }
  } catch {
    // A rejected Proxy may throw while instanceof walks its prototype chain.
    rawMessage = undefined;
  }
  const sanitized = rawMessage == null ? "" : sanitizeErrorMessage(rawMessage);
  const message =
    sanitized.trim() && !/^(?:[A-Za-z_$][\w$]*)?Error:\s*$/.test(sanitized)
      ? sanitized
      : TLS_CLIENT_REQUEST_FAILED;
  return { message, name };
}

export function sanitizeTlsClientErrorMessage(error: unknown): string {
  return projectTlsClientError(error).message;
}

export function createSanitizedTlsStreamError(error: unknown): Error {
  const projection = projectTlsClientError(error);
  const sanitizedError = new Error(projection.message);
  sanitizedError.name = projection.name;
  // Do not retain the native error as `cause`: it can contain credentials and
  // absolute paths. Keep a safe single-line stack for consumers that inspect it.
  sanitizedError.stack = `${sanitizedError.name}: ${sanitizedError.message}`;
  return sanitizedError;
}

function tailFileVariantA(
  path: string,
  eofSymbol: string,
  done: Promise<unknown>,
  signal: AbortSignal | null
): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    async start(controller) {
      let fd: FileHandle;
      try {
        fd = await open(path, "r");
      } catch (err) {
        await cleanupTempPathSubstring(path);
        controller.error(createSanitizedTlsStreamError(err));
        return;
      }
      const buf = Buffer.alloc(64 * 1024);
      let offset = 0;
      let finished = false;
      let aborted = false;
      let upstreamError: Error | null = null;

      done.then(
        () => {
          finished = true;
        },
        (err) => {
          upstreamError = createSanitizedTlsStreamError(err);
          finished = true;
        }
      );

      const onAbort = () => {
        aborted = true;
      };
      if (signal) {
        if (signal.aborted) aborted = true;
        else signal.addEventListener("abort", onAbort, { once: true });
      }

      let errored = false;
      try {
        while (!aborted) {
          const { bytesRead } = await fd.read(buf, 0, buf.length, offset);
          if (bytesRead > 0) {
            const chunk = buf.subarray(0, bytesRead);
            offset += bytesRead;
            const text = chunk.toString("utf8");
            if (text.includes(eofSymbol)) {
              const cutAt = text.indexOf(eofSymbol) + eofSymbol.length;
              controller.enqueue(new Uint8Array(chunk.subarray(0, cutAt)));
              break;
            }
            controller.enqueue(new Uint8Array(chunk));
          } else if (finished) {
            if (upstreamError) {
              errored = true;
              controller.error(upstreamError);
            }
            break;
          } else {
            await sleep(25);
          }
        }
      } catch (err) {
        if (!errored) {
          errored = true;
          controller.error(createSanitizedTlsStreamError(err));
        }
      } finally {
        if (signal) signal.removeEventListener("abort", onAbort);
        // The handle is no longer used; a close error must not skip temp cleanup or replace EOF.
        await fd.close().catch(() => {});
        await cleanupTempPathSubstring(path);
        if (!errored) controller.close();
      }
    },
  });
}

function tailFileVariantB1(
  path: string,
  eofSymbol: string,
  done: Promise<unknown>,
  signal: AbortSignal | null
): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    async start(controller) {
      let fd: FileHandle;
      try {
        fd = await open(path, "r");
      } catch (err) {
        await cleanupTempPathDirname(path);
        controller.error(createSanitizedTlsStreamError(err));
        return;
      }
      const buf = Buffer.alloc(64 * 1024);
      let offset = 0;
      let finished = false;
      let aborted = false;
      let upstreamError: Error | null = null;

      done.then(
        () => {
          finished = true;
        },
        (err) => {
          upstreamError = createSanitizedTlsStreamError(err);
          finished = true;
        }
      );

      const onAbort = () => {
        aborted = true;
      };
      if (signal) {
        if (signal.aborted) aborted = true;
        else signal.addEventListener("abort", onAbort, { once: true });
      }

      let errored = false;
      try {
        while (!aborted) {
          const { bytesRead } = await fd.read(buf, 0, buf.length, offset);
          if (bytesRead > 0) {
            const chunk = buf.subarray(0, bytesRead);
            offset += bytesRead;
            const text = chunk.toString("utf8");

            if (text.includes(eofSymbol)) {
              const beforeEof = text.substring(0, text.indexOf(eofSymbol));
              if (beforeEof) controller.enqueue(Buffer.from(beforeEof, "utf8"));
              controller.close();
              return;
            }

            controller.enqueue(Buffer.from(chunk));
          }

          if (finished) {
            while (true) {
              const { bytesRead } = await fd.read(buf, 0, buf.length, offset);
              if (bytesRead === 0) break;
              const chunk = buf.subarray(0, bytesRead);
              offset += bytesRead;
              const text = chunk.toString("utf8");

              if (text.includes(eofSymbol)) {
                const beforeEof = text.substring(0, text.indexOf(eofSymbol));
                if (beforeEof) controller.enqueue(Buffer.from(beforeEof, "utf8"));
                controller.close();
                return;
              }

              controller.enqueue(Buffer.from(chunk));
            }

            if (upstreamError && !errored) {
              errored = true;
              controller.error(upstreamError);
              return;
            }

            controller.close();
            return;
          }

          await sleep(25);
        }
      } catch (err) {
        if (!errored) {
          errored = true;
          controller.error(createSanitizedTlsStreamError(err));
        }
      } finally {
        // The handle is no longer used; a close error must not skip temp cleanup or replace EOF.
        await fd.close().catch(() => {});
        await cleanupTempPathDirname(path);
        if (signal) signal.removeEventListener("abort", onAbort);
      }
    },
  });
}

function enqueueChunkMaybeEof(
  controller: ReadableStreamDefaultController<Uint8Array>,
  chunk: Buffer,
  eofSymbol: string
): boolean {
  const text = chunk.toString("utf8");
  if (!text.includes(eofSymbol)) {
    controller.enqueue(Buffer.from(chunk));
    return false;
  }
  const beforeEof = text.substring(0, text.indexOf(eofSymbol));
  if (beforeEof) controller.enqueue(Buffer.from(beforeEof, "utf8"));
  controller.close();
  return true;
}

async function drainRemaining(
  fd: FileHandle,
  buf: Buffer,
  offsetRef: { offset: number },
  controller: ReadableStreamDefaultController<Uint8Array>,
  eofSymbol: string
): Promise<"closed" | "drained"> {
  while (true) {
    const { bytesRead } = await fd.read(buf, 0, buf.length, offsetRef.offset);
    if (bytesRead === 0) return "drained";
    const chunk = buf.subarray(0, bytesRead);
    offsetRef.offset += bytesRead;
    if (enqueueChunkMaybeEof(controller, chunk, eofSymbol)) return "closed";
  }
}

function tailFileVariantB2(
  path: string,
  eofSymbol: string,
  done: Promise<unknown>,
  signal: AbortSignal | null
): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    async start(controller) {
      let fd: FileHandle;
      try {
        fd = await open(path, "r");
      } catch (err) {
        await cleanupTempPathDirname(path);
        controller.error(createSanitizedTlsStreamError(err));
        return;
      }
      const buf = Buffer.alloc(64 * 1024);
      const offsetRef = { offset: 0 };
      let finished = false;
      let aborted = false;
      let upstreamError: Error | null = null;
      let errored = false;

      done.then(
        () => {
          finished = true;
        },
        (err) => {
          upstreamError = createSanitizedTlsStreamError(err);
          finished = true;
        }
      );

      const onAbort = () => {
        aborted = true;
      };
      if (signal) {
        if (signal.aborted) aborted = true;
        else signal.addEventListener("abort", onAbort, { once: true });
      }

      try {
        while (!aborted) {
          const { bytesRead } = await fd.read(buf, 0, buf.length, offsetRef.offset);
          if (bytesRead > 0) {
            const chunk = buf.subarray(0, bytesRead);
            offsetRef.offset += bytesRead;
            if (enqueueChunkMaybeEof(controller, chunk, eofSymbol)) return;
          }

          if (!finished) {
            await sleep(25);
            continue;
          }

          const drained = await drainRemaining(fd, buf, offsetRef, controller, eofSymbol);
          if (drained === "closed") return;
          if (upstreamError && !errored) {
            errored = true;
            controller.error(upstreamError);
            return;
          }
          controller.close();
          return;
        }
      } catch (err) {
        if (!errored) {
          errored = true;
          controller.error(createSanitizedTlsStreamError(err));
        }
      } finally {
        // The handle is no longer used; a close error must not skip temp cleanup or replace EOF.
        await fd.close().catch(() => {});
        await cleanupTempPathDirname(path);
        if (signal) signal.removeEventListener("abort", onAbort);
      }
    },
  });
}

const TAIL_FILE_VARIANTS = {
  A: tailFileVariantA,
  B1: tailFileVariantB1,
  B2: tailFileVariantB2,
} as const;

export function createTlsClientTailStream({
  variant,
  path,
  eofSymbol,
  done,
  signal,
}: {
  variant: TlsClientTailVariant;
  path: string;
  eofSymbol: string;
  done: Promise<unknown>;
  signal: AbortSignal | null;
}): ReadableStream<Uint8Array> {
  return TAIL_FILE_VARIANTS[variant](path, eofSymbol, done, signal);
}
