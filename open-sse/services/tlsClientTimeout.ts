/** Timeout and abort primitives shared by every native TLS client wrapper. */

export class TlsClientHangError extends Error {
  override name = "TlsClientHangError";

  constructor(message = "TLS client operation timed out") {
    super(message);
  }
}

export function makeAbortError(signal: AbortSignal): Error {
  const reason = signal.reason;
  try {
    if (reason instanceof Error) return reason;
  } catch {
    // A hostile Proxy reason must not keep the already-aborted race pending.
  }
  const err = new Error(typeof reason === "string" ? reason : "The operation was aborted");
  err.name = "AbortError";
  return err;
}

export async function raceWithTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  signal: AbortSignal | null | undefined
): Promise<T> {
  return await new Promise<T>((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const cleanup = () => {
      if (timer !== undefined) clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };

    const done = (fn: () => void) => {
      if (!settled) {
        settled = true;
        cleanup();
        fn();
      }
    };

    const onAbort = () => {
      if (signal) done(() => reject(makeAbortError(signal)));
    };

    timer = setTimeout(() => {
      done(() => reject(new TlsClientHangError()));
    }, timeoutMs);

    if (signal) {
      if (signal.aborted) {
        onAbort();
      } else {
        signal.addEventListener("abort", onAbort, { once: true });
      }
    }

    promise.then(
      (value) => {
        done(() => resolve(value));
      },
      (error) => {
        done(() => reject(error));
      }
    );
  });
}
