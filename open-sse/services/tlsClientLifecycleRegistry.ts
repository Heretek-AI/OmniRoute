/**
 * Process-wide ownership for tls-client-node's native backend.
 *
 * The dependency caches one binding per native library path and implements
 * `TLSClient.stop()` as binding-wide `destroyAll()`. A per-provider singleton
 * therefore cannot decide independently when stop is safe. This registry keeps
 * that global fact behind a process-wide lease interface.
 */

import { realpath } from "node:fs/promises";
import { resolve } from "node:path";

declare const nativeTlsLeaseBrand: unique symbol;

export type NativeTlsClientLease = {
  readonly [nativeTlsLeaseBrand]: true;
};

type InternalLease = NativeTlsClientLease & {
  cleanup: () => Promise<void>;
  cleanupTimeoutMs: number;
  completion: Promise<void> | null;
  state: NativeLibraryState;
  status: "pending" | "active" | "released";
};

type NativeLibraryState = {
  cleanupBarrier: Promise<void> | null;
  cleanupCandidate: (() => Promise<void>) | null;
  cleanupFailed: boolean;
  cleanupToken: symbol | null;
  owners: Set<InternalLease>;
};

type NativeLibraryPathCanonicalizer = (nativeLibraryPath: string) => Promise<string>;
type BeforeOwnerReservationHook = () => Promise<void>;

const nativeLibraryStates = new Map<string, NativeLibraryState>();
const RESOLVED_VOID = Promise.resolve();
let exitCleanupStarted = false;
let exitHookInstalled = false;

async function canonicalizeNativeLibraryPath(nativeLibraryPath: string): Promise<string> {
  const absolutePath = resolve(nativeLibraryPath);
  try {
    return await realpath(absolutePath);
  } catch {
    // Tests and early failures may use a path that cannot be resolved yet. The
    // absolute spelling is still a stable key for all callers using that path.
    return absolutePath;
  }
}

function getNativeLibraryState(
  states: Map<string, NativeLibraryState>,
  canonicalPath: string
): NativeLibraryState {
  let state = states.get(canonicalPath);
  if (!state) {
    state = {
      cleanupBarrier: null,
      cleanupCandidate: null,
      cleanupFailed: false,
      cleanupToken: null,
      owners: new Set(),
    };
    states.set(canonicalPath, state);
  }
  return state;
}

function waitBounded(promise: Promise<void>, timeoutMs: number): Promise<void> {
  return new Promise<void>((resolvePromise, rejectPromise) => {
    const timer = setTimeout(
      () => rejectPromise(new Error("Native TLS cleanup did not finish within its safety budget")),
      Math.max(1, timeoutMs)
    );
    timer.unref?.();
    void promise.then(
      () => {
        clearTimeout(timer);
        resolvePromise();
      },
      (error: unknown) => {
        clearTimeout(timer);
        rejectPromise(error);
      }
    );
  });
}

function startCleanup(
  state: NativeLibraryState,
  cleanup: () => Promise<void>,
  timeoutMs: number
): Promise<void> {
  let rawCleanup: Promise<void>;
  try {
    rawCleanup = Promise.resolve(cleanup());
  } catch (error) {
    rawCleanup = Promise.reject(error);
  }

  const cleanupToken = Symbol("native-tls-cleanup");
  state.cleanupBarrier = rawCleanup;
  state.cleanupToken = cleanupToken;
  void rawCleanup.then(
    () => {
      if (state.cleanupToken !== cleanupToken) return;
      state.cleanupBarrier = null;
      state.cleanupCandidate = null;
      state.cleanupFailed = false;
      state.cleanupToken = null;
    },
    () => {
      if (state.cleanupToken !== cleanupToken) return;
      state.cleanupBarrier = null;
      state.cleanupFailed = true;
      state.cleanupToken = null;
    }
  );

  return waitBounded(rawCleanup, timeoutMs);
}

/**
 * Acquire ownership before starting a native client.
 *
 * A cleanup that already became the last-owner cleanup is an ordering barrier:
 * no successor may start until its raw Promise settles. Callers wait only for
 * their bounded safety budget and fail closed if the barrier is still pending.
 */
async function acquireNativeTlsClientLeaseFromRegistry(
  states: Map<string, NativeLibraryState>,
  canonicalizePath: NativeLibraryPathCanonicalizer,
  nativeLibraryPath: string,
  cleanup: () => Promise<void>,
  cleanupTimeoutMs: number,
  beforeOwnerReservation?: BeforeOwnerReservationHook
): Promise<NativeTlsClientLease> {
  const canonicalPath = await canonicalizePath(nativeLibraryPath);
  const state = getNativeLibraryState(states, canonicalPath);
  const lease = {
    cleanup,
    cleanupTimeoutMs,
    completion: null,
    state,
    status: "pending",
  } as InternalLease;
  let reservationHookInvoked = false;

  while (true) {
    if (state.cleanupFailed) {
      throw new Error("Native TLS cleanup failed; refusing to start a new owner");
    }
    const cleanupBarrier = state.cleanupBarrier;
    if (cleanupBarrier) {
      try {
        await waitBounded(cleanupBarrier, cleanupTimeoutMs);
      } catch {
        throw new Error("Native TLS cleanup is incomplete; refusing to start a new owner");
      }
      continue;
    }

    if (!reservationHookInvoked && beforeOwnerReservation) {
      reservationHookInvoked = true;
      await beforeOwnerReservation();
      continue;
    }

    // No await is allowed between this final state check and the reservation.
    // A last-owner release is synchronous too, so exactly one side wins: the
    // new owner is counted first, or its acquire observes the raw cleanup.
    if (state.cleanupFailed || state.cleanupBarrier) continue;
    state.owners.add(lease);
    return lease;
  }
}

export async function acquireNativeTlsClientLease(
  nativeLibraryPath: string,
  cleanup: () => Promise<void>,
  cleanupTimeoutMs: number
): Promise<NativeTlsClientLease> {
  return acquireNativeTlsClientLeaseFromRegistry(
    nativeLibraryStates,
    canonicalizeNativeLibraryPath,
    nativeLibraryPath,
    cleanup,
    cleanupTimeoutMs
  );
}

/** Create an isolated acquirer for deterministic registry race tests. */
export function createNativeTlsClientLeaseAcquirerForTesting(
  beforeOwnerReservation: BeforeOwnerReservationHook
): (
  nativeLibraryPath: string,
  cleanup: () => Promise<void>,
  cleanupTimeoutMs: number
) => Promise<NativeTlsClientLease> {
  const states = new Map<string, NativeLibraryState>();
  return (nativeLibraryPath, cleanup, cleanupTimeoutMs) =>
    acquireNativeTlsClientLeaseFromRegistry(
      states,
      async (path) => resolve(path),
      nativeLibraryPath,
      cleanup,
      cleanupTimeoutMs,
      beforeOwnerReservation
    );
}

export function activateNativeTlsClientLease(lease: NativeTlsClientLease): void {
  const internalLease = lease as InternalLease;
  if (internalLease.status !== "pending") return;
  internalLease.status = "active";
  internalLease.state.cleanupCandidate = internalLease.cleanup;
}

/** Install one coordinated process-exit hook for every native library path. */
export function installNativeTlsClientExitHook(
  installExitHook: (hook: () => void) => void = (hook) => process.on("exit", hook)
): void {
  if (exitHookInstalled) return;

  const hook = () => {
    if (exitCleanupStarted) return;
    exitCleanupStarted = true;
    for (const state of nativeLibraryStates.values()) {
      for (const lease of [...state.owners]) {
        // `exit` cannot await Promises; release already invokes the final native stop synchronously.
        void releaseNativeTlsClientLease(lease, lease.cleanupTimeoutMs).catch(() => {});
      }
    }
  };

  installExitHook(hook);
  exitHookInstalled = true;
}

/**
 * Release one owner. The preserved active cleanup candidate is invoked only
 * for the final owner. A timed-out start remains pending until its raw start
 * settles; there is deliberately no TTL or pending-owner cap in this wrapper.
 *
 * Invocation is synchronous so process-exit hooks can at least begin native
 * cleanup; Promise completion remains best-effort during exit.
 */
export function releaseNativeTlsClientLease(
  lease: NativeTlsClientLease,
  cleanupTimeoutMs: number
): Promise<void> {
  const internalLease = lease as InternalLease;
  if (internalLease.status === "released") {
    return internalLease.completion ?? RESOLVED_VOID;
  }

  const wasActive = internalLease.status === "active";
  internalLease.status = "released";
  internalLease.state.owners.delete(internalLease);
  if (wasActive) internalLease.state.cleanupCandidate = internalLease.cleanup;
  if (internalLease.state.owners.size > 0) {
    internalLease.completion = RESOLVED_VOID;
    return RESOLVED_VOID;
  }

  const cleanup = internalLease.state.cleanupCandidate ?? internalLease.cleanup;
  const completion = startCleanup(internalLease.state, cleanup, cleanupTimeoutMs);
  internalLease.completion = completion;
  return completion;
}
