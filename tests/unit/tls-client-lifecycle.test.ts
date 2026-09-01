import { after, test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const originalDataDir = process.env.DATA_DIR;
const lifecycleDataDir = mkdtempSync(join(tmpdir(), "omniroute-tls-lifecycle-"));
const processExitHooks: Array<() => void> = [];
const installProcessExitHook = (hook: () => void): void => {
  processExitHooks.push(hook);
};
process.env.DATA_DIR = lifecycleDataDir;

function hostileTlsError(): Error {
  return new Proxy(
    new Error("native failure at /srv/private/tls-client.ts:7; access_token=tls-hostile-secret"),
    {
      getPrototypeOf() {
        throw new Error("tls-prototype-secret");
      },
    }
  );
}

after(() => {
  if (originalDataDir === undefined) delete process.env.DATA_DIR;
  else process.env.DATA_DIR = originalDataDir;
  rmSync(lifecycleDataDir, { recursive: true, force: true });
});

test("client initialization retries after a transient verifier failure without exposing details", async () => {
  const { createGetClient, TlsClientUnavailableError } =
    await import("../../open-sse/services/tlsClientBase.ts");
  let verificationAttempts = 0;
  let starts = 0;

  class FakeTlsClient {
    constructor(_options: Record<string, unknown>) {}
    async start() {
      starts++;
    }
    async request(_url: string, _options: Record<string, unknown>) {
      return { status: 200, headers: {}, body: "ok" };
    }
    async stop() {}
  }

  const getClient = createGetClient(
    { providerName: "test-provider", tlsProfile: "chrome_146" },
    {
      loadTlsClient: async () => ({ TLSClient: FakeTlsClient }),
      installExitHook: installProcessExitHook,
      resolveNativeLibrary: async () => {
        verificationAttempts++;
        if (verificationAttempts === 1) {
          throw {
            toString() {
              throw new Error(
                "EACCES /srv/private/tls/cache; api_key=sk-super-secret\n    at /srv/private/stack.ts:1"
              );
            },
          };
        }
        return "/verified/retry-verifier.so";
      },
    }
  );

  await assert.rejects(getClient(), (err: unknown) => {
    assert.ok(err instanceof TlsClientUnavailableError);
    assert.match(err.message, /verification failed for test-provider/);
    assert.doesNotMatch(err.message, /srv\/private|sk-super-secret|stack\.ts/);
    return true;
  });

  const client = await getClient();
  assert.equal((await client.request("https://example.test", {})).status, 200);
  assert.equal(verificationAttempts, 2);
  assert.equal(starts, 1);
});

test("client initialization sanitizes start failures, stops the partial client, and retries", async () => {
  const { createGetClient, TlsClientUnavailableError } =
    await import("../../open-sse/services/tlsClientBase.ts");
  let instances = 0;
  let starts = 0;
  let stops = 0;

  class FakeTlsClient {
    readonly instance = ++instances;
    constructor(_options: Record<string, unknown>) {}
    async start() {
      starts++;
      if (this.instance === 1) {
        throw hostileTlsError();
      }
    }
    async request(_url: string, _options: Record<string, unknown>) {
      return { status: 200, headers: {}, body: "ok" };
    }
    async stop() {
      stops++;
    }
  }

  const getClient = createGetClient(
    { providerName: "start-failure-provider", tlsProfile: "chrome_146" },
    {
      loadTlsClient: async () => ({ TLSClient: FakeTlsClient }),
      installExitHook: installProcessExitHook,
      resolveNativeLibrary: async () => "/verified/start-failure.so",
    }
  );

  await assert.rejects(getClient(), (err: unknown) => {
    assert.ok(err instanceof TlsClientUnavailableError);
    assert.match(err.message, /initialization failed for start-failure-provider/i);
    assert.doesNotMatch(err.message, /srv\/private|sk-super-secret|stack\.ts/);
    return true;
  });
  assert.equal(stops, 1, "a partially started client must be stopped before retry");

  const client = await getClient();
  assert.equal((await client.request("https://example.test", {})).status, 200);
  assert.equal(instances, 2);
  assert.equal(starts, 2);
  assert.equal(stops, 1);
});

test("client initialization bounds a hung native start and remains retryable", async () => {
  const { createGetClient, TlsClientUnavailableError } =
    await import("../../open-sse/services/tlsClientBase.ts");
  let instances = 0;
  let starts = 0;
  let stops = 0;

  class FakeTlsClient {
    readonly instance = ++instances;
    constructor(_options: Record<string, unknown>) {}
    async start() {
      starts++;
      if (this.instance === 1) {
        await new Promise<void>(() => {});
      }
    }
    async request(_url: string, _options: Record<string, unknown>) {
      return { status: 200, headers: {}, body: "ok" };
    }
    async stop() {
      stops++;
    }
  }

  const getClient = createGetClient(
    { providerName: "hung-start-provider", tlsProfile: "chrome_146" },
    {
      loadTlsClient: async () => ({ TLSClient: FakeTlsClient }),
      installExitHook: installProcessExitHook,
      resolveNativeLibrary: async () => "/verified/hung-start.so",
      startTimeoutMs: 10,
      cleanupTimeoutMs: 10,
    }
  );

  let watchdog: ReturnType<typeof setTimeout> | undefined;
  try {
    await assert.rejects(
      Promise.race([
        getClient(),
        new Promise<never>((_, reject) => {
          watchdog = setTimeout(
            () => reject(new Error("getClient exceeded the native start budget")),
            250
          );
        }),
      ]),
      (err: unknown) => {
        assert.ok(err instanceof TlsClientUnavailableError);
        assert.match(err.message, /initialization failed for hung-start-provider/i);
        return true;
      }
    );
  } finally {
    if (watchdog) clearTimeout(watchdog);
  }

  assert.equal(stops, 0, "a still-pending start must retain safe backend ownership");
  const client = await getClient();
  assert.equal((await client.request("https://example.test", {})).status, 200);
  assert.equal(instances, 2);
  assert.equal(starts, 2);
  assert.equal(stops, 0);
});

test("a late discarded start cannot destroy the shared backend of its active successor", async () => {
  const { createGetClient, TlsClientUnavailableError } =
    await import("../../open-sse/services/tlsClientBase.ts");
  let instances = 0;
  let resolveLateStart: (() => void) | undefined;
  let destroyAllCalls = 0;
  const backendSessions = new Set<number>();

  class FakeTlsClient {
    readonly instance = ++instances;
    constructor(_options: Record<string, unknown>) {}
    async start() {
      if (this.instance === 1) {
        await new Promise<void>((resolve) => {
          resolveLateStart = resolve;
        });
      }
      backendSessions.add(this.instance);
    }
    async request(_url: string, _options: Record<string, unknown>) {
      if (!backendSessions.has(this.instance)) throw new Error("shared backend was destroyed");
      return { status: 200, headers: {}, body: `ok-${this.instance}` };
    }
    async stop() {
      destroyAllCalls++;
      backendSessions.clear();
    }
  }

  const getClient = createGetClient(
    { providerName: "late-start-provider", tlsProfile: "chrome_146" },
    {
      loadTlsClient: async () => ({ TLSClient: FakeTlsClient }),
      installExitHook: installProcessExitHook,
      resolveNativeLibrary: async () => "/verified/late-start-after-successor.so",
      startTimeoutMs: 10,
      cleanupTimeoutMs: 50,
    }
  );

  await assert.rejects(getClient(), TlsClientUnavailableError);
  assert.equal(destroyAllCalls, 0);

  const secondClient = await getClient();
  assert.equal(secondClient.instance, 2);
  assert.equal((await secondClient.request("https://example.test", {})).body, "ok-2");

  assert.ok(resolveLateStart);
  resolveLateStart();
  for (let attempt = 0; attempt < 10 && !backendSessions.has(1); attempt++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  await new Promise<void>((resolve) => setImmediate(resolve));

  assert.equal(destroyAllCalls, 0, "late cleanup must transfer ownership to the successor");
  assert.equal((await secondClient.request("https://example.test", {})).body, "ok-2");
  assert.equal(await getClient(), secondClient);

  await getClient.invalidate(secondClient);
  assert.equal(destroyAllCalls, 1, "the final owner must clean the shared backend exactly once");
});

test("a late start settled before retry is cleaned before the successor starts", async () => {
  const { createGetClient, TlsClientUnavailableError } =
    await import("../../open-sse/services/tlsClientBase.ts");
  let instances = 0;
  let resolveLateStart: (() => void) | undefined;
  let destroyAllCalls = 0;
  const events: string[] = [];

  class FakeTlsClient {
    readonly instance = ++instances;
    constructor(_options: Record<string, unknown>) {}
    async start() {
      events.push(`start-${this.instance}`);
      if (this.instance === 1) {
        await new Promise<void>((resolve) => {
          resolveLateStart = resolve;
        });
      }
    }
    async request(_url: string, _options: Record<string, unknown>) {
      return { status: 200, headers: {}, body: `ok-${this.instance}` };
    }
    async stop() {
      events.push(`stop-${this.instance}`);
      destroyAllCalls++;
    }
  }

  const getClient = createGetClient(
    { providerName: "late-start-before-retry-provider", tlsProfile: "chrome_146" },
    {
      loadTlsClient: async () => ({ TLSClient: FakeTlsClient }),
      installExitHook: installProcessExitHook,
      resolveNativeLibrary: async () => "/verified/late-start-before-retry.so",
      startTimeoutMs: 10,
      cleanupTimeoutMs: 50,
    }
  );

  await assert.rejects(getClient(), TlsClientUnavailableError);
  assert.equal(destroyAllCalls, 0);
  assert.ok(resolveLateStart);
  resolveLateStart();
  for (let attempt = 0; attempt < 10 && destroyAllCalls !== 1; attempt++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  assert.equal(destroyAllCalls, 1);

  const secondClient = await getClient();
  assert.deepEqual(events.slice(0, 3), ["start-1", "stop-1", "start-2"]);
  assert.equal((await secondClient.request("https://example.test", {})).body, "ok-2");
  await getClient.invalidate(secondClient);
  assert.equal(destroyAllCalls, 2);
});

test("client initialization fails closed while a raw native cleanup remains hung", async () => {
  const { createGetClient, TlsClientUnavailableError } =
    await import("../../open-sse/services/tlsClientBase.ts");
  let instances = 0;
  let starts = 0;
  let stops = 0;

  class FakeTlsClient {
    readonly instance = ++instances;
    constructor(_options: Record<string, unknown>) {}
    async start() {
      starts++;
      if (this.instance === 1) {
        throw new Error(
          "dlopen EACCES /Users/private/tls cache/native.dylib; api_key=sk-super-secret\n" +
            "    at /Users/private/stack.ts:1"
        );
      }
    }
    async request(_url: string, _options: Record<string, unknown>) {
      return { status: 200, headers: {}, body: "ok" };
    }
    async stop() {
      stops++;
      if (this.instance === 1) {
        await new Promise<void>(() => {});
      }
    }
  }

  const getClient = createGetClient(
    { providerName: "hung-cleanup-provider", tlsProfile: "chrome_146" },
    {
      loadTlsClient: async () => ({ TLSClient: FakeTlsClient }),
      installExitHook: installProcessExitHook,
      resolveNativeLibrary: async () => "/verified/tls-client.dylib",
      cleanupTimeoutMs: 10,
    }
  );

  let watchdog: ReturnType<typeof setTimeout> | undefined;
  try {
    await assert.rejects(
      Promise.race([
        getClient(),
        new Promise<never>((_, reject) => {
          watchdog = setTimeout(
            () => reject(new Error("getClient exceeded the bounded cleanup budget")),
            250
          );
        }),
      ]),
      (err: unknown) => {
        assert.ok(err instanceof TlsClientUnavailableError);
        assert.match(err.message, /initialization failed for hung-cleanup-provider/i);
        assert.doesNotMatch(err.message, /Users\/private|sk-super-secret|stack\.ts|native\.dylib/);
        return true;
      }
    );
  } finally {
    if (watchdog) clearTimeout(watchdog);
  }

  await assert.rejects(getClient(), (err: unknown) => {
    assert.ok(err instanceof TlsClientUnavailableError);
    assert.equal(err.message, "tls-client native initialization failed for hung-cleanup-provider");
    return true;
  });
  assert.equal(instances, 2);
  assert.equal(starts, 1, "a new native owner must not start across an unknown cleanup");
  assert.equal(stops, 1);
});

test("managed client invalidation stops once, stays bounded, and preserves one exit hook", async () => {
  const { createGetClient } = await import("../../open-sse/services/tlsClientBase.ts");
  let instances = 0;
  const starts = new Map<number, number>();
  const stops = new Map<number, number>();
  let resolveFirstStop: (() => void) | undefined;

  class FakeTlsClient {
    readonly instance = ++instances;
    constructor(_options: Record<string, unknown>) {}
    async start() {
      starts.set(this.instance, (starts.get(this.instance) ?? 0) + 1);
    }
    async request(_url: string, _options: Record<string, unknown>) {
      return { status: 200, headers: {}, body: `ok-${this.instance}` };
    }
    async stop() {
      stops.set(this.instance, (stops.get(this.instance) ?? 0) + 1);
      if (this.instance === 1) {
        await new Promise<void>((resolve) => {
          resolveFirstStop = resolve;
        });
      }
    }
  }

  const getClient = createGetClient(
    { providerName: "managed-lifecycle-provider", tlsProfile: "chrome_146" },
    {
      loadTlsClient: async () => ({ TLSClient: FakeTlsClient }),
      resolveNativeLibrary: async () => "/verified/managed-lifecycle.so",
      cleanupTimeoutMs: 100,
      installExitHook: installProcessExitHook,
    }
  );

  const firstClient = await getClient();
  assert.equal(starts.get(1), 1);
  assert.equal(processExitHooks.length, 1);

  let watchdog: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      Promise.all([
        getClient.invalidate(firstClient),
        getClient.invalidate(firstClient),
        getClient.invalidate(firstClient),
      ]),
      new Promise<never>((_, reject) => {
        watchdog = setTimeout(
          () => reject(new Error("managed invalidation exceeded the cleanup budget")),
          250
        );
      }),
    ]);
  } finally {
    if (watchdog) clearTimeout(watchdog);
  }

  assert.equal(stops.get(1), 1, "concurrent invalidations must share one bounded stop");
  const secondClientPromise = getClient();
  for (let attempt = 0; attempt < 10 && instances !== 2; attempt++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  assert.equal(instances, 2);
  assert.equal(starts.get(2), undefined, "the successor must wait for the raw cleanup barrier");
  assert.ok(resolveFirstStop);
  resolveFirstStop();
  const secondClient = await secondClientPromise;
  assert.notEqual(secondClient, firstClient);
  assert.equal(starts.get(2), 1);
  assert.equal(processExitHooks.length, 1, "reinitialization must reuse the process exit hook");

  await getClient.invalidate(firstClient);
  assert.equal(
    await getClient(),
    secondClient,
    "a stale invalidation must not evict the new client"
  );
  assert.equal(stops.get(1), 1);
  assert.equal(stops.get(2), undefined);

  await getClient.invalidate(secondClient);
  assert.equal(stops.get(2), 1, "the final owner must be stopped once");
});

test("independent getters share backend ownership and destroy it only after the final release", async () => {
  const { createGetClient } = await import("../../open-sse/services/tlsClientBase.ts");
  let instances = 0;
  let destroyAllCalls = 0;
  const backendSessions = new Set<number>();

  class FakeTlsClient {
    readonly instance = ++instances;
    constructor(_options: Record<string, unknown>) {}
    async start() {
      backendSessions.add(this.instance);
    }
    async request(_url: string, _options: Record<string, unknown>) {
      if (!backendSessions.has(this.instance)) throw new Error("shared backend was destroyed");
      return { status: 200, headers: {}, body: `ok-${this.instance}` };
    }
    async stop() {
      destroyAllCalls++;
      backendSessions.clear();
    }
  }

  const dependencies = {
    loadTlsClient: async () => ({ TLSClient: FakeTlsClient }),
    resolveNativeLibrary: async () => "/verified/shared-provider-backend.so",
  };
  const getClientA = createGetClient(
    { providerName: "shared-provider-a", tlsProfile: "chrome_146" },
    { ...dependencies, installExitHook: installProcessExitHook }
  );
  const getClientB = createGetClient(
    { providerName: "shared-provider-b", tlsProfile: "chrome_146" },
    { ...dependencies, installExitHook: installProcessExitHook }
  );

  const clientA1 = await getClientA();
  const clientB = await getClientB();
  await getClientA.invalidate(clientA1);
  assert.equal(destroyAllCalls, 0, "releasing provider A must not destroy provider B");
  assert.equal((await clientB.request("https://example.test", {})).body, "ok-2");

  const clientA2 = await getClientA();
  assert.equal(processExitHooks.length, 1);
  await getClientA.invalidate(clientA2);
  assert.equal(destroyAllCalls, 0, "releasing provider A must preserve the other owner");
  assert.equal((await clientB.request("https://example.test", {})).body, "ok-2");
  await getClientB.invalidate(clientB);
  assert.equal(destroyAllCalls, 1, "the final owner release must destroy the backend once");

  await getClientA.invalidate(clientA2);
  await getClientB.invalidate(clientB);
  assert.equal(destroyAllCalls, 1, "repeated invalidations must not destroy the backend again");
  assert.equal(clientA2.instance, 3);
});

test("the final pending rejection uses the preserved active cleanup candidate", async () => {
  const { createGetClient, TlsClientUnavailableError } =
    await import("../../open-sse/services/tlsClientBase.ts");
  let instances = 0;
  let destroyAllCalls = 0;
  let pendingStopCalls = 0;
  let rejectPendingStart: ((error: Error) => void) | undefined;

  class FakeTlsClient {
    readonly instance = ++instances;
    constructor(_options: Record<string, unknown>) {}
    async start() {
      if (this.instance === 2) {
        await new Promise<void>((_resolve, reject) => {
          rejectPendingStart = reject;
        });
      }
    }
    async request(_url: string, _options: Record<string, unknown>) {
      return { status: 200, headers: {}, body: `ok-${this.instance}` };
    }
    async stop() {
      if (this.instance === 1) destroyAllCalls++;
      else pendingStopCalls++;
    }
  }

  const dependencies = {
    loadTlsClient: async () => ({ TLSClient: FakeTlsClient }),
    installExitHook: installProcessExitHook,
    resolveNativeLibrary: async () => "/verified/preserved-cleanup-candidate.so",
  };
  const getActiveClient = createGetClient(
    { providerName: "cleanup-candidate-active", tlsProfile: "chrome_146" },
    dependencies
  );
  const getPendingClient = createGetClient(
    { providerName: "cleanup-candidate-pending", tlsProfile: "chrome_146" },
    { ...dependencies, startTimeoutMs: 10 }
  );

  const activeClient = await getActiveClient();
  await assert.rejects(getPendingClient(), TlsClientUnavailableError);
  await getActiveClient.invalidate(activeClient);
  assert.equal(destroyAllCalls, 0);
  assert.equal(pendingStopCalls, 0);

  assert.ok(rejectPendingStart);
  rejectPendingStart(new Error("late start rejection at /srv/private/native.ts"));
  for (let attempt = 0; attempt < 10 && destroyAllCalls !== 1; attempt++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }

  assert.equal(destroyAllCalls, 1, "the preserved active owner must perform destroyAll");
  assert.equal(pendingStopCalls, 0, "a never-active pending owner is not a cleanup candidate");
});

test("a rejected raw cleanup poisons the native path and blocks successor starts", async () => {
  const { createGetClient, TlsClientUnavailableError } =
    await import("../../open-sse/services/tlsClientBase.ts");
  let instances = 0;
  let starts = 0;
  let stops = 0;

  class FakeTlsClient {
    readonly instance = ++instances;
    constructor(_options: Record<string, unknown>) {}
    async start() {
      starts++;
    }
    async request(_url: string, _options: Record<string, unknown>) {
      return { status: 200, headers: {}, body: "ok" };
    }
    async stop() {
      stops++;
      throw new Error("destroyAll failed at /srv/private/native.ts; access_token=stop-secret");
    }
  }

  const getClient = createGetClient(
    { providerName: "poisoned-cleanup-provider", tlsProfile: "chrome_146" },
    {
      loadTlsClient: async () => ({ TLSClient: FakeTlsClient }),
      resolveNativeLibrary: async () => "/verified/poisoned-cleanup.so",
      installExitHook: installProcessExitHook,
    }
  );

  const firstClient = await getClient();
  await getClient.invalidate(firstClient);
  assert.equal(stops, 1);

  await assert.rejects(getClient(), (err: unknown) => {
    assert.ok(err instanceof TlsClientUnavailableError);
    assert.equal(
      err.message,
      "tls-client native initialization failed for poisoned-cleanup-provider"
    );
    assert.doesNotMatch(err.message, /srv\/private|stop-secret|native\.ts/);
    return true;
  });
  assert.equal(instances, 2);
  assert.equal(starts, 1, "a poisoned path must reject before the successor calls start");
  assert.equal(stops, 1);
});

test("owner reservation cannot cross a cleanup started in the former await window", async () => {
  const {
    acquireNativeTlsClientLease: _processAcquire,
    activateNativeTlsClientLease,
    createNativeTlsClientLeaseAcquirerForTesting,
    releaseNativeTlsClientLease,
  } = await import("../../open-sse/services/tlsClientLifecycleRegistry.ts");
  let acquisition = 0;
  let destroyAllCalls = 0;
  let successorStarts = 0;
  let previousLease: Awaited<ReturnType<typeof _processAcquire>> | undefined;
  let resolveRawCleanup: (() => void) | undefined;
  const releasePromises: Promise<void>[] = [];

  const acquire = createNativeTlsClientLeaseAcquirerForTesting(async () => {
    acquisition++;
    if (acquisition !== 2) return;
    assert.ok(previousLease);
    releasePromises.push(releaseNativeTlsClientLease(previousLease, 1_000));
    assert.equal(destroyAllCalls, 1, "the former last owner must begin raw destroyAll");
  });

  previousLease = await acquire(
    "/verified/atomic-owner-reservation.so",
    async () => {
      destroyAllCalls++;
      await new Promise<void>((resolve) => {
        resolveRawCleanup = resolve;
      });
    },
    1_000
  );
  activateNativeTlsClientLease(previousLease);

  const successorPromise = acquire(
    "/verified/atomic-owner-reservation.so",
    async () => {},
    1_000
  ).then((lease) => {
    successorStarts++;
    activateNativeTlsClientLease(lease);
    return lease;
  });

  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(successorStarts, 0, "a successor must not start inside raw destroyAll");
  assert.ok(resolveRawCleanup);
  resolveRawCleanup();

  const successorLease = await successorPromise;
  await Promise.all(releasePromises);
  assert.equal(successorStarts, 1);
  await releaseNativeTlsClientLease(successorLease, 1_000);
});

test("the exit hook invokes stop synchronously and absorbs a synchronous native throw", async () => {
  const { createGetClient } = await import("../../open-sse/services/tlsClientBase.ts");
  let stopCalls = 0;

  class FakeTlsClient {
    constructor(_options: Record<string, unknown>) {}
    async start() {}
    async request(_url: string, _options: Record<string, unknown>) {
      return { status: 200, headers: {}, body: "ok" };
    }
    stop(): Promise<void> {
      stopCalls++;
      throw new Error("native stop failed at /srv/private/native.ts; access_token=exit-secret");
    }
  }

  const getClient = createGetClient(
    { providerName: "exit-hook-provider", tlsProfile: "chrome_146" },
    {
      loadTlsClient: async () => ({ TLSClient: FakeTlsClient }),
      resolveNativeLibrary: async () => "/verified/exit-hook.so",
      installExitHook: installProcessExitHook,
    }
  );

  await getClient();
  assert.equal(processExitHooks.length, 1);
  assert.doesNotThrow(() => processExitHooks[0]?.());
  assert.equal(stopCalls, 1, "stop must be invoked before the exit hook returns");
  assert.doesNotThrow(() => processExitHooks[0]?.());
  assert.equal(stopCalls, 1, "the process exit hook must release each path at most once");
});

test("streaming and non-streaming requests tolerate hostile prototype inspection", async (t) => {
  const { createTlsClientModule } = await import("../../open-sse/services/tlsClientBase.ts");
  const module = createTlsClientModule({
    providerName: "hostile-request-provider",
    tlsProfile: "chrome_146",
    domain: "https://example.test",
    tempDirPrefix: "tls-hostile-request-",
    tailFileVariant: "A",
    responseValidation: "sse",
    exportCloudflareCheck: false,
    exposeStreamingForTesting: true,
  });

  await t.test("streaming fallback is sanitized and cleaned", async () => {
    let streamPath = "";
    const result = await module.__tlsFetchStreamingForTesting(
      {
        request: (_url, options) => {
          streamPath = String(options.streamOutputPath);
          return Promise.reject(hostileTlsError());
        },
      },
      "https://example.test/stream",
      {},
      "[DONE]",
      null,
      1_000,
      100
    );
    assert.equal(result.status, 502);
    assert.equal(result.text, "TLS client request failed");
    assert.doesNotMatch(result.text, /tls-(?:hostile|prototype)-secret|srv\/private/);
    assert.equal(existsSync(streamPath), false);
    assert.equal(existsSync(dirname(streamPath)), false);
  });

  await t.test(
    "non-streaming rejection preserves the unknown for the public boundary",
    async () => {
      const hostile = hostileTlsError();
      assert.ok(module.__tlsFetchNonStreamingForTesting);
      await assert.rejects(
        module.__tlsFetchNonStreamingForTesting(
          { request: async () => Promise.reject(hostile) },
          "https://example.test/non-stream",
          {},
          null,
          1_000
        ),
        (err: unknown) => err === hostile
      );
    }
  );
});

test("TLS stream error projection fails closed for hostile prototype and metadata", async () => {
  const {
    createSanitizedTlsStreamError,
    createTlsClientTailStream,
    sanitizeTlsClientErrorMessage,
  } = await import("../../open-sse/services/tlsClientStream.ts");
  const hostileMetadata = new Error("");
  Object.defineProperties(hostileMetadata, {
    message: {
      get() {
        throw new Error("tls-message-secret");
      },
    },
    name: {
      get() {
        throw new Error("tls-name-secret");
      },
    },
  });

  for (const hostile of [hostileTlsError(), hostileMetadata]) {
    assert.equal(sanitizeTlsClientErrorMessage(hostile), "TLS client request failed");
    const projected = createSanitizedTlsStreamError(hostile);
    assert.equal(projected.name, "Error");
    assert.equal(projected.message, "TLS client request failed");
    assert.equal(projected.stack, "Error: TLS client request failed");
  }

  const alternatingMetadata = new Error("safe message");
  let nameReads = 0;
  Object.defineProperty(alternatingMetadata, "name", {
    get() {
      nameReads += 1;
      return nameReads === 1 ? "Error" : "access_token=alternating-secret /srv/private/x.ts";
    },
  });
  const alternatingProjection = createSanitizedTlsStreamError(alternatingMetadata);
  assert.equal(alternatingProjection.name, "Error");
  assert.equal(alternatingProjection.stack, "Error: safe message");

  const credentialName = new Error("safe message");
  credentialName.name = "sk_abcdefghijklmnopqrstuvwxyz";
  const credentialProjection = createSanitizedTlsStreamError(credentialName);
  assert.equal(credentialProjection.name, "Error");
  assert.equal(credentialProjection.stack, "Error: safe message");

  const internalName = new Error("safe message");
  internalName.name = "InternalUpstreamError";
  const internalProjection = createSanitizedTlsStreamError(internalName);
  assert.equal(internalProjection.name, "Error");
  assert.equal(internalProjection.stack, "Error: safe message");

  for (const safeName of [
    "Error",
    "AbortError",
    "TimeoutError",
    "BodyTimeoutError",
    "TlsClientHangError",
    "NativeTlsError",
  ]) {
    const namedError = new Error("safe message");
    namedError.name = safeName;
    assert.equal(createSanitizedTlsStreamError(namedError).name, safeName);
  }

  for (const variant of ["A", "B1", "B2"] as const) {
    const dir = mkdtempSync(join(tmpdir(), `tls-hostile-done-${variant}-`));
    const path = join(dir, "body.sse");
    writeFileSync(path, 'data: {"delta":"ok"}\n\n');
    let rejectDone: ((reason: unknown) => void) | undefined;
    const done = new Promise<never>((_resolve, reject) => {
      rejectDone = reject;
    });
    const reader = createTlsClientTailStream({
      variant,
      path,
      eofSymbol: "[DONE]",
      done,
      signal: null,
    }).getReader();
    assert.equal((await reader.read()).done, false, variant);
    assert.ok(rejectDone);
    rejectDone(hostileTlsError());
    await assert.rejects(reader.read(), (err: unknown) => {
      assert.ok(err instanceof Error, variant);
      assert.equal(err.name, "Error", variant);
      assert.equal(err.message, "TLS client request failed", variant);
      assert.equal(err.stack, "Error: TLS client request failed", variant);
      assert.doesNotMatch(err.stack, /tls-(?:hostile|prototype)-secret|srv\/private/, variant);
      return true;
    });
    reader.releaseLock();
    for (let attempt = 0; attempt < 50 && existsSync(dir); attempt++) {
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(existsSync(dir), false, variant);
  }
});
