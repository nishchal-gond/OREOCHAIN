/**
 * Key derivation off the main thread.
 *
 * Two things need proving, and they need different tests:
 *
 *   1. That js/core/kdf-worker.js actually runs as a worker — its imports
 *      resolve, its message wiring is correct. Only a real thread shows this.
 *   2. That the client handles every way a worker can misbehave: never
 *      loading, never answering, answering with an error, answering late, or
 *      answering something else's question. A fake worker covers those, since
 *      a real one cannot be made to fail on demand.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { Worker as NodeWorker } from "node:worker_threads";

import { equalBytes, randomBytes, toHex } from "../js/core/bytes.js";
import {
  deriveKeyEncryptionKey,
  handleKdfRequest,
  setKdfWorkerFactory,
} from "../js/core/kdf.js";

const SPEC = { name: "argon2id", memoryKiB: 8, iterations: 1, parallelism: 1 };

/*
 * An unknown KDF name is rejected during normalisation, before a worker is ever
 * created, so it cannot test the worker's error path. This one normalises
 * cleanly and only fails once Argon2 actually runs — which is what makes a
 * failure travel back across the message boundary.
 */
const SPEC_THAT_FAILS_IN_THE_HASH = {
  name: "argon2id",
  memoryKiB: 8,
  iterations: 0,
  parallelism: 1,
};
const PASSPHRASE = "a worker test passphrase";

/** Present Node's worker_threads Worker with the DOM Worker shape the client speaks. */
function realWorkerFactory() {
  const worker = new NodeWorker(new URL("../js/core/kdf-worker.js", import.meta.url));
  const adapter = {
    onmessage: null,
    onerror: null,
    postMessage: (message) => worker.postMessage(message),
    terminate: () => worker.terminate(),
  };
  worker.on("message", (data) => adapter.onmessage && adapter.onmessage({ data }));
  worker.on("error", (error) => adapter.onerror && adapter.onerror({ message: error.message }));
  return adapter;
}

/**
 * A worker that can be made to fail in each of the ways a real one can.
 * `fail`: "load" (never loaded), "silent" (never answers), null (answers).
 */
function fakeWorkerFactory({ fail = null, delayMs = 0, forgeId = null, onCreate } = {}) {
  return () => {
    const worker = {
      onmessage: null,
      onerror: null,
      terminated: false,
      postCount: 0,
      postMessage(request) {
        worker.postCount++;
        setTimeout(async () => {
          if (worker.terminated) return;
          if (fail === "load") {
            worker.onerror && worker.onerror({ message: "worker script failed to load" });
            return;
          }
          if (fail === "silent") return;
          const response = await handleKdfRequest(request);
          if (forgeId !== null) response.id = forgeId;
          worker.onmessage && worker.onmessage({ data: response });
        }, delayMs);
      },
      terminate() {
        worker.terminated = true;
      },
    };
    if (onCreate) onCreate(worker);
    return worker;
  };
}

// ------------------------------------------------------------- the real thing

test("the worker script runs in a real thread and derives the same key", async () => {
  // If this fails, the worker's imports do not resolve when loaded as a worker
  // — the failure mode that no amount of in-process testing would reveal.
  const salt = randomBytes(16);

  const inThread = await deriveKeyEncryptionKey(PASSPHRASE, salt, SPEC, {
    worker: realWorkerFactory,
  });
  const inline = await deriveKeyEncryptionKey(PASSPHRASE, salt, SPEC, { worker: false });

  assert.equal(inThread.length, 32);
  assert.ok(equalBytes(inThread, inline), "worker and inline derivation disagreed");
});

test("a real worker sends a failure back rather than hanging", async () => {
  await assert.rejects(
    () =>
      deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), SPEC_THAT_FAILS_IN_THE_HASH, {
        worker: realWorkerFactory,
        workerTimeoutMs: 5000,
      }),
    (error) => {
      assert.ok(!/timed out/.test(error.message), "the failure did not come back as a message");
      return true;
    }
  );
});

test("an unusable specification is rejected before a worker is even created", async () => {
  let created = 0;
  await assert.rejects(
    () =>
      deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), { name: "scrypt" }, {
        worker: () => {
          created++;
          return null;
        },
      }),
    /unsupported key-derivation/
  );
  assert.equal(created, 0, "a thread was spawned for a request that could never succeed");
});

test("two real workers running at once do not cross their answers", async () => {
  const saltA = randomBytes(16);
  const saltB = randomBytes(16);

  const [a, b] = await Promise.all([
    deriveKeyEncryptionKey("passphrase A", saltA, SPEC, { worker: realWorkerFactory }),
    deriveKeyEncryptionKey("passphrase B", saltB, SPEC, { worker: realWorkerFactory }),
  ]);

  assert.ok(equalBytes(a, await deriveKeyEncryptionKey("passphrase A", saltA, SPEC, { worker: false })));
  assert.ok(equalBytes(b, await deriveKeyEncryptionKey("passphrase B", saltB, SPEC, { worker: false })));
  assert.notEqual(toHex(a), toHex(b));
});

// ------------------------------------------------------------- the protocol

test("handleKdfRequest answers a well-formed request", async () => {
  const salt = randomBytes(16);
  const response = await handleKdfRequest({
    id: "req-1",
    type: "derive",
    passphrase: PASSPHRASE,
    salt,
    spec: SPEC,
  });

  assert.equal(response.id, "req-1");
  assert.equal(response.ok, true);
  assert.ok(response.key instanceof ArrayBuffer, "the key must be transferable");
  assert.equal(response.key.byteLength, 32);
});

test("handleKdfRequest accepts a salt that arrived as a plain ArrayBuffer", async () => {
  // Structured clone may deliver it either way depending on the runtime.
  const salt = randomBytes(16);
  const response = await handleKdfRequest({
    id: "req-2",
    type: "derive",
    passphrase: PASSPHRASE,
    salt: salt.buffer,
    spec: SPEC,
  });

  assert.equal(response.ok, true);
  const viaBuffer = new Uint8Array(response.key);
  const direct = await deriveKeyEncryptionKey(PASSPHRASE, salt, SPEC, { worker: false });
  assert.ok(equalBytes(viaBuffer, direct));
});

test("handleKdfRequest returns failures as data, never as a throw", async () => {
  // A throw inside a worker cannot reach the caller; it has to be a message.
  for (const request of [
    undefined,
    {},
    { id: "x", type: "something-else" },
    { id: "x", type: "derive", passphrase: "", salt: randomBytes(16), spec: SPEC },
    { id: "x", type: "derive", passphrase: "pw", salt: randomBytes(2), spec: SPEC },
    { id: "x", type: "derive", passphrase: "pw", salt: randomBytes(16), spec: { name: "md5" } },
  ]) {
    const response = await handleKdfRequest(request);
    assert.equal(response.ok, false, `expected a failure response for ${JSON.stringify(request)}`);
    assert.equal(typeof response.error, "string");
    assert.ok(response.error.length > 0);
  }
});

// --------------------------------------------------------- failure handling

test("no worker in this runtime falls back to deriving inline", async () => {
  const fallbacks = [];
  const key = await deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), SPEC, {
    worker: () => null,
    onFallback: (error) => fallbacks.push(error.message),
  });

  assert.equal(key.length, 32);
  assert.equal(fallbacks.length, 1);
  assert.match(fallbacks[0], /no worker implementation available/);
});

test("a worker that fails to load falls back instead of breaking the app", async () => {
  // A bad deployment — wrong MIME type, missing file — should degrade to a
  // slow derivation, not to a page that cannot decrypt anything.
  const fallbacks = [];
  const key = await deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), SPEC, {
    worker: fakeWorkerFactory({ fail: "load" }),
    onFallback: (error) => fallbacks.push(error.message),
  });

  assert.equal(key.length, 32);
  assert.equal(fallbacks.length, 1);
  assert.match(fallbacks[0], /failed to load/);
});

test("a factory that throws falls back", async () => {
  const key = await deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), SPEC, {
    worker: () => {
      throw new Error("SecurityError: worker blocked");
    },
  });
  assert.equal(key.length, 32);
});

test("a derivation error from the worker is propagated, not retried inline", async () => {
  // The inline attempt would block the thread and then fail identically.
  const fallbacks = [];
  await assert.rejects(
    () =>
      deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), SPEC_THAT_FAILS_IN_THE_HASH, {
        worker: fakeWorkerFactory(),
        onFallback: (error) => fallbacks.push(error),
      }),
    (error) => !/timed out|no worker/.test(error.message)
  );
  assert.equal(fallbacks.length, 0, "a real failure must not be treated as a missing worker");
});

test("a worker that never answers times out rather than hanging forever", async () => {
  await assert.rejects(
    () =>
      deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), SPEC, {
        worker: fakeWorkerFactory({ fail: "silent" }),
        workerTimeoutMs: 50,
      }),
    /timed out after 50ms/
  );
});

test("a timeout is not silently followed by an inline attempt", async () => {
  // Otherwise a one-second wait quietly becomes a minute-long one.
  const fallbacks = [];
  await assert.rejects(
    () =>
      deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), SPEC, {
        worker: fakeWorkerFactory({ fail: "silent" }),
        workerTimeoutMs: 50,
        onFallback: (error) => fallbacks.push(error),
      }),
    /timed out/
  );
  assert.equal(fallbacks.length, 0);
});

test("a response carrying someone else's id is ignored", async () => {
  await assert.rejects(
    () =>
      deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), SPEC, {
        worker: fakeWorkerFactory({ forgeId: "not-my-request" }),
        workerTimeoutMs: 100,
      }),
    /timed out/
  );
});

// ------------------------------------------------------------- housekeeping

test("the worker is terminated on success, on failure and on timeout", async () => {
  // It still holds the passphrase and tens of megabytes of Argon2 state, and
  // there is no way to scrub either, so it must not outlive the request.
  const created = [];
  const track = (options) => fakeWorkerFactory({ ...options, onCreate: (w) => created.push(w) });

  await deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), SPEC, { worker: track({}) });

  await assert.rejects(() =>
    deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), SPEC_THAT_FAILS_IN_THE_HASH, {
      worker: track({}),
    })
  );

  await assert.rejects(() =>
    deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), SPEC, {
      worker: track({ fail: "silent" }),
      workerTimeoutMs: 50,
    })
  );

  assert.equal(created.length, 3);
  for (const [i, worker] of created.entries()) {
    assert.equal(worker.terminated, true, `worker ${i} was left running`);
  }
});

test("the caller's salt is not detached by sending it to the worker", async () => {
  const salt = randomBytes(16);
  const before = toHex(salt);

  await deriveKeyEncryptionKey(PASSPHRASE, salt, SPEC, { worker: fakeWorkerFactory() });

  assert.equal(salt.length, 16, "salt was detached by a transfer");
  assert.equal(toHex(salt), before);
});

test("each request gets a distinct id", async () => {
  const seen = [];
  const factory = () => {
    const worker = {
      onmessage: null,
      onerror: null,
      postMessage(request) {
        seen.push(request.id);
        handleKdfRequest(request).then((r) => worker.onmessage && worker.onmessage({ data: r }));
      },
      terminate() {},
    };
    return worker;
  };

  await deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), SPEC, { worker: factory });
  await deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), SPEC, { worker: factory });

  assert.equal(seen.length, 2);
  assert.notEqual(seen[0], seen[1]);
});

test("a globally installed factory is used when no per-call worker is given", async () => {
  const created = [];
  setKdfWorkerFactory(fakeWorkerFactory({ onCreate: (w) => created.push(w) }));
  try {
    const key = await deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), SPEC);
    assert.equal(key.length, 32);
    assert.equal(created.length, 1);
  } finally {
    setKdfWorkerFactory(null);
  }
});

test("worker: false skips the worker entirely", async () => {
  let created = 0;
  setKdfWorkerFactory(() => {
    created++;
    return null;
  });
  try {
    const key = await deriveKeyEncryptionKey(PASSPHRASE, randomBytes(16), SPEC, { worker: false });
    assert.equal(key.length, 32);
    assert.equal(created, 0, "worker: false still consulted the factory");
  } finally {
    setKdfWorkerFactory(null);
  }
});
