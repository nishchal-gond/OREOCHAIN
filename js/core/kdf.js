/**
 * Passphrase key-derivation functions.
 *
 * WHY THIS IS THE MOST IMPORTANT FILE IN THE PROJECT
 *
 * Every other defence here assumes the attacker does not have the file key.
 * The file key is wrapped by a key derived from a human-chosen passphrase, and
 * the wrapped key is public — it travels in the manifest. So an attacker who
 * fetches a manifest can guess passphrases offline, as fast as their hardware
 * allows, with no rate limit and nobody watching.
 *
 * That makes the cost of a single guess the real security parameter. Not the
 * cipher. AES-256 is irrelevant if "summer2024" takes a millisecond to test.
 *
 * PBKDF2 raises that cost by iterating, but it needs almost no memory, so a GPU
 * runs thousands of guesses in parallel and an ASIC does far better. Argon2id is
 * *memory-hard*: each guess must allocate and randomly traverse tens of
 * megabytes, which is exactly the resource parallel hardware cannot cheaply
 * multiply. The same attacker budget buys orders of magnitude fewer guesses.
 *
 * Argon2id specifically — rather than Argon2i or Argon2d — is the hybrid RFC
 * 9106 recommends by default: Argon2d's data-dependent addressing resists
 * time-memory trade-offs but leaks through cache side channels, Argon2i is the
 * reverse, and Argon2id takes one pass of each.
 *
 * PBKDF2 remains implemented, because files sealed before this existed must
 * still open. It is readable, never written for new files.
 */

import { argon2id } from "../../node_modules/@noble/hashes/esm/argon2.js";
import { utf8, webcrypto } from "./bytes.js";

export const KDF_ARGON2ID = "argon2id";
export const KDF_PBKDF2 = "pbkdf2-sha256";

/** New files use Argon2id. PBKDF2 is read-only legacy. */
export const DEFAULT_KDF = KDF_ARGON2ID;

const KEY_BYTES = 32;

/**
 * THE SHIPPED ARGON2ID PROFILE — THE ONLY PLACE THESE NUMBERS ARE WRITTEN.
 *
 * Every other mention of them in this repository is derived from here: the
 * example config points at this file instead of restating the numbers, the
 * settings tables and prose in docs/SECURITY.md, docs/SEALING.md and Readme.md
 * are written from here by scripts/sync-kdf-docs.mjs, test/docs-kdf.test.js
 * fails while any of that prose disagrees with these values, and
 * test/kdf.test.js ratchets them against a floor instead of restating them.
 * Change the profile here, run `npm run kdf-docs`, and the repository agrees
 * with itself again.
 *
 * Memory is the parameter that hurts a parallel attacker most, so it gets the
 * larger share of the budget, but passes are not free to an attacker either:
 * cost scales roughly with memory x passes. Deliberately no figure appears in
 * this comment; the numbers are directly below, and a comment restating them is
 * how the last six copies started.
 *
 * The cost is affordable only because derivation runs in a worker
 * (js/core/kdf-worker.js) and no longer freezes the page — on the main thread
 * this would have been an unusable amount of jank, which is exactly why the
 * worker came first. A server, where nobody is watching a spinner, can raise it
 * further.
 */
export const ARGON2ID_DEFAULTS = Object.freeze({
  memoryKiB: 65536,
  iterations: 2,
  parallelism: 1,
});

/**
 * Claims about the profile above, rather than the profile itself, kept out of
 * ARGON2ID_DEFAULTS because that object is a parameter set handed to Argon2 and
 * compared against manifests. These are the two things the documentation says
 * that cannot be read off the parameters, so they live here for the same reason
 * the parameters do.
 */
export const ARGON2ID_PROFILE = Object.freeze({
  /**
   * Measured, not computed: one derivation in pure JavaScript on a desktop,
   * with no worker. A phone is slower, sometimes several times slower. Re-time
   * it when the parameters change — `npm run kdf-docs` cannot.
   */
  estimatedSeconds: 2.2,

  /**
   * The first Argon2id profile OREOCHAIN shipped (PR #5), kept as the cost floor
   * the defaults must never fall back below. Raising the defaults is always
   * welcome and needs no edit here; dropping under this line weakens a file's
   * only defence against an offline guess, and test/kdf.test.js fails rather
   * than let that pass for a typo.
   *
   * It is also the profile test/kdf.test.js seals a file under to prove older
   * files still open, so it stays a real historical profile and not a round
   * number.
   */
  costFloor: Object.freeze({ memoryKiB: 47104, iterations: 1, parallelism: 1 }),
});

/**
 * What an attacker's budget actually buys against a profile: memory x passes.
 * Halving either number halves this, which is why it is the quantity the tests
 * and the documentation compare rather than memory alone.
 */
export function argon2idCost(spec = ARGON2ID_DEFAULTS) {
  return spec.memoryKiB * spec.iterations;
}

/** OWASP's floor for PBKDF2-HMAC-SHA256. Legacy files only. */
export const PBKDF2_DEFAULTS = Object.freeze({ iterations: 600000 });

/**
 * Manifests written before Argon2id existed spell the name "PBKDF2-SHA256".
 * Normalising here keeps every reader on one spelling.
 */
export function normalizeKdfName(name) {
  const lower = String(name || "").toLowerCase();
  if (lower === KDF_ARGON2ID || lower === "argon2") return KDF_ARGON2ID;
  if (lower === KDF_PBKDF2 || lower === "pbkdf2" || lower === "pbkdf2-hmac-sha256") {
    return KDF_PBKDF2;
  }
  throw new Error(`unsupported key-derivation function: ${name}`);
}

/** Build a parameter set, filling in defaults for anything unspecified. */
export function kdfSpec(input = DEFAULT_KDF) {
  // Reject anything that is not a name or a parameter set. An earlier version
  // of this API took a bare PBKDF2 iteration count positionally; spreading a
  // number yields {} and would silently hand back defaults, turning an
  // upgrade into a quiet change of security parameters.
  if (typeof input === "number" || typeof input === "boolean" || input === null) {
    throw new Error(
      `kdf must be a name or a parameter object, received ${typeof input} — ` +
        `e.g. "argon2id" or { name: "argon2id", memoryKiB: ${ARGON2ID_DEFAULTS.memoryKiB} }`
    );
  }
  const raw = typeof input === "string" ? { name: input } : { ...input };
  const name = normalizeKdfName(raw.name || DEFAULT_KDF);

  if (name === KDF_ARGON2ID) {
    const spec = {
      name,
      memoryKiB: raw.memoryKiB ?? ARGON2ID_DEFAULTS.memoryKiB,
      iterations: raw.iterations ?? ARGON2ID_DEFAULTS.iterations,
      parallelism: raw.parallelism ?? ARGON2ID_DEFAULTS.parallelism,
    };
    assertArgon2Shape(spec);
    return spec;
  }
  return { name, iterations: raw.iterations ?? PBKDF2_DEFAULTS.iterations };
}

/**
 * Argon2 requires at least 8 KiB of memory per lane. Checking it here turns a
 * cryptic failure from deep inside the hash into a clear one at the point the
 * parameters were chosen.
 */
export function assertArgon2Shape(spec) {
  if (spec.memoryKiB < 8 * spec.parallelism) {
    throw new Error(
      `Argon2id needs memoryKiB >= 8 * parallelism (got ${spec.memoryKiB} with p=${spec.parallelism})`
    );
  }
  return spec;
}

/** A short description for a UI or a log line. */
export function describeKdf(spec) {
  const normalized = kdfSpec(spec);
  return normalized.name === KDF_ARGON2ID
    ? `Argon2id (${normalized.memoryKiB} KiB, ${normalized.iterations} pass${
        normalized.iterations === 1 ? "" : "es"
      }, p=${normalized.parallelism})`
    : `PBKDF2-SHA256 (${normalized.iterations} iterations)`;
}

async function derivePbkdf2(passphrase, salt, iterations) {
  const subtle = webcrypto().subtle;
  const material = await subtle.importKey("raw", utf8(passphrase), "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    material,
    KEY_BYTES * 8
  );
  return new Uint8Array(bits);
}

function deriveArgon2id(passphrase, salt, spec) {
  return argon2id(utf8(passphrase), salt, {
    t: spec.iterations,
    m: spec.memoryKiB,
    p: spec.parallelism,
    dkLen: KEY_BYTES,
  });
}

/**
 * Stretch a passphrase into a 256-bit key-encryption key.
 *
 * @param {string} passphrase
 * @param {Uint8Array} salt unique per file, so one cracking effort buys one file
 * @param {object|string} spec see kdfSpec()
 */
export async function deriveKeyEncryptionKey(passphrase, salt, spec = DEFAULT_KDF, options = {}) {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new Error("a passphrase is required");
  }
  if (!(salt instanceof Uint8Array) || salt.length < 8) {
    throw new Error("a salt of at least 8 bytes is required");
  }

  const normalized = kdfSpec(spec);
  const { worker = "auto", workerTimeoutMs = WORKER_TIMEOUT_MS, onFallback } = options;

  if (worker !== false) {
    const factory =
      typeof worker === "function" ? worker : injectedWorkerFactory || defaultWorkerFactory;
    try {
      return await deriveViaWorker(passphrase, salt, normalized, factory, workerTimeoutMs);
    } catch (error) {
      /*
       * Only fall back when no usable worker exists — no Worker in this
       * runtime, or the script failed to load. A derivation that ran and
       * failed, or timed out, is propagated: repeating it inline would block
       * the thread for the same reason and then fail identically, and a
       * timeout silently followed by a second attempt is how a one-second
       * wait becomes a minute-long one.
       */
      if (!error.workerUnavailable) throw error;
      if (onFallback) onFallback(error);
    }
  }

  return normalized.name === KDF_ARGON2ID
    ? deriveArgon2id(passphrase, salt, normalized)
    : derivePbkdf2(passphrase, salt, normalized.iterations);
}

export const _internals = { deriveArgon2id, derivePbkdf2, KEY_BYTES };

// ---------------------------------------------------------------- worker path

/**
 * A derivation should never take this long. Reaching it means something is
 * wrong with the worker, not that the parameters were ambitious.
 */
const WORKER_TIMEOUT_MS = 60_000;

let requestCounter = 0;
let injectedWorkerFactory = null;

/** Override how workers are created. Used by tests and by bundled builds. */
export function setKdfWorkerFactory(factory) {
  injectedWorkerFactory = factory;
}

/**
 * Node's worker_threads.Worker, when this module is running on Node and there
 * is no browser Worker to use.
 *
 * Resolved once, at module load, because defaultWorkerFactory() has to be
 * synchronous — deriveViaWorker() calls it and needs a worker back, not a
 * promise. The import is reached only on Node, exactly as bytes.js resolves
 * WebCrypto, so a browser never evaluates it.
 */
let nodeWorkerCtor = null;

if (
  typeof Worker === "undefined" &&
  typeof process !== "undefined" &&
  process.versions &&
  process.versions.node
) {
  try {
    nodeWorkerCtor = (await import("node:worker_threads")).Worker;
  } catch {
    // No worker_threads (an unusual build); derivation falls back to inline.
  }
}

/**
 * Adapt a Node worker to the browser Worker surface deriveViaWorker() uses.
 *
 * Node emits "message" and "error" events where a browser sets .onmessage and
 * .onerror, and delivers the message value directly rather than wrapped in an
 * event — which deriveViaWorker() already unwraps either way. unref() keeps a
 * derivation from holding a CLI or a test runner open if it is ever abandoned.
 */
function adaptNodeWorker(worker) {
  const adapter = {
    onmessage: null,
    onerror: null,
    postMessage: (message) => worker.postMessage(message),
    terminate: () => worker.terminate(),
  };
  worker.on("message", (data) => adapter.onmessage && adapter.onmessage(data));
  worker.on("error", (error) => adapter.onerror && adapter.onerror(error));
  worker.unref();
  return adapter;
}

/**
 * A worker to derive in, or null if this runtime has none.
 *
 * Returning null on Node was the whole story until now: `typeof Worker` is
 * undefined there, so every server-side and CLI derivation fell back to running
 * Argon2id inline — tens of megabytes and seconds of hashing on the thread that
 * was meant to be serving other requests — even though kdf-worker.js has
 * supported worker_threads all along and nothing but this function stood
 * between them.
 */
function defaultWorkerFactory() {
  const url = new URL("./kdf-worker.js", import.meta.url);
  if (typeof Worker !== "undefined") return new Worker(url, { type: "module" });
  if (nodeWorkerCtor) return adaptNodeWorker(new nodeWorkerCtor(url));
  return null; // no worker support in this runtime
}

/**
 * The worker side of the protocol, kept here rather than in the worker file so
 * it can be exercised directly by tests without spawning a thread.
 *
 * Returns a response object instead of throwing: a failure has to travel back
 * across postMessage as data either way.
 */
export async function handleKdfRequest(request) {
  const id = request ? request.id : undefined;
  try {
    if (!request || request.type !== "derive") {
      throw new Error(`unknown request type: ${request ? request.type : typeof request}`);
    }

    const salt = request.salt instanceof Uint8Array ? request.salt : new Uint8Array(request.salt);
    // worker: false — this is already the worker; anything else would recurse.
    const key = await deriveKeyEncryptionKey(request.passphrase, salt, request.spec, {
      worker: false,
    });

    // Copy into an exactly-sized buffer so the whole thing can be transferred.
    const out = new Uint8Array(key);
    return { id, ok: true, key: out.buffer };
  } catch (error) {
    return { id, ok: false, error: error.message };
  }
}

function deriveViaWorker(passphrase, salt, spec, factory, timeoutMs) {
  return new Promise((resolve, reject) => {
    let worker;
    try {
      worker = factory();
    } catch (error) {
      error.workerUnavailable = true;
      reject(error);
      return;
    }
    if (!worker) {
      const error = new Error("no worker implementation available");
      error.workerUnavailable = true;
      reject(error);
      return;
    }

    const id = `kdf-${++requestCounter}`;
    let settled = false;

    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      // Terminate rather than pool: the worker still holds the passphrase and
      // tens of megabytes of Argon2 state, and there is no way to scrub them.
      try {
        worker.terminate();
      } catch {
        /* a worker that cannot be terminated is not worth failing over */
      }
      fn(value);
    };

    const timer = setTimeout(
      () => finish(reject, new Error(`key derivation timed out after ${timeoutMs}ms`)),
      timeoutMs
    );

    worker.onmessage = (event) => {
      const data = event && "data" in event ? event.data : event;
      if (!data || data.id !== id) return; // not ours
      if (data.ok) finish(resolve, new Uint8Array(data.key));
      else finish(reject, new Error(data.error || "key derivation failed in the worker"));
    };

    worker.onerror = (event) => {
      // The worker script failed to load or threw at the top level — a broken
      // deployment, not a broken passphrase. Flagged so the caller can fall
      // back to deriving inline rather than failing outright.
      const error = new Error(
        (event && (event.message || event.error?.message)) || "key derivation worker failed"
      );
      error.workerUnavailable = true;
      finish(reject, error);
    };

    worker.postMessage({
      id,
      type: "derive",
      passphrase,
      // A copy, cloned rather than transferred, so the caller's salt survives.
      salt: salt.slice(),
      spec,
    });
  });
}
