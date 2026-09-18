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
 * OWASP's recommended Argon2id profile with the largest memory of the
 * practical options: m=46 MiB, t=1, p=1.
 *
 * Memory is the parameter that hurts a parallel attacker, so it is preferred
 * over passes when a budget has to be spent on one of them. This costs roughly
 * 0.7s in pure JavaScript on a desktop — the ceiling worth paying when the
 * derivation blocks the UI thread. Raise it for server-side use.
 */
export const ARGON2ID_DEFAULTS = Object.freeze({
  memoryKiB: 47104,
  iterations: 1,
  parallelism: 1,
});

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
        'e.g. "argon2id" or { name: "argon2id", memoryKiB: 47104 }'
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

function defaultWorkerFactory() {
  if (typeof Worker === "undefined") return null; // Node, or no worker support
  return new Worker(new URL("./kdf-worker.js", import.meta.url), { type: "module" });
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
