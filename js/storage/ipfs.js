/**
 * Storage adapters.
 *
 * The chunking/encryption core never touches a network. Adapters do, and they
 * all present the same two methods:
 *
 *   put(bytes, name, opts) -> Promise<string>      store a block, return its id
 *   get(id, opts)          -> Promise<Uint8Array>
 *
 * Everything here assumes the network is unreliable, because it is: gateways
 * time out, pinning services rate-limit, and a chunked upload multiplies every
 * per-request failure probability by the number of chunks. A 400-chunk upload
 * with a 1% per-request failure rate fails outright 98% of the time without
 * retries. With them it essentially always completes.
 */

import { NETWORK_LIMITS } from "../core/limits.js";
import { parseRetryAfter, refusalAdvice } from "../core/refusals.js";

const DEFAULT_GATEWAYS = [
  "https://ipfs.io/ipfs/",
  "https://cloudflare-ipfs.com/ipfs/",
  "https://gateway.pinata.cloud/ipfs/",
];

/** A refusal body is a few fields; anything larger is not one worth parsing. */
const MAX_REFUSAL_BYTES = 64 * 1024;

/** CIDs are alphanumeric; anything else could escape a path or switch scheme. */
const SAFE_LOCATION = /^[A-Za-z0-9_-]{1,512}$/;

function assertSafeLocation(cid) {
  if (typeof cid !== "string" || !SAFE_LOCATION.test(cid)) {
    throw new Error(`refusing to fetch unsafe storage location: ${JSON.stringify(cid)}`);
  }
  return cid;
}

function abortError() {
  const error = new Error("operation aborted");
  error.name = "AbortError";
  return error;
}

function isAbort(error) {
  return error && (error.name === "AbortError" || error.code === "ABORT_ERR");
}

/**
 * Transient failures are worth retrying; permanent ones are not.
 * Retrying a 401 or a 400 just wastes time and hammers the service.
 *
 * A refusal code, where the gateway sent one, outranks the status. 429 is sent
 * both for "you sent that too fast" and for "you have spent your allowance for
 * the hour"; the first clears in a second and the second does not, and only
 * the code tells them apart. Retrying the second is how a client turns one
 * refusal into four and leaves the user watching a spinner that cannot win.
 */
function isRetryable(error) {
  if (isAbort(error)) return false;

  const advice = refusalAdvice(error.code);
  if (advice) return advice.retry;

  if (typeof error.status === "number") {
    return error.status === 408 || error.status === 429 || error.status >= 500;
  }
  return true; // network-level failure: DNS, reset connection, timeout
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) return reject(abortError());
    const timer = setTimeout(resolve, ms);
    if (signal) {
      signal.addEventListener(
        "abort",
        () => {
          clearTimeout(timer);
          reject(abortError());
        },
        { once: true }
      );
    }
  });
}

/**
 * Retry with exponential backoff and full jitter.
 *
 * Jitter matters more than it looks: without it, every chunk that failed at the
 * same moment retries at the same moment, reproducing the burst that caused the
 * failure. Randomising across the whole interval spreads them out.
 *
 * A `Retry-After` from the service wins over the computed backoff, because the
 * service knows when its window rolls and this side is guessing. It is a floor
 * rather than an exact delay: jitter still goes on top, or every client the
 * gateway pushed back reconverges on the same instant.
 */
export async function withRetry(operation, options = {}) {
  const {
    maxAttempts = NETWORK_LIMITS.maxAttempts,
    backoffBaseMs = NETWORK_LIMITS.backoffBaseMs,
    maxBackoffMs = NETWORK_LIMITS.maxBackoffMs,
    maxRetryAfterMs = NETWORK_LIMITS.maxRetryAfterMs,
    signal,
    onRetry,
  } = options;

  let lastError;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (signal && signal.aborted) throw abortError();
    try {
      return await operation(attempt);
    } catch (error) {
      lastError = error;
      if (attempt === maxAttempts || !isRetryable(error)) throw error;

      const ceiling = Math.min(backoffBaseMs * 2 ** (attempt - 1), maxBackoffMs);
      const jitter = Math.floor(Math.random() * ceiling);

      let delay = jitter;
      if (typeof error.retryAfterMs === "number") {
        // A long Retry-After is not a wobble to sleep through. Holding a tab
        // for two minutes to retry silently is worse than saying what happened
        // and letting the user decide, so it is surfaced rather than waited on.
        if (error.retryAfterMs > maxRetryAfterMs) throw error;
        delay = error.retryAfterMs + Math.floor(Math.random() * Math.min(ceiling, 1000));
      }

      if (onRetry) onRetry(attempt, delay, error);
      await sleep(delay, signal);
    }
  }
  throw lastError;
}

/**
 * Read a failed response's JSON body, for the refusal code and for anything
 * else the caller can use.
 *
 * Not every useful 4xx or 5xx is a refusal. The proof endpoints answer 404
 * with "no record of that document" and 503 with "the gateway could not reach
 * the chain", and both carry a full body the caller wants — so the parsed
 * body comes back whether or not it has a `code`.
 *
 * Best-effort by design: a gateway that fell over behind a proxy answers HTML,
 * and a body that cannot be read must not replace the status error with a
 * parse error. Bounded because this runs on a response nobody has vetted.
 */
async function readRefusal(response) {
  try {
    const type = response.headers && response.headers.get && response.headers.get("Content-Type");
    if (typeof type === "string" && !type.includes("json")) return null;
    if (typeof response.text !== "function") return null;

    const text = await response.text();
    if (typeof text !== "string" || text.length === 0 || text.length > MAX_REFUSAL_BYTES) {
      return null;
    }
    const body = JSON.parse(text);
    return body && typeof body === "object" ? body : null;
  } catch {
    return null;
  }
}

/** fetch with a timeout, composed with any caller-supplied abort signal. */
async function timedFetch(url, init = {}, { signal, timeoutMs } = {}) {
  const limit = timeoutMs ?? NETWORK_LIMITS.requestTimeoutMs;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), limit);

  const onAbort = () => controller.abort();
  if (signal) {
    if (signal.aborted) {
      clearTimeout(timer);
      throw abortError();
    }
    signal.addEventListener("abort", onAbort, { once: true });
  }

  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    if (!response.ok) {
      const error = new Error(`HTTP ${response.status}`);
      error.status = response.status;

      const header =
        response.headers && response.headers.get && response.headers.get("Retry-After");
      const retryAfterMs = parseRetryAfter(header);
      if (retryAfterMs !== null) error.retryAfterMs = retryAfterMs;

      const parsed = await readRefusal(response);
      if (parsed) {
        // The whole body, for an endpoint whose 404 or 503 is an answer rather
        // than a refusal and carries materials the caller needs.
        error.refusalBody = parsed;

        if (typeof parsed.code === "string") {
          error.code = parsed.code;
          // Kept for the log, never shown: the gateway's prose is for
          // operators and may be reworded, so the UI writes its own from the
          // code.
          error.serverMessage = typeof parsed.error === "string" ? parsed.error : undefined;
          error.message = `HTTP ${response.status} (${parsed.code})`;
        }
      }
      throw error;
    }
    return response;
  } catch (error) {
    // Distinguish "the caller cancelled" from "we timed out".
    if (isAbort(error) && !(signal && signal.aborted)) {
      const timeout = new Error(`request timed out after ${limit}ms`);
      timeout.status = 408;
      throw timeout;
    }
    throw error;
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener("abort", onAbort);
  }
}

/**
 * Fetch a CID, trying each gateway in turn and retrying transient failures on
 * each. A gateway returning 404 for content another gateway has is normal on
 * IPFS, so a permanent failure moves to the next gateway rather than aborting.
 */
async function fetchFromGateways(cid, gateways, options = {}) {
  assertSafeLocation(cid);
  const { signal, timeoutMs, retry = {} } = options;
  const errors = [];

  for (const gateway of gateways) {
    try {
      return await withRetry(
        async () => {
          const response = await timedFetch(
            `${gateway}${cid}`,
            { redirect: "follow" },
            { signal, timeoutMs }
          );
          return new Uint8Array(await response.arrayBuffer());
        },
        { ...retry, signal }
      );
    } catch (error) {
      if (isAbort(error)) throw error;
      errors.push(`${gateway}: ${error.message}`);
    }
  }

  throw new Error(`could not fetch ${cid} from any gateway (${errors.join("; ")})`);
}

export function createGatewayAdapter({ gateways = DEFAULT_GATEWAYS, retry, timeoutMs } = {}) {
  return {
    readOnly: true,
    async put() {
      throw new Error("this adapter is read-only — configure a pinning service to upload");
    },
    get(cid, options = {}) {
      return fetchFromGateways(cid, gateways, { retry, timeoutMs, ...options });
    },
  };
}

/**
 * @param {object} options
 * @param {"backend"|"direct"} [options.mode]
 *   "backend"  POST each block to your own server, which holds the pinning
 *              credentials. The browser never sees a token. The only safe
 *              option for anything public.
 *   "direct"   Call Pinata straight from the browser using a JWT from config.
 *              ANY VISITOR CAN READ THAT TOKEN out of the page and use your
 *              account. Local development only.
 */
export function createPinataAdapter(options = {}) {
  const {
    mode = "backend",
    endpoint = "/api/storage/pin",
    jwt = null,
    gateways = DEFAULT_GATEWAYS,
    retry,
    timeoutMs,
  } = options;

  if (mode === "direct") {
    if (!jwt) {
      throw new Error(
        'direct mode needs a Pinata JWT. Set storage.jwt in js/config.js, or switch to mode "backend".'
      );
    }
    console.warn(
      "[OREOCHAIN] Pinata credentials are exposed to every visitor in direct mode. " +
        "Use mode 'backend' outside local development."
    );
  } else if (mode !== "backend") {
    throw new Error(`unknown storage mode "${mode}" — expected "backend" or "direct"`);
  }

  function readCid(data) {
    const cid = data && (data.cid || data.IpfsHash);
    if (!cid) throw new Error("upload endpoint did not return a cid");
    return assertSafeLocation(cid);
  }

  async function putDirect(bytes, name, { signal } = {}) {
    const form = new FormData();
    form.append("file", new Blob([bytes], { type: "application/octet-stream" }), name);
    form.append("pinataMetadata", JSON.stringify({ name }));
    form.append("pinataOptions", JSON.stringify({ cidVersion: 1 }));

    const response = await timedFetch(
      "https://api.pinata.cloud/pinning/pinFileToIPFS",
      { method: "POST", headers: { Authorization: `Bearer ${jwt}` }, body: form },
      { signal, timeoutMs }
    );
    return readCid(await response.json());
  }

  /**
   * Raw bytes rather than multipart: the gateway needs no multipart parser
   * (a perennial source of parsing bugs) and the body size is trivially bounded.
   */
  async function putViaBackend(bytes, name, { signal } = {}) {
    const response = await timedFetch(
      endpoint,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
          "X-Chunk-Name": encodeURIComponent(name),
        },
        body: bytes,
        credentials: "same-origin",
      },
      { signal, timeoutMs }
    );
    return readCid(await response.json());
  }

  return {
    readOnly: false,
    mode,
    put(bytes, name = "chunk", callOptions = {}) {
      const send = mode === "direct" ? putDirect : putViaBackend;
      return withRetry(() => send(bytes, name, callOptions), {
        ...retry,
        signal: callOptions.signal,
      });
    },
    get(cid, callOptions = {}) {
      return fetchFromGateways(cid, gateways, { retry, timeoutMs, ...callOptions });
    },
  };
}

/** Build the adapter described by js/config.js. */
export function createAdapterFromConfig(config = {}) {
  const storage = config.storage || {};
  if (storage.provider === "pinata") return createPinataAdapter(storage);
  return createGatewayAdapter(storage);
}

/**
 * Upload every chunk, `concurrency` at a time.
 *
 * Pass `resumeFrom` — the locations array from an interrupted run — to skip
 * chunks that already uploaded. On a 2 GB file that is the difference between
 * losing an hour of work to one dropped connection and losing a few seconds.
 */
export async function putAll(adapter, chunks, options = {}) {
  const {
    concurrency = NETWORK_LIMITS.concurrency,
    onProgress,
    namePrefix = "chunk",
    signal,
    resumeFrom = null,
  } = options;

  const locations = new Array(chunks.length);
  if (resumeFrom) {
    for (let i = 0; i < chunks.length; i++) {
      if (typeof resumeFrom[i] === "string" && resumeFrom[i].length > 0) {
        locations[i] = resumeFrom[i];
      }
    }
  }

  const pending = [];
  for (let i = 0; i < chunks.length; i++) if (!locations[i]) pending.push(i);

  let cursor = 0;
  let done = chunks.length - pending.length;
  if (onProgress && done > 0) onProgress(done, chunks.length);

  /*
   * When one chunk hits a wall the others must stop too.
   *
   * Without this, a gateway that refuses because the day's budget is spent
   * gets three more concurrent uploads for its trouble — each retrying, each
   * refused — which is a small denial-of-service aimed at a service that has
   * already said no, and several seconds of a progress bar the user watches
   * advance towards a failure that has already happened.
   */
  const stop = new AbortController();
  const relay = () => stop.abort();
  if (signal) {
    if (signal.aborted) throw abortError();
    signal.addEventListener("abort", relay, { once: true });
  }
  let failure = null;

  async function worker() {
    while (true) {
      if (stop.signal.aborted) throw abortError();
      const slot = cursor++;
      if (slot >= pending.length) return;

      const index = pending[slot];
      try {
        locations[index] = await adapter.put(
          chunks[index].payload,
          `${namePrefix}-${String(index).padStart(6, "0")}`,
          { signal: stop.signal }
        );
      } catch (error) {
        // The first real failure is the one worth reporting; the aborts it
        // causes in its siblings are noise that would otherwise race to
        // replace it.
        if (!failure && !(isAbort(error) && stop.signal.aborted)) failure = error;
        stop.abort();
        throw error;
      }
      done++;
      if (onProgress) onProgress(done, chunks.length);
    }
  }

  const width = Math.max(1, Math.min(concurrency, pending.length));
  try {
    await Promise.all(Array.from({ length: width }, () => worker()));
  } catch (error) {
    throw failure || error;
  } finally {
    if (signal) signal.removeEventListener("abort", relay);
  }

  const missing = locations.findIndex((cid) => !cid);
  if (missing !== -1) throw new Error(`chunk ${missing} did not upload`);

  return locations;
}

export { timedFetch };

export const _internals = { isRetryable, assertSafeLocation, readRefusal, SAFE_LOCATION };
