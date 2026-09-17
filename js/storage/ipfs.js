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

const DEFAULT_GATEWAYS = [
  "https://ipfs.io/ipfs/",
  "https://cloudflare-ipfs.com/ipfs/",
  "https://gateway.pinata.cloud/ipfs/",
];

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
 */
function isRetryable(error) {
  if (isAbort(error)) return false;
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
 */
export async function withRetry(operation, options = {}) {
  const {
    maxAttempts = NETWORK_LIMITS.maxAttempts,
    backoffBaseMs = NETWORK_LIMITS.backoffBaseMs,
    maxBackoffMs = NETWORK_LIMITS.maxBackoffMs,
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
      const delay = Math.floor(Math.random() * ceiling);
      if (onRetry) onRetry(attempt, delay, error);
      await sleep(delay, signal);
    }
  }
  throw lastError;
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

  async function worker() {
    while (true) {
      if (signal && signal.aborted) throw abortError();
      const slot = cursor++;
      if (slot >= pending.length) return;

      const index = pending[slot];
      locations[index] = await adapter.put(
        chunks[index].payload,
        `${namePrefix}-${String(index).padStart(6, "0")}`,
        { signal }
      );
      done++;
      if (onProgress) onProgress(done, chunks.length);
    }
  }

  const width = Math.max(1, Math.min(concurrency, pending.length));
  await Promise.all(Array.from({ length: width }, () => worker()));

  const missing = locations.findIndex((cid) => !cid);
  if (missing !== -1) throw new Error(`chunk ${missing} did not upload`);

  return locations;
}

export const _internals = { isRetryable, assertSafeLocation, SAFE_LOCATION };
