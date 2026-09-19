/**
 * Server-side storage backends.
 *
 * This is the only place the pinning credential exists. It is read from the
 * environment, used to sign upstream requests, and never written to a log, a
 * response body or an error message.
 */

import { withRetry } from "../js/storage/ipfs.js";
import { MANIFEST_LIMITS } from "../js/core/limits.js";

/** A stored chunk is its plaintext plus at most the largest AEAD expansion. */
const MAX_AEAD_OVERHEAD = MANIFEST_LIMITS.maxAeadOverhead;

const PINATA_PIN_URL = "https://api.pinata.cloud/pinning/pinFileToIPFS";
const SAFE_CID = /^[A-Za-z0-9_-]{1,512}$/;

/**
 * Read a response body with a hard ceiling.
 *
 * response.arrayBuffer() buffers whatever arrives. The read gateways are third
 * parties named in config, so a hostile or broken one could hand back
 * gigabytes and the process would hold all of it — the one place where the
 * careful cap on request bodies had no counterpart on the way back.
 */
async function readCapped(response, maxBytes) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw Object.assign(new Error(`upstream body declares ${declared} bytes, over the ${maxBytes} cap`), {
      status: 502,
    });
  }

  if (!response.body) {
    // No streaming body (an older runtime, or a mocked response in a test).
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > maxBytes) {
      throw Object.assign(new Error(`upstream body exceeds ${maxBytes} bytes`), { status: 502 });
    }
    return bytes;
  }

  const parts = [];
  let received = 0;
  for await (const part of response.body) {
    received += part.length;
    if (received > maxBytes) {
      // Stop pulling rather than discovering the size after buffering it.
      await response.body.cancel().catch(() => {});
      throw Object.assign(new Error(`upstream body exceeds ${maxBytes} bytes`), { status: 502 });
    }
    parts.push(part);
  }

  const out = new Uint8Array(received);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function assertSafeCid(cid) {
  if (typeof cid !== "string" || !SAFE_CID.test(cid)) {
    throw new Error("unsafe storage identifier");
  }
  return cid;
}

async function withTimeout(promiseFactory, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await promiseFactory(controller.signal);
  } finally {
    clearTimeout(timer);
  }
}

export function createPinataBackend({ jwt, gateways, upstreamTimeoutMs, maxBodyBytes, retry }) {
  if (!jwt) throw new Error("createPinataBackend requires a JWT");

  const cap = maxBodyBytes ?? 64 * 1024 * 1024;

  return {
    name: "pinata",

    async put(bytes, name) {
      /*
       * Retried, because a chunked upload multiplies every per-request failure
       * by the number of chunks — the same arithmetic js/storage/ipfs.js spells
       * out for the browser. Without it a single transient 502 from the pinning
       * service fails the client's chunk, and the browser's own retry then
       * re-sends the whole chunk over the network instead of this process
       * retrying locally, where it is a fraction of the cost.
       */
      return withRetry(
        async () => {
          // Rebuilt per attempt: a FormData body is consumed once.
          const form = new FormData();
          form.append("file", new Blob([bytes], { type: "application/octet-stream" }), name);
          form.append("pinataMetadata", JSON.stringify({ name }));
          form.append("pinataOptions", JSON.stringify({ cidVersion: 1 }));

          const response = await withTimeout(
            (signal) =>
              fetch(PINATA_PIN_URL, {
                method: "POST",
                headers: { Authorization: `Bearer ${jwt}` },
                body: form,
                signal,
              }),
            upstreamTimeoutMs
          );

          if (!response.ok) {
            // Upstream text can echo request details; keep it out of our
            // response. The upstream status rides along so withRetry can tell
            // a transient 5xx from a permanent 401, and so it reaches the log.
            const error = new Error(`pinning service returned HTTP ${response.status}`);
            error.status = response.status;
            error.upstreamStatus = response.status;
            error.clientStatus = 502;
            throw error;
          }

          const data = await response.json();
          const cid = data && (data.IpfsHash || data.cid);
          if (!cid) throw new Error("pinning service returned no CID");
          return assertSafeCid(cid);
        },
        { ...retry }
      ).catch((error) => {
        // Whatever the upstream said, the client is told 502: its request was
        // fine, ours was not.
        throw Object.assign(error, { status: error.clientStatus || error.status || 502 });
      });
    },

    async get(cid) {
      assertSafeCid(cid);
      const failures = [];

      for (const gateway of gateways) {
        try {
          // Each gateway is retried before moving on: a 404 from one gateway
          // for content another holds is normal on IPFS, but a timeout or a
          // 5xx is worth a second attempt at the same one first.
          return await withRetry(async () => {
            const response = await withTimeout(
              (signal) => fetch(`${gateway}${cid}`, { signal, redirect: "follow" }),
              upstreamTimeoutMs
            );
            if (!response.ok) {
              throw Object.assign(new Error(`HTTP ${response.status}`), {
                status: response.status,
              });
            }
            return readCapped(response, cap);
          }, { ...retry });
        } catch (error) {
          failures.push(`${gateway}: ${error.message}`);
        }
      }

      const error = new Error(`content not retrievable (${failures.join("; ")})`);
      error.status = 502;
      throw error;
    },
  };
}

/** In-memory backend for local development and tests. Nothing is persisted. */
export function createMemoryBackend() {
  const blocks = new Map();
  let counter = 0;

  return {
    name: "memory",
    blocks,
    async put(bytes) {
      const cid = `memory${String(counter++).padStart(10, "0")}`;
      blocks.set(cid, Uint8Array.from(bytes));
      return cid;
    },
    async get(cid) {
      assertSafeCid(cid);
      if (!blocks.has(cid)) {
        const error = new Error("not found");
        error.status = 404;
        throw error;
      }
      return blocks.get(cid);
    },
  };
}

export function createBackend(config) {
  return config.storage === "memory"
    ? createMemoryBackend()
    : createPinataBackend({
        jwt: config.pinataJwt,
        gateways: config.gateways,
        upstreamTimeoutMs: config.upstreamTimeoutMs,
        maxBodyBytes: config.maxChunkBytes + MAX_AEAD_OVERHEAD,
      });
}

export const _internals = { assertSafeCid, SAFE_CID, readCapped };
