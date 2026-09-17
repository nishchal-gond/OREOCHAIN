/**
 * Server-side storage backends.
 *
 * This is the only place the pinning credential exists. It is read from the
 * environment, used to sign upstream requests, and never written to a log, a
 * response body or an error message.
 */

const PINATA_PIN_URL = "https://api.pinata.cloud/pinning/pinFileToIPFS";
const SAFE_CID = /^[A-Za-z0-9_-]{1,512}$/;

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

export function createPinataBackend({ jwt, gateways, upstreamTimeoutMs }) {
  if (!jwt) throw new Error("createPinataBackend requires a JWT");

  return {
    name: "pinata",

    async put(bytes, name) {
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
        // Upstream text can echo request details; keep it out of our response.
        const error = new Error(`pinning service returned HTTP ${response.status}`);
        error.status = response.status === 401 ? 502 : 502;
        error.upstreamStatus = response.status;
        throw error;
      }

      const data = await response.json();
      const cid = data && (data.IpfsHash || data.cid);
      if (!cid) throw new Error("pinning service returned no CID");
      return assertSafeCid(cid);
    },

    async get(cid) {
      assertSafeCid(cid);
      const failures = [];

      for (const gateway of gateways) {
        try {
          const response = await withTimeout(
            (signal) => fetch(`${gateway}${cid}`, { signal, redirect: "follow" }),
            upstreamTimeoutMs
          );
          if (!response.ok) {
            failures.push(`${gateway}: HTTP ${response.status}`);
            continue;
          }
          return new Uint8Array(await response.arrayBuffer());
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
      });
}

export const _internals = { assertSafeCid, SAFE_CID };
