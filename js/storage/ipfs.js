/**
 * Storage adapters.
 *
 * The chunking/encryption core never talks to a network. Adapters do, and they
 * all present the same two methods:
 *
 *   put(bytes, name) -> Promise<string>   store a block, return its id (a CID)
 *   get(id)          -> Promise<Uint8Array>
 *
 * Two are provided:
 *
 *   createGatewayAdapter  read-only, fetches from public IPFS gateways with
 *                         failover. Used by the verify page, which never uploads.
 *
 *   createPinataAdapter   read/write. Its `mode` decides where the credentials
 *                         live — see the warning on direct mode below.
 */

const DEFAULT_GATEWAYS = [
  "https://ipfs.io/ipfs/",
  "https://cloudflare-ipfs.com/ipfs/",
  "https://gateway.pinata.cloud/ipfs/",
];

async function fetchFromGateways(cid, gateways, signal) {
  const errors = [];
  for (const gateway of gateways) {
    try {
      const response = await fetch(`${gateway}${cid}`, { signal });
      if (!response.ok) {
        errors.push(`${gateway}: HTTP ${response.status}`);
        continue;
      }
      return new Uint8Array(await response.arrayBuffer());
    } catch (err) {
      errors.push(`${gateway}: ${err.message}`);
    }
  }
  throw new Error(`could not fetch ${cid} from any gateway (${errors.join("; ")})`);
}

export function createGatewayAdapter({ gateways = DEFAULT_GATEWAYS } = {}) {
  return {
    readOnly: true,
    async put() {
      throw new Error("this adapter is read-only — configure a pinning service to upload");
    },
    get(cid, { signal } = {}) {
      return fetchFromGateways(cid, gateways, signal);
    },
  };
}

/**
 * @param {object} options
 * @param {"backend"|"direct"} [options.mode]
 *   "backend"  POST each block to your own server, which holds the Pinata
 *              credentials and forwards the upload. The only safe option for
 *              anything public.
 *   "direct"   Call Pinata straight from the browser using a JWT from config.
 *              ANY VISITOR CAN READ THAT TOKEN out of the page and use your
 *              account. Acceptable for local development only.
 * @param {string} [options.endpoint] your backend's upload URL (backend mode)
 * @param {string} [options.jwt] a Pinata JWT (direct mode)
 * @param {string[]} [options.gateways] read gateways
 */
export function createPinataAdapter(options = {}) {
  const {
    mode = "backend",
    endpoint = "/api/storage/pin",
    jwt = null,
    gateways = DEFAULT_GATEWAYS,
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

  async function putDirect(bytes, name) {
    const form = new FormData();
    form.append("file", new Blob([bytes], { type: "application/octet-stream" }), name);
    form.append("pinataMetadata", JSON.stringify({ name }));
    form.append("pinataOptions", JSON.stringify({ cidVersion: 1 }));

    const response = await fetch("https://api.pinata.cloud/pinning/pinFileToIPFS", {
      method: "POST",
      headers: { Authorization: `Bearer ${jwt}` },
      body: form,
    });
    if (!response.ok) {
      throw new Error(`Pinata upload failed: HTTP ${response.status} ${await response.text()}`);
    }
    const data = await response.json();
    return data.IpfsHash;
  }

  async function putViaBackend(bytes, name) {
    const form = new FormData();
    form.append("file", new Blob([bytes], { type: "application/octet-stream" }), name);
    form.append("name", name);

    const response = await fetch(endpoint, {
      method: "POST",
      body: form,
      credentials: "same-origin",
    });
    if (!response.ok) {
      throw new Error(`upload failed: HTTP ${response.status} ${await response.text()}`);
    }
    const data = await response.json();
    const cid = data.cid || data.IpfsHash;
    if (!cid) throw new Error("upload endpoint did not return a cid");
    return cid;
  }

  return {
    readOnly: false,
    mode,
    put(bytes, name = "chunk") {
      return mode === "direct" ? putDirect(bytes, name) : putViaBackend(bytes, name);
    },
    get(cid, { signal } = {}) {
      return fetchFromGateways(cid, gateways, signal);
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
 * Run up to `concurrency` uploads at a time. IPFS pinning is latency-bound, so
 * a large file with hundreds of chunks uploads several times faster this way —
 * while still bounding how many requests are in flight.
 */
export async function putAll(adapter, chunks, { concurrency = 4, onProgress, namePrefix = "chunk" } = {}) {
  const locations = new Array(chunks.length);
  let next = 0;
  let done = 0;

  async function worker() {
    while (true) {
      const index = next++;
      if (index >= chunks.length) return;
      locations[index] = await adapter.put(
        chunks[index].payload,
        `${namePrefix}-${String(index).padStart(6, "0")}`
      );
      done++;
      if (onProgress) onProgress(done, chunks.length);
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(concurrency, chunks.length) }, () => worker())
  );
  return locations;
}
