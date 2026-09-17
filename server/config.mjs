/**
 * Gateway configuration, read from the environment and validated at startup.
 *
 * Misconfiguration is the most common way a service like this ends up insecure:
 * it starts with no API keys and silently accepts anonymous uploads, or it
 * starts with a default secret nobody changed. So every setting is checked
 * here, and the process refuses to start rather than running in a state the
 * operator did not intend.
 */

const KIB = 1024;

function readInt(name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;

  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}, got "${raw}"`);
  }
  return value;
}

function readList(name, fallback = []) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  return raw
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function loadConfig(env = process.env) {
  const previous = process.env;
  process.env = env;

  try {
    const apiKeys = readList("OREOCHAIN_API_KEYS");
    const allowAnonymous = env.OREOCHAIN_ALLOW_ANONYMOUS === "true";

    if (apiKeys.length === 0 && !allowAnonymous) {
      throw new Error(
        "No API keys configured. Set OREOCHAIN_API_KEYS to a comma-separated list, " +
          "or set OREOCHAIN_ALLOW_ANONYMOUS=true if this gateway is genuinely public."
      );
    }
    for (const key of apiKeys) {
      if (key.length < 32) {
        throw new Error(
          `API keys must be at least 32 characters; one is ${key.length}. ` +
            "Generate one with: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\""
        );
      }
    }

    const pinataJwt = env.PINATA_JWT || null;
    if (!pinataJwt && env.OREOCHAIN_STORAGE !== "memory") {
      throw new Error(
        "PINATA_JWT is not set. Set it, or set OREOCHAIN_STORAGE=memory for local testing."
      );
    }

    return {
      port: readInt("PORT", 8787, { min: 1, max: 65535 }),
      host: env.HOST || "127.0.0.1",

      apiKeys,
      allowAnonymous,

      storage: env.OREOCHAIN_STORAGE === "memory" ? "memory" : "pinata",
      pinataJwt,

      /**
       * A chunk is 256 KiB of plaintext plus AEAD overhead. 1 MiB leaves room
       * for a larger configured chunk size without allowing arbitrary bodies.
       */
      maxChunkBytes: readInt("OREOCHAIN_MAX_CHUNK_BYTES", KIB * KIB, {
        min: KIB,
        max: 64 * KIB * KIB,
      }),

      /** Token bucket: sustained rate and burst, per API key. */
      rateLimitPerMinute: readInt("OREOCHAIN_RATE_LIMIT_PER_MINUTE", 600, { min: 1 }),
      rateLimitBurst: readInt("OREOCHAIN_RATE_LIMIT_BURST", 120, { min: 1 }),

      /**
       * Browser origins allowed to call this gateway. Empty means same-origin
       * only — no CORS headers are sent, so no cross-origin page can read a
       * response. "*" is rejected because these endpoints are authenticated.
       */
      allowedOrigins: readList("OREOCHAIN_ALLOWED_ORIGINS"),

      readTimeoutMs: readInt("OREOCHAIN_READ_TIMEOUT_MS", 30_000, { min: 1000 }),
      upstreamTimeoutMs: readInt("OREOCHAIN_UPSTREAM_TIMEOUT_MS", 60_000, { min: 1000 }),

      gateways: readList("OREOCHAIN_IPFS_GATEWAYS", [
        "https://gateway.pinata.cloud/ipfs/",
        "https://ipfs.io/ipfs/",
        "https://cloudflare-ipfs.com/ipfs/",
      ]),

      /** Serve the static frontend from the repository root. */
      serveStatic: env.OREOCHAIN_SERVE_STATIC === "true",
    };
  } finally {
    process.env = previous;
  }
}

export function assertSafeConfig(config) {
  if (config.allowedOrigins.includes("*")) {
    throw new Error(
      'OREOCHAIN_ALLOWED_ORIGINS must not be "*" — these endpoints are authenticated, ' +
        "so a wildcard origin would let any site spend your quota."
    );
  }
  if (config.allowAnonymous && config.storage === "pinata") {
    console.warn(
      "[oreochain] WARNING: anonymous access is enabled and uploads are billed to your " +
        "Pinata account. Anyone who can reach this port can spend your quota."
    );
  }
  if (config.host === "0.0.0.0" && config.allowAnonymous) {
    console.warn(
      "[oreochain] WARNING: listening on all interfaces with anonymous access enabled."
    );
  }
  return config;
}
