/**
 * Gateway configuration, read from the environment and validated at startup.
 *
 * Misconfiguration is the most common way a service like this ends up insecure:
 * it starts with no API keys and silently accepts anonymous uploads, or it
 * starts with a default secret nobody changed. So every setting is checked
 * here, and the process refuses to start rather than running in a state the
 * operator did not intend.
 */

import { readFileSync } from "node:fs";

import { LEVELS } from "./log.mjs";

const KIB = 1024;

/**
 * Read a setting that may be supplied directly or through a file.
 *
 * `FOO_FILE=/run/secrets/foo` is how Docker, Kubernetes and systemd hand a
 * secret to a process without putting it in the environment, where it is
 * visible to anything that can read /proc, gets inherited by every child
 * process, and turns up in `docker inspect` and crash dumps. Supporting it
 * costs three lines and is the difference between this being deployable with
 * a secret manager and not.
 */
export function readSecret(env, name) {
  const fromFile = env[`${name}_FILE`];
  if (!fromFile) return env[name] || null;

  // Checked before the read, so the ambiguity is reported even when the file
  // is also unreadable — that is the more useful of the two errors.
  if (env[name]) {
    throw new Error(
      `both ${name} and ${name}_FILE are set — remove one, rather than leaving it ambiguous ` +
        "which credential is in use"
    );
  }

  let contents;
  try {
    contents = readFileSync(fromFile, "utf8");
  } catch (error) {
    throw new Error(
      `${name}_FILE is set to "${fromFile}" but could not be read: ${error.message}`
    );
  }

  // A file written by `echo` has a trailing newline; a credential with one
  // appended fails authentication in a way that is miserable to diagnose.
  const value = contents.trim();
  if (!value) throw new Error(`${name}_FILE is set to "${fromFile}" but the file is empty`);
  return value;
}

function readInt(env, name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = env[name];
  if (raw === undefined || raw === "") return fallback;

  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}, got "${raw}"`);
  }
  return value;
}

function readList(env, name, fallback = []) {
  const raw = readSecret(env, name);
  if (raw === undefined || raw === null || raw === "") return fallback;
  return raw
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function readLevel(env, name, fallback) {
  const raw = (env[name] || fallback).toLowerCase();
  if (!(raw in LEVELS)) {
    throw new Error(`${name} must be one of ${Object.keys(LEVELS).join(", ")}, got "${raw}"`);
  }
  return raw;
}

export function loadConfig(env = process.env) {
  const apiKeys = readList(env, "OREOCHAIN_API_KEYS");
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

  /*
   * The subset of keys allowed to drive anchoring. A separate privilege on
   * purpose: an uploader's key that could also declare a batch anchored could
   * point every verifier of that batch at a transaction that does not exist,
   * and then block the real one as a conflict.
   */
  const anchorApiKeys = readList(env, "OREOCHAIN_ANCHOR_API_KEYS");
  for (const key of anchorApiKeys) {
    if (!apiKeys.includes(key)) {
      throw new Error(
        "every OREOCHAIN_ANCHOR_API_KEYS entry must also be in OREOCHAIN_API_KEYS — one is " +
          "not, so the worker holding it would be rejected before its privileges were " +
          "considered at all"
      );
    }
  }

  const pinataJwt = readSecret(env, "PINATA_JWT");
  if (!pinataJwt && env.OREOCHAIN_STORAGE !== "memory") {
    throw new Error(
      "PINATA_JWT is not set. Set it, or set OREOCHAIN_STORAGE=memory for local testing."
    );
  }

  return {
    port: readInt(env, "PORT", 8787, { min: 1, max: 65535 }),
    host: env.HOST || "127.0.0.1",

    apiKeys,
    anchorApiKeys,
    allowAnonymous,

    storage: env.OREOCHAIN_STORAGE === "memory" ? "memory" : "pinata",
    pinataJwt,

    /**
     * A chunk is 256 KiB of plaintext plus AEAD overhead. 1 MiB leaves room
     * for a larger configured chunk size without allowing arbitrary bodies.
     */
    maxChunkBytes: readInt(env, "OREOCHAIN_MAX_CHUNK_BYTES", KIB * KIB, {
      min: KIB,
      max: 64 * KIB * KIB,
    }),

    /**
     * How many request bodies may be buffered at once, process-wide.
     *
     * The per-request cap bounds one body; nothing bounded how many are in
     * flight. A token bucket does not help — a burst of 120 spends fine in
     * parallel — so at the default chunk cap that was ~360 MiB from one
     * well-behaved client, and 23 GiB at a 64 MiB chunk cap. Past this the
     * gateway sheds load with a 503 instead of running the host out of
     * memory.
     */
    maxConcurrentUploads: readInt(env, "OREOCHAIN_MAX_CONCURRENT_UPLOADS", 32, { min: 1 }),

    /** Token bucket: sustained rate and burst, per API key. */
    rateLimitPerMinute: readInt(env, "OREOCHAIN_RATE_LIMIT_PER_MINUTE", 600, { min: 1 }),
    rateLimitBurst: readInt(env, "OREOCHAIN_RATE_LIMIT_BURST", 120, { min: 1 }),

    /**
     * Browser origins allowed to call this gateway. Empty means same-origin
     * only — no CORS headers are sent, so no cross-origin page can read a
     * response. "*" is rejected because these endpoints are authenticated.
     */
    allowedOrigins: readList(env, "OREOCHAIN_ALLOWED_ORIGINS"),

    readTimeoutMs: readInt(env, "OREOCHAIN_READ_TIMEOUT_MS", 30_000, { min: 1000 }),
    upstreamTimeoutMs: readInt(env, "OREOCHAIN_UPSTREAM_TIMEOUT_MS", 60_000, { min: 1000 }),

    gateways: readList(env, "OREOCHAIN_IPFS_GATEWAYS", [
      "https://gateway.pinata.cloud/ipfs/",
      "https://ipfs.io/ipfs/",
      "https://cloudflare-ipfs.com/ipfs/",
    ]),

    /** Serve the static frontend from the repository root. */
    serveStatic: env.OREOCHAIN_SERVE_STATIC === "true",

    /**
     * Where recorded documents and built batches are kept.
     *
     * Durable by default. An anchored batch's ordered document list is the
     * only thing that can prove a document is in it, so holding it in memory
     * means a restart leaves documents anchored on-chain and unprovable.
     * ":memory:" opts back into that, for tests.
     */
    dbPath: env.OREOCHAIN_DB_PATH || "./oreochain-proofs.log",

    /**
     * How much the service says. "info" is one line per request outcome;
     * "warn" is problems only; "debug" adds per-request detail that is too
     * chatty to leave on. Validated here so a typo fails at startup rather
     * than silently losing every log line.
     */
    logLevel: readLevel(env, "OREOCHAIN_LOG_LEVEL", "info"),

    /**
     * Check a document against its manifest before signing a receipt for it.
     *
     * On by default, because a receipt that says "this service accepted this
     * exact document" while having checked nothing is worse than no receipt:
     * it carries a valid signature over an unverified claim. Turning it off
     * trades that guarantee for not depending on a manifest read at record
     * time, and the process says so at startup.
     */
    verifyManifests: env.OREOCHAIN_VERIFY_MANIFESTS !== "false",

    /**
     * How long to keep serving after SIGTERM before the listener closes.
     *
     * Readiness is only useful if something gets to observe it. An
     * orchestrator notices an instance is unready on its next probe, which is
     * seconds away; closing the listener in the same tick as flipping the flag
     * means traffic is still being routed here when the socket goes, and those
     * requests fail. This window is the gap between "stop sending me work" and
     * "I have stopped listening".
     *
     * Zero by default so a local Ctrl-C stays instant. In Kubernetes set it to
     * a little more than the readiness probe interval.
     */
    shutdownDelayMs: readInt(env, "OREOCHAIN_SHUTDOWN_DELAY_MS", 0, { min: 0, max: 120_000 }),
  };
}

/**
 * Configuration for the anchoring worker (server/anchor-worker.mjs).
 *
 * Separate from the gateway's because the two processes are deliberately
 * unalike: this one holds a key that can spend and never accepts a request,
 * and the gateway is the other way round. Sharing one config object would mean
 * every gateway also had the anchoring key in its environment.
 *
 * Everything the worker cannot work without is required here rather than
 * defaulted, so an incomplete deployment fails on the first line of output
 * instead of running for a week without anchoring anything.
 */
export function loadAnchorConfig(env = process.env) {
  const missing = [];
  const need = (name, value, hint) => {
    if (!value) missing.push(`${name} — ${hint}`);
    return value;
  };

  const rpcUrl = need(
    "OREOCHAIN_CHAIN_RPC",
    env.OREOCHAIN_CHAIN_RPC,
    "the JSON-RPC endpoint to submit anchors through"
  );
  const contractAddress = need(
    "OREOCHAIN_CONTRACT_ADDRESS",
    env.OREOCHAIN_CONTRACT_ADDRESS,
    "the deployed ChunkedVerification address"
  );

  /*
   * The one setting most likely to be left unset, and the one whose absence
   * used to be invisible: with no key nothing can be submitted, and a worker
   * that starts anyway would poll for ever while receipts kept promising an
   * anchor that was never coming.
   */
  const privateKey = need(
    "OREOCHAIN_ANCHOR_KEY",
    readSecret(env, "OREOCHAIN_ANCHOR_KEY"),
    "the funded private key that signs anchor transactions (or OREOCHAIN_ANCHOR_KEY_FILE)"
  );
  const apiKey = need(
    "OREOCHAIN_ANCHOR_API_KEY",
    readSecret(env, "OREOCHAIN_ANCHOR_API_KEY"),
    "an OREOCHAIN_API_KEYS entry the worker authenticates to the gateway with"
  );

  if (missing.length > 0) {
    throw new Error(
      `the anchoring worker cannot start, ${missing.length} setting(s) are missing:\n  ` +
        missing.join("\n  ")
    );
  }

  if (!/^0x[0-9a-fA-F]{40}$/.test(contractAddress)) {
    throw new Error(
      `OREOCHAIN_CONTRACT_ADDRESS must be a 20-byte hex address, got "${contractAddress}"`
    );
  }
  // Checked by shape only, and never echoed: a key pasted with a stray newline
  // or missing its 0x fails deep inside web3 with a message that does not say
  // which setting is wrong.
  if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) {
    throw new Error(
      "OREOCHAIN_ANCHOR_KEY must be a 0x-prefixed 32-byte hex private key " +
        `(got ${privateKey.length} characters)`
    );
  }

  return {
    rpcUrl,
    contractAddress,
    privateKey,

    gatewayUrl: env.OREOCHAIN_GATEWAY_URL || "http://127.0.0.1:8787",
    apiKey,

    /** How often to look for work. Anchoring is periodic by design. */
    intervalMs: readInt(env, "OREOCHAIN_ANCHOR_INTERVAL_MS", 60_000, { min: 1000 }),

    /**
     * Blocks to wait before recording an anchor as final.
     *
     * A receipt records the transaction a proof points at. Reporting one block
     * deep means a reorg can leave every receipt in that batch pointing at a
     * transaction that no longer exists, and a receipt is not something a user
     * comes back to re-check. Three is a floor for a fast chain; a public L1
     * wants more.
     */
    confirmations: readInt(env, "OREOCHAIN_ANCHOR_CONFIRMATIONS", 3, { min: 1, max: 1000 }),

    /**
     * How long to wait for a sent transaction to mine before sending another.
     * The contract rejects a duplicate anchor, so the cost of being wrong here
     * is one reverted transaction, not a second anchor.
     */
    pendingTimeoutMs: readInt(env, "OREOCHAIN_ANCHOR_PENDING_TIMEOUT_MS", 600_000, {
      min: 10_000,
    }),

    /**
     * Written into the anchor as where this batch's inclusion proofs live.
     * "{root}" is substituted. Empty means the anchor carries no pointer,
     * which is valid but leaves a verifier nothing to follow.
     */
    uriTemplate: env.OREOCHAIN_ANCHOR_URI || "",

    logLevel: readLevel(env, "OREOCHAIN_LOG_LEVEL", "info"),
  };
}

/**
 * Refuse settings that are unsafe, and warn about settings that are merely
 * dangerous.
 *
 * @param {object} config from loadConfig()
 * @param {{warn: (message: string, fields?: object) => void}} [sink] where
 *   warnings go; defaults to console so this stays usable from a script
 */
export function assertSafeConfig(config, sink = { warn: (message) => console.warn(message) }) {
  if (config.allowedOrigins.includes("*")) {
    throw new Error(
      'OREOCHAIN_ALLOWED_ORIGINS must not be "*" — these endpoints are authenticated, ' +
        "so a wildcard origin would let any site spend your quota."
    );
  }
  if (config.allowAnonymous && config.storage === "pinata") {
    sink.warn(
      "anonymous access is enabled and uploads are billed to your Pinata account: anyone " +
        "who can reach this port can spend your quota"
    );
  }
  if (config.dbPath === ":memory:") {
    sink.warn(
      'OREOCHAIN_DB_PATH is ":memory:", so recorded documents and anchored batches are lost ' +
        "on restart. A document anchored on-chain then has no recoverable inclusion proof. " +
        "Point it at a file on persistent storage."
    );
  }
  if (config.anchorApiKeys.length === 0 && !config.allowAnonymous) {
    sink.warn(
      "OREOCHAIN_ANCHOR_API_KEYS is not set, so the anchoring endpoints refuse every caller " +
        "and batches will be built but never anchored. Set it to the key the anchoring " +
        "worker uses, which must also appear in OREOCHAIN_API_KEYS."
    );
  }
  if (config.host === "0.0.0.0" && config.allowAnonymous) {
    sink.warn("listening on all interfaces with anonymous access enabled");
  }
  return config;
}
