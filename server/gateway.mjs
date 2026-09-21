/**
 * The OREOCHAIN gateway: an HTTP service that sits between your users and your
 * pinning provider.
 *
 * It exists so that the pinning credential never reaches a browser. Users
 * authenticate to this service; this service authenticates to the provider. It
 * also gives you the things a browser cannot enforce for you — rate limits,
 * quotas, request size caps, and an audit point where every upload is visible.
 *
 * What it deliberately does NOT do: decrypt anything. Chunks arrive already
 * encrypted by the client, and this process never sees a passphrase or a file
 * key. A full compromise of this server exposes ciphertext and traffic patterns,
 * not documents. Keep it that way — it is the property that makes the service
 * safe to operate on someone else's behalf.
 *
 * Endpoints:
 *   GET  /health                 liveness, unauthenticated
 *   GET  /ready                  readiness — safe to send traffic to
 *   GET  /metrics                Prometheus exposition, authenticated
 *   POST /api/storage/pin        store one chunk (raw body) -> { cid }
 *   GET  /api/storage/<cid>      retrieve one chunk
 */

import { randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import path from "node:path";

import { authenticate } from "./auth.mjs";
import { createLogger } from "./log.mjs";
import { createMetrics } from "./metrics.mjs";
import { createRateLimiter } from "./ratelimit.mjs";
import { clientAddress } from "./clientaddr.mjs";
import { createQuota } from "./quota.mjs";
import { REFUSAL_CODES } from "./refusals.mjs";
import { ABSENT, CONFIRMED, UNAVAILABLE } from "./confirm.mjs";
import { verifyInBatch } from "../js/core/anchor.js";

const CID_ROUTE = /^\/api\/storage\/([A-Za-z0-9_-]{1,512})$/;
const INCLUSION_ROUTE = /^\/api\/proofs\/inclusion\/(0x[0-9a-fA-F]{64})$/;
const VERIFY_ROUTE = /^\/api\/proofs\/verify\/(0x[0-9a-fA-F]{64})$/;

/**
 * Endpoints that must work without a key. Verifying someone else's document is
 * a public act — a court, an employer or a regulator checking a certificate has
 * no account here and should not need one.
 */
const PUBLIC_API = new Set(["/api/proofs/key"]);

/** JSON bodies are metadata, not payloads, so they get a much tighter cap. */
const MAX_JSON_BYTES = 64 * 1024;

/**
 * How many unanchored batches one listing returns. The worker anchors them
 * oldest first and comes back, so a backlog drains over several ticks rather
 * than in one unbounded response.
 */
const ANCHOR_PAGE = 100;

/**
 * A client-supplied request id is echoed and logged, so it has to be inert:
 * bounded, and made only of characters that cannot break a header, forge a log
 * field or inject a newline into the JSON line it lands in.
 */
const SAFE_REQUEST_ID = /^[A-Za-z0-9._:-]{1,64}$/;

/**
 * Re-exported, not defined here: see server/refusals.mjs for why, and for
 * what this set is. Kept exported from this module because that is where the
 * browser client's cross-check imports it from.
 */
export { REFUSAL_CODES } from "./refusals.mjs";

function requestId(req) {
  const supplied = req.headers["x-request-id"];
  if (typeof supplied === "string" && SAFE_REQUEST_ID.test(supplied)) return supplied;
  return randomUUID();
}

/**
 * The route label a request is counted under.
 *
 * Deliberately not the path: a cid or a file hash in a metric label makes one
 * time series per document, which is how a metrics backend is destroyed.
 */
function routeLabel(pathname, method) {
  if (pathname === "/health" || pathname === "/ready" || pathname === "/metrics") return pathname;
  if (pathname === "/api/storage/pin") return "pin";
  if (CID_ROUTE.test(pathname)) return "fetch";
  if (pathname.startsWith("/api/proofs/inclusion/")) return "inclusion";
  if (pathname.startsWith("/api/proofs/")) return pathname.slice("/api/".length);
  if (pathname.startsWith("/api/")) return "unknown_api";
  return method === "GET" ? "static" : "other";
}

/**
 * Directories the frontend is served from, relative to the static root.
 *
 * The root is the repository itself, so without an allowlist every file in it
 * is a URL: `.git` (and through it the entire history), the server sources, and
 * `js/config.js`, which holds deployment settings and, in direct mode, a
 * pinning token. A denylist is the wrong shape here — it has to anticipate
 * every future file, and the first one it misses is served.
 *
 * node_modules is on the list only for the bundles the pages genuinely load:
 * web3 from a <script> tag on every page, and @noble's ES modules, which
 * js/core/kdf.js and js/core/suites.js import by relative path so that no
 * bundler is required.
 */
const STATIC_DIRECTORIES = [
  "css/",
  "js/",
  "assets/",
  "files/",
  "node_modules/web3/dist/",
  "node_modules/@noble/hashes/esm/",
  "node_modules/@noble/ciphers/esm/",
];

const STATIC_TYPES = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".png", "image/png"],
  [".jpg", "image/jpeg"],
  [".jpeg", "image/jpeg"],
  [".ico", "image/x-icon"],
  [".mp4", "video/mp4"],
  [".woff2", "font/woff2"],
]);

function securityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  // The app needs WebCrypto and talks to this origin plus IPFS gateways.
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; " +
      "connect-src 'self' https:; style-src 'self' 'unsafe-inline' https:; " +
      // worker-src is required for key derivation. Browsers that honour it do
      // not fall back to script-src, so omitting it blocks the worker and
      // silently forces every derivation back onto the main thread — the exact
      // freeze the worker exists to prevent.
      "script-src 'self' https:; worker-src 'self' blob:; " +
      "font-src 'self' https: data:; object-src 'none'; " +
      "base-uri 'none'; frame-ancestors 'none'"
  );
}

function sendJson(res, status, payload, { close = false } = {}) {
  const body = JSON.stringify(payload);
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
  };
  // When we stop reading a request early, the connection cannot be reused:
  // the unread body would be parsed as the next request. Closing it is also
  // what lets the client actually receive this response instead of a reset.
  if (close) headers.Connection = "close";
  res.writeHead(status, headers);
  res.end(body);
}

function applyCors(req, res, config) {
  const origin = req.headers.origin;
  if (!origin || config.allowedOrigins.length === 0) return true;

  if (!config.allowedOrigins.includes(origin)) {
    // Not an error for a normal request — simply no CORS grant, so a browser
    // will refuse to expose the response to the calling page.
    return false;
  }

  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Chunk-Name");
  res.setHeader("Access-Control-Max-Age", "600");
  return true;
}

/**
 * Read a request body with a hard cap.
 *
 * The cap is enforced as bytes arrive, not after buffering, so a client cannot
 * make the process allocate more than the limit no matter what Content-Length
 * claims. A client that lies is disconnected rather than served an error, since
 * continuing to read is exactly what the attack wants.
 */
function readBody(req, { maxBytes, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared > maxBytes) {
      const error = new Error(`body exceeds ${maxBytes} bytes`);
      error.status = 413;
      error.stopReading = true;
      reject(error);
      return;
    }

    const parts = [];
    let received = 0;
    let settled = false;

    const timer = setTimeout(() => {
      req.pause();
      finish(
        Object.assign(new Error("request body timed out"), { status: 408, stopReading: true })
      );
    }, timeoutMs);

    function finish(error, value) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      error ? reject(error) : resolve(value);
    }

    req.on("data", (part) => {
      received += part.length;
      if (received > maxBytes) {
        // Stop accumulating immediately — the cap must bound memory, not just
        // the reported result. Pause rather than destroy so the 413 can still
        // be written; the handler closes the connection afterwards.
        parts.length = 0;
        req.pause();
        finish(
          Object.assign(new Error(`body exceeds ${maxBytes} bytes`), {
            status: 413,
            stopReading: true,
          })
        );
        return;
      }
      parts.push(part);
    });

    req.on("end", () => finish(null, Buffer.concat(parts, received)));
    req.on("error", (error) => finish(error));
    req.on("aborted", () =>
      finish(Object.assign(new Error("client aborted the request"), { status: 400 }))
    );
  });
}

async function readJson(req, { timeoutMs }) {
  const raw = await readBody(req, { maxBytes: MAX_JSON_BYTES, timeoutMs });
  if (raw.length === 0) {
    throw Object.assign(new Error("empty body"), { status: 400 });
  }
  try {
    const parsed = JSON.parse(raw.toString("utf8"));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("expected a JSON object");
    }
    return parsed;
  } catch (error) {
    throw Object.assign(new Error(`invalid JSON body: ${error.message}`), { status: 400 });
  }
}

function chunkName(req) {
  const raw = req.headers["x-chunk-name"];
  if (typeof raw !== "string") return "chunk";
  try {
    // Keep only characters that are safe as an upstream metadata label.
    return decodeURIComponent(raw).replace(/[^A-Za-z0-9._-]/g, "").slice(0, 128) || "chunk";
  } catch {
    return "chunk";
  }
}

/**
 * Is this path part of the frontend?
 *
 * @param {string} relative path from the static root, with "/" separators
 */
function isServablePath(relative) {
  // The pages sit at the root, and only pages do: package.json, the lockfile
  // and auto_update.txt are all root files that are nobody's business.
  if (!relative.includes("/")) return relative.endsWith(".html");
  return STATIC_DIRECTORIES.some((directory) => relative.startsWith(directory));
}

async function serveStatic(req, res, root) {
  const url = new URL(req.url, "http://localhost");
  const requested = url.pathname === "/" ? "/index.html" : url.pathname;

  // Resolve, then confirm the result is still inside the root. This is the only
  // reliable traversal check: it catches encoded dots, symlinked paths and
  // anything else a cleverer string filter would miss.
  const resolved = path.resolve(root, "." + path.posix.normalize(requested));
  if (resolved !== root && !resolved.startsWith(root + path.sep)) {
    sendJson(res, 403, { code: REFUSAL_CODES.FORBIDDEN, error: "forbidden" });
    return true;
  }

  const relative = path.relative(root, resolved).split(path.sep).join("/");
  // Not on the allowlist, or an extension the frontend never asks for (a .map,
  // a .ts source, a stray .java): fall through to the same 404 a missing file
  // gets, so this says nothing about what exists on disk.
  const contentType = STATIC_TYPES.get(path.extname(resolved).toLowerCase());
  if (!contentType || !isServablePath(relative)) return false;

  let info;
  try {
    info = await stat(resolved);
  } catch {
    return false;
  }
  if (!info.isFile()) return false;

  res.writeHead(200, {
    "Content-Type": contentType,
    "Content-Length": info.size,
    "Cache-Control": "no-cache",
  });
  createReadStream(resolved).pipe(res);
  return true;
}

/**
 * Build the request handler.
 *
 * @param {object} config from loadConfig()
 * @param {object} backend from createBackend()
 * @param {object} [deps] injectable for testing
 */
export function createHandler(config, backend, deps = {}) {
  const proofs = deps.proofs || null;
  const limiter =
    deps.limiter ||
    createRateLimiter({ perMinute: config.rateLimitPerMinute, burst: config.rateLimitBurst });

  /*
   * Public verification is the only unauthenticated route that does outside
   * work — a chain read the operator pays for — so it gets its own, much
   * tighter bucket, keyed by source address since there is no key to key it
   * on. Sharing the upload limiter would mean either metering verification
   * like an upload, which is far too generous, or metering uploads like
   * verification, which would break them.
   */
  const verifyLimiter =
    deps.verifyLimiter ||
    createRateLimiter({
      perMinute: config.verifyRateLimitPerMinute,
      burst: config.verifyRateLimitBurst,
    });

  /** Read-only chain access, when the operator has configured it. */
  const confirmer = deps.confirmer || null;

  const staticRoot = config.serveStatic
    ? path.resolve(deps.staticRoot || path.resolve(process.cwd()))
    : null;

  /**
   * The one place the gateway decides who a request came from.
   *
   * Every meter — the rate limiter, the per-client byte and object budgets —
   * goes through this, so the proxy setting applies everywhere at once and no
   * route can keep its own idea of who the client is.
   */
  const addressOf = (req) => {
    /*
     * A request arriving with X-Forwarded-For while no proxy is trusted means
     * either someone is trying to forge an address — harmless, it is ignored
     * — or there is a proxy in front of this process that the configuration
     * does not know about, which silently collapses every visitor into one
     * budget. The second is worth noticing, so it is counted, and said once.
     */
    if (config.trustedProxyHops === 0 && req.headers["x-forwarded-for"]) {
      forwardedForIgnored++;
      if (forwardedForIgnored === 1) {
        logger.warn(
          "a request arrived with X-Forwarded-For but OREOCHAIN_TRUSTED_PROXY_HOPS is 0, so " +
            "it was ignored. If there is a proxy in front of this gateway, set it: every " +
            "visitor is currently sharing one rate limit and one byte budget."
        );
      }
    }
    return clientAddress(req, config.trustedProxyHops);
  };
  let forwardedForIgnored = 0;

  const quota =
    deps.quota ||
    createQuota({
      clientBytes: config.clientBytesPerWindow,
      clientObjects: config.clientObjectsPerWindow,
      windowMs: config.quotaWindowMs,
      dailyBytes: config.dailyBytes,
      dailyObjects: config.dailyObjects,
    });

  const logger = deps.logger || createLogger({ level: config.logLevel });
  const metrics = deps.metrics || createMetrics();

  /*
   * Whether this process should be sent traffic. index.mjs flips `draining` on
   * SIGTERM, which is the point of having readiness at all: a rolling deploy
   * takes the instance out of the load balancer *before* the drain rather than
   * discovering it is gone when requests start failing.
   */
  const readiness = deps.readiness || { draining: false };

  /*
   * Bodies buffered right now, process-wide. The per-request cap bounds one
   * body; this bounds how many exist at once. Rate limiting cannot do it —
   * a burst of tokens spends in parallel — so without this one client within
   * its limit could hold hundreds of megabytes, or gigabytes at a raised
   * chunk cap.
   */
  let inFlightUploads = 0;
  const maxConcurrentUploads = deps.maxConcurrentUploads ?? config.maxConcurrentUploads ?? 32;

  metrics.gauge(
    "oreochain_uploads_in_flight",
    () => inFlightUploads,
    "Request bodies buffered right now"
  );
  metrics.gauge(
    "oreochain_upload_slots",
    () => maxConcurrentUploads,
    "Ceiling on concurrently buffered bodies"
  );
  if (proofs) {
    // The pending count is the one number that silently grows into an
    // incident: documents are receipted but nothing is anchoring them, and
    // nothing else in the system says so.
    metrics.gauge(
      "oreochain_documents_pending",
      () => proofs.status().pending,
      "Recorded documents not yet in a batch"
    );
    metrics.gauge(
      "oreochain_documents_total",
      () => proofs.status().documents,
      "Documents recorded since the store was created"
    );
    metrics.gauge("oreochain_batches_total", () => proofs.status().batches, "Batches built");

    /*
     * The store's own health, from the check run at startup.
     *
     * A gateway started with OREOCHAIN_ALLOW_DAMAGED_STORE is up and serving
     * while some of what it anchored cannot be proved — exactly the state
     * that needs an alert rather than a log line that has scrolled away.
     * Alert on damaged_batches above zero.
     *
     * The timestamp is here because the check happens once, at startup: a
     * process running for months is reporting on the store as it was when it
     * opened. `npm run verify-store` from cron is what re-checks a live one,
     * out of process so a rehash cannot stall the gateway.
     */
    metrics.gauge(
      "oreochain_store_damaged_batches",
      () => (proofs.integrity() ? proofs.integrity().damagedRoots.length : 0),
      "Batches that failed the last integrity check"
    );
    metrics.gauge(
      "oreochain_store_check_timestamp_seconds",
      () => (proofs.integrity() ? Math.floor(proofs.integrity().checkedAt / 1000) : 0),
      "When the store was last checked; 0 if it never was"
    );
  }

  /*
   * The spend, visible before it bites rather than diagnosed afterwards.
   *
   * oreochain_trusted_proxy_hops is here for one specific failure: a gateway
   * behind a load balancer with hops left at 0 looks perfectly healthy and is
   * one heavy visitor away from shutting everyone else out, because every
   * visitor is sharing one budget. Reading 0 on a deployment that has a proxy
   * in front of it is the warning.
   */
  metrics.gauge(
    "oreochain_trusted_proxy_hops",
    () => config.trustedProxyHops,
    "Proxies trusted in X-Forwarded-For; 0 means caps are per connecting address"
  );
  metrics.gauge(
    "oreochain_forwarded_for_ignored_total",
    () => forwardedForIgnored,
    "Requests carrying X-Forwarded-For while no proxy is trusted"
  );
  metrics.gauge(
    "oreochain_daily_bytes_pinned",
    () => quota.snapshot().dailyBytes,
    "Bytes pinned today, service-wide"
  );
  metrics.gauge(
    "oreochain_daily_bytes_budget",
    () => quota.snapshot().dailyBytesBudget ?? 0,
    "Daily byte ceiling; 0 means no limit is configured"
  );
  metrics.gauge(
    "oreochain_daily_objects_pinned",
    () => quota.snapshot().dailyObjects,
    "Objects pinned today, service-wide"
  );
  metrics.gauge(
    "oreochain_daily_objects_budget",
    () => quota.snapshot().dailyObjectsBudget ?? 0,
    "Daily object ceiling; 0 means no limit is configured"
  );
  metrics.gauge(
    "oreochain_quota_clients",
    () => quota.snapshot().clients,
    "Clients with an open quota window"
  );

  const METRIC_HELP = {
    oreochain_requests_total: "Requests completed, by route and status class",
    oreochain_auth_failures_total: "Requests rejected for a missing or invalid key",
    oreochain_rate_limited_total: "Requests rejected by the token bucket",
    oreochain_uploads_shed_total: "Uploads rejected because every slot was busy",
    oreochain_bytes_pinned_total: "Bytes accepted for pinning",
    oreochain_quota_rejections_total: "Uploads refused by a byte or object ceiling",
  };

  // Idle rate-limit buckets are swept periodically so memory stays bounded.
  const sweeper =
    deps.sweeper === false
      ? null
      : setInterval(() => {
          limiter.sweep();
          quota.sweep();
          verifyLimiter.sweep();
        }, 600000);
  if (sweeper && typeof sweeper.unref === "function") sweeper.unref();

  /**
   * Answer "is this document anchored?" in terms a person can act on.
   *
   * There are two ways a document reaches the contract, and a verifier
   * holding a certificate does not know which was used:
   *
   *  - **a batch anchor**: this gateway receipted the document, put it in a
   *    batch, and the anchoring worker submitted that batch's root;
   *  - **a registration**: the uploader's own wallet wrote one record for
   *    this document, paying its own gas, with no receipt involved.
   *
   * Both are looked up, the answer says which applies, and it carries what an
   * independent checker needs to redo the work without trusting this reply.
   */
  async function verifyDocument(fileHash) {
    /*
     * The gateway's own verdict is labelled as the gateway's own verdict.
     *
     * Asking this service "is this document verified?" and believing the
     * answer reinstates exactly the party a signed receipt exists to bound.
     * So the body leads with the materials — the receipt, the inclusion
     * proof, the batch root, the transaction, the on-chain record — and the
     * conclusion sits in one clearly named field that a caller is free to
     * ignore and redo.
     */
    const answer = (httpStatus, claim, materials = {}) => ({
      status: claim.status,
      httpStatus,
      body: {
        fileHash,
        ...materials,
        gatewayClaim: claim,
        howToCheck:
          "Do not take gatewayClaim on trust. Verify the receipt's signature against the " +
          "key at GET /api/proofs/key, recompute the inclusion proof against batch.root, " +
          "and read findBatch(batch.root) or findDocument(fileHash) on the contract named " +
          "in chainRead.",
      },
    });

    /**
     * Recorded, receipted, and not yet in a batch.
     *
     * This window is every upload's first OREOCHAIN_BATCH_MAX_AGE_MS, and it
     * used to answer 404 "unknown" — the same answer a document nobody has
     * ever heard of gets — while the signed receipt for it sat in this
     * gateway's own store. That is the one output this endpoint's whole design
     * says must never be produced carelessly: a verifier who acts on "no
     * record" does something irreversible, and here they would have been
     * acting on a document that had been accepted minutes earlier.
     *
     * `receipted` rather than `not-anchored`, which is the next state along:
     * that one has a batch and a valid inclusion proof and is waiting only on
     * the chain, and a verifier can do real work with it. This one has
     * neither yet. Collapsing the two would hide exactly the difference a
     * verifier needs — whether there is anything to check — behind a `batch`
     * field they would have to know to look at.
     *
     * The word is the one the browser client already uses for this state.
     */
    const pendingClaim = () => ({
      verified: false,
      status: "receipted",
      anchoredBy: [],
      explain:
        "this gateway accepted this document and signed a receipt for it, and the anchor is " +
        "still owed. It is not in a batch yet, so there is no inclusion proof to check and " +
        "nothing on-chain to find. Check the receipt's signature; this is not a statement " +
        "that the document is unregistered.",
    });

    const batchedClaim = () => ({
      verified: false,
      status: "not-anchored",
      anchoredBy: [],
      explain:
        "the document is recorded here and its inclusion proof is valid, but the batch it " +
        "belongs to has not been anchored on-chain yet, and it has no per-document " +
        "registration either",
    });

    const proof = await proofs.proofFor(fileHash);
    const receipt = proofs.receiptFor(fileHash);

    let batch = null;
    const warnings = [];

    if (proof) {
      // Our own proof, against our own root. If this ever fails, the store
      // and the tree disagree — a fault here, not an answer about the
      // document.
      const inclusion = await verifyInBatch(proof, proof.batchRoot);
      if (!inclusion.valid) {
        logger.error("a stored inclusion proof does not verify", {
          fileHash,
          batchRoot: proof.batchRoot,
          reason: inclusion.reason,
        });
        return answer(500, {
          verified: false,
          status: "internal",
          anchoredBy: [],
          explain: "this gateway could not reproduce its own proof for that document",
        });
      }

      batch = {
        root: proof.batchRoot,
        index: proof.index,
        size: proof.batchSize ?? null,
        document: proof.document,
        proof: proof.proof,
        inclusionValid: true,
        recorded: proof.txHash ? { txHash: proof.txHash, block: proof.block } : null,
        onChain: null,
      };
    }

    if (!confirmer) {
      if (!proof && !receipt) {
        return answer(404, {
          verified: false,
          status: "unknown",
          anchoredBy: [],
          explain:
            "this gateway has no record of that document, and it is not configured to read " +
            "the chain, so it cannot say whether the document is registered there",
        });
      }
      if (!proof) {
        return answer(200, pendingClaim(), { receipt, batch: null, registration: null, chainRead: null });
      }
      return answer(
        200,
        {
          verified: false,
          status: "unchecked",
          anchoredBy: [],
          explain:
            "the inclusion proof is valid, but this gateway is not configured to read the " +
            "chain. Check batch.root against findBatch() on the contract yourself: the " +
            "proof verifies against whatever root the contract holds.",
        },
        { receipt, batch, registration: null, chainRead: null }
      );
    }

    const [anchor, registration] = await Promise.all([
      batch ? confirmer.check(batch.root) : Promise.resolve(null),
      confirmer.checkDocument(fileHash),
    ]);

    /*
     * Never an answer about the document. Someone acting on a false "this is
     * not anchored" is the worst thing this endpoint can produce, so a chain
     * it could not reach says exactly that and asks to be asked again.
     */
    const unavailable = [anchor, registration].some((r) => r && r.state === UNAVAILABLE);
    if (unavailable) {
      return answer(
        503,
        {
          verified: false,
          status: "unavailable",
          anchoredBy: [],
          explain:
            "this gateway could not reach the chain to check. This is not a statement that " +
            "the document is unanchored.",
        },
        { receipt, batch, registration: null, chainRead: chainReadFrom(anchor, registration) }
      );
    }

    const anchoredBy = [];

    if (anchor && anchor.state === CONFIRMED) {
      batch.onChain = {
        block: anchor.block,
        size: anchor.size,
        txHash: anchor.txHash,
        confirmations: anchor.confirmations,
      };

      /*
       * The contract holding this root while disagreeing about how many
       * documents it covers means the root was anchored by something that
       * does not share this store's idea of the batch. The Merkle root would
       * not match if the contents differed, so this is close to impossible —
       * which is exactly why it is worth reporting rather than ignoring.
       */
      if (typeof batch.size === "number" && anchor.size !== batch.size) {
        logger.error("the anchored batch size disagrees with the store", {
          batchRoot: batch.root,
          onChain: anchor.size,
          stored: batch.size,
        });
        metrics.increment("oreochain_anchor_discrepancies_total", { kind: "size" });
        warnings.push(
          "the contract holds this batch root but says it covers a different number of " +
            "documents than this gateway recorded"
        );
      } else {
        anchoredBy.push("batch");
      }
    } else if (batch && batch.recorded) {
      /*
       * We recorded a transaction and the contract does not hold the root: a
       * reorg, or an RPC pointed at a different network. An alarm, not a
       * routine "not yet".
       */
      logger.error("a recorded anchor is not on the chain", {
        batchRoot: batch.root,
        txHash: batch.recorded.txHash,
        block: batch.recorded.block,
      });
      metrics.increment("oreochain_anchor_discrepancies_total", { kind: "missing" });
      warnings.push(
        "this gateway recorded an anchoring transaction for this batch, but the contract " +
          "does not hold that root. Do not treat this as unanchored until an operator has " +
          "checked that transaction independently."
      );
    }

    let registered = null;
    if (registration && registration.state === CONFIRMED) {
      registered = {
        block: registration.block,
        timestamp: registration.timestamp,
        merkleRoot: registration.merkleRoot,
        manifestCID: registration.manifestCID,
        totalChunks: registration.totalChunks,
        fileSize: registration.fileSize,
        encrypted: registration.encrypted,
        exporter: registration.exporter,
        confirmations: registration.confirmations,
      };

      // Both paths describing the same file must describe the same file.
      const receiptedRoot = proof && proof.document ? proof.document.merkleRoot : null;
      if (receiptedRoot && receiptedRoot.toLowerCase() !== registration.merkleRoot) {
        logger.error("the registered Merkle root disagrees with the receipted one", {
          fileHash,
          onChain: registration.merkleRoot,
          receipted: receiptedRoot,
        });
        metrics.increment("oreochain_anchor_discrepancies_total", { kind: "root" });
        warnings.push(
          "the on-chain registration for this document names a different Merkle root than " +
            "the one this gateway receipted"
        );
      } else {
        anchoredBy.push("registration");
      }
    }

    const materials = {
      receipt,
      batch,
      registration: registered,
      chainRead: chainReadFrom(anchor, registration),
    };
    const claim = { status: "", anchoredBy, verified: false };
    if (warnings.length > 0) claim.warnings = warnings;

    /*
     * A disagreement outranks a confirmation, even when the other path checked
     * out perfectly.
     *
     * If the chain says this document's Merkle root is one thing and this
     * gateway receipted another, the two are not describing the same file, and
     * "anchored" is not a useful thing to say about it — whichever path
     * happened to verify. Reporting verified with a warning attached invites
     * exactly the reading that matters least: the word, not the caveat.
     */
    if (warnings.length > 0) {
      claim.status = "disputed";
      claim.explain =
        anchoredBy.length > 0
          ? "what is on the chain disagrees with what this gateway recorded about this " +
            "document, so it is not being called anchored even though " +
            `${anchoredBy.join(" and ")} checked out. See warnings.`
          : "this document could not be confirmed, and what is on the chain disagrees with " +
            "what this gateway recorded. See warnings.";
      return answer(200, claim, materials);
    }

    if (anchoredBy.length > 0) {
      claim.verified = true;
      claim.status = "verified";
      claim.explain = explainVerified(anchoredBy, batch, registered);
      return answer(200, claim, materials);
    }

    if (!proof && !receipt) {
      claim.status = "unknown";
      claim.explain = "neither this gateway nor the contract has any record of that document";
      return answer(404, claim, materials);
    }

    Object.assign(claim, proof ? batchedClaim() : pendingClaim());
    return answer(200, claim, materials);
  }

  /**
   * Which contract, on which chain, the answer actually came from.
   *
   * Taken from the lookup itself rather than read separately, so the two
   * halves of a response cannot disagree: a verifier told which chain was
   * read, and an anchor that came from a different one, is worse off than a
   * verifier told nothing.
   */
  function chainReadFrom(...results) {
    for (const result of results) {
      if (result && result.chainId) {
        return { contract: result.contract, chainId: result.chainId };
      }
    }
    // Reached only when nothing could be read at all; naming the contract we
    // would have asked still tells a verifier where to look themselves.
    return confirmer && confirmer.reader
      ? { contract: confirmer.reader.contractAddress, chainId: null }
      : null;
  }

  /** One sentence a person can read, for each way a document can be anchored. */
  function explainVerified(anchoredBy, batch, registered) {
    const parts = [];
    if (anchoredBy.includes("batch")) {
      parts.push(
        `it is one of ${batch.onChain.size} documents in a batch whose root the contract ` +
          `holds, anchored at block ${batch.onChain.block}` +
          (batch.onChain.txHash ? ` in transaction ${batch.onChain.txHash}` : "") +
          `, ${batch.onChain.confirmations} confirmation(s) deep`
      );
    }
    if (anchoredBy.includes("registration")) {
      parts.push(
        `it is registered on-chain in its own right at block ${registered.block}, ` +
          `${registered.confirmations} confirmation(s) deep`
      );
    }
    return `This document is anchored: ${parts.join("; and ")}.`;
  }

  return async function handle(req, res) {
    const started = Date.now();
    securityHeaders(res);

    /*
     * One id, carried on every line this request produces and handed back to
     * the client. A user reporting "it failed at about two o'clock" is very
     * hard to find in a log; a user quoting an id is one grep.
     */
    const reqId = requestId(req);
    res.setHeader("X-Request-Id", reqId);
    const log = logger.child({ reqId });

    /*
     * Every failure carries its id in the body as well as the header. A user
     * reporting a problem pastes what they saw, and what they saw is the JSON;
     * with the id in it, the line that explains their failure is one grep away
     * instead of a hunt through a timestamp range.
     */
    const fail = (status, payload, options) =>
      sendJson(res, status, { ...payload, requestId: reqId }, options);

    let url;
    try {
      url = new URL(req.url, "http://localhost");
    } catch {
      log.warn("malformed request URL", { method: req.method });
      metrics.increment("oreochain_requests_total", { route: "other", status: "4xx" });
      fail(400, { error: "malformed request URL" });
      return;
    }

    const route = routeLabel(url.pathname, req.method);
    let counted = false;
    const countOnce = (status) => {
      if (counted) return;
      counted = true;
      metrics.increment("oreochain_requests_total", {
        route,
        status: `${Math.floor(status / 100)}xx`,
      });
    };
    res.on("finish", () => countOnce(res.statusCode));
    // A connection dropped before the response was written would otherwise be
    // invisible — the one class of failure a client notices and the server
    // does not.
    res.on("close", () => {
      if (counted) return;
      counted = true;
      metrics.increment("oreochain_requests_total", { route, status: "aborted" });
    });

    const corsOk = applyCors(req, res, config);

    if (req.method === "OPTIONS") {
      res.writeHead(corsOk ? 204 : 403).end();
      return;
    }

    try {
      /*
       * Liveness: is this process running? Nothing else. A liveness probe that
       * checks a dependency gets the container killed and restarted when the
       * dependency is down, which turns one outage into a crash loop.
       */
      if (url.pathname === "/health" && req.method === "GET") {
        sendJson(res, 200, {
          status: "ok",
          storage: backend.name,
          uptime: process.uptime(),
          inFlightUploads,
        });
        return;
      }

      /*
       * Readiness: should this instance be sent traffic? That is a different
       * question, and until now nothing answered it.
       *
       * It checks what this process controls — it is not draining, and the
       * proof store it must write to before issuing a receipt is readable.
       * It deliberately does not probe Pinata: an upstream wobble would fail
       * readiness on every replica at once and take the whole service out for
       * a dependency that only affects one endpoint.
       */
      if (url.pathname === "/ready" && req.method === "GET") {
        const checks = { draining: readiness.draining === true, store: "ok" };
        if (proofs) {
          try {
            proofs.status();
          } catch (error) {
            checks.store = error.message;
          }
        }
        const ready = !checks.draining && checks.store === "ok";
        if (!ready) log.warn("not ready", checks);
        sendJson(res, ready ? 200 : 503, { status: ready ? "ready" : "not ready", ...checks });
        return;
      }

      /*
       * Metrics carry operational shape — request volume, error rates, how
       * much is queued — so they go behind the same key as the API whenever
       * the gateway has keys at all. A scraper sends a bearer token like any
       * other client.
       */
      if (url.pathname === "/metrics" && req.method === "GET") {
        const auth = authenticate(req, config);
        if (!auth.ok) {
          res.setHeader("WWW-Authenticate", 'Bearer realm="oreochain"');
          fail(401, { code: REFUSAL_CODES.UNAUTHORIZED, error: "unauthorized" });
          return;
        }
        const body = metrics.render(METRIC_HELP);
        res.writeHead(200, {
          "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
          "Content-Length": Buffer.byteLength(body),
          "Cache-Control": "no-store",
        });
        res.end(body);
        return;
      }

      const isApi = url.pathname.startsWith("/api/");

      // Public proof endpoints, before the auth gate.
      if (proofs && req.method === "GET") {
        if (PUBLIC_API.has(url.pathname)) {
          /*
           * With a kid, the key that signed some particular receipt — which
           * may be one this gateway has since rotated away from. A receipt is
           * portable and long-lived, so someone can come back a year later
           * with one, and serving only the current key would make every
           * receipt issued before a rotation fail to verify, with the same
           * answer a forgery gets.
           */
          const wanted = url.searchParams.get("kid");
          if (wanted) {
            const key = proofs.publicKeyFor(wanted);
            if (!key) {
              sendJson(res, 404, {
                /*
                 * bad_request, deliberately, on a 404. The closed set has no
                 * not-found code, and adding one would change a contract the
                 * browser client compares against — for a refusal whose cause
                 * really is the request: a kid this gateway has never held is
                 * a kid the caller should not have asked for. The status code
                 * already says not-found; the code says whose fault it is.
                 */
                code: REFUSAL_CODES.BAD_REQUEST,
                error: "this gateway has never signed with that key",
                kid: wanted,
              });
              return;
            }
            sendJson(res, 200, {
              kid: key.kid,
              publicJwk: key.publicJwk,
              algorithm: "ECDSA-P256-SHA256",
              retiredAt: key.retiredAt,
            });
            return;
          }

          sendJson(res, 200, {
            kid: proofs.kid,
            publicJwk: proofs.publicJwk,
            algorithm: "ECDSA-P256-SHA256",
            ephemeral: proofs.ephemeral,
            keys: proofs.keys(),
          });
          return;
        }

        /*
         * The whole point of receipts, made checkable by someone with no
         * account, no wallet and no RPC endpoint of their own. A court, an
         * employer or a regulator holding a certificate can ask this and get
         * an answer, rather than being told to go and read a blockchain.
         *
         * It is also the only public route that does outside work per call,
         * so it is metered, cached, and careful about the difference between
         * "no" and "I could not check".
         */
        const verify = VERIFY_ROUTE.exec(url.pathname);
        if (verify) {
          /*
           * Through addressOf like every other meter, not off the socket.
           * This route is unauthenticated, so the address is the only thing
           * metering it — and behind a reverse proxy the socket address is
           * the proxy's. Reading it directly would put every verifier in the
           * world into one 30-per-minute bucket, and the first person to
           * check a batch of certificates would lock out everyone else.
           */
          const allowance = verifyLimiter.take(`verify:${addressOf(req)}`);
          if (!allowance.allowed) {
            res.setHeader("Retry-After", String(allowance.retryAfterSeconds));
            sendJson(res, 429, {
              code: REFUSAL_CODES.RATE_LIMITED,
              error: "rate limit exceeded",
              retryAfterSeconds: allowance.retryAfterSeconds,
            });
            metrics.increment("oreochain_rate_limited_total", {});
            return;
          }

          const answer = await verifyDocument(verify[1]);
          if (answer.status === "unavailable") {
            res.setHeader("Retry-After", "30");
          }
          sendJson(res, answer.httpStatus, answer.body);
          metrics.increment("oreochain_verifications_total", { status: answer.body.status });
          return;
        }

        const inclusion = INCLUSION_ROUTE.exec(url.pathname);
        if (inclusion) {
          const proof = await proofs.proofFor(inclusion[1]);
          if (!proof) {
            sendJson(res, 404, { error: "no inclusion proof for that document yet" });
            return;
          }
          sendJson(res, 200, proof);
          return;
        }
      }

      if (isApi) {
        if (!corsOk) {
          fail(403, { code: REFUSAL_CODES.FORBIDDEN, error: "origin not allowed" });
          return;
        }

        const auth = authenticate(req, config);
        if (!auth.ok) {
          // A uniform message avoids telling an attacker which part was wrong.
          res.setHeader("WWW-Authenticate", 'Bearer realm="oreochain"');
          fail(401, { code: REFUSAL_CODES.UNAUTHORIZED, error: "unauthorized" });
          log.warn("authentication failed", { reason: auth.reason, route });
          metrics.increment("oreochain_auth_failures_total", { reason: auth.reason });
          return;
        }

        // Anonymous callers share a key id, so bucket them by source address
        // instead — otherwise one client exhausts the bucket for everyone.
        const quotaKey =
          auth.keyId === "anonymous" ? `ip:${addressOf(req)}` : auth.keyId;
        const allowance = limiter.take(quotaKey);
        if (!allowance.allowed) {
          res.setHeader("Retry-After", String(allowance.retryAfterSeconds));
          fail(429, {
            code: REFUSAL_CODES.RATE_LIMITED,
            error: "rate limit exceeded",
            retryAfterSeconds: allowance.retryAfterSeconds,
          });
          log.warn("rate limited", { keyId: auth.keyId, route });
          metrics.increment("oreochain_rate_limited_total", {});
          return;
        }

        if (url.pathname === "/api/storage/pin" && req.method === "POST") {
          if (inFlightUploads >= maxConcurrentUploads) {
            // Shed load rather than run the host out of memory. A client that
            // retries — which the browser adapter does, with backoff — sees a
            // brief slowdown instead of a dead gateway.
            res.setHeader("Retry-After", "1");
            fail(
              503,
              { code: REFUSAL_CODES.BUSY, error: "too many uploads in flight" },
              { close: true }
            );
            log.warn("upload shed, every slot busy", {
              keyId: auth.keyId,
              inFlight: inFlightUploads,
              slots: maxConcurrentUploads,
            });
            metrics.increment("oreochain_uploads_shed_total", {});
            return;
          }

          /*
           * What this client, and the service as a whole, may still spend.
           * Checked against Content-Length before the body is read, because
           * refusing 50 MB before reading it is the difference between a
           * cheap rejection and an expensive one. A client that omits the
           * header is charged after the fact instead.
           */
          const declared = Number(req.headers["content-length"]);
          const spend = quota.check(quotaKey, Number.isFinite(declared) ? declared : 0);
          if (!spend.allowed) {
            res.setHeader("Retry-After", String(spend.retryAfterSeconds));
            fail(spend.status, {
              code: spend.code,
              error: spend.message,
              scope: spend.scope,
              retryAfterSeconds: spend.retryAfterSeconds,
            });
            log.warn("quota exceeded", {
              keyId: auth.keyId,
              scope: spend.scope,
              declaredBytes: Number.isFinite(declared) ? declared : null,
            });
            metrics.increment("oreochain_quota_rejections_total", { scope: spend.scope });
            return;
          }

          inFlightUploads++;
          try {
            const body = await readBody(req, {
              maxBytes: config.maxChunkBytes,
              timeoutMs: config.readTimeoutMs,
            });
            if (body.length === 0) {
              fail(400, { code: REFUSAL_CODES.BAD_REQUEST, error: "empty body" });
              return;
            }

            const cid = await backend.put(body, chunkName(req));
            // Charged on what was stored, not on what was promised: a client
            // may send less than it declared, and only what reached the
            // pinning service costs anything.
            quota.record(quotaKey, body.length);
            sendJson(res, 200, { cid });
            metrics.increment("oreochain_bytes_pinned_total", {}, body.length);
            log.info("pinned", {
              keyId: auth.keyId,
              bytes: body.length,
              cid,
              ms: Date.now() - started,
            });
          } finally {
            inFlightUploads--;
          }
          return;
        }

        if (proofs && url.pathname === "/api/proofs/record" && req.method === "POST") {
          const document = await readJson(req, { timeoutMs: config.readTimeoutMs });
          let result;
          try {
            result = await proofs.record(document);
          } catch (error) {
            // A manifest that could not be read is worth retrying; one that
            // disagrees with the document never will be. Saying which saves
            // the client guessing from a status code alone.
            if (error.retryable && !res.headersSent) res.setHeader("Retry-After", "5");
            throw Object.assign(error, { status: error.status || 400 });
          }
          sendJson(res, 200, result);
          log.info("document recorded", {
            keyId: auth.keyId,
            fileHash: document.fileHash,
            pending: result.pending,
            ms: Date.now() - started,
          });
          return;
        }

        /*
         * Anchoring is a privilege of its own, held by the worker's key and
         * nothing else. Checked once here rather than at each of the three
         * routes, so a fourth cannot be added without it.
         */
        const anchoring =
          url.pathname === "/api/proofs/batch" ||
          url.pathname === "/api/proofs/unanchored" ||
          url.pathname === "/api/proofs/anchored";
        if (proofs && anchoring && !auth.canAnchor) {
          fail(403, {
            error:
              "this key may not drive anchoring — add it to OREOCHAIN_ANCHOR_API_KEYS if it " +
              "belongs to the anchoring worker",
          });
          log.warn("anchoring refused", { keyId: auth.keyId, route });
          metrics.increment("oreochain_auth_failures_total", { reason: "not an anchor key" });
          return;
        }

        if (proofs && url.pathname === "/api/proofs/status" && req.method === "GET") {
          sendJson(res, 200, proofs.status());
          return;
        }

        /*
         * What the anchoring worker reads on startup and on every tick. A
         * batch listed here was built but never confirmed on-chain, which
         * after a worker crash is the only record that it is owed a
         * transaction.
         */
        if (proofs && url.pathname === "/api/proofs/unanchored" && req.method === "GET") {
          sendJson(res, 200, { batches: proofs.unanchoredBatches(ANCHOR_PAGE) });
          return;
        }

        /*
         * Where the anchoring worker reports back what it submitted.
         *
         * The worker cannot write the proof store directly: it is a separate
         * process, and the store takes a single-writer lock precisely to stop
         * that. So the transaction it sent comes back over the API, which also
         * keeps the funded key in a process that never accepts public uploads.
         */
        if (proofs && url.pathname === "/api/proofs/anchored" && req.method === "POST") {
          const body = await readJson(req, { timeoutMs: config.readTimeoutMs });
          let anchored;
          try {
            anchored = proofs.recordAnchor(body.root, {
              txHash: body.txHash,
              block: body.block,
            });
          } catch (error) {
            throw Object.assign(error, { status: error.status || 400 });
          }
          sendJson(res, 200, {
            root: anchored.root,
            size: anchored.size,
            txHash: anchored.txHash,
            block: anchored.block,
          });
          log.info("batch anchored", {
            keyId: auth.keyId,
            root: anchored.root,
            size: anchored.size,
            txHash: anchored.txHash,
            block: anchored.block,
          });
          return;
        }

        if (proofs && url.pathname === "/api/proofs/batch" && req.method === "POST") {
          const batch = await proofs.buildPendingBatch();
          if (!batch) {
            sendJson(res, 200, { batch: null, message: "nothing pending to anchor" });
            return;
          }
          sendJson(res, 200, { batch });
          log.info("batch built", { keyId: auth.keyId, root: batch.root, size: batch.size });
          return;
        }

        const match = CID_ROUTE.exec(url.pathname);
        if (match && req.method === "GET") {
          const bytes = await backend.get(match[1]);
          res.writeHead(200, {
            "Content-Type": "application/octet-stream",
            "Content-Length": bytes.length,
            "Cache-Control": "public, max-age=31536000, immutable",
          });
          res.end(Buffer.from(bytes));
          log.info("chunk served", {
            keyId: auth.keyId,
            cid: match[1],
            bytes: bytes.length,
            ms: Date.now() - started,
          });
          return;
        }

        fail(404, { error: "no such endpoint" });
        return;
      }

      if (staticRoot && req.method === "GET" && (await serveStatic(req, res, staticRoot))) return;

      fail(404, { error: "not found" });
    } catch (error) {
      const status = Number.isInteger(error.status) ? error.status : 500;
      // Internal details go to the log, never to the client — an error message
      // is a fine place to leak a credential or an internal hostname.
      // A 500 is ours and needs the stack; a 4xx is the client's and would
      // only fill the log with other people's mistakes at error level.
      const report = status >= 500 ? log.error : log.warn;
      report.call(log, "request failed", {
        status,
        route,
        message: error.message,
        upstreamStatus: error.upstreamStatus,
        stack: status >= 500 ? error.stack : undefined,
      });
      if (!res.headersSent) {
        fail(
          status,
          { error: status === 500 ? "internal error" : error.message },
          { close: Boolean(error.stopReading) }
        );
      } else {
        res.destroy();
      }
    }
  };
}

export const _internals = {
  readBody,
  chunkName,
  serveStatic,
  isServablePath,
  requestId,
  routeLabel,
  STATIC_DIRECTORIES,
  CID_ROUTE,
};
