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

const CID_ROUTE = /^\/api\/storage\/([A-Za-z0-9_-]{1,512})$/;
const INCLUSION_ROUTE = /^\/api\/proofs\/inclusion\/(0x[0-9a-fA-F]{64})$/;

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
    sendJson(res, 403, { error: "forbidden" });
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
        }, 600000);
  if (sweeper && typeof sweeper.unref === "function") sweeper.unref();

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
          fail(401, { error: "unauthorized" });
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
          sendJson(res, 200, {
            kid: proofs.kid,
            publicJwk: proofs.publicJwk,
            algorithm: "ECDSA-P256-SHA256",
            ephemeral: proofs.ephemeral,
          });
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
          fail(403, { error: "origin not allowed" });
          return;
        }

        const auth = authenticate(req, config);
        if (!auth.ok) {
          // A uniform message avoids telling an attacker which part was wrong.
          res.setHeader("WWW-Authenticate", 'Bearer realm="oreochain"');
          fail(401, { error: "unauthorized" });
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
            fail(503, { error: "too many uploads in flight" }, { close: true });
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
              fail(400, { error: "empty body" });
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
