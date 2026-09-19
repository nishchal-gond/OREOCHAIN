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
 *   POST /api/storage/pin        store one chunk (raw body) -> { cid }
 *   GET  /api/storage/<cid>      retrieve one chunk
 */

import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import path from "node:path";

import { authenticate } from "./auth.mjs";
import { createRateLimiter } from "./ratelimit.mjs";

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

  const log = deps.log || ((entry) => console.log(JSON.stringify(entry)));

  // Idle rate-limit buckets are swept periodically so memory stays bounded.
  const sweeper = deps.sweeper === false ? null : setInterval(() => limiter.sweep(), 600000);
  if (sweeper && typeof sweeper.unref === "function") sweeper.unref();

  return async function handle(req, res) {
    const started = Date.now();
    securityHeaders(res);

    let url;
    try {
      url = new URL(req.url, "http://localhost");
    } catch {
      sendJson(res, 400, { error: "malformed request URL" });
      return;
    }

    const corsOk = applyCors(req, res, config);

    if (req.method === "OPTIONS") {
      res.writeHead(corsOk ? 204 : 403).end();
      return;
    }

    try {
      if (url.pathname === "/health" && req.method === "GET") {
        sendJson(res, 200, { status: "ok", storage: backend.name, uptime: process.uptime() });
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
          const proof = proofs.proofFor(inclusion[1]);
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
          sendJson(res, 403, { error: "origin not allowed" });
          return;
        }

        const auth = authenticate(req, config);
        if (!auth.ok) {
          // A uniform message avoids telling an attacker which part was wrong.
          res.setHeader("WWW-Authenticate", 'Bearer realm="oreochain"');
          sendJson(res, 401, { error: "unauthorized" });
          log({ event: "auth_failed", reason: auth.reason, path: url.pathname });
          return;
        }

        // Anonymous callers share a key id, so bucket them by source address
        // instead — otherwise one client exhausts the bucket for everyone.
        const quotaKey =
          auth.keyId === "anonymous"
            ? `ip:${req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : "unknown"}`
            : auth.keyId;
        const quota = limiter.take(quotaKey);
        if (!quota.allowed) {
          res.setHeader("Retry-After", String(quota.retryAfterSeconds));
          sendJson(res, 429, {
            error: "rate limit exceeded",
            retryAfterSeconds: quota.retryAfterSeconds,
          });
          log({ event: "rate_limited", keyId: auth.keyId });
          return;
        }

        if (url.pathname === "/api/storage/pin" && req.method === "POST") {
          const body = await readBody(req, {
            maxBytes: config.maxChunkBytes,
            timeoutMs: config.readTimeoutMs,
          });
          if (body.length === 0) {
            sendJson(res, 400, { error: "empty body" });
            return;
          }

          const cid = await backend.put(body, chunkName(req));
          sendJson(res, 200, { cid });
          log({
            event: "pin",
            keyId: auth.keyId,
            bytes: body.length,
            cid,
            ms: Date.now() - started,
          });
          return;
        }

        if (proofs && url.pathname === "/api/proofs/record" && req.method === "POST") {
          const document = await readJson(req, { timeoutMs: config.readTimeoutMs });
          let result;
          try {
            result = await proofs.record(document);
          } catch (error) {
            throw Object.assign(error, { status: error.status || 400 });
          }
          sendJson(res, 200, result);
          log({
            event: "receipt",
            keyId: auth.keyId,
            fileHash: document.fileHash,
            pending: result.pending,
          });
          return;
        }

        if (proofs && url.pathname === "/api/proofs/status" && req.method === "GET") {
          sendJson(res, 200, proofs.status());
          return;
        }

        if (proofs && url.pathname === "/api/proofs/batch" && req.method === "POST") {
          const batch = await proofs.buildPendingBatch();
          if (!batch) {
            sendJson(res, 200, { batch: null, message: "nothing pending to anchor" });
            return;
          }
          sendJson(res, 200, { batch });
          log({ event: "batch_built", keyId: auth.keyId, root: batch.root, size: batch.size });
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
          log({ event: "fetch", keyId: auth.keyId, cid: match[1], bytes: bytes.length });
          return;
        }

        sendJson(res, 404, { error: "no such endpoint" });
        return;
      }

      if (staticRoot && req.method === "GET" && (await serveStatic(req, res, staticRoot))) return;

      sendJson(res, 404, { error: "not found" });
    } catch (error) {
      const status = Number.isInteger(error.status) ? error.status : 500;
      // Internal details go to the log, never to the client — an error message
      // is a fine place to leak a credential or an internal hostname.
      log({
        event: "error",
        status,
        path: url.pathname,
        message: error.message,
        upstreamStatus: error.upstreamStatus,
      });
      if (!res.headersSent) {
        sendJson(
          res,
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
  STATIC_DIRECTORIES,
  CID_ROUTE,
};
