/**
 * Structured logging.
 *
 * WHY THIS EXISTS
 *
 * The gateway logged with bare `console.log(JSON.stringify(entry))` in one
 * place and free-text `console.warn("[oreochain] …")` in several others. Two
 * problems follow from that, and both only bite once the service is running
 * somewhere you cannot attach a debugger to.
 *
 * There was no time and no severity. A log aggregator has nothing to order
 * lines by except arrival, and nothing to alert on: an authentication failure
 * and a successful upload are the same kind of line. Turning the noise down in
 * production was not possible either, because there was no level to turn down.
 *
 * There was no way to tie lines together. A request that pinned a chunk and
 * then failed produced two unrelated records; with concurrent requests
 * interleaved, nothing said which "error" belonged to which "pin".
 *
 * So: one JSON object per line, always carrying a timestamp, a level and — for
 * anything happening inside a request — a request id that the client is also
 * told, so a user reporting a failure can quote the id that identifies their
 * exact request in the log.
 *
 * REDACTION
 *
 * The premise of this service is that it holds credentials the browser must
 * not, so a log line is the most plausible way one escapes. Field names that
 * name a secret are replaced with a marker before serialisation, and a value
 * that looks like a bearer token or a JWT is truncated even under an innocent
 * key. This is a backstop, not a licence: do not log secrets and rely on it.
 */

export const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };

const DEFAULT_LEVEL = "info";

/**
 * Field names whose value is never printed. Matched case-insensitively on the
 * whole key, so `jwt` and `pinataJwt` both redact but `jwtIssuedAt` does not
 * have to be anticipated as a special case — it simply is not on the list.
 */
const SECRET_KEYS = new Set([
  "apikey",
  "apikeys",
  "authorization",
  "cookie",
  "jwt",
  "key",
  "passphrase",
  "password",
  "pinatajwt",
  "privatekey",
  "receiptkey",
  "secret",
  "token",
]);

const REDACTED = "[redacted]";

/**
 * A credential appearing as a value under a key nobody thought to list.
 *
 * Only two shapes, deliberately. "Any long opaque string" was the first
 * attempt and it is wrong here: a file hash is 66 hex characters and a CID is
 * about 60 of base32, so that rule redacted exactly the identifiers an
 * operator needs to follow a request through the log. A JWT and an
 * Authorization value are unambiguous; nothing else is worth the false
 * positives.
 */
const TOKEN_SHAPED = /^(?:ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}|Bearer\s+\S+)/;

function redactValue(key, value) {
  if (SECRET_KEYS.has(String(key).toLowerCase())) return REDACTED;
  if (typeof value === "string" && TOKEN_SHAPED.test(value)) {
    // Keep enough to correlate two sightings of the same value, never enough
    // to use it.
    return `${value.slice(0, 6)}…[${value.length} chars]`;
  }
  return value;
}

/**
 * Flatten one entry into a printable object.
 *
 * Depth is capped: a logged object that contains a request, a socket or an
 * error with a cause chain can be effectively unbounded, and a logger that
 * can hang the process on a cyclic structure is worse than no logger.
 */
function sanitize(value, key = "", depth = 0) {
  const direct = redactValue(key, value);
  if (direct !== value) return direct;

  if (value === null || typeof value !== "object") return value;
  if (value instanceof Error) {
    return { name: value.name, message: value.message, stack: value.stack };
  }
  if (depth >= 4) return "[deep]";

  if (Array.isArray(value)) {
    return value.slice(0, 32).map((item, index) => sanitize(item, String(index), depth + 1));
  }

  const out = {};
  for (const [childKey, childValue] of Object.entries(value)) {
    if (childValue === undefined) continue;
    out[childKey] = sanitize(childValue, childKey, depth + 1);
  }
  return out;
}

/**
 * Build a logger.
 *
 * @param {object} [options]
 * @param {string} [options.level] one of LEVELS; below it, nothing is written
 * @param {(line: string) => void} [options.write] where lines go
 * @param {() => number} [options.now] injectable clock
 * @param {object} [options.base] fields added to every line
 */
export function createLogger({
  level = process.env.OREOCHAIN_LOG_LEVEL || DEFAULT_LEVEL,
  write = (line) => process.stdout.write(line + "\n"),
  now = () => Date.now(),
  base = {},
} = {}) {
  const normalized = String(level).toLowerCase();
  if (!(normalized in LEVELS)) {
    throw new Error(
      `unknown log level "${level}" — expected one of ${Object.keys(LEVELS).join(", ")}`
    );
  }
  const threshold = LEVELS[normalized];
  // Sanitised once, not per line: base fields are set by this process, but a
  // child logger is the natural place for someone to attach something they
  // should not, and doing it here costs nothing at write time.
  const baseFields = sanitize(base);

  function emit(levelName, message, fields) {
    if (LEVELS[levelName] < threshold) return;

    const entry = {
      time: new Date(now()).toISOString(),
      level: levelName,
      msg: message,
      ...baseFields,
      ...(fields ? sanitize(fields) : null),
    };

    // A logger that throws takes the request down with it. Losing a line is
    // the lesser failure, so serialisation problems are reported and dropped.
    let line;
    try {
      line = JSON.stringify(entry);
    } catch (error) {
      line = JSON.stringify({
        time: entry.time,
        level: "error",
        msg: "log entry could not be serialised",
        reason: error.message,
      });
    }
    write(line);
  }

  const logger = {
    level: normalized,
    enabled: (levelName) => LEVELS[levelName] >= threshold,
    /** A logger carrying extra fields — one per request, in practice. */
    child: (fields) => createLogger({ level: normalized, write, now, base: { ...base, ...fields } }),
  };

  for (const levelName of ["debug", "info", "warn", "error"]) {
    logger[levelName] = (message, fields) => emit(levelName, message, fields);
  }

  return logger;
}

export const _internals = { sanitize, redactValue, SECRET_KEYS, TOKEN_SHAPED };
