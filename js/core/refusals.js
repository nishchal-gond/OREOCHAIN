/**
 * What a gateway refusal means, and what a client should do about it.
 *
 * The gateway answers a refusal with a machine-readable `code` alongside its
 * human `error` prose. The code is the contract; the prose is for people and
 * may be reworded at any time, so nothing here reads it. This module is the
 * client's half of that contract: one switch over the codes the gateway can
 * send, with no fall-through for a known one.
 *
 * The distinction that matters is not the status code. 429 covers both "you
 * sent that too fast, wait a moment" and "you have used your share for the
 * hour" — the first is a wobble worth retrying through, the second is a cap
 * that will still be there in four attempts' time. Retrying a cap turns one
 * refusal into a small denial-of-service against a gateway that has already
 * said no, and leaves the user watching a spinner that cannot succeed.
 *
 * Refusals stack in the order the route checks them, so a malformed request to
 * a gateway whose burst is spent comes back `rate_limited` rather than
 * `bad_request`. Nothing may be inferred about the request from which refusal
 * arrived; the code says what to do next and nothing more.
 */

/** Every code the gateway can send. Mirrors REFUSAL_CODES in server/gateway.mjs. */
export const REFUSAL_CODES = Object.freeze({
  RATE_LIMITED: "rate_limited",
  BUSY: "busy",
  CLIENT_QUOTA: "client_quota",
  GATEWAY_BUDGET: "gateway_budget",
  UNAUTHORIZED: "unauthorized",
  FORBIDDEN: "forbidden",
  BAD_REQUEST: "bad_request",
});

/**
 * How a client should treat each refusal.
 *
 * `retry`  whether backing off and trying again can plausibly succeed.
 * `fault`  "caller" — something about this request or this client;
 *          "service" — the gateway's own limit, nothing the user did;
 *          "transient" — neither; the moment is wrong, not the request.
 * `message` what to tell the user, written here rather than echoed from the
 *          server so the wording survives a server-side rephrasing.
 */
const ADVICE = Object.freeze({
  [REFUSAL_CODES.RATE_LIMITED]: {
    retry: true,
    fault: "transient",
    message: "Going a little too fast for the service — pausing and trying again.",
  },
  [REFUSAL_CODES.BUSY]: {
    retry: true,
    fault: "transient",
    message: "The service is busy right now — pausing and trying again.",
  },
  [REFUSAL_CODES.CLIENT_QUOTA]: {
    retry: false,
    fault: "caller",
    message:
      "You have used your upload allowance for now. Nothing was stored. " +
      "Your allowance refreshes shortly — try again then.",
  },
  [REFUSAL_CODES.GATEWAY_BUDGET]: {
    retry: false,
    fault: "service",
    message:
      "The service has reached its storage limit for today. This is not " +
      "something you did, and nothing was stored. Nothing is retrying in the " +
      "background — please try again tomorrow.",
  },
  [REFUSAL_CODES.UNAUTHORIZED]: {
    retry: false,
    fault: "caller",
    message: "The service did not accept this request's credentials.",
  },
  [REFUSAL_CODES.FORBIDDEN]: {
    retry: false,
    fault: "caller",
    message: "The service refused this request from this page.",
  },
  [REFUSAL_CODES.BAD_REQUEST]: {
    retry: false,
    fault: "caller",
    message: "The service rejected the request as malformed.",
  },
});

/**
 * Advice for a refusal code, or null when the code is not one of ours.
 *
 * Null rather than a default, deliberately: an unrecognised code means this
 * client is older than the gateway, and guessing at it either retries a cap or
 * abandons a wobble. The caller falls back to the status code, which is a
 * worse signal but an honest one.
 */
export function refusalAdvice(code) {
  if (typeof code !== "string") return null;
  return ADVICE[code] || null;
}

/** Whether a refusal is worth another attempt. Unknown codes are not refusals. */
export function isRetryableRefusal(code) {
  const advice = refusalAdvice(code);
  return advice ? advice.retry : null;
}

/**
 * Seconds-from-now a `Retry-After` header asks for, in milliseconds.
 *
 * The header comes in two spellings — delta-seconds and an HTTP-date — and a
 * gateway may send either. Returns null for anything unparseable or in the
 * past, so a malformed header degrades to ordinary backoff rather than to a
 * NaN-length sleep.
 */
export function parseRetryAfter(value, now = () => Date.now()) {
  if (typeof value !== "string" || value.trim() === "") return null;

  const seconds = Number(value.trim());
  if (Number.isFinite(seconds)) return seconds >= 0 ? Math.round(seconds * 1000) : null;

  const at = Date.parse(value);
  if (Number.isNaN(at)) return null;
  return Math.max(0, at - now());
}
