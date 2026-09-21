/**
 * Why a request was refused, as one stable token a client can switch on.
 *
 * Status codes are not enough here, because two of them mean opposite things
 * on the same route. A 429 from the token bucket means "slow down and try
 * again"; a 429 from a per-window byte cap means "not until your window
 * rolls". A 503 from load shedding means "try in a second"; a 503 from the
 * daily budget means "not today". A client that cannot tell them apart either
 * retries a spent budget in a loop, or tells a user the service is out of
 * quota when two uploads happened to be in flight for a second.
 *
 * Prose is for people and changes freely. This does not.
 *
 * It lives in its own module so that every server module can import it
 * without importing the gateway. server/quota.mjs is why: the gateway imports
 * quota, so quota cannot import the gateway back without a cycle, and it was
 * writing two of these seven codes as bare strings instead — in a module
 * other than the one that defines them, where nothing compares them to
 * anything. server/gateway.mjs re-exports it, because that export is what the
 * browser client's cross-check imports.
 *
 * js/core/refusals.js holds a second copy on purpose: the pages load their
 * modules directly and must never import server code. test/refusals.test.js
 * asserts the two agree.
 */
export const REFUSAL_CODES = Object.freeze({
  RATE_LIMITED: "rate_limited",
  BUSY: "busy",
  CLIENT_QUOTA: "client_quota",
  GATEWAY_BUDGET: "gateway_budget",
  UNAUTHORIZED: "unauthorized",
  FORBIDDEN: "forbidden",
  BAD_REQUEST: "bad_request",
});
