/**
 * Which address a request actually came from.
 *
 * Everything that meters an anonymous caller — the rate limiter, the byte and
 * object budgets — is keyed on this, so getting it wrong breaks the meter in
 * one of two ways. Take the socket address behind a reverse proxy and every
 * visitor shares one bucket, so one of them exhausts the service for
 * everyone. Trust `X-Forwarded-For` blindly and anyone can put whatever they
 * like in it, giving themselves a fresh budget per request.
 *
 * So the header is used only as far as the operator says it can be trusted,
 * and not at all by default.
 */

/** Conservative: enough to reject junk, not a full address parser. */
const LOOKS_LIKE_AN_ADDRESS = /^[0-9a-fA-F:.]{3,45}$/;

/**
 * @param {object} req
 * @param {number} hops how many proxies in front of this one are ours
 * @returns {string} an address, or "unknown"
 */
export function clientAddress(req, hops = 0) {
  const socket = normalize(req.socket && req.socket.remoteAddress);

  if (!hops || hops < 1) return socket;

  const header = req.headers["x-forwarded-for"];
  if (!header) return socket;

  const chain = String(header)
    .split(",")
    .map((entry) => normalize(entry.trim()))
    .filter((entry) => entry !== "unknown");

  /*
   * Each proxy appends the address it saw, so the rightmost entries are the
   * ones our own infrastructure wrote and the leftmost are whatever the
   * client claimed. With `hops` proxies of our own, the furthest entry we
   * have any reason to believe is `hops` from the right.
   */
  const index = chain.length - hops;
  if (index < 0 || !chain[index]) {
    // Fewer entries than there are trusted proxies: the header is not what
    // the configuration says it should be, so it is not evidence of anything.
    return socket;
  }
  return chain[index];
}

function normalize(value) {
  if (typeof value !== "string" || value === "") return "unknown";

  // Node reports an IPv4 connection to a dual-stack socket as ::ffff:1.2.3.4.
  // Left alone, the same client counts as two.
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value);
  const address = mapped ? mapped[1] : value;

  return LOOKS_LIKE_AN_ADDRESS.test(address) ? address : "unknown";
}
