/**
 * What an anonymous visitor, and the service as a whole, may spend.
 *
 * Rate limiting bounds how *often* someone calls; it says nothing about how
 * much they store. A caller well within 600 requests a minute can pin a
 * gigabyte an hour, for ever, on the operator's account. For a public gateway
 * — which this is designed to be, because the premise is that a visitor needs
 * no account — that is the whole exposure.
 *
 * Two layers, because they fail differently:
 *
 *  - **Per client, per window.** One visitor cannot spend everyone else's
 *    share. Exceeding it is a 429: their window will roll over.
 *  - **Per day, whole service.** The operator's bill has a ceiling even if a
 *    thousand visitors each stay politely under their own cap. Exceeding it is
 *    a 503: nothing the caller does will help until the day turns.
 *
 * The daily counter lives in memory and starts again if the process restarts.
 * That is a deliberate limit, not an oversight: persisting it means another
 * durable store, and this is a guard rail on a bill rather than a ledger. It
 * is written down in server/README.md so nobody discovers it the hard way.
 */

import { REFUSAL_CODES } from "./refusals.mjs";

const DAY_MS = 86_400_000;

export const CLIENT_BYTES = "client-bytes";
export const CLIENT_OBJECTS = "client-objects";
export const DAILY_BYTES = "daily-bytes";
export const DAILY_OBJECTS = "daily-objects";

/**
 * The `code` on a refusal is the stable token a client switches on; `scope`
 * says which of the two limits inside that code was hit, for an operator
 * reading logs. See REFUSAL_CODES in server/refusals.mjs.
 *
 * @param {object} options all limits are "no limit" when null
 * @param {number|null} options.clientBytes bytes one client may pin per window
 * @param {number|null} options.clientObjects objects one client may pin per window
 * @param {number} [options.windowMs]
 * @param {number|null} options.dailyBytes bytes the whole service may pin per day
 * @param {number|null} options.dailyObjects objects the whole service may pin per day
 */
export function createQuota(options = {}) {
  const {
    clientBytes = null,
    clientObjects = null,
    windowMs = 3_600_000,
    dailyBytes = null,
    dailyObjects = null,
    maxClients = 100_000,
    now = () => Date.now(),
  } = options;

  const clients = new Map();
  let day = { index: Math.floor(now() / DAY_MS), bytes: 0, objects: 0 };
  const rejections = new Map();

  function today() {
    const index = Math.floor(now() / DAY_MS);
    if (index !== day.index) day = { index, bytes: 0, objects: 0 };
    return day;
  }

  function windowFor(key) {
    const timestamp = now();
    let client = clients.get(key);
    if (!client || timestamp - client.start >= windowMs) {
      client = { start: timestamp, bytes: 0, objects: 0 };
      clients.set(key, client);
      /*
       * Bounded, because the key is chosen by whoever connects. Oldest first:
       * a client evicted early gets a fresh window, which is the safe way to
       * be wrong — the daily budget is still standing behind it.
       */
      while (clients.size > maxClients) clients.delete(clients.keys().next().value);
    }
    return client;
  }

  function count(scope) {
    rejections.set(scope, (rejections.get(scope) || 0) + 1);
  }

  const secondsUntil = (timestamp) => Math.max(1, Math.ceil((timestamp - now()) / 1000));

  return {
    /**
     * May this client pin `bytes` more?
     *
     * Called before the body is read, with Content-Length when the client
     * supplied one — refusing 50 MB before reading it is the difference
     * between a cheap rejection and an expensive one.
     *
     * @returns {{allowed: true} | {allowed: false, scope: string, status: number,
     *   retryAfterSeconds: number, message: string}}
     */
    check(key, bytes = 0) {
      const current = today();

      if (dailyObjects !== null && current.objects + 1 > dailyObjects) {
        count(DAILY_OBJECTS);
        return {
          allowed: false,
          scope: DAILY_OBJECTS,
          code: REFUSAL_CODES.GATEWAY_BUDGET,
          status: 503,
          retryAfterSeconds: secondsUntil((current.index + 1) * DAY_MS),
          message: "this gateway has pinned as much as it is allowed to today",
        };
      }
      if (dailyBytes !== null && current.bytes + bytes > dailyBytes) {
        count(DAILY_BYTES);
        return {
          allowed: false,
          scope: DAILY_BYTES,
          code: REFUSAL_CODES.GATEWAY_BUDGET,
          status: 503,
          retryAfterSeconds: secondsUntil((current.index + 1) * DAY_MS),
          message: "this gateway has pinned as much as it is allowed to today",
        };
      }

      const client = windowFor(key);

      if (clientObjects !== null && client.objects + 1 > clientObjects) {
        count(CLIENT_OBJECTS);
        return {
          allowed: false,
          scope: CLIENT_OBJECTS,
          code: REFUSAL_CODES.CLIENT_QUOTA,
          status: 429,
          retryAfterSeconds: secondsUntil(client.start + windowMs),
          message: "you have pinned as many objects as one client may in this window",
        };
      }
      if (clientBytes !== null && client.bytes + bytes > clientBytes) {
        count(CLIENT_BYTES);
        return {
          allowed: false,
          scope: CLIENT_BYTES,
          code: REFUSAL_CODES.CLIENT_QUOTA,
          status: 429,
          retryAfterSeconds: secondsUntil(client.start + windowMs),
          message: "you have pinned as many bytes as one client may in this window",
        };
      }

      return { allowed: true };
    },

    /** Charge what was actually stored, once it is known. */
    record(key, bytes) {
      const current = today();
      current.bytes += bytes;
      current.objects += 1;

      const client = windowFor(key);
      client.bytes += bytes;
      client.objects += 1;
    },

    /** What /metrics reports, so an operator can see a cap before it bites. */
    snapshot() {
      const current = today();
      return {
        dailyBytes: current.bytes,
        dailyObjects: current.objects,
        dailyBytesBudget: dailyBytes,
        dailyObjectsBudget: dailyObjects,
        clients: clients.size,
        rejections: Object.fromEntries(rejections),
      };
    },

    /** Drop windows that have rolled over, so memory follows live clients. */
    sweep() {
      const timestamp = now();
      for (const [key, client] of clients) {
        if (timestamp - client.start >= windowMs) clients.delete(key);
      }
      return clients.size;
    },
  };
}
