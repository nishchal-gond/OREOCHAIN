/**
 * "Is this batch root really on the chain?", answered without hammering an RPC.
 *
 * This backs the one public endpoint that does outside work on every call, so
 * it is built around three rules:
 *
 *  1. **A confirmed anchor never changes.** Once the contract holds a root at
 *     a block, that fact is immutable short of a reorg, so it is cached for a
 *     long time. Only the chain head is re-read often, and one read of it
 *     serves every request in its window.
 *  2. **"Not anchored" is cached briefly.** Otherwise a scan of unknown
 *     documents becomes a scan of the operator's RPC quota.
 *  3. **"Cannot check" is never cached, and is never reported as "no".** An
 *     RPC that is down must not turn into a confident negative: someone acting
 *     on a false "this document is not anchored" is the worst thing this can
 *     produce.
 */

export const CONFIRMED = "confirmed";
export const ABSENT = "absent";
export const UNAVAILABLE = "unavailable";

/**
 * @param {object} options
 * @param {object} options.reader a createChainReader()
 * @param {object} options.log
 * @param {number} [options.ttlMs] how long a confirmed anchor is held
 * @param {number} [options.negativeTtlMs] how long an absent one is held
 * @param {number} [options.documentTtlMs] how long a registration is held, which
 *   is shorter than an anchor because a registration can be revoked
 * @param {number} [options.headTtlMs] how long the chain head is held
 * @param {number} [options.maxEntries] cache ceiling, so it cannot grow forever
 */
export function createAnchorConfirmer(options) {
  const {
    reader,
    log,
    ttlMs = 3_600_000,
    negativeTtlMs = 15_000,
    documentTtlMs = 300_000,
    headTtlMs = 5_000,
    maxEntries = 2048,
    now = () => Date.now(),
  } = options;

  const cache = new Map();
  const documents = new Map();
  let head = { at: 0, value: null };
  const counts = { lookups: 0, hits: 0, chainReads: 0, failures: 0 };

  function remember(store, key, entry, lifetime) {
    store.set(key, { at: now(), expires: now() + lifetime, entry });
    // Oldest-inserted out first. A cache that can be made to grow without
    // bound by an unauthenticated caller is a memory exhaustion bug wearing a
    // performance hat.
    while (store.size > maxEntries) store.delete(store.keys().next().value);
  }

  async function chainHead() {
    if (head.value !== null && now() - head.at < headTtlMs) return head.value;
    const value = await reader.blockNumber();
    head = { at: now(), value };
    return value;
  }

  return {
    /** Exposed so a caller can name the contract and chain it read. */
    reader,

    stats: () => ({ ...counts, cached: cache.size + documents.size }),

    /**
     * @param {string} root
     * @returns {Promise<{state: string, block?: number, size?: number,
     *   txHash?: string|null, confirmations?: number, message?: string}>}
     */
    async check(root) {
      counts.lookups++;

      const cached = cache.get(root);
      if (cached && cached.expires > now()) {
        counts.hits++;
        if (cached.entry.state !== CONFIRMED) return cached.entry;

        // The anchor is immutable; how deep it is buried is not. Recomputing
        // it against a briefly-cached head keeps the answer current without a
        // second lookup of the anchor itself.
        try {
          const confirmations = (await chainHead()) - cached.entry.block + 1;
          return { ...cached.entry, confirmations };
        } catch (error) {
          counts.failures++;
          return { state: UNAVAILABLE, message: error.message };
        }
      }

      try {
        counts.chainReads++;
        const [found, currentHead] = await Promise.all([reader.findBatch(root), chainHead()]);

        if (!found) {
          const entry = { state: ABSENT };
          remember(cache, root, entry, negativeTtlMs);
          return entry;
        }

        const entry = {
          state: CONFIRMED,
          block: found.block,
          size: found.size,
          txHash: found.txHash,
        };
        remember(cache, root, entry, ttlMs);
        return { ...entry, confirmations: currentHead - found.block + 1 };
      } catch (error) {
        /*
         * Deliberately not cached and deliberately not ABSENT. The caller
         * turns this into a 503 with a Retry-After, because "I could not
         * check" and "it is not there" are different answers and only one of
         * them is safe to be wrong about.
         */
        counts.failures++;
        log.warn("chain lookup failed", { root, message: error.message });
        return { state: UNAVAILABLE, message: error.message };
      }
    },

    /**
     * The other anchoring path: one on-chain record per document.
     *
     * Held for a shorter time than a batch anchor, because unlike an anchor a
     * registration can be taken back — revokeDocument() deletes it — so a
     * long cache would keep reporting a revoked document as registered.
     */
    async checkDocument(fileHash) {
      counts.lookups++;

      const cached = documents.get(fileHash);
      if (cached && cached.expires > now()) {
        counts.hits++;
        if (cached.entry.state !== CONFIRMED) return cached.entry;
        try {
          const confirmations = (await chainHead()) - cached.entry.block + 1;
          return { ...cached.entry, confirmations };
        } catch (error) {
          counts.failures++;
          return { state: UNAVAILABLE, message: error.message };
        }
      }

      try {
        counts.chainReads++;
        const [found, currentHead] = await Promise.all([
          reader.findDocument(fileHash),
          chainHead(),
        ]);

        if (!found) {
          const entry = { state: ABSENT };
          remember(documents, fileHash, entry, negativeTtlMs);
          return entry;
        }

        const entry = { state: CONFIRMED, ...found };
        remember(documents, fileHash, entry, documentTtlMs);
        return { ...entry, confirmations: currentHead - found.block + 1 };
      } catch (error) {
        counts.failures++;
        log.warn("chain document lookup failed", { fileHash, message: error.message });
        return { state: UNAVAILABLE, message: error.message };
      }
    },
  };
}
