/**
 * The anchoring worker: what actually puts a batch root on-chain.
 *
 * Until now the gateway built a batch and handed the operator a root to submit
 * by hand. A root nobody submits is a receipt that promises something untrue:
 * the user holds a signed statement that their document is anchored, and there
 * is no transaction anywhere that says so.
 *
 * It is a separate process on purpose, for two reasons.
 *
 *  1. The key that pays for anchoring can spend. A signing key with spending
 *     power does not belong in the process that accepts public uploads, where
 *     any request-handling bug is a path to it.
 *  2. The proof store takes a single-writer lock (server/store.mjs), so a
 *     second process cannot open it. The worker therefore reads and reports
 *     over the gateway's own API, with an API key like any other client.
 *
 * The loop never blocks waiting for a transaction to confirm. A submitted
 * batch stays in the gateway's unanchored list until its confirmations are in,
 * so each tick re-examines it and reports it the tick after it settles. That
 * is also what makes a crash recoverable: after a restart the worker asks the
 * chain whether a batch is already anchored before submitting anything, and
 * the contract itself reverts a duplicate anchor, so the worst case of a race
 * is one failed transaction rather than two conflicting records.
 */

/** A batch the chain has accepted but which has not been reported yet. */
const SETTLED = "settled";
const WAITING = "waiting";
const SUBMITTED = "submitted";

export class AnchorError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = "AnchorError";
    if (options.cause) this.cause = options.cause;
  }
}

/**
 * Talk to the gateway as an ordinary API client.
 *
 * @param {object} options
 * @param {string} options.url base URL of the gateway
 * @param {string} options.apiKey a key from OREOCHAIN_API_KEYS
 * @param {Function} [options.fetchImpl] injected in tests
 * @param {number} [options.timeoutMs]
 */
export function createGatewayClient({ url, apiKey, fetchImpl = fetch, timeoutMs = 30_000 }) {
  const base = String(url).replace(/\/+$/, "");

  async function call(path, { method = "GET", body } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response;
    try {
      response = await fetchImpl(`${base}${path}`, {
        method,
        signal: controller.signal,
        headers: {
          Authorization: `Bearer ${apiKey}`,
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (error) {
      throw new AnchorError(`gateway ${method} ${path} failed: ${error.message}`, { cause: error });
    } finally {
      clearTimeout(timer);
    }

    const text = await response.text();
    let parsed = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      // Left null: a non-JSON body from a proxy in front of the gateway is
      // worth reporting as a status, not as a parse failure.
    }

    if (!response.ok) {
      const detail = parsed?.error || text.slice(0, 200) || "(no body)";
      throw Object.assign(
        new AnchorError(`gateway ${method} ${path} returned ${response.status}: ${detail}`),
        { status: response.status }
      );
    }
    return parsed;
  }

  return {
    status: () => call("/api/proofs/status"),
    unanchored: () => call("/api/proofs/unanchored").then((body) => body.batches),
    buildBatch: () => call("/api/proofs/batch", { method: "POST" }).then((body) => body.batch),
    reportAnchored: (root, { txHash, block }) =>
      call("/api/proofs/anchored", { method: "POST", body: { root, txHash, block } }),
  };
}

/**
 * @param {object} options
 * @param {object} options.gateway a createGatewayClient()
 * @param {object} options.chain a chain client (see server/chain.mjs)
 * @param {object} options.log a createLogger()
 * @param {number} [options.confirmations] blocks to wait before reporting
 * @param {number} [options.intervalMs] how often to tick
 * @param {(batch: object) => string} [options.uriFor] the on-chain proof URI
 * @param {number} [options.pendingTimeoutMs] when to give up on a sent tx
 */
export function createAnchorWorker(options) {
  const {
    gateway,
    chain,
    log,
    confirmations = 3,
    intervalMs = 60_000,
    uriFor = () => "",
    pendingTimeoutMs = 600_000,
    now = () => Date.now(),
  } = options;

  /**
   * Transactions this process sent whose batch is not on-chain yet, keyed by
   * batch root. Purely an optimisation against resubmitting into the mempool:
   * losing it costs a duplicate transaction, which the contract reverts, not a
   * duplicate anchor.
   */
  const sent = new Map();

  let running = false;
  let timer = null;
  const counts = { ticks: 0, submitted: 0, anchored: 0, failures: 0 };

  /**
   * Move one batch as far towards anchored as the chain currently allows.
   *
   * @returns {Promise<"settled"|"waiting"|"submitted">}
   */
  async function advance(batch) {
    const onChain = await chain.findBatch(batch.root);

    if (onChain) {
      const head = await chain.blockNumber();
      if (head - onChain.block + 1 < confirmations) {
        log.debug("batch anchored but not confirmed", {
          root: batch.root,
          block: onChain.block,
          head,
          confirmations,
        });
        return WAITING;
      }

      if (!onChain.txHash) {
        /*
         * The batch is on-chain but the transaction that put it there could
         * not be found — the RPC's log retention does not reach that block.
         * The anchor is valid and inclusion proofs still verify against the
         * contract; what is missing is the convenience pointer in the
         * receipt. An operator can supply it by hand, and saying so is more
         * use than retrying forever.
         */
        log.warn("anchored batch has no recoverable transaction hash", {
          root: batch.root,
          block: onChain.block,
          hint: "POST /api/proofs/anchored with the transaction hash to record it",
        });
        return WAITING;
      }

      sent.delete(batch.root);
      await gateway.reportAnchored(batch.root, { txHash: onChain.txHash, block: onChain.block });
      counts.anchored++;
      log.info("batch anchored", {
        root: batch.root,
        size: batch.size,
        txHash: onChain.txHash,
        block: onChain.block,
      });
      return SETTLED;
    }

    const inFlight = sent.get(batch.root);
    if (inFlight) {
      // Still in the mempool, or dropped from it. Either way resubmitting
      // immediately just competes with our own transaction.
      if (now() - inFlight.at < pendingTimeoutMs) {
        log.debug("waiting for a sent anchor to mine", {
          root: batch.root,
          txHash: inFlight.txHash,
        });
        return WAITING;
      }
      log.warn("a sent anchor never mined, resubmitting", {
        root: batch.root,
        txHash: inFlight.txHash,
        afterMs: now() - inFlight.at,
      });
      sent.delete(batch.root);
    }

    const submitted = await chain.anchorBatch({
      root: batch.root,
      size: batch.size,
      uri: uriFor(batch),
    });
    sent.set(batch.root, { txHash: submitted.txHash, at: now() });
    counts.submitted++;
    log.info("anchor transaction sent", {
      root: batch.root,
      size: batch.size,
      txHash: submitted.txHash,
    });
    return SUBMITTED;
  }

  async function tick() {
    counts.ticks++;

    let batches;
    try {
      batches = await gateway.unanchored();
    } catch (error) {
      counts.failures++;
      log.error("cannot read unanchored batches", { message: error.message });
      return counts;
    }

    // Build a new batch only once the backlog is clear. Adding to a queue that
    // is not draining turns one stuck batch into many.
    if (batches.length === 0) {
      try {
        const status = await gateway.status();
        if (status.shouldFlush) {
          const built = await gateway.buildBatch();
          if (built) {
            log.info("batch built", { root: built.root, size: built.size });
            batches = [built];
          }
        }
      } catch (error) {
        counts.failures++;
        log.error("cannot build a batch", { message: error.message });
        return counts;
      }
    }

    for (const batch of batches) {
      try {
        await advance(batch);
      } catch (error) {
        counts.failures++;
        // One batch the chain will not accept must not stop the others: a
        // later batch is a different root and a different transaction.
        log.error("cannot anchor batch", { root: batch.root, message: error.message });
      }
    }

    return counts;
  }

  return {
    tick,
    counts: () => ({ ...counts }),

    /**
     * Run the loop until stop(). The timer is deliberately not unref'd: this
     * loop is the worker process's whole reason to be running, so it is what
     * keeps it alive between ticks.
     */
    start() {
      if (running) return;
      running = true;
      const schedule = () => {
        timer = setTimeout(async () => {
          try {
            await tick();
          } catch (error) {
            counts.failures++;
            log.error("anchor tick failed", { message: error.message, stack: error.stack });
          }
          if (running) schedule();
        }, intervalMs);
      };
      schedule();
    },

    stop() {
      running = false;
      if (timer) clearTimeout(timer);
      timer = null;
    },
  };
}
