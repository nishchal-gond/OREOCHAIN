/**
 * The chain side of the anchoring worker, over web3.
 *
 * Kept behind the same three-method interface the worker is written against
 * (findBatch, anchorBatch, blockNumber) so the loop is testable without an RPC
 * endpoint, and so swapping web3 for anything else means reimplementing one
 * file.
 *
 * Nothing here waits for a transaction to mine. anchorBatch resolves as soon
 * as the transaction has a hash; whether it landed is a question for the next
 * tick, which asks the contract rather than the mempool. A worker that blocks
 * on a receipt is a worker that stops doing anything else for however long the
 * chain feels like taking.
 */

import { CHUNKED_VERIFICATION_ABI } from "../js/contract-abi.js";

/** web3 v4 returns chain integers as BigInt; everything downstream wants Number. */
function toNumber(value) {
  if (typeof value === "bigint") {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`chain returned ${value}, which does not fit in a JS number`);
    }
    return Number(value);
  }
  return Number(value);
}

/**
 * Read-only access to the contract. No key, so nothing here can spend.
 *
 * Split out from the client below because the gateway needs exactly this and
 * must never hold an anchoring key: it is the process that parses public
 * uploads. A reader it cannot send transactions with is a reader that cannot
 * be turned into one by a bug.
 *
 * @param {object} options
 * @param {string} options.rpcUrl
 * @param {string} options.contractAddress
 * @param {object} options.log
 * @param {object} [options.web3Module] injected in tests
 */
export async function createChainReader(options) {
  const { rpcUrl, contractAddress, log } = options;

  const { Web3 } = options.web3Module || (await import("web3"));
  const web3 = new Web3(rpcUrl);
  const contract = new web3.eth.Contract(CHUNKED_VERIFICATION_ABI, contractAddress);

  return {
    web3,
    contract,
    contractAddress,

    /**
     * Asked every time rather than memoised.
     *
     * A running process is not entitled to assume its RPC endpoint still
     * points where it did: a DNS change, a failover, or an operator editing a
     * URL can put a different network behind the same address. Caching this
     * meant the answer could name one chain while the data came from another,
     * which is worse than either being wrong on its own.
     */
    chainId: async () => toNumber(await web3.eth.getChainId()),

    blockNumber: async () => toNumber(await web3.eth.getBlockNumber()),

    /**
     * Where a batch root landed, or null if the contract has never seen it.
     *
     * The transaction hash is not stored on-chain — the contract keeps the
     * block, not the transaction — so it is recovered from the BatchAnchored
     * event in that one block. An RPC that has pruned logs that far back
     * returns null for it, which callers report rather than retry.
     */
    async findBatch(root) {
      const found = await contract.methods.findBatch(root).call();
      const block = toNumber(found.blockNumber ?? found[0]);
      if (block === 0) return null;

      let txHash = null;
      try {
        const events = await contract.getPastEvents("BatchAnchored", {
          filter: { batchRoot: root },
          fromBlock: block,
          toBlock: block,
        });
        txHash = events[0]?.transactionHash ?? null;
      } catch (error) {
        log.warn("could not read the BatchAnchored log", {
          root,
          block,
          message: error.message,
        });
      }

      return { block, size: toNumber(found.size ?? found[2]), txHash };
    },

    /**
     * A per-document registration, or null.
     *
     * The other way a document reaches this contract: one record per
     * document, written from the uploader's own wallet, with no batch and no
     * receipt. A verifier asking about a document does not know or care which
     * path put it there, so both are looked up.
     *
     * Note what null cannot tell you: revokeDocument() deletes the record
     * outright, so a revoked document and one that was never registered are
     * the same read. The DocumentRevoked event is the audit trail for that,
     * and finding it means a log scan over an unbounded range, which this
     * deliberately does not do on a public request.
     */
    async findDocument(fileHash) {
      const found = await contract.methods.findDocument(fileHash).call();
      const block = toNumber(found.blockNumber ?? found[0]);
      if (block === 0) return null;

      return {
        block,
        timestamp: toNumber(found.timestamp ?? found[1]),
        merkleRoot: String(found.merkleRoot ?? found[2]).toLowerCase(),
        manifestCID: found.manifestCID ?? found[3],
        totalChunks: toNumber(found.totalChunks ?? found[4]),
        fileSize: toNumber(found.fileSize ?? found[5]),
        encrypted: Boolean(found.encrypted ?? found[6]),
        exporter: found.exporter ?? found[7],
      };
    },
  };
}

/**
 * @param {object} options
 * @param {string} options.rpcUrl
 * @param {string} options.contractAddress
 * @param {string} options.privateKey 0x-prefixed, funded, and an authorised exporter
 * @param {object} options.log
 * @param {object} [options.web3Module] injected in tests
 * @param {number} [options.gasLimitPadding] multiplier over the gas estimate
 */
export async function createChainClient(options) {
  const { rpcUrl, contractAddress, privateKey, log, gasLimitPadding = 1.25 } = options;

  const reader = await createChainReader(options);
  const { web3, contract } = reader;

  const account = web3.eth.accounts.privateKeyToAccount(privateKey);
  web3.eth.accounts.wallet.add(account);

  // Without this a revert surfaces as an opaque failure; with it the custom
  // error the contract declares comes back, which is the difference between
  // "transaction failed" and "NotAuthorisedExporter".
  contract.handleRevert = true;

  return {
    address: account.address,
    blockNumber: reader.blockNumber,
    findBatch: reader.findBatch,

    /**
     * Refuse to run against a chain where every anchor would revert.
     *
     * Each of these is a misconfiguration the operator can fix and would
     * otherwise learn about only from a stream of failed transactions, having
     * paid gas for each.
     */
    async preflight() {
      const chainId = toNumber(await web3.eth.getChainId());

      const code = await web3.eth.getCode(contractAddress);
      if (!code || code === "0x") {
        throw new Error(
          `no contract deployed at ${contractAddress} on chain ${chainId} — check ` +
            "OREOCHAIN_CONTRACT_ADDRESS and OREOCHAIN_CHAIN_RPC point at the same network"
        );
      }

      const authorised = await contract.methods.isExporter(account.address).call();
      if (!authorised) {
        throw new Error(
          `${account.address} is not an authorised exporter on ${contractAddress} — the ` +
            "contract owner must call addExporter(address, info) before this worker can anchor"
        );
      }

      const balance = await web3.eth.getBalance(account.address);
      if (balance === 0n || balance === "0") {
        throw new Error(
          `${account.address} holds no native balance on chain ${chainId}, so every anchor ` +
            "would fail for gas — fund it before starting"
        );
      }

      return {
        chainId,
        address: account.address,
        balanceWei: String(balance),
      };
    },

    /**
     * Submit an anchor and return as soon as it has a hash.
     *
     * Resolving on the hash rather than the receipt is deliberate: see the
     * file header. It also means a duplicate submission is possible after a
     * crash, which is safe because anchorBatch reverts with AlreadyExists on a
     * root the contract already holds.
     */
    async anchorBatch({ root, size, uri }) {
      const method = contract.methods.anchorBatch(root, size, uri || "");

      const estimated = await method.estimateGas({ from: account.address });
      const gas = BigInt(Math.ceil(toNumber(estimated) * gasLimitPadding));

      const pending = method.send({ from: account.address, gas: gas.toString() });

      /*
       * Attached now, before the await below, and not after it.
       *
       * The send promise stays alive until the receipt arrives and nothing is
       * awaiting it, so a later revert would surface as an unhandled
       * rejection and take the process down. It is logged instead; the
       * authority on whether the anchor landed is the contract, next tick.
       *
       * Attaching it after the await covered only the case where the send had
       * already succeeded. A failure at submission — an address out of gas
       * money, a nonce the node rejects, a revert the node catches before
       * mining — rejects the awaited promise, so this line was never reached,
       * the send promise's own rejection went unhandled, and the worker
       * exited. Anchoring then stopped dead on a faucet running dry, which is
       * exactly the failure a worker is supposed to sit through: the batch is
       * still in the store, and the next tick would have retried it.
       */
      let txHash = null;
      Promise.resolve(pending).catch((error) => {
        // Before a hash exists the caller is about to be told by the rejection
        // below, and reports it as "cannot anchor batch". Saying it twice
        // would only suggest two different failures.
        if (txHash === null) return;
        log.warn("anchor transaction did not complete cleanly", {
          root,
          txHash,
          message: error.message,
        });
      });

      txHash = await new Promise((resolve, reject) => {
        pending.once("transactionHash", resolve);
        pending.once("error", reject);
      });

      return { txHash };
    },
  };
}
