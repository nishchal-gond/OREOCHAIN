/**
 * A single-process Ethereum chain, just large enough for the browser to talk to.
 *
 * The end-to-end test drives the real pages, which build a real `web3.js`
 * instance over `window.ethereum`. Something has to answer that provider, and
 * the alternatives are both worse than this file: a stub `web3.eth.Contract`
 * skips the ABI encoding that is the most likely thing to break, and a real
 * node is a download, a daemon and a funded account in CI.
 *
 * So: the contract in Contract/ChunkedVerification.sol is compiled with solc
 * and executed in @ethereumjs/evm. Calldata, return data, revert reasons and
 * logs are the real thing; only the block production is fiction, and it is the
 * minimum fiction that keeps web3 happy — one block per transaction, mined
 * immediately, no mempool and no signing (`eth_sendTransaction` is what
 * MetaMask exposes, and the "node" holds the keys here).
 *
 * `block.number` is not fiction we can skip. The contract writes
 * `uint64(block.number)` into every record and treats zero as "does not
 * exist", so a chain that leaves it at zero registers documents that
 * `findDocument` then reports as unregistered.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

import { Web3 } from "web3";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Dev-only dependencies. Report their absence rather than crashing. */
export function loadToolchain() {
  try {
    return {
      solc: require("solc"),
      evm: require("@ethereumjs/evm"),
      statemanager: require("@ethereumjs/statemanager"),
      common: require("@ethereumjs/common"),
      util: require("@ethereumjs/util"),
      keccak: require("ethereum-cryptography/keccak"),
    };
  } catch (error) {
    return null;
  }
}

export function compileContract(solc) {
  const source = fs.readFileSync(path.join(ROOT, "Contract/ChunkedVerification.sol"), "utf8");
  const out = JSON.parse(
    solc.compile(
      JSON.stringify({
        language: "Solidity",
        sources: { "ChunkedVerification.sol": { content: source } },
        settings: {
          optimizer: { enabled: true, runs: 200 },
          evmVersion: "paris",
          outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
        },
      })
    )
  );
  const errors = (out.errors || []).filter((e) => e.severity === "error");
  if (errors.length > 0) throw new Error(errors.map((e) => e.formattedMessage).join("\n"));
  return out.contracts["ChunkedVerification.sol"].ChunkedVerification;
}

const CHAIN_ID = 31337n;

function hex(value) {
  return "0x" + value.toString(16);
}

function randomHash(keccak, seed) {
  return "0x" + Buffer.from(keccak(new TextEncoder().encode(seed))).toString("hex");
}

/**
 * Deploy the contract and return an object with a `request({method, params})`
 * that speaks enough JSON-RPC for web3.js.
 *
 * @param {object} [options]
 * @param {string[]} [options.accounts] 0x addresses; the first is the owner and
 *   is authorised as an exporter, which is what registerDocument requires.
 */
export async function startChain(options = {}) {
  const toolchain = loadToolchain();
  if (!toolchain) throw new Error("contract toolchain not installed");
  const { solc, evm: evmMod, statemanager, common: commonMod, util, keccak } = toolchain;

  const accounts = options.accounts || ["0x" + "a1".repeat(20)];
  const artifact = compileContract(solc);

  const stateManager = new statemanager.DefaultStateManager();
  const common = new commonMod.Common({
    chain: commonMod.Chain.Mainnet,
    hardfork: commonMod.Hardfork.Paris,
  });
  const evm = await evmMod.EVM.create({ stateManager, common });

  for (const address of accounts) {
    await stateManager.putAccount(
      new util.Address(util.hexToBytes(address)),
      new util.Account(0n, 10n ** 20n)
    );
  }

  /** Blocks are numbered from 1: zero is the contract's "no record" sentinel. */
  let blockNumber = 1n;
  const receipts = new Map();
  const transactions = new Map();
  const logs = [];
  const unsupported = new Set();

  function blockContext() {
    return {
      header: {
        number: blockNumber,
        timestamp: BigInt(Math.floor(Date.now() / 1000)),
        difficulty: 0n,
        prevRandao: new Uint8Array(32),
        gasLimit: 30_000_000n,
        baseFeePerGas: 0n,
        coinbase: new util.Address(util.hexToBytes("0x" + "00".repeat(20))),
        getBlobGasPrice: () => 0n,
      },
    };
  }

  async function execute(from, to, data, { commit }) {
    // eth_call must not leave state behind, even if something calls a
    // non-view method through it. Wrapping the read in a checkpoint that is
    // always reverted is cheaper than trusting every caller to be careful.
    if (!commit) await stateManager.checkpoint();
    try {
      return await evm.runCall({
        caller: new util.Address(util.hexToBytes(from)),
        to: to ? new util.Address(util.hexToBytes(to)) : undefined,
        data: util.hexToBytes(data && data !== "0x" ? data : "0x"),
        gasLimit: 30_000_000n,
        gasPrice: 0n,
        value: 0n,
        block: blockContext(),
      });
    } finally {
      if (!commit) await stateManager.revert();
    }
  }

  const deployment = await execute(accounts[0], null, "0x" + artifact.evm.bytecode.object, {
    commit: true,
  });
  if (deployment.execResult.exceptionError) {
    throw new Error(`contract deployment failed: ${deployment.execResult.exceptionError.error}`);
  }
  const contractAddress = deployment.createdAddress.toString();

  /**
   * registerDocument is onlyExporter, so an account that can upload has to be
   * authorised first. The deployer is the owner, which is the only account
   * that can do it.
   */
  const abiCoder = new Web3().eth.abi;
  for (const account of accounts) {
    blockNumber += 1n;
    const authorised = await execute(
      accounts[0],
      contractAddress,
      abiCoder.encodeFunctionCall(
        artifact.abi.find((e) => e.type === "function" && e.name === "addExporter"),
        [account, options.exporterInfo || "OREOCHAIN end-to-end test"]
      ),
      { commit: true }
    );
    if (authorised.execResult.exceptionError) {
      throw new Error(`could not authorise ${account} as an exporter`);
    }
  }

  /**
   * A revert carries ABI-encoded data. web3 surfaces whatever string it gets,
   * and the app matches on the custom-error name, so decode the selector back
   * to a name the way a real node's error message would carry it.
   */
  const errorSelectors = new Map();
  for (const entry of artifact.abi) {
    if (entry.type !== "error") continue;
    const signature = `${entry.name}(${entry.inputs.map((i) => i.type).join(",")})`;
    const selector = Buffer.from(keccak.keccak256(new TextEncoder().encode(signature)).slice(0, 4));
    errorSelectors.set(selector.toString("hex"), entry.name);
  }

  function revertMessage(returnValue) {
    const bytes = Buffer.from(returnValue || []);
    if (bytes.length >= 4) {
      const name = errorSelectors.get(bytes.subarray(0, 4).toString("hex"));
      if (name) return `execution reverted: ${name}()`;
    }
    return "execution reverted";
  }

  function recordLogs(result, transactionHash) {
    const entries = result.execResult.logs || [];
    for (const [address, topics, dataBytes] of entries) {
      logs.push({
        address: "0x" + Buffer.from(address).toString("hex"),
        topics: topics.map((t) => "0x" + Buffer.from(t).toString("hex")),
        data: "0x" + Buffer.from(dataBytes).toString("hex"),
        blockNumber: hex(blockNumber),
        blockHash: randomHash(keccak.keccak256, `block-${blockNumber}`),
        transactionHash,
        transactionIndex: "0x0",
        logIndex: hex(logs.length),
        removed: false,
      });
    }
  }

  function block(number) {
    return {
      number: hex(number),
      hash: randomHash(keccak.keccak256, `block-${number}`),
      parentHash: randomHash(keccak.keccak256, `block-${number - 1n}`),
      nonce: "0x0000000000000000",
      sha3Uncles: "0x" + "00".repeat(32),
      logsBloom: "0x" + "00".repeat(256),
      transactionsRoot: "0x" + "00".repeat(32),
      stateRoot: "0x" + "00".repeat(32),
      receiptsRoot: "0x" + "00".repeat(32),
      miner: "0x" + "00".repeat(20),
      difficulty: "0x0",
      totalDifficulty: "0x0",
      extraData: "0x",
      size: "0x0",
      gasLimit: "0x1c9c380",
      gasUsed: "0x0",
      timestamp: hex(BigInt(Math.floor(Date.now() / 1000))),
      transactions: [],
      uncles: [],
      baseFeePerGas: "0x0",
    };
  }

  async function request({ method, params = [] }) {
    switch (method) {
      case "eth_chainId":
        return hex(CHAIN_ID);
      case "net_version":
        return CHAIN_ID.toString();
      case "eth_accounts":
      case "eth_requestAccounts":
        return accounts;
      case "eth_getBalance":
        return hex(10n ** 20n);
      case "eth_blockNumber":
        return hex(blockNumber);
      case "eth_gasPrice":
      case "eth_maxPriorityFeePerGas":
        return "0x0";
      case "eth_estimateGas":
        return "0x1c9c380";
      case "eth_getCode": {
        const code = await stateManager.getContractCode(
          new util.Address(util.hexToBytes(params[0]))
        );
        return "0x" + Buffer.from(code).toString("hex");
      }
      case "eth_getBlockByNumber":
      case "eth_getBlockByHash":
        return block(blockNumber);
      case "eth_getTransactionCount":
        return "0x0";
      case "eth_call": {
        const [call] = params;
        const result = await execute(call.from || accounts[0], call.to, call.data, {
          commit: false,
        });
        if (result.execResult.exceptionError) {
          const error = new Error(revertMessage(result.execResult.returnValue));
          error.code = 3;
          error.data = "0x" + Buffer.from(result.execResult.returnValue || []).toString("hex");
          throw error;
        }
        return "0x" + Buffer.from(result.execResult.returnValue).toString("hex");
      }
      case "eth_sendTransaction": {
        const [tx] = params;
        blockNumber += 1n;
        const result = await execute(tx.from || accounts[0], tx.to, tx.data, { commit: true });
        const transactionHash = randomHash(
          keccak.keccak256,
          `tx-${blockNumber}-${tx.data || ""}`.slice(0, 256)
        );
        if (result.execResult.exceptionError) {
          const error = new Error(revertMessage(result.execResult.returnValue));
          error.code = 3;
          error.data = "0x" + Buffer.from(result.execResult.returnValue || []).toString("hex");
          throw error;
        }
        recordLogs(result, transactionHash);
        const receipt = {
          transactionHash,
          transactionIndex: "0x0",
          blockNumber: hex(blockNumber),
          blockHash: randomHash(keccak.keccak256, `block-${blockNumber}`),
          from: tx.from || accounts[0],
          to: tx.to || null,
          cumulativeGasUsed: hex(result.execResult.executionGasUsed),
          gasUsed: hex(result.execResult.executionGasUsed),
          contractAddress: null,
          logs: logs.filter((l) => l.transactionHash === transactionHash),
          logsBloom: "0x" + "00".repeat(256),
          status: "0x1",
          effectiveGasPrice: "0x0",
          type: "0x0",
        };
        receipts.set(transactionHash, receipt);
        transactions.set(transactionHash, {
          hash: transactionHash,
          nonce: "0x0",
          blockHash: receipt.blockHash,
          blockNumber: receipt.blockNumber,
          transactionIndex: "0x0",
          from: receipt.from,
          to: receipt.to,
          value: "0x0",
          gas: "0x1c9c380",
          gasPrice: "0x0",
          input: tx.data || "0x",
          type: "0x0",
        });
        return transactionHash;
      }
      case "eth_getTransactionReceipt":
        return receipts.get(params[0]) || null;
      case "eth_getTransactionByHash":
        return transactions.get(params[0]) || null;
      case "eth_getLogs": {
        const [filter = {}] = params;
        const wanted = filter.topics && filter.topics[0];
        return logs.filter((entry) => !wanted || entry.topics[0] === wanted);
      }
      case "eth_subscribe":
      case "eth_unsubscribe":
        // No subscriptions: web3 falls back to polling when this fails.
        throw new Error("subscriptions are not supported");
      default:
        unsupported.add(method);
        throw new Error(`unsupported RPC method: ${method}`);
    }
  }

  return {
    abi: artifact.abi,
    address: contractAddress,
    accounts,
    chainId: Number(CHAIN_ID),
    request,
    unsupportedMethods: () => [...unsupported],
    blockNumber: () => Number(blockNumber),
  };
}
