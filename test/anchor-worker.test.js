/**
 * The anchoring worker, against a real contract in a real EVM.
 *
 * The thing worth testing here is not the polling loop in isolation — it is
 * whether a batch the gateway built ends up anchored on a chain that enforces
 * its own rules, and whether the worker survives the ways that goes wrong: a
 * transaction that has not confirmed yet, a process that died between sending
 * and recording, an account the contract will not accept. So the contract is
 * compiled and executed here, with blocks, logs and reverts, rather than
 * replaced by an object that agrees with whatever the worker does.
 *
 * The gateway is real too: the worker reaches it over HTTP with an API key,
 * because that is the only way it can reach the proof store at all.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

import { assertSafeConfig, loadAnchorConfig, loadConfig } from "../server/config.mjs";
import { createAnchorWorker, createGatewayClient } from "../server/anchor.mjs";
import { createHandler } from "../server/gateway.mjs";
import { createLogger } from "../server/log.mjs";
import { createMemoryBackend } from "../server/storage.mjs";
import { createProofService } from "../server/proofs.mjs";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const KEY = "w".repeat(48);
/** The worker's own credential; an uploader's key may not drive anchoring. */
const UPLOAD_KEY = "u".repeat(48);
const OWNER_HEX = "0x" + "11".repeat(20);
const ANCHOR_HEX = "0x" + "22".repeat(20);

/** Dev-only dependencies; skip rather than fail if they are absent. */
function loadToolchain() {
  try {
    return {
      solc: require("solc"),
      evm: require("@ethereumjs/evm"),
      util: require("@ethereumjs/util"),
      keccak: require("ethereum-cryptography/keccak"),
    };
  } catch {
    return null;
  }
}

const toolchain = loadToolchain();
const skip = toolchain
  ? false
  : "solc / @ethereumjs/evm not installed — run `npm install` to enable contract tests";

const silent = createLogger({ level: "silent" });

// ------------------------------------------------------------- the test chain

/**
 * A chain client backed by @ethereumjs/evm and the real contract.
 *
 * It implements exactly the three methods server/anchor.mjs is written
 * against, the same way server/chain.mjs does over web3 — including
 * recovering a transaction hash from the BatchAnchored log rather than from
 * anything the contract stores, because the contract does not store one.
 */
async function testChain() {
  const { solc, evm: evmMod, util, keccak } = toolchain;

  const source = fs.readFileSync(path.join(ROOT, "Contract/ChunkedVerification.sol"), "utf8");
  const compiled = JSON.parse(
    solc.compile(
      JSON.stringify({
        language: "Solidity",
        sources: { "ChunkedVerification.sol": { content: source } },
        settings: {
          optimizer: { enabled: true, runs: 200 },
          evmVersion: "paris",
          outputSelection: { "*": { "*": ["evm.bytecode.object"] } },
        },
      })
    )
  );
  const errors = (compiled.errors || []).filter((e) => e.severity === "error");
  assert.equal(errors.length, 0, errors.map((e) => e.formattedMessage).join("\n"));
  const bytecode = compiled.contracts["ChunkedVerification.sol"].ChunkedVerification.evm.bytecode.object;

  const machine = await evmMod.EVM.create();
  const owner = new util.Address(util.hexToBytes(OWNER_HEX));
  const anchor = new util.Address(util.hexToBytes(ANCHOR_HEX));

  let head = 0;
  const block = (number) => ({
    header: {
      number: BigInt(number),
      timestamp: BigInt(1_700_000_000 + number * 12),
      coinbase: owner,
      difficulty: 0n,
      gasLimit: 30_000_000n,
      prevRandao: new Uint8Array(32),
      getBlobGasPrice: () => 0n,
    },
  });

  const created = await machine.runCall({
    data: util.hexToBytes("0x" + bytecode),
    caller: owner,
    block: block(++head),
  });
  assert.ok(!created.execResult.exceptionError, "contract failed to deploy");
  const address = created.createdAddress;
  const code = created.execResult.returnValue;

  const selector = (sig) => keccak.keccak256(new TextEncoder().encode(sig)).slice(0, 4);
  const word = (n) => {
    const out = new Uint8Array(32);
    let hex = BigInt(n).toString(16);
    if (hex.length % 2) hex = "0" + hex;
    const bytes = util.hexToBytes("0x" + hex);
    out.set(bytes, 32 - bytes.length);
    return out;
  };
  const addressWord = (a) => {
    const out = new Uint8Array(32);
    out.set(a.bytes, 12);
    return out;
  };
  const stringArg = (value) => {
    const bytes = new TextEncoder().encode(value);
    const padded = new Uint8Array(Math.ceil(bytes.length / 32) * 32);
    padded.set(bytes);
    return [word(bytes.length), padded];
  };
  const concat = (...parts) => {
    const total = parts.reduce((sum, p) => sum + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  };

  /** Every log the chain has ever emitted, with the block it landed in. */
  const logs = [];
  let submissions = 0;

  async function send(caller, data) {
    const number = ++head;
    const result = await machine.runCall({ to: address, code, caller, block: block(number), data });
    if (result.execResult.exceptionError) {
      // Blocks are still consumed by a reverted transaction, as on a real
      // chain: the gas is spent either way.
      const revertData = util.bytesToHex(result.execResult.returnValue);
      const error = new Error(`transaction reverted (${revertData || "no data"})`);
      error.revertData = revertData;
      throw error;
    }

    // A deterministic stand-in for a transaction hash. Real chains derive it
    // from the signed transaction; what matters to the worker is that it is 32
    // bytes, unique, and recoverable from the log afterwards.
    const txHash = util.bytesToHex(keccak.keccak256(concat(data, word(number))));
    for (const entry of result.execResult.logs || []) {
      logs.push({ block: number, txHash, topics: entry[1].map((t) => util.bytesToHex(t)) });
    }
    return { txHash, block: number };
  }

  async function callStatic(data) {
    const result = await machine.runCall({
      to: address,
      code,
      caller: owner,
      block: block(head),
      data,
    });
    assert.ok(!result.execResult.exceptionError, "static call reverted");
    return result.execResult.returnValue;
  }

  const BATCH_ANCHORED = util.bytesToHex(
    keccak.keccak256(new TextEncoder().encode("BatchAnchored(address,bytes32,uint32,string)"))
  );

  async function addExporter(account = anchor) {
    await send(owner, concat(selector("addExporter(address,string)"), addressWord(account), word(64), ...stringArg("worker")));
  }

  await addExporter();

  return {
    address: address.toString(),
    submissions: () => submissions,
    head: () => head,
    /** Advance the chain without a transaction, the way time passing does. */
    mine(count = 1) {
      head += count;
    },
    addExporter,
    async removeExporter(account = anchor) {
      await send(owner, concat(selector("removeExporter(address)"), addressWord(account)));
    },
    /** Anchor a root directly, bypassing the worker. */
    anchorDirectly(root, size, uri = "") {
      return send(
        anchor,
        concat(selector("anchorBatch(bytes32,uint32,string)"), util.hexToBytes(root), word(size), word(96), ...stringArg(uri))
      );
    },
    async uriOf(root) {
      const returned = await callStatic(concat(selector("findBatch(bytes32)"), util.hexToBytes(root)));
      // head is (blockNumber, timestamp, size, anchor, offset-to-uri).
      const offset = Number(util.bytesToBigInt(returned.slice(4 * 32, 5 * 32)));
      const length = Number(util.bytesToBigInt(returned.slice(offset, offset + 32)));
      return new TextDecoder().decode(returned.slice(offset + 32, offset + 32 + length));
    },

    // ---- the interface server/anchor.mjs is written against

    blockNumber: async () => head,

    async findBatch(root) {
      const returned = await callStatic(
        concat(selector("findBatch(bytes32)"), util.hexToBytes(root))
      );
      const blockNumber = Number(util.bytesToBigInt(returned.slice(0, 32)));
      if (blockNumber === 0) return null;

      const log = logs.find(
        (entry) =>
          entry.block === blockNumber &&
          entry.topics[0] === BATCH_ANCHORED &&
          entry.topics[2] === root
      );
      return {
        block: blockNumber,
        size: Number(util.bytesToBigInt(returned.slice(2 * 32, 3 * 32))),
        txHash: log ? log.txHash : null,
      };
    },

    async anchorBatch({ root, size, uri }) {
      submissions++;
      return send(
        anchor,
        concat(
          selector("anchorBatch(bytes32,uint32,string)"),
          util.hexToBytes(root),
          word(size),
          word(96),
          ...stringArg(uri || "")
        )
      );
    },
  };
}

// ---------------------------------------------------------------- the gateway

/** A real gateway on an ephemeral port, with a real proof service behind it. */
async function startGateway({ batchMaxSize = 2, batchMaxAgeMs = 3_600_000 } = {}) {
  const config = assertSafeConfig(
    loadConfig({
      OREOCHAIN_API_KEYS: `${UPLOAD_KEY},${KEY}`,
      OREOCHAIN_ANCHOR_API_KEYS: KEY,
      OREOCHAIN_STORAGE: "memory",
    }),
    { warn: () => {} }
  );
  const proofs = await createProofService({ batchMaxSize, batchMaxAgeMs });
  const handler = createHandler(config, createMemoryBackend(), {
    logger: silent,
    sweeper: false,
    proofs,
  });

  const server = http.createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

  const url = `http://127.0.0.1:${server.address().port}`;
  return {
    url,
    proofs,
    client: createGatewayClient({ url, apiKey: KEY }),
    stop: () => new Promise((resolve) => server.close(resolve)),
  };
}

let nextDocument = 0;
function aDocument() {
  const n = ++nextDocument;
  return {
    fileHash: "0x" + n.toString(16).padStart(64, "0"),
    merkleRoot: "0x" + (n + 0x5000).toString(16).padStart(64, "0"),
    manifestCID: `bafyAnchor${n}`,
    fileSize: 1024 + n,
  };
}

async function recordDocuments(gw, count) {
  const documents = [];
  for (let i = 0; i < count; i++) {
    const document = aDocument();
    const response = await fetch(`${gw.url}/api/proofs/record`, {
      method: "POST",
      headers: { Authorization: `Bearer ${UPLOAD_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify(document),
    });
    assert.equal(response.status, 200);
    documents.push(document);
  }
  return documents;
}

function workerFor(gw, chain, overrides = {}) {
  return createAnchorWorker({
    gateway: gw.client,
    chain,
    log: silent,
    confirmations: 3,
    uriFor: (batch) => `https://proofs.example/${batch.root}`,
    ...overrides,
  });
}

// --------------------------------------------------------------------- tests

test("a pending batch is built, anchored on-chain and reported back", { skip }, async () => {
  const chain = await testChain();
  const gw = await startGateway({ batchMaxSize: 2 });
  try {
    const documents = await recordDocuments(gw, 2);

    // First tick: the queue is full enough to flush, so the worker builds a
    // batch and sends a transaction. It does not report it — nothing is
    // confirmed yet.
    await workerFor(gw, chain).tick();
    assert.equal(chain.submissions(), 1);
    assert.equal((await gw.client.unanchored()).length, 1, "still owed a confirmation");

    const beforeConfirmation = await (
      await fetch(`${gw.url}/api/proofs/inclusion/${documents[0].fileHash}`)
    ).json();
    assert.equal(
      beforeConfirmation.txHash,
      undefined,
      "a receipt must not point at a transaction that could still reorg out"
    );

    // Second tick, once the anchor is deep enough: the transaction comes back
    // from the chain's own log and is recorded against the batch.
    chain.mine(3);
    await workerFor(gw, chain).tick();

    assert.deepEqual(await gw.client.unanchored(), [], "the batch is anchored");

    const inclusion = await (
      await fetch(`${gw.url}/api/proofs/inclusion/${documents[0].fileHash}`)
    ).json();
    assert.match(inclusion.txHash, /^0x[0-9a-f]{64}$/);
    assert.ok(inclusion.block > 0);
  } finally {
    await gw.stop();
  }
});

test("the anchor carries the configured proof URI", { skip }, async () => {
  const chain = await testChain();
  const gw = await startGateway({ batchMaxSize: 1 });
  try {
    await recordDocuments(gw, 1);
    const worker = workerFor(gw, chain);
    await worker.tick();

    const [batch] = await gw.client.unanchored();
    assert.equal(await chain.uriOf(batch.root), `https://proofs.example/${batch.root}`);
  } finally {
    await gw.stop();
  }
});

test("a worker that dies after submitting does not anchor twice", { skip }, async () => {
  const chain = await testChain();
  const gw = await startGateway({ batchMaxSize: 2 });
  try {
    await recordDocuments(gw, 2);

    // The worker sends the transaction and is then lost, along with every
    // note it had made of having sent it.
    await workerFor(gw, chain).tick();
    assert.equal(chain.submissions(), 1);

    chain.mine(3);

    // A new process, with nothing in memory, asks the contract first.
    const replacement = workerFor(gw, chain);
    await replacement.tick();

    assert.equal(chain.submissions(), 1, "the replacement must not send a second anchor");
    assert.deepEqual(await gw.client.unanchored(), []);
    assert.equal(replacement.counts().anchored, 1);
  } finally {
    await gw.stop();
  }
});

test("the contract itself refuses a second anchor for one root", { skip }, async () => {
  // This is what makes a duplicate submission survivable rather than
  // corrupting: the worker's recovery leans on it, so it is tested here
  // against the real contract rather than assumed.
  const chain = await testChain();
  const root = "0x" + "c1".repeat(32);
  await chain.anchorDirectly(root, 4);
  await assert.rejects(() => chain.anchorDirectly(root, 4), /reverted/);
});

test("a chain that rejects the anchor leaves the batch to be retried", { skip }, async () => {
  const chain = await testChain();
  const gw = await startGateway({ batchMaxSize: 2 });
  try {
    await recordDocuments(gw, 2);

    // The commonest way this fails in a real deployment: the address holding
    // the key was never authorised, or was removed.
    await chain.removeExporter();

    const worker = workerFor(gw, chain);
    await worker.tick();
    assert.equal(worker.counts().failures, 1);
    assert.equal((await gw.client.unanchored()).length, 1, "the batch is still owed an anchor");

    // Fixing the authorisation is enough; nothing has to be replayed by hand.
    await chain.addExporter();
    await worker.tick();
    chain.mine(3);
    await worker.tick();

    assert.deepEqual(await gw.client.unanchored(), []);
  } finally {
    await gw.stop();
  }
});

test("one unanchorable batch does not block the ones behind it", { skip }, async () => {
  const chain = await testChain();
  const gw = await startGateway({ batchMaxSize: 1 });
  try {
    await recordDocuments(gw, 1);
    await gw.client.buildBatch();
    await recordDocuments(gw, 1);
    await gw.client.buildBatch();

    const [first, second] = await gw.client.unanchored();
    assert.ok(first && second, "two batches are waiting");

    const poisoned = {
      ...chain,
      anchorBatch: async (batch) => {
        if (batch.root === first.root) throw new Error("this one always fails");
        return chain.anchorBatch(batch);
      },
    };

    const worker = workerFor(gw, poisoned);
    await worker.tick();

    assert.equal(worker.counts().failures, 1);
    assert.equal(worker.counts().submitted, 1, "the second batch was still submitted");
  } finally {
    await gw.stop();
  }
});

test("no new batch is built while a backlog is waiting", { skip }, async () => {
  const chain = await testChain();
  const gw = await startGateway({ batchMaxSize: 1 });
  try {
    await recordDocuments(gw, 1);
    const worker = workerFor(gw, chain);
    await worker.tick();

    // Enough pending documents to flush again, but the first batch has not
    // confirmed. Queueing more work onto a queue that is not draining turns
    // one stuck batch into a pile of them.
    await recordDocuments(gw, 3);
    await worker.tick();

    assert.equal((await gw.client.unanchored()).length, 1);
    assert.equal(chain.submissions(), 1);
  } finally {
    await gw.stop();
  }
});

test("a transaction that never mines is resent once, not on every tick", { skip }, async () => {
  const chain = await testChain();
  const gw = await startGateway({ batchMaxSize: 1 });
  try {
    await recordDocuments(gw, 1);

    // A transaction that returns a hash and is then dropped from the mempool:
    // the chain never hears of it again.
    let sent = 0;
    const dropping = {
      ...chain,
      anchorBatch: async () => {
        sent++;
        return { txHash: "0x" + "ef".repeat(32) };
      },
      findBatch: async () => null,
    };

    let clock = 1_000;
    const worker = workerFor(gw, dropping, {
      pendingTimeoutMs: 500,
      now: () => clock,
    });

    await worker.tick();
    assert.equal(sent, 1);

    // Still inside the window: resending now would just compete with our own
    // transaction for the same nonce.
    clock += 100;
    await worker.tick();
    assert.equal(sent, 1);

    clock += 1_000;
    await worker.tick();
    assert.equal(sent, 2, "past the timeout it is resent");
  } finally {
    await gw.stop();
  }
});

test("an anchored batch with no recoverable transaction is reported, not retried", { skip }, async () => {
  const chain = await testChain();
  const gw = await startGateway({ batchMaxSize: 1 });
  try {
    await recordDocuments(gw, 1);

    // An RPC that has pruned the logs: the anchor is on-chain and valid, but
    // the transaction that carried it cannot be found.
    const pruned = {
      ...chain,
      findBatch: async (root) => {
        const found = await chain.findBatch(root);
        return found ? { ...found, txHash: null } : null;
      },
    };

    const worker = workerFor(gw, pruned);
    await worker.tick();
    chain.mine(3);
    await worker.tick();

    // Not reported — the store would rather hold no transaction hash than a
    // made-up one — and not resubmitted either.
    assert.equal(chain.submissions(), 1);
    assert.equal((await gw.client.unanchored()).length, 1);
    assert.equal(worker.counts().failures, 0, "this is a warning, not a failure to retry");
  } finally {
    await gw.stop();
  }
});

// ------------------------------------------------------------- configuration

test("the worker refuses to start without the settings it cannot work without", () => {
  assert.throws(
    () => loadAnchorConfig({}),
    /OREOCHAIN_ANCHOR_KEY — the funded private key/,
    "an unset anchoring key must fail at startup, not silently anchor nothing"
  );

  // Every missing setting is named at once: fixing them one restart at a time
  // is how a deployment takes an afternoon.
  assert.throws(() => loadAnchorConfig({}), /4 setting\(s\) are missing/);
});

test("a malformed key or address is rejected by name", () => {
  const base = {
    OREOCHAIN_CHAIN_RPC: "http://127.0.0.1:8545",
    OREOCHAIN_CONTRACT_ADDRESS: "0x" + "ab".repeat(20),
    OREOCHAIN_ANCHOR_KEY: "0x" + "cd".repeat(32),
    OREOCHAIN_ANCHOR_API_KEY: KEY,
  };

  assert.deepEqual(loadAnchorConfig(base).confirmations, 3);

  assert.throws(
    () => loadAnchorConfig({ ...base, OREOCHAIN_CONTRACT_ADDRESS: "0xnope" }),
    /OREOCHAIN_CONTRACT_ADDRESS must be a 20-byte hex address/
  );
  assert.throws(
    () => loadAnchorConfig({ ...base, OREOCHAIN_ANCHOR_KEY: "deadbeef" }),
    /OREOCHAIN_ANCHOR_KEY must be a 0x-prefixed 32-byte hex private key/
  );
  assert.throws(
    () => loadAnchorConfig({ ...base, OREOCHAIN_ANCHOR_CONFIRMATIONS: "0" }),
    /OREOCHAIN_ANCHOR_CONFIRMATIONS must be an integer between 1 and 1000/
  );
});

test("the anchoring key can come from a file, and never from both", () => {
  const file = path.join(ROOT, "test", `.anchor-key-${process.pid}.tmp`);
  fs.writeFileSync(file, "0x" + "ab".repeat(32) + "\n");
  try {
    const base = {
      OREOCHAIN_CHAIN_RPC: "http://127.0.0.1:8545",
      OREOCHAIN_CONTRACT_ADDRESS: "0x" + "ab".repeat(20),
      OREOCHAIN_ANCHOR_API_KEY: KEY,
    };

    // The trailing newline `echo` leaves behind would otherwise become part of
    // the key and fail somewhere far from here.
    assert.equal(
      loadAnchorConfig({ ...base, OREOCHAIN_ANCHOR_KEY_FILE: file }).privateKey,
      "0x" + "ab".repeat(32)
    );

    assert.throws(
      () =>
        loadAnchorConfig({
          ...base,
          OREOCHAIN_ANCHOR_KEY_FILE: file,
          OREOCHAIN_ANCHOR_KEY: "0x" + "cd".repeat(32),
        }),
      /both OREOCHAIN_ANCHOR_KEY and OREOCHAIN_ANCHOR_KEY_FILE are set/
    );
  } finally {
    fs.rmSync(file, { force: true });
  }
});

// ------------------------------------------------------- the web3 adapter

/**
 * server/chain.mjs is the glue between the worker and web3. The contract
 * behaviour it drives is covered above against a real EVM; what is left here
 * is the glue itself, and it is tested against a stand-in for web3's surface
 * rather than a live RPC endpoint.
 *
 * Said plainly: these tests prove the adapter does the right thing with what
 * web3 v4 returns, not that web3 v4 returns it. The parts that would only
 * show up against a real node — gas pricing, nonce handling, an RPC that
 * disagrees with the docs — are not covered by anything here.
 */
function fakeWeb3({ code = "0x60", isExporter = true, balance = 10n ** 18n, found, onSend } = {}) {
  const calls = [];

  class FakeWeb3 {
    constructor(rpcUrl) {
      this.rpcUrl = rpcUrl;
      this.eth = {
        // web3 v4 hands back BigInt for every chain integer.
        getChainId: async () => 31337n,
        getBlockNumber: async () => 4321n,
        getCode: async () => code,
        getBalance: async () => balance,
        accounts: {
          privateKeyToAccount: (key) => ({ address: "0x" + "77".repeat(20), privateKey: key }),
          wallet: { add: () => {} },
        },
        Contract: class {
          constructor(abi, address) {
            this.address = address;
            this.methods = {
              isExporter: () => ({ call: async () => isExporter }),
              findBatch: (root) => ({ call: async () => found(root) }),
              anchorBatch: (...args) => ({
                estimateGas: async () => 120_000n,
                send: (options) => {
                  calls.push({ args, options });
                  return onSend();
                },
              }),
            };
          }
          async getPastEvents() {
            return [{ transactionHash: "0x" + "7f".repeat(32) }];
          }
        },
      };
    }
  }

  return { module: { Web3: FakeWeb3 }, calls };
}

const CHAIN_BASE = {
  rpcUrl: "http://127.0.0.1:8545",
  contractAddress: "0x" + "ab".repeat(20),
  privateKey: "0x" + "cd".repeat(32),
  log: silent,
};

test("preflight names the misconfiguration rather than failing on-chain", async () => {
  const { createChainClient } = await import("../server/chain.mjs");

  const cases = [
    [{ code: "0x" }, /no contract deployed at/],
    [{ isExporter: false }, /is not an authorised exporter/],
    [{ balance: 0n }, /holds no native balance/],
  ];

  for (const [overrides, expected] of cases) {
    const fake = fakeWeb3({ found: () => ({ blockNumber: 0n }), onSend: () => {}, ...overrides });
    const chain = await createChainClient({ ...CHAIN_BASE, web3Module: fake.module });
    await assert.rejects(() => chain.preflight(), expected);
  }

  // The healthy case reports what it found, so the startup line says which
  // chain and which address are actually in use.
  const healthy = fakeWeb3({ found: () => ({ blockNumber: 0n }), onSend: () => {} });
  const chain = await createChainClient({ ...CHAIN_BASE, web3Module: healthy.module });
  assert.deepEqual(await chain.preflight(), {
    chainId: 31337,
    address: "0x" + "77".repeat(20),
    balanceWei: String(10n ** 18n),
  });
});

test("an unanchored root reads as null, an anchored one carries its transaction", async () => {
  const { createChainClient } = await import("../server/chain.mjs");
  const root = "0x" + "aa".repeat(32);

  const missing = fakeWeb3({ found: () => ({ blockNumber: 0n, size: 0n }), onSend: () => {} });
  const empty = await createChainClient({ ...CHAIN_BASE, web3Module: missing.module });
  assert.equal(await empty.findBatch(root), null);

  const present = fakeWeb3({ found: () => ({ blockNumber: 99n, size: 7n }), onSend: () => {} });
  const chain = await createChainClient({ ...CHAIN_BASE, web3Module: present.module });
  assert.deepEqual(await chain.findBatch(root), {
    block: 99,
    size: 7,
    txHash: "0x" + "7f".repeat(32),
  });

  // Every one of these arrives as a BigInt and must not leak downstream,
  // where it would throw the moment it met a number.
  assert.equal(typeof (await chain.blockNumber()), "number");
});

test("anchorBatch returns on the transaction hash, not on the receipt", async () => {
  const { createChainClient } = await import("../server/chain.mjs");

  // A stand-in for web3's PromiEvent: a promise that also emits, and that
  // settles long after the hash is known.
  let settle;
  const pending = new Promise((resolve, reject) => {
    settle = { resolve, reject };
  });
  const listeners = new Map();
  pending.once = (event, handler) => {
    listeners.set(event, handler);
    return pending;
  };

  const fake = fakeWeb3({
    found: () => ({ blockNumber: 0n }),
    onSend: () => {
      setImmediate(() => listeners.get("transactionHash")?.("0x" + "8e".repeat(32)));
      return pending;
    },
  });
  const chain = await createChainClient({ ...CHAIN_BASE, web3Module: fake.module });

  const submitted = await chain.anchorBatch({ root: "0x" + "bb".repeat(32), size: 3, uri: "u" });
  assert.equal(submitted.txHash, "0x" + "8e".repeat(32), "resolved before the receipt");
  assert.equal(fake.calls.length, 1);
  // Estimate plus the 25% margin, as a string: web3 rejects a float.
  assert.equal(fake.calls[0].options.gas, "150000");

  /*
   * The send promise outlives the call. A revert arriving later used to be an
   * unhandled rejection, which by default takes the process down — losing a
   * worker over a transaction whose outcome the next tick would have read off
   * the contract anyway.
   *
   * This bites: remove the catch in server/chain.mjs and the test runner
   * fails the file on the unhandled rejection.
   */
  settle.reject(new Error("reverted later"));
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
});
