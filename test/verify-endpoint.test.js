/**
 * The public verification endpoint.
 *
 * This is the one route an outsider uses: someone holding a certificate, with
 * no account here, no wallet and no RPC endpoint of their own. So the tests
 * are about what it tells them, and specifically about the answers that must
 * never be confused with each other — "not anchored", "I could not check",
 * and "what I recorded is not on the chain".
 *
 * The chain behind it is a stand-in, not an EVM: what is under test is the
 * gateway's reasoning about what the chain said, and the reading of the real
 * contract is covered against a real EVM in test/anchor-worker.test.js.
 */

import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { assertSafeConfig, loadConfig } from "../server/config.mjs";
import { createAnchorConfirmer } from "../server/confirm.mjs";
import { createHandler } from "../server/gateway.mjs";
import { createLogger } from "../server/log.mjs";
import { createMemoryBackend } from "../server/storage.mjs";
import { createProofService } from "../server/proofs.mjs";
import { generateSigningKey, importPublicKey, verifyReceipt } from "../js/core/receipt.js";
import { verifyInBatch } from "../js/core/anchor.js";

const KEY = "v".repeat(48);
const CONTRACT = "0x" + "c0".repeat(20);
const silent = createLogger({ level: "silent" });

/** A path in a fresh directory, for the tests that need a store on disk. */
function scratch(name) {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), "oreochain-verify-")), name);
}

/** A chain that says exactly what a test tells it to. */
function stubChain({
  batches = new Map(),
  documents = new Map(),
  head = 100,
  fail = null,
  chainId = 31337,
} = {}) {
  let reads = 0;
  return {
    reads: () => reads,
    contractAddress: CONTRACT,
    // Settable, because an RPC endpoint can come to point at a different
    // network under a running process: DNS, a failover, an edited URL.
    setChainId: (value) => {
      chainId = value;
    },
    chainId: async () => {
      if (fail) throw new Error(fail);
      return chainId;
    },
    blockNumber: async () => {
      if (fail) throw new Error(fail);
      return head;
    },
    findBatch: async (root) => {
      reads++;
      if (fail) throw new Error(fail);
      return batches.get(root) || null;
    },
    findDocument: async (fileHash) => {
      reads++;
      if (fail) throw new Error(fail);
      return documents.get(fileHash) || null;
    },
  };
}

async function startGateway({ reader = null, proofsOptions = {}, env = {} } = {}) {
  const config = assertSafeConfig(
    loadConfig({
      OREOCHAIN_API_KEYS: KEY,
      OREOCHAIN_ANCHOR_API_KEYS: KEY,
      OREOCHAIN_STORAGE: "memory",
      ...env,
    }),
    { warn: () => {} }
  );
  const proofs = await createProofService(proofsOptions);
  const handler = createHandler(config, createMemoryBackend(), {
    logger: silent,
    sweeper: false,
    proofs,
    confirmer: reader ? createAnchorConfirmer({ reader, log: silent }) : null,
  });

  const server = http.createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

  return {
    url: `http://127.0.0.1:${server.address().port}`,
    proofs,
    stop: () => new Promise((resolve) => server.close(resolve)),
  };
}

let counter = 0;
function aDocument() {
  const n = ++counter;
  return {
    fileHash: "0x" + n.toString(16).padStart(64, "0"),
    merkleRoot: "0x" + (n + 0x9000).toString(16).padStart(64, "0"),
    manifestCID: `bafyVerify${n}`,
    fileSize: 2048 + n,
  };
}

/** Record one document and build its batch; returns the document and root. */
async function recorded(gw, { build = true } = {}) {
  const document = aDocument();
  await gw.proofs.record(document);
  const batch = build ? await gw.proofs.buildPendingBatch() : null;
  return { document, root: batch ? batch.root : null };
}

const verify = (gw, fileHash) => fetch(`${gw.url}/api/proofs/verify/${fileHash}`);

// --------------------------------------------------------------------- tests

test("a verifier needs no credential, and gets the materials, not just a verdict", async () => {
  const chain = stubChain();
  const gw = await startGateway({ reader: chain });
  try {
    const { document, root } = await recorded(gw);
    chain.findBatch = async () => ({ block: 90, size: 1, txHash: "0x" + "11".repeat(32) });

    // No Authorization header anywhere in this test. That is the point.
    const response = await verify(gw, document.fileHash);
    assert.equal(response.status, 200);
    const body = await response.json();

    // Everything needed to redo the work without trusting this reply.
    assert.equal(body.batch.root, root);
    assert.ok(Array.isArray(body.batch.proof));
    assert.equal(body.batch.onChain.block, 90);
    assert.equal(body.batch.onChain.txHash, "0x" + "11".repeat(32));
    assert.deepEqual(body.chainRead, { contract: CONTRACT, chainId: 31337 });
    assert.ok(body.receipt, "the signed receipt travels with the proof");
    assert.match(body.howToCheck, /Do not take gatewayClaim on trust/);

    // The verdict is present but fenced off as the gateway's own.
    assert.equal(body.gatewayClaim.verified, true);
    assert.deepEqual(body.gatewayClaim.anchoredBy, ["batch"]);
    assert.equal(body.verified, undefined, "no bare verdict at the top level");

    // And the materials really do stand on their own: both checks pass here
    // without the gateway's opinion being consulted.
    const { publicJwk } = await (await fetch(`${gw.url}/api/proofs/key`)).json();
    const checkedReceipt = await verifyReceipt(body.receipt, await importPublicKey(publicJwk));
    assert.equal(checkedReceipt.valid, true);

    const checkedInclusion = await verifyInBatch(
      { ...body.batch, fileHash: document.fileHash, batchRoot: body.batch.root },
      body.batch.root
    );
    assert.equal(checkedInclusion.valid, true);
  } finally {
    await gw.stop();
  }
});

test("the key that signed the receipt travels with it", async () => {
  /*
   * The point of this route is that one request hands a verifier everything
   * they need. A receipt they cannot check the signature on is not that, and
   * telling them to go and fetch the key themselves puts a second round trip
   * in front of the one thing the route exists to make easy.
   *
   * The key served is the one the receipt *names*, not whichever key is
   * current — see the rotation test below for why that distinction is the
   * whole feature.
   */
  const gw = await startGateway();
  try {
    const { document } = await recorded(gw);
    const body = await (await verify(gw, document.fileHash)).json();

    assert.equal(body.receiptKey.kid, body.receipt.statement.kid);

    // Not merely present: it verifies the receipt it arrived with, with
    // nothing else fetched.
    const checked = await verifyReceipt(
      body.receipt,
      await importPublicKey(body.receiptKey.publicJwk)
    );
    assert.equal(checked.valid, true, checked.reason);

    // And it is the same key the keyring serves by name, so a caller who
    // would rather not trust this field can still check it against the route
    // that is the authority on it.
    const served = await (
      await fetch(`${gw.url}/api/proofs/key?kid=${body.receiptKey.kid}`)
    ).json();
    assert.deepEqual(served.publicJwk, body.receiptKey.publicJwk);

    assert.match(body.howToCheck, /receiptKey\.publicJwk/);
  } finally {
    await gw.stop();
  }
});

test("a receipt from before a rotation comes back with the key that verifies it", async () => {
  const keyringPath = scratch("keys.json");
  const dbPath = scratch("proofs.log");

  const original = await generateSigningKey();
  const replacement = await generateSigningKey();

  // Day one: a document is recorded and batched under the original key.
  const before = await createProofService({ ...original.exported, keyringPath, dbPath });
  const document = aDocument();
  const { receipt } = await before.record(document);
  await before.buildPendingBatch();
  before.close();

  // Later: the operator rotates the signing key and restarts.
  const gw = await startGateway({
    proofsOptions: { ...replacement.exported, keyringPath, dbPath },
  });
  try {
    assert.notEqual(gw.proofs.kid, receipt.statement.kid, "a different key signs now");

    const body = await (await verify(gw, document.fileHash)).json();

    // Serving the *current* key here would hand every pre-rotation verifier
    // a key that fails, with the same answer a forgery gets.
    assert.equal(body.receiptKey.kid, receipt.statement.kid);
    assert.notEqual(body.receiptKey.kid, gw.proofs.kid);
    assert.ok(body.receiptKey.retiredAt, "a retired key says when it was retired");

    const checked = await verifyReceipt(
      body.receipt,
      await importPublicKey(body.receiptKey.publicJwk)
    );
    assert.equal(checked.valid, true, checked.reason);
  } finally {
    await gw.stop();
  }
});

test("a chain it cannot reach is never reported as 'not anchored'", async () => {
  const chain = stubChain({ fail: "ECONNREFUSED" });
  const gw = await startGateway({ reader: chain });
  try {
    const { document } = await recorded(gw);

    const response = await verify(gw, document.fileHash);
    assert.equal(response.status, 503, "an unreachable chain is not an answer about the document");
    assert.equal(response.headers.get("retry-after"), "30");

    const body = await response.json();
    assert.equal(body.gatewayClaim.status, "unavailable");
    assert.equal(body.gatewayClaim.verified, false);
    assert.match(body.gatewayClaim.explain, /not a statement that the document is unanchored/);

    // The materials it does have are still there, so a caller with its own
    // RPC endpoint can finish the job.
    assert.ok(body.batch.root);
    assert.ok(body.receipt);
  } finally {
    await gw.stop();
  }
});

test("a batch that is simply not anchored yet says so plainly", async () => {
  const chain = stubChain();
  const gw = await startGateway({ reader: chain });
  try {
    const { document } = await recorded(gw);

    const body = await (await verify(gw, document.fileHash)).json();
    assert.equal(body.gatewayClaim.status, "not-anchored");
    assert.equal(body.gatewayClaim.verified, false);
    assert.equal(body.gatewayClaim.warnings, undefined, "nothing is wrong, it is just early");
  } finally {
    await gw.stop();
  }
});

test("a recorded anchor the chain does not hold is an alarm, not a 'no'", async () => {
  const chain = stubChain();
  const gw = await startGateway({ reader: chain });
  try {
    const { document, root } = await recorded(gw);
    // The gateway recorded a transaction; the contract has never heard of it.
    gw.proofs.recordAnchor(root, { txHash: "0x" + "ab".repeat(32), block: 42 });

    const response = await verify(gw, document.fileHash);
    assert.equal(response.status, 200);
    const body = await response.json();

    assert.equal(body.gatewayClaim.status, "disputed");
    assert.equal(body.gatewayClaim.verified, false);
    assert.equal(body.batch.recorded.txHash, "0x" + "ab".repeat(32));
    assert.match(
      body.gatewayClaim.warnings.join(" "),
      /recorded an anchoring transaction .* does not hold that root/
    );
    assert.match(body.gatewayClaim.warnings.join(" "), /checked that transaction independently/);
  } finally {
    await gw.stop();
  }
});

test("a document registered on-chain by a wallet verifies with no batch at all", async () => {
  // The other anchoring path: no receipt, no batch, one record written from
  // the user's own wallet. A verifier does not know which path was used.
  const document = aDocument();
  const chain = stubChain({
    documents: new Map([
      [
        document.fileHash,
        {
          block: 77,
          timestamp: 1_700_000_000,
          merkleRoot: document.merkleRoot,
          manifestCID: document.manifestCID,
          totalChunks: 3,
          fileSize: document.fileSize,
          encrypted: true,
          exporter: "0x" + "ee".repeat(20),
        },
      ],
    ]),
  });
  const gw = await startGateway({ reader: chain });
  try {
    const body = await (await verify(gw, document.fileHash)).json();

    assert.equal(body.gatewayClaim.verified, true);
    assert.deepEqual(body.gatewayClaim.anchoredBy, ["registration"]);
    assert.equal(body.registration.block, 77);
    assert.equal(body.registration.confirmations, 100 - 77 + 1);
    assert.equal(body.batch, null, "this document was never receipted here");
    assert.equal(body.receipt, null);
  } finally {
    await gw.stop();
  }
});

test("a registration naming a different Merkle root is disputed, not verified", async () => {
  const chain = stubChain();
  const gw = await startGateway({ reader: chain });
  try {
    const { document } = await recorded(gw);
    chain.findDocument = async () => ({
      block: 50,
      timestamp: 1,
      merkleRoot: "0x" + "99".repeat(32), // not the one we receipted
      manifestCID: document.manifestCID,
      totalChunks: 1,
      fileSize: document.fileSize,
      encrypted: true,
      exporter: "0x" + "ee".repeat(20),
    });

    const body = await (await verify(gw, document.fileHash)).json();
    assert.equal(body.gatewayClaim.verified, false);
    assert.equal(body.gatewayClaim.status, "disputed");
    assert.match(body.gatewayClaim.warnings.join(" "), /different Merkle root/);
  } finally {
    await gw.stop();
  }
});

test("a document nobody has heard of is a 404, from either source", async () => {
  const chain = stubChain();
  const gw = await startGateway({ reader: chain });
  try {
    const response = await verify(gw, "0x" + "fe".repeat(32));
    assert.equal(response.status, 404);
    const body = await response.json();
    assert.equal(body.gatewayClaim.status, "unknown");
    assert.match(body.gatewayClaim.explain, /neither this gateway nor the contract/);
  } finally {
    await gw.stop();
  }
});

test("without chain access the gateway says it cannot check, and shows its work", async () => {
  const gw = await startGateway({ reader: null });
  try {
    const { document, root } = await recorded(gw);

    const response = await verify(gw, document.fileHash);
    assert.equal(response.status, 200);
    const body = await response.json();

    assert.equal(body.gatewayClaim.status, "unchecked");
    assert.equal(body.gatewayClaim.verified, false);
    assert.equal(body.batch.root, root, "the proof is still served, to check elsewhere");
    assert.match(body.gatewayClaim.explain, /not configured to read the chain/);
  } finally {
    await gw.stop();
  }
});

test("an anchor is read from the chain once, however many verifiers ask", async () => {
  // The endpoint is unauthenticated and every miss costs an RPC call the
  // operator pays for. Without the cache this is an amplifier pointed at
  // their own quota.
  const chain = stubChain();
  const gw = await startGateway({ reader: chain });
  try {
    const { document, root } = await recorded(gw);
    chain.findBatch = async (asked) => {
      assert.equal(asked, root);
      return { block: 90, size: 1, txHash: "0x" + "11".repeat(32) };
    };

    let reads = 0;
    const counted = chain.findBatch;
    chain.findBatch = async (asked) => {
      reads++;
      return counted(asked);
    };

    for (let i = 0; i < 5; i++) {
      const body = await (await verify(gw, document.fileHash)).json();
      assert.equal(body.gatewayClaim.verified, true);
    }
    assert.equal(reads, 1, "five requests, one chain read");
  } finally {
    await gw.stop();
  }
});

test("public verification is metered separately and much more tightly", async () => {
  const chain = stubChain();
  const gw = await startGateway({
    reader: chain,
    env: { OREOCHAIN_VERIFY_RATE_LIMIT_PER_MINUTE: "60", OREOCHAIN_VERIFY_RATE_LIMIT_BURST: "2" },
  });
  try {
    const { document } = await recorded(gw);

    const statuses = [];
    for (let i = 0; i < 4; i++) {
      statuses.push((await verify(gw, document.fileHash)).status);
    }
    assert.ok(statuses.includes(429), `expected a 429 among ${statuses.join(", ")}`);

    const limited = await verify(gw, document.fileHash);
    assert.equal(limited.status, 429);
    assert.ok(Number(limited.headers.get("retry-after")) >= 1);

    // An upload's bucket is untouched by a scan of the verification endpoint.
    const status = await fetch(`${gw.url}/api/proofs/status`, {
      headers: { Authorization: `Bearer ${KEY}` },
    });
    assert.equal(status.status, 200);
  } finally {
    await gw.stop();
  }
});

test("a chain that disagrees is disputed even when the other path checked out", async () => {
  /*
   * The finding this covers: a valid batch anchor alongside a registration
   * naming a different Merkle root used to come back "verified", with the
   * disagreement demoted to a warning nobody reads. The two records are not
   * describing the same file, and "anchored" is not a useful thing to say
   * about it, whichever half happened to check out.
   */
  const chain = stubChain();
  const gw = await startGateway({ reader: chain });
  try {
    const { document, root } = await recorded(gw);

    chain.findBatch = async () => ({ block: 90, size: 1, txHash: "0x" + "11".repeat(32) });
    chain.findDocument = async () => ({
      block: 60,
      timestamp: 1,
      merkleRoot: "0x" + "77".repeat(32), // not the root we receipted
      manifestCID: document.manifestCID,
      totalChunks: 1,
      fileSize: document.fileSize,
      encrypted: true,
      exporter: "0x" + "ee".repeat(20),
    });

    const body = await (await verify(gw, document.fileHash)).json();

    assert.equal(body.gatewayClaim.verified, false, "a disagreement outranks a confirmation");
    assert.equal(body.gatewayClaim.status, "disputed");
    assert.match(body.gatewayClaim.warnings.join(" "), /different Merkle root/);

    // And the sentence a person reads says so, rather than opening with
    // "This document is anchored".
    assert.match(body.gatewayClaim.explain, /disagrees/);
    assert.doesNotMatch(body.gatewayClaim.explain, /^This document is anchored/);

    // The batch really did check out; that is what makes this worth testing.
    assert.equal(body.batch.root, root);
    assert.equal(body.batch.onChain.block, 90);
    assert.deepEqual(body.gatewayClaim.anchoredBy, ["batch"]);
  } finally {
    await gw.stop();
  }
});

test("a cached anchor cannot outlive the network it was read from", async () => {
  /*
   * An anchor is immutable on the chain that holds it and means nothing on
   * any other. When an RPC endpoint comes to point somewhere else, a cache
   * keyed on the root alone keeps answering from the old network's data for
   * the rest of its lifetime — while the response says it read the new one.
   */
  const chain = stubChain({ chainId: 1 });
  const gw = await startGateway({ reader: chain });
  try {
    const { document } = await recorded(gw);

    let reads = 0;
    chain.findBatch = async () => {
      reads++;
      // Only the first network has ever held this root.
      return (await chain.chainId()) === 1
        ? { block: 90, size: 1, txHash: "0x" + "11".repeat(32) }
        : null;
    };

    const first = await (await verify(gw, document.fileHash)).json();
    assert.equal(first.gatewayClaim.verified, true);
    assert.equal(first.chainRead.chainId, 1);
    assert.equal(reads, 1);

    // The endpoint now answers for a different network entirely.
    chain.setChainId(999);

    const second = await (await verify(gw, document.fileHash)).json();
    assert.equal(reads, 2, "a different network is a cache miss, not a hit");
    assert.equal(second.gatewayClaim.verified, false);
    assert.equal(second.gatewayClaim.status, "not-anchored");

    // The two halves of the answer agree: this is what was read, and it is
    // the network the answer came from.
    assert.equal(second.chainRead.chainId, 999);

    // Going back finds the original answer still valid for that network.
    chain.setChainId(1);
    const third = await (await verify(gw, document.fileHash)).json();
    assert.equal(third.gatewayClaim.verified, true);
    assert.equal(third.chainRead.chainId, 1);
  } finally {
    await gw.stop();
  }
});

test("chain access is configured as a pair or not at all", () => {
  const base = { OREOCHAIN_API_KEYS: KEY, OREOCHAIN_STORAGE: "memory" };

  assert.throws(
    () => loadConfig({ ...base, OREOCHAIN_CHAIN_RPC: "http://127.0.0.1:8545" }),
    /must be set together/
  );
  assert.throws(
    () => loadConfig({ ...base, OREOCHAIN_CONTRACT_ADDRESS: CONTRACT }),
    /must be set together/
  );
  assert.throws(
    () =>
      loadConfig({
        ...base,
        OREOCHAIN_CHAIN_RPC: "http://127.0.0.1:8545",
        OREOCHAIN_CONTRACT_ADDRESS: "0xnope",
      }),
    /must be a 20-byte hex address/
  );

  const config = loadConfig({
    ...base,
    OREOCHAIN_CHAIN_RPC: "http://127.0.0.1:8545",
    OREOCHAIN_CONTRACT_ADDRESS: CONTRACT,
  });
  assert.equal(config.chainRpc, "http://127.0.0.1:8545");
  assert.equal(config.contractAddress, CONTRACT);
});
