/**
 * Batch anchoring and signed receipts — the two mechanisms that let a user
 * register a document without holding a wallet or paying gas.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { randomBytes, to0x } from "../js/core/bytes.js";
import { sha256 } from "../js/core/chunker.js";
import {
  assertAnchorableDocument,
  buildBatch,
  createBatchQueue,
  documentLeaf,
  documentPreimage,
  MAX_BATCH_SIZE,
  proveInBatch,
  verifyInBatch,
} from "../js/core/anchor.js";
import {
  canonicalize,
  generateSigningKey,
  issueReceipt,
  keyId,
  receiptMatchesAnchor,
  RECEIPT_VERSION,
  verifyReceipt,
} from "../js/core/receipt.js";

/** Distinct, well-formed test documents. Hex-encoding the index keeps the
 *  hashes unique for any n — a naive repeat/slice scheme collides. */
function doc(n) {
  return {
    fileHash: "0x" + n.toString(16).padStart(64, "0"),
    merkleRoot: "0x" + (n + 0x1000000).toString(16).padStart(64, "0"),
    fileSize: 1000 + n,
    manifestCID: `bafyManifest${n}`,
  };
}

// ------------------------------------------------------------------ batching

test("a batch produces one root committing to every document", async () => {
  const batch = await buildBatch([doc(1), doc(2), doc(3)]);
  assert.match(batch.root, /^0x[0-9a-f]{64}$/);
  assert.equal(batch.size, 3);
  assert.equal(batch.leaves.length, 3);
});

test("every document in a batch gets a working inclusion proof", async () => {
  for (const count of [1, 2, 3, 5, 8, 17, 64]) {
    const documents = Array.from({ length: count }, (_, i) => doc(i));
    const batch = await buildBatch(documents);

    for (const document of documents) {
      const inclusion = await proveInBatch(batch, document.fileHash);
      const result = await verifyInBatch(inclusion, batch.root);
      assert.ok(result.valid, `proof failed for ${document.fileHash} in a batch of ${count}`);
    }
  }
});

test("proof size grows logarithmically, so large batches stay cheap to prove", async () => {
  const small = await buildBatch(Array.from({ length: 8 }, (_, i) => doc(i)));
  const large = await buildBatch(Array.from({ length: 4096 }, (_, i) => doc(i)));

  const smallProof = await proveInBatch(small, doc(0).fileHash);
  const largeProof = await proveInBatch(large, doc(0).fileHash);

  assert.equal(smallProof.proof.length, 3); // log2(8)
  assert.equal(largeProof.proof.length, 12); // log2(4096)
  // 512 times the documents, four extra sibling hashes.
  assert.ok(largeProof.proof.length < 16);
});

test("a proof against the wrong batch root fails", async () => {
  const batch = await buildBatch([doc(1), doc(2), doc(3)]);
  const inclusion = await proveInBatch(batch, doc(2).fileHash);

  const result = await verifyInBatch(inclusion, "0x" + "11".repeat(32));
  assert.equal(result.valid, false);
  assert.match(result.reason, /does not reach the batch root/);
});

test("a document from another batch cannot borrow this batch's proof", async () => {
  const batchA = await buildBatch([doc(1), doc(2), doc(3)]);
  const batchB = await buildBatch([doc(7), doc(8), doc(9)]);

  const inclusion = await proveInBatch(batchA, doc(2).fileHash);
  assert.equal((await verifyInBatch(inclusion, batchB.root)).valid, false);
});

test("altering the document in a proof invalidates it", async () => {
  // The leaf is recomputed from the document's fields, so a proof cannot be
  // reused for a document it does not describe.
  const batch = await buildBatch([doc(1), doc(2), doc(3)]);
  const inclusion = await proveInBatch(batch, doc(2).fileHash);

  inclusion.document = { ...inclusion.document, manifestCID: "bafySubstituted" };
  assert.equal((await verifyInBatch(inclusion, batch.root)).valid, false);
});

test("a proof whose document disagrees with its own fileHash is rejected", async () => {
  const batch = await buildBatch([doc(1), doc(2)]);
  const inclusion = await proveInBatch(batch, doc(1).fileHash);
  inclusion.fileHash = doc(2).fileHash;

  const result = await verifyInBatch(inclusion, batch.root);
  assert.equal(result.valid, false);
});

test("duplicate documents in a batch are rejected", async () => {
  await assert.rejects(() => buildBatch([doc(1), doc(1)]), /appears twice/);
});

test("an empty or oversized batch is rejected", async () => {
  await assert.rejects(() => buildBatch([]), /at least one document/);
  await assert.rejects(() => buildBatch(null), /at least one document/);
  const tooMany = Array.from({ length: MAX_BATCH_SIZE + 1 }, (_, i) => ({
    ...doc(0),
    fileHash: "0x" + i.toString(16).padStart(64, "0"),
  }));
  await assert.rejects(() => buildBatch(tooMany), /at most/);
});

test("the document preimage is fixed-layout and rejects malformed input", async () => {
  const preimage = documentPreimage(doc(1));
  // 32 + 32 + 8 + len("bafyManifest1")
  assert.equal(preimage.length, 32 + 32 + 8 + 13);

  assert.throws(() => documentPreimage({ ...doc(1), fileHash: "nope" }), /fileHash must be/);
  assert.throws(() => documentPreimage({ ...doc(1), merkleRoot: "0x12" }), /merkleRoot must be/);
  assert.throws(() => documentPreimage({ ...doc(1), fileSize: -1 }), /fileSize must be/);
  assert.throws(() => documentPreimage({ ...doc(1), manifestCID: "" }), /manifestCID must be/);
});

test("fileSize is encoded big-endian, matching abi.encodePacked", () => {
  const preimage = documentPreimage({ ...doc(1), fileSize: 1 });
  assert.deepEqual(Array.from(preimage.subarray(64, 72)), [0, 0, 0, 0, 0, 0, 0, 1]);
});

test("the leaf is the domain-separated hash of the preimage", async () => {
  const document = doc(1);
  const expected = to0x(
    await sha256(new Uint8Array([0x00, ...documentPreimage(document)]))
  );
  assert.equal(to0x(await documentLeaf(document)), expected);
});

// --------------------------------------------------------------- batch queue

test("the queue flushes on size", () => {
  const queue = createBatchQueue({ maxSize: 3, maxAgeMs: 1e9 });
  queue.add(doc(1));
  queue.add(doc(2));
  assert.equal(queue.shouldFlush(), false);
  queue.add(doc(3));
  assert.equal(queue.shouldFlush(), true);
  assert.equal(queue.drain().length, 3);
  assert.equal(queue.size(), 0);
});

test("the queue flushes on age, so a quiet period still anchors", () => {
  let now = 0;
  const queue = createBatchQueue({ maxSize: 1000, maxAgeMs: 60000, now: () => now });

  queue.add(doc(1));
  assert.equal(queue.shouldFlush(), false);

  now = 60000;
  assert.equal(queue.shouldFlush(), true);
});

test("draining a count takes the oldest entries and leaves the rest", () => {
  const queue = createBatchQueue({ maxSize: 10 });
  for (let i = 1; i <= 5; i++) queue.add(doc(i));

  // What a caller peeks is what a later drain(n) removes, so a batch can be
  // built first and the queue trimmed only once it succeeded.
  const peeked = queue.peek().slice(0, 3);
  queue.add(doc(6)); // arrives mid-build
  queue.drain(3);

  assert.deepEqual(
    queue.peek().map((entry) => entry.fileHash),
    [doc(4), doc(5), doc(6)].map((entry) => entry.fileHash)
  );
  assert.deepEqual(
    peeked.map((entry) => entry.fileHash),
    [doc(1), doc(2), doc(3)].map((entry) => entry.fileHash)
  );
});

test("a peek that is never drained leaves the queue untouched", () => {
  const queue = createBatchQueue({ maxSize: 10 });
  for (let i = 1; i <= 3; i++) queue.add(doc(i));

  // The batch step reads through peek() precisely so a failure costs nothing.
  // Draining first was how one unbatchable document took the whole queue out.
  const documents = queue.peek();
  documents[0] = doc(99); // a caller mutating its copy must not reach the queue

  assert.equal(queue.size(), 3);
  assert.equal(queue.peek()[0].fileHash, doc(1).fileHash);
});

test("a partially drained queue keeps asking to flush on age", () => {
  let now = 0;
  const queue = createBatchQueue({ maxSize: 1000, maxAgeMs: 60000, now: () => now });
  queue.add(doc(1));
  queue.add(doc(2));

  now = 1000;
  queue.drain(1);
  assert.equal(queue.shouldFlush(), false, "the remainder should not flush immediately");

  now = 61000;
  assert.equal(queue.shouldFlush(), true, "the remainder should still age out");
});

test("a document that cannot be anchored is rejected before it is queued", () => {
  assert.throws(() => assertAnchorableDocument({ ...doc(1), fileHash: "0xNOPE" }), /fileHash must be/);
  assert.throws(() => assertAnchorableDocument({ ...doc(1), merkleRoot: "0x12" }), /merkleRoot must be/);
  assert.throws(() => assertAnchorableDocument({ ...doc(1), fileSize: undefined }), /fileSize must be/);
  assert.throws(() => assertAnchorableDocument({ ...doc(1), manifestCID: "" }), /manifestCID must be/);
  assert.throws(() => assertAnchorableDocument(null), /must be an object/);

  // Uppercase hex is a real submission shape and is not anchorable as-is —
  // callers normalise before they get here.
  assert.throws(
    () => assertAnchorableDocument({ ...doc(1), fileHash: `0x${"AB".repeat(32)}` }),
    /fileHash must be/
  );

  const valid = doc(1);
  assert.equal(assertAnchorableDocument(valid), valid, "a valid document passes through");
});

test("the queue ignores duplicates and is empty-safe", () => {
  const queue = createBatchQueue({ maxSize: 10 });
  assert.equal(queue.add(doc(1)).queued, true);
  assert.equal(queue.add(doc(1)).queued, false);
  assert.equal(queue.size(), 1);

  queue.drain();
  assert.equal(queue.shouldFlush(), false, "an empty queue should never ask to flush");
});

// ------------------------------------------------------------------ receipts

test("a receipt verifies against the issuing key", async () => {
  const keys = await generateSigningKey();
  const receipt = await issueReceipt(
    { ...doc(1), totalChunks: 4, encrypted: true, suite: "aes-256-gcm" },
    keys.privateKey
  );

  const result = await verifyReceipt(receipt, keys.publicKey);
  assert.ok(result.valid, result.reason);
  assert.equal(result.statement.version, RECEIPT_VERSION);
  assert.equal(result.statement.fileHash, doc(1).fileHash);
});

test("a receipt does not verify against a different key", async () => {
  const issuer = await generateSigningKey();
  const impostor = await generateSigningKey();

  const receipt = await issueReceipt({ ...doc(1), totalChunks: 1 }, issuer.privateKey);
  const result = await verifyReceipt(receipt, impostor.publicKey);

  assert.equal(result.valid, false);
  assert.match(result.reason, /signature does not verify/);
});

test("tampering with any field invalidates the receipt", async () => {
  const keys = await generateSigningKey();
  const base = await issueReceipt({ ...doc(1), totalChunks: 4 }, keys.privateKey);

  for (const field of ["fileHash", "merkleRoot", "manifestCID", "fileSize", "issuedAt"]) {
    const tampered = {
      ...base,
      statement: { ...base.statement, [field]: field === "fileSize" ? 999999 : "0xchanged" },
    };
    const result = await verifyReceipt(tampered, keys.publicKey);
    assert.equal(result.valid, false, `tampering with ${field} was not detected`);
  }
});

test("a malformed receipt is rejected without throwing", async () => {
  const keys = await generateSigningKey();
  for (const bad of [null, {}, { statement: {} }, { signature: "x" }, "string"]) {
    const result = await verifyReceipt(bad, keys.publicKey);
    assert.equal(result.valid, false);
  }
});

test("a receipt with a bad signature encoding is rejected", async () => {
  const keys = await generateSigningKey();
  const receipt = await issueReceipt({ ...doc(1), totalChunks: 1 }, keys.privateKey);
  receipt.signature = "!!!not base64!!!";

  const result = await verifyReceipt(receipt, keys.publicKey);
  assert.equal(result.valid, false);
});

test("a receipt dated in the future is rejected", async () => {
  const keys = await generateSigningKey();
  const receipt = await issueReceipt({ ...doc(1), totalChunks: 1 }, keys.privateKey, {
    now: () => new Date(Date.now() + 86400000),
  });

  const result = await verifyReceipt(receipt, keys.publicKey);
  assert.equal(result.valid, false);
  assert.match(result.reason, /dated in the future/);
});

test("a receipt older than the accepted window is rejected when a window is set", async () => {
  const keys = await generateSigningKey();
  const receipt = await issueReceipt({ ...doc(1), totalChunks: 1 }, keys.privateKey, {
    now: () => new Date(Date.now() - 7200000),
  });

  assert.equal((await verifyReceipt(receipt, keys.publicKey)).valid, true, "no window means no expiry");
  const windowed = await verifyReceipt(receipt, keys.publicKey, { maxAgeMs: 3600000 });
  assert.equal(windowed.valid, false);
  assert.match(windowed.reason, /older than the accepted window/);
});

test("issuing a receipt requires the fields it commits to", async () => {
  const keys = await generateSigningKey();
  await assert.rejects(
    () => issueReceipt({ merkleRoot: "0x1", manifestCID: "x" }, keys.privateKey),
    /requires fileHash/
  );
});

test("canonical JSON is key-order independent", () => {
  // Signatures cover bytes; two orderings of the same object must serialise
  // identically or a valid signature fails to verify.
  assert.equal(canonicalize({ b: 1, a: 2 }), canonicalize({ a: 2, b: 1 }));
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalize({ n: [3, { z: 1, y: 2 }] }), '{"n":[3,{"y":2,"z":1}]}');
  assert.equal(canonicalize({ a: undefined, b: 1 }), '{"b":1}');
});

test("a key id is short, stable and not the key itself", async () => {
  const keys = await generateSigningKey();
  const first = await keyId(keys.publicKey);
  const second = await keyId(keys.publicKey);

  assert.equal(first, second);
  assert.equal(first.length, 16);

  const other = await generateSigningKey();
  assert.notEqual(first, await keyId(other.publicKey));
});

// ------------------------------------------------------------- cross-checks

test("a receipt and an anchor must describe the same document", async () => {
  const keys = await generateSigningKey();
  const documents = [doc(1), doc(2), doc(3)];
  const batch = await buildBatch(documents);

  const receipt = await issueReceipt({ ...documents[1], totalChunks: 2 }, keys.privateKey);
  const inclusion = await proveInBatch(batch, documents[1].fileHash);

  assert.equal(receiptMatchesAnchor(receipt, inclusion).consistent, true);
});

test("a service that anchors something other than what it receipted is caught", async () => {
  const keys = await generateSigningKey();
  const batch = await buildBatch([doc(1), doc(2)]);

  // Receipt says document 1; the anchor proof is for document 2.
  const receipt = await issueReceipt({ ...doc(1), totalChunks: 1 }, keys.privateKey);
  const inclusion = await proveInBatch(batch, doc(2).fileHash);

  const result = receiptMatchesAnchor(receipt, inclusion);
  assert.equal(result.consistent, false);
  assert.match(result.reason, /fileHash differs/);
});

test("the full no-wallet flow: store, receipt, batch, anchor, prove", async () => {
  const keys = await generateSigningKey();
  const kid = await keyId(keys.publicKey);

  // 1. Documents are stored through the day. Each user gets a receipt at once —
  //    no wallet, no gas, no waiting for a block.
  const queue = createBatchQueue({ maxSize: 5, maxAgeMs: 3600000 });
  const receipts = [];

  for (let i = 0; i < 5; i++) {
    const document = { ...doc(i), totalChunks: 3, encrypted: true, suite: "aes-256-gcm" };
    receipts.push(await issueReceipt(document, keys.privateKey, { kid }));
    queue.add(document);
  }

  // 2. The operator anchors the whole batch with ONE transaction.
  assert.equal(queue.shouldFlush(), true);
  const batch = await buildBatch(queue.drain());

  // 3. Every user can now prove their document independently.
  for (let i = 0; i < 5; i++) {
    const receiptResult = await verifyReceipt(receipts[i], keys.publicKey);
    assert.ok(receiptResult.valid, `receipt ${i}: ${receiptResult.reason}`);

    const inclusion = await proveInBatch(batch, doc(i).fileHash);
    const anchorResult = await verifyInBatch(inclusion, batch.root);
    assert.ok(anchorResult.valid, `anchor ${i}`);

    assert.equal(receiptMatchesAnchor(receipts[i], inclusion).consistent, true);
  }
});
