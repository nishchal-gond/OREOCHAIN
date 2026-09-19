/**
 * The proof store, and the property it exists for: a document anchored on-chain
 * stays provable across a restart.
 *
 * These run against a real file in a temporary directory rather than a mock,
 * because what is being tested is durability — whether the bytes are on disk
 * when the call returns, and whether a fresh process can read them back. A
 * mocked filesystem would assert nothing.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { openStore, StoreError, STORE_VERSION } from "../server/store.mjs";
import { createProofService } from "../server/proofs.mjs";
import { verifyInBatch } from "../js/core/anchor.js";
import { generateSigningKey } from "../js/core/receipt.js";

function tempDir() {
  const dir = mkdtempSync(path.join(tmpdir(), "oreochain-store-"));
  test.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function doc(n) {
  return {
    fileHash: "0x" + n.toString(16).padStart(64, "0"),
    merkleRoot: "0x" + (n + 0x1000000).toString(16).padStart(64, "0"),
    fileSize: 1000 + n,
    manifestCID: `bafyManifest${n}`,
  };
}

// --------------------------------------------------------------------- store

test("a recorded document is on disk by the time record() returns", () => {
  const file = path.join(tempDir(), "proofs.log");
  const store = openStore({ path: file });

  store.recordDocument(doc(1), { statement: {}, signature: "sig" });

  // Read the file directly, without going through the store: this is the
  // property a receipt depends on, so it must hold outside this process.
  const lines = readFileSync(file, "utf8").trim().split("\n");
  assert.equal(lines.length, 1);
  assert.equal(JSON.parse(lines[0]).fileHash, doc(1).fileHash);
  store.close();
});

test("a reopened store sees everything the previous one wrote", () => {
  const file = path.join(tempDir(), "proofs.log");

  const first = openStore({ path: file });
  for (let i = 1; i <= 3; i++) first.recordDocument(doc(i), { signature: `sig${i}` });
  first.close();

  const second = openStore({ path: file });
  assert.equal(second.stats().documents, 3);
  assert.equal(second.stats().pending, 3);
  assert.equal(second.findDocument(doc(2).fileHash).manifestCID, "bafyManifest2");
  second.close();
});

test("the same document recorded twice is one record and one anchor", () => {
  const file = path.join(tempDir(), "proofs.log");
  const store = openStore({ path: file });

  assert.equal(store.recordDocument(doc(1), { signature: "a" }).stored, true);
  assert.equal(store.recordDocument(doc(1), { signature: "b" }).stored, false);

  assert.equal(store.stats().documents, 1);
  assert.equal(readFileSync(file, "utf8").trim().split("\n").length, 1);
  store.close();
});

test("saving a batch marks its documents, so pending means unanchored", () => {
  const store = openStore({ path: ":memory:" });
  for (let i = 1; i <= 3; i++) store.recordDocument(doc(i), { signature: "s" });

  assert.equal(store.pendingDocuments().length, 3);

  store.saveBatch({
    root: "0x" + "ab".repeat(32),
    documents: [doc(1), doc(2)],
  });

  assert.deepEqual(
    store.pendingDocuments().map((d) => d.fileHash),
    [doc(3).fileHash]
  );
  assert.equal(store.findDocument(doc(1).fileHash).batchIndex, 0);
  assert.equal(store.findDocument(doc(2).fileHash).batchIndex, 1);
  assert.equal(store.findDocument(doc(3).fileHash).batchRoot, null);
});

test("pending documents come back oldest first, which is the batch order", () => {
  const store = openStore({ path: ":memory:" });
  for (const i of [5, 2, 9, 1]) store.recordDocument(doc(i), { signature: "s" });

  assert.deepEqual(
    store.pendingDocuments().map((d) => d.manifestCID),
    ["bafyManifest5", "bafyManifest2", "bafyManifest9", "bafyManifest1"]
  );
});

test("a crash mid-append costs the torn line and nothing before it", () => {
  const file = path.join(tempDir(), "proofs.log");

  const first = openStore({ path: file });
  for (let i = 1; i <= 3; i++) first.recordDocument(doc(i), { signature: "s" });
  first.close();

  // A process killed between the write and the newline leaves exactly this.
  appendFileSync(file, '{"v":1,"t":"doc","fileHash":"0xdead');

  const second = openStore({ path: file });
  assert.equal(second.stats().documents, 3, "an intact record was lost");

  // The log is usable again, not permanently broken by the stub.
  second.recordDocument(doc(4), { signature: "s" });
  second.close();

  const third = openStore({ path: file });
  assert.equal(third.stats().documents, 4);
  third.close();
});

test("corruption before the last line refuses to start rather than serving a hole", () => {
  const file = path.join(tempDir(), "proofs.log");
  writeFileSync(file, 'not json\n{"v":1,"t":"doc","fileHash":"0x01"}\n');

  // Silently skipping a record would mean a batch naming a document the store
  // cannot produce — a proof that cannot be rebuilt, discovered much later.
  assert.throws(() => openStore({ path: file }), StoreError);
});

test("a log from a future store version is refused", () => {
  const file = path.join(tempDir(), "proofs.log");
  writeFileSync(file, JSON.stringify({ v: STORE_VERSION + 1, t: "doc", fileHash: "0x01" }) + "\n");
  assert.throws(() => openStore({ path: file }), /store version/);
});

test("an unknown record type is refused rather than ignored", () => {
  const file = path.join(tempDir(), "proofs.log");
  writeFileSync(file, JSON.stringify({ v: STORE_VERSION, t: "who-knows" }) + "\n");
  assert.throws(() => openStore({ path: file }), /unknown record type/);
});

// ----------------------------------------------------- the property that counts

test("an anchored document is still provable after a restart", async () => {
  const file = path.join(tempDir(), "proofs.log");
  const keys = await generateSigningKey();
  const documents = Array.from({ length: 6 }, (_, i) => doc(i + 1));

  // Session one: record, batch, anchor — then the process ends.
  const before = await createProofService({ ...keys.exported, dbPath: file });
  for (const document of documents) await before.record(document);
  const batch = await before.buildPendingBatch();
  before.recordAnchor(batch.root, { txHash: "0x" + "fe".repeat(32), block: 1234 });
  const proofBefore = await before.proofFor(doc(3).fileHash);
  before.close();

  assert.ok(proofBefore, "no proof even before the restart");

  // Session two: a cold start with nothing but the log on disk. This is what
  // used to return null forever, for a document already anchored on-chain.
  const after = await createProofService({ ...keys.exported, dbPath: file });
  const proofAfter = await after.proofFor(doc(3).fileHash);

  assert.ok(proofAfter, "an anchored document lost its proof across a restart");
  assert.equal(proofAfter.batchRoot, batch.root);
  assert.deepEqual(proofAfter.proof, proofBefore.proof);

  // And it still verifies against the root that went on-chain.
  const result = await verifyInBatch(proofAfter, batch.root);
  assert.ok(result.valid, result.reason);

  // The transaction is carried through, so a verifier can find the root.
  assert.equal(proofAfter.txHash, "0x" + "fe".repeat(32));
  assert.equal(proofAfter.block, 1234);
  after.close();
});

test("every document in a restarted batch proves, not just one", async () => {
  const file = path.join(tempDir(), "proofs.log");
  const keys = await generateSigningKey();
  const documents = Array.from({ length: 9 }, (_, i) => doc(i + 1));

  const before = await createProofService({ ...keys.exported, dbPath: file });
  for (const document of documents) await before.record(document);
  const batch = await before.buildPendingBatch();
  before.close();

  const after = await createProofService({ ...keys.exported, dbPath: file });
  for (const document of documents) {
    const proof = await after.proofFor(document.fileHash);
    assert.ok(proof, `no proof for ${document.manifestCID}`);
    assert.ok((await verifyInBatch(proof, batch.root)).valid, `${document.manifestCID} failed`);
  }
  after.close();
});

test("pending documents survive a restart and anchor afterwards", async () => {
  const file = path.join(tempDir(), "proofs.log");
  const keys = await generateSigningKey();

  const before = await createProofService({ ...keys.exported, dbPath: file });
  for (let i = 1; i <= 4; i++) await before.record(doc(i));
  before.close(); // killed before anything was batched

  const after = await createProofService({ ...keys.exported, dbPath: file });
  assert.equal(after.status().pending, 4, "pending documents were lost");

  const batch = await after.buildPendingBatch();
  assert.equal(batch.size, 4);
  assert.ok(await after.proofFor(doc(1).fileHash));
  after.close();
});

test("a document is never receipted unless it was stored", async () => {
  const keys = await generateSigningKey();
  const failing = {
    recordDocument() {
      throw new Error("disk is full");
    },
    stats: () => ({ documents: 0, batches: 0, pending: 0 }),
    pendingDocuments: () => [],
    findDocument: () => null,
    findBatch: () => null,
    close() {},
  };

  const proofs = await createProofService({ ...keys.exported, store: failing });
  // The caller gets an error, not a signed promise about a document that was
  // never written down.
  await assert.rejects(() => proofs.record(doc(1)), /disk is full/);
});

test("a batch whose stored order does not rebuild its root is refused", async () => {
  const keys = await generateSigningKey();
  const store = openStore({ path: ":memory:" });
  const proofs = await createProofService({ ...keys.exported, store });

  await proofs.record(doc(1));
  await proofs.record(doc(2));
  const batch = await proofs.buildPendingBatch();

  // Corrupt the stored order behind the service's back. Serving a proof from a
  // list that no longer rebuilds the anchored root would be worse than serving
  // none: it would look valid and prove the wrong thing.
  store.findBatch(batch.root).documents.reverse();

  await assert.rejects(() => proofs.proofFor(doc(1).fileHash), /does not match the stored root/);
});

// --------------------------------------------------------------- proof shape

test("proofs are derived, so the log stays a record of documents not paths", async () => {
  const file = path.join(tempDir(), "proofs.log");
  const keys = await generateSigningKey();

  const proofs = await createProofService({ ...keys.exported, dbPath: file });
  for (let i = 1; i <= 4; i++) await proofs.record(doc(i));
  await proofs.buildPendingBatch();
  assert.ok(await proofs.proofFor(doc(2).fileHash));
  proofs.close();

  // A stored proof is a second copy of what the batch already determines, and
  // two copies can disagree. Only the order is written down.
  const log = readFileSync(file, "utf8");
  assert.ok(!log.includes('"side"'), "a proof path was written to the log");
  assert.ok(log.includes('"t":"batch"'));
});
