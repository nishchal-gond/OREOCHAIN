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
import { mkdtempSync, readFileSync, rmSync, writeFileSync, appendFileSync, existsSync } from "node:fs";
import os, { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { spawn, spawnSync } from "node:child_process";

import {
  openStore,
  StoreError,
  StoreLockedError,
  STORE_VERSION,
  _internals as storeInternals,
} from "../server/store.mjs";
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

// ------------------------------------------------------- one writer, or none

test("a second store on the same file refuses to open", () => {
  const file = path.join(tempDir(), "proofs.log");
  const first = openStore({ path: file });

  // Two appenders interleave their records and neither sees the other's, so a
  // batch written by one names documents the other cannot produce. That is a
  // proof that will not rebuild, discovered long after the root is on-chain.
  assert.throws(() => openStore({ path: file }), StoreLockedError);

  first.close();
  // Released on close, so a restart is not blocked by its predecessor.
  const second = openStore({ path: file });
  second.close();
});

test("a lock from another host is refused, with no takeover", () => {
  const file = path.join(tempDir(), "proofs.log");
  const store = openStore({ path: file });
  store.close();

  // What a second Kubernetes replica leaves: a different pod name. There is no
  // safe way to tell "that replica crashed" from "that replica is busy" across
  // machines, so this never expires and never takes over.
  writeFileSync(
    `${path.resolve(file)}.lock`,
    JSON.stringify({ host: "oreochain-gateway-7f9c-2", pid: 1, since: "2026-09-19T08:00:00Z" })
  );

  assert.throws(() => openStore({ path: file }), StoreLockedError);

  // And it stays refused: no timeout, no second chance, however old the lock.
  assert.throws(() => openStore({ path: file }), StoreLockedError);
});

test("the refusal names the other holder and what to do about it", () => {
  const file = path.join(tempDir(), "proofs.log");
  writeFileSync(
    `${path.resolve(file)}.lock`,
    JSON.stringify({ host: "gateway-replica-2", pid: 1, since: "2026-09-19T08:00:00Z" })
  );

  const error = (() => {
    try {
      openStore({ path: file });
    } catch (e) {
      return e;
    }
  })();

  assert.ok(error instanceof StoreLockedError);
  assert.match(error.message, /gateway-replica-2/);
  assert.match(error.message, /single writer/);
  assert.match(error.message, /OREOCHAIN_DB_PATH/);
  assert.equal(error.holder.host, "gateway-replica-2");
});

test("a container restart takes over its own lock instead of refusing", () => {
  const file = path.join(tempDir(), "proofs.log");

  // A pod keeps its name across a container restart and the process is pid 1
  // again, so the lock it left behind looks exactly like its own. Treating
  // that as a conflict would refuse to start after every crash.
  writeFileSync(
    `${path.resolve(file)}.lock`,
    JSON.stringify({
      host: os.hostname(),
      pid: process.pid,
      since: "2026-09-19T08:00:00Z",
    })
  );

  const store = openStore({ path: file });
  store.recordDocument(doc(1), { signature: "s" });
  store.close();
});

test("a lock left by a dead process on this host is taken over", () => {
  const file = path.join(tempDir(), "proofs.log");

  // A pid that has certainly exited: a child we just reaped.
  const dead = spawnSync(process.execPath, ["-e", "process.exit(0)"]);
  assert.equal(dead.status, 0);

  writeFileSync(
    `${path.resolve(file)}.lock`,
    JSON.stringify({ host: os.hostname(), pid: dead.pid, since: "2026-09-19T08:00:00Z" })
  );

  const store = openStore({ path: file });
  store.close();
});

test("a live process on this host holds the store against a second start", () => {
  const file = path.join(tempDir(), "proofs.log");

  // Our own parent is alive and is not us — the shape of someone running the
  // gateway twice on one machine.
  writeFileSync(
    `${path.resolve(file)}.lock`,
    JSON.stringify({ host: os.hostname(), pid: process.ppid, since: "2026-09-19T08:00:00Z" })
  );

  assert.throws(() => openStore({ path: file }), /already open by pid/);
});

test("an unreadable lock is refused rather than ignored", () => {
  const file = path.join(tempDir(), "proofs.log");
  writeFileSync(`${path.resolve(file)}.lock`, "not json at all");

  // Something holds this store and we cannot tell what. Assuming it is safe is
  // the one answer that risks the corruption the lock exists to prevent.
  assert.throws(() => openStore({ path: file }), StoreLockedError);
});

test("a real second process is refused, not just a synthetic lock file", async () => {
  const file = path.join(tempDir(), "proofs.log");
  const held = openStore({ path: file });

  // The lock is advisory and built on exclusive file creation, so what matters
  // is whether a genuinely separate process is stopped. A fabricated lock file
  // cannot show that.
  const child = spawnSync(
    process.execPath,
    [
      "-e",
      `import("${pathToFileURL(path.resolve("server/store.mjs")).href}")
         .then((m) => { m.openStore({ path: ${JSON.stringify(file)} }); console.log("OPENED"); })
         .catch((e) => { console.log(e.name); });`,
    ],
    { encoding: "utf8" }
  );

  assert.equal(child.stdout.trim(), "StoreLockedError", `child said: ${child.stdout}${child.stderr}`);
  held.close();
});

test("the lock can be turned off where a caller knows it is alone", () => {
  const file = path.join(tempDir(), "proofs.log");
  const store = openStore({ path: file, lock: false });
  store.close();
  assert.equal(existsSync(`${path.resolve(file)}.lock`), false);
});

test("the /proc state parser survives an executable name full of punctuation", () => {
  // comm is unescaped in /proc/<pid>/stat, so a process named "my (weird) app"
  // puts parentheses and spaces inside the field. Splitting on whitespace
  // reads the wrong character — and reading a live process as a zombie is the
  // direction that matters: it would hand the store to a second writer.
  const { parseProcState } = storeInternals;

  assert.equal(parseProcState("123 (node) S 1 123 123 0 -1 4194304"), "S");
  assert.equal(parseProcState("123 (my (weird) app) R 1 123"), "R");
  assert.equal(parseProcState("123 (a b) c) Z 1 123"), "Z");
  assert.equal(parseProcState("nonsense"), null);
});

test("a live process is never mistaken for a zombie", { skip: !existsSync("/proc") }, () => {
  // This process is demonstrably running. A false "zombie" here is what would
  // let a second replica take a held lock.
  assert.equal(storeInternals.isZombie(process.pid), false);
  assert.equal(storeInternals.isRunning(process.pid), true);
});

test("a pid that no longer exists is not running", () => {
  const dead = spawnSync(process.execPath, ["-e", "process.exit(0)"]);
  assert.equal(dead.status, 0);
  // spawnSync reaps, so this pid is fully gone rather than a zombie. A real
  // zombie cannot be manufactured portably — every shell tried here reaps
  // promptly — so the zombie path is covered by the parser tests above and was
  // verified by hand against a killed gateway.
  assert.equal(storeInternals.isRunning(dead.pid), false);
});
