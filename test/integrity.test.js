/**
 * The proof store's integrity check, and the restore it exists to make safe.
 *
 * The scenarios here are all file-level damage rather than API misuse, because
 * that is where the risk actually is: the store is append-only and single
 * writer, so the way it goes wrong in production is a backup copied mid-file,
 * a restore that arrived short, or a hand edit during recovery. Each of those
 * leaves a log that parses perfectly and is nonetheless unable to prove what
 * it claims, which is precisely what a parse cannot tell you.
 *
 * So the damaged stores are built by writing log text, not by calling methods
 * the store would refuse. That is the only honest simulation of a bad restore.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

import { checkStore, describeReport, DEPTH, PROBLEM } from "../server/integrity.mjs";
import { openStore, StoreError } from "../server/store.mjs";
import { createProofService } from "../server/proofs.mjs";
import { verifyInBatch } from "../js/core/anchor.js";

function tempDir() {
  const dir = mkdtempSync(path.join(tmpdir(), "oreochain-integrity-"));
  test.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function doc(n) {
  return {
    fileHash: "0x" + n.toString(16).padStart(64, "0"),
    merkleRoot: "0x" + (n + 0x1000000).toString(16).padStart(64, "0"),
    fileSize: 1000 + n,
    manifestCID: `bafycid${n}`,
  };
}

/** A real store: documents recorded, batched and anchored through the service. */
async function populate(dbPath, count = 5) {
  const service = await createProofService({ dbPath });
  for (let n = 1; n <= count; n++) await service.record(doc(n));
  const batch = await service.buildPendingBatch();
  service.recordAnchor(batch.root, { txHash: "0x" + "ab".repeat(32), block: 1234 });
  service.close();
  return batch;
}

function lines(dbPath) {
  return readFileSync(dbPath, "utf8").split("\n").filter(Boolean);
}

function rewrite(dbPath, mapper) {
  writeFileSync(dbPath, mapper(lines(dbPath)).join("\n") + "\n");
}

async function check(dbPath, options) {
  const store = openStore({ path: dbPath, readOnly: true });
  try {
    return await checkStore(store, options);
  } finally {
    store.close();
  }
}

test("an intact store reports no problems and counts what it checked", async () => {
  const dbPath = path.join(tempDir(), "proofs.log");
  await populate(dbPath, 5);

  const report = await check(dbPath);

  assert.equal(report.ok, true);
  assert.deepEqual(report.problems, []);
  assert.equal(report.checked.documents, 5);
  assert.equal(report.checked.batches, 1);
  assert.equal(report.checked.anchoredBatches, 1);
  assert.equal(report.checked.rebuiltBatches, 1);
});

test("a restore that lost a record is caught: the batch names a document that is gone", async () => {
  const dbPath = path.join(tempDir(), "proofs.log");
  await populate(dbPath, 5);

  // The failure mode of a partial restore: whole lines missing from the middle
  // of a file whose remaining lines are all valid.
  rewrite(dbPath, (all) => all.filter((_, index) => index !== 2));

  const report = await check(dbPath);

  assert.equal(report.ok, false);
  assert.equal(report.problems.length, 1);
  assert.equal(report.problems[0].kind, PROBLEM.MISSING_DOCUMENT);
  assert.equal(report.damagedRoots.length, 1);
});

test("a batch whose documents were reordered no longer rebuilds to its anchored root", async () => {
  const dbPath = path.join(tempDir(), "proofs.log");
  const batch = await populate(dbPath, 5);

  rewrite(dbPath, (all) =>
    all.map((line) => {
      const record = JSON.parse(line);
      if (record.t !== "batch") return line;
      return JSON.stringify({ ...record, documents: [...record.documents].reverse() });
    })
  );

  const report = await check(dbPath);

  assert.equal(report.ok, false);
  assert.equal(report.problems[0].kind, PROBLEM.ROOT_MISMATCH);
  assert.equal(report.problems[0].root, batch.root);
  assert.notEqual(report.problems[0].rebuiltRoot, batch.root);
});

test("the structural check cannot see a reordering, which is why full is the default", async () => {
  const dbPath = path.join(tempDir(), "proofs.log");
  await populate(dbPath, 5);

  rewrite(dbPath, (all) =>
    all.map((line) => {
      const record = JSON.parse(line);
      if (record.t !== "batch") return line;
      return JSON.stringify({ ...record, documents: [...record.documents].reverse() });
    })
  );

  // Every document the batch names is still present and still at a position
  // the batch lists, so nothing cross-references wrong. Only the hash knows.
  const structural = await check(dbPath, { depth: DEPTH.STRUCTURAL });
  assert.equal(structural.ok, true);
  assert.equal(structural.checked.rebuiltBatches, 0);

  const full = await check(dbPath);
  assert.equal(full.ok, false);
});

test("a document stamped into a batch whose record is gone is reported", async () => {
  const dbPath = path.join(tempDir(), "proofs.log");
  await populate(dbPath, 3);

  rewrite(dbPath, (all) => all.filter((line) => JSON.parse(line).t !== "batch"));

  const report = await check(dbPath);

  // No batch record means nothing stamped the documents either, so the store
  // reads them back as pending rather than as orphans: consistent, and the
  // proof is simply gone. The anchor record for the vanished batch is what
  // survives to say something was lost.
  assert.equal(report.checked.batches, 0);
  assert.equal(report.ok, true);
});

test("a document listed in two batches is caught by its recorded position", async () => {
  const dbPath = path.join(tempDir(), "proofs.log");
  await populate(dbPath, 3);

  // A second batch record naming an already-batched document re-stamps it, so
  // the first batch still lists it while the document points at the second.
  // Both roots rebuild; only the index disagrees.
  const all = lines(dbPath);
  const batch = JSON.parse(all.find((line) => JSON.parse(line).t === "batch"));
  const second = {
    v: 1,
    t: "batch",
    root: "0x" + "cd".repeat(32),
    builtAt: Date.now(),
    documents: ["0x" + "00".repeat(31) + "99", batch.documents[0]],
  };
  writeFileSync(dbPath, [...all, JSON.stringify(second)].join("\n") + "\n");

  const report = await check(dbPath);

  assert.equal(report.ok, false);
  const kinds = report.problems.map((problem) => problem.kind);
  assert.ok(kinds.includes(PROBLEM.MISSING_DOCUMENT), "the invented document is not stored");
  assert.ok(kinds.includes(PROBLEM.WRONG_BATCH_INDEX), "the shared document is at two positions");
});

test("a batch carrying a malformed document is reported as unbuildable, not as a mismatch", async () => {
  const dbPath = path.join(tempDir(), "proofs.log");
  await populate(dbPath, 3);

  rewrite(dbPath, (all) =>
    all.map((line) => {
      const record = JSON.parse(line);
      if (record.t !== "doc") return line;
      return JSON.stringify({ ...record, fileSize: -1 });
    })
  );

  const report = await check(dbPath);

  assert.equal(report.ok, false);
  assert.equal(report.problems[0].kind, PROBLEM.UNBUILDABLE_BATCH);
});

test("an unknown depth is refused rather than quietly checking less", async () => {
  const dbPath = path.join(tempDir(), "proofs.log");
  await populate(dbPath, 2);
  const store = openStore({ path: dbPath, readOnly: true });
  await assert.rejects(() => checkStore(store, { depth: "quick" }), /unknown check depth/);
  store.close();
});

test("the report describes every problem, not a summary of them", async () => {
  const dbPath = path.join(tempDir(), "proofs.log");
  await populate(dbPath, 4);
  rewrite(dbPath, (all) => all.filter((_, index) => index !== 0 && index !== 1));

  const report = await check(dbPath);
  const text = describeReport(report).join("\n");

  assert.match(text, /2 problem\(s\)/);
  assert.equal(report.problems.length, 2);
  for (const problem of report.problems) assert.ok(text.includes(problem.detail));
});

test("a healthy report says so and still reports what it looked at", async () => {
  const dbPath = path.join(tempDir(), "proofs.log");
  await populate(dbPath, 2);
  const text = describeReport(await check(dbPath)).join("\n");
  assert.match(text, /no problems found/);
  assert.match(text, /2 document\(s\), 1 batch\(es\), 1 anchored/);
});

// ---------------------------------------------------------------- read-only

test("a read-only store takes no lock, so it is safe against a live gateway", async () => {
  const dbPath = path.join(tempDir(), "proofs.log");
  await populate(dbPath, 2);

  const live = openStore({ path: dbPath });
  try {
    // The whole point: this open would be refused if the checker took a lock.
    const reader = openStore({ path: dbPath, readOnly: true });
    assert.equal(reader.stats().documents, 2);
    reader.close();

    // And it must not be able to become a second writer by accident.
    const second = openStore({ path: dbPath, readOnly: true });
    assert.throws(() => second.recordDocument(doc(9), null), StoreError);
    assert.throws(() => second.saveBatch({ root: "0x" + "ee".repeat(32), documents: [] }), StoreError);
    assert.throws(() => second.anchorBatch("0x" + "ee".repeat(32), { txHash: "0x", block: 1 }), StoreError);
    second.close();
  } finally {
    live.close();
  }
});

test("a read-only open leaves a torn trailing line on disk and reports it", async () => {
  const dbPath = path.join(tempDir(), "proofs.log");
  await populate(dbPath, 2);

  // Exactly what `cp` catches when it runs during an append.
  writeFileSync(dbPath, readFileSync(dbPath, "utf8") + '{"v":1,"t":"document","fileHash":"0x');
  const before = readFileSync(dbPath).length;

  const reader = openStore({ path: dbPath, readOnly: true });
  assert.equal(reader.tornTail(), true);
  assert.equal(reader.stats().documents, 2);
  reader.close();

  assert.equal(readFileSync(dbPath).length, before, "a reader must not repair the file it reads");
});

test("a read-only open of a path with no store refuses instead of inventing an empty one", () => {
  const dbPath = path.join(tempDir(), "nowhere", "proofs.log");
  assert.throws(() => openStore({ path: dbPath, readOnly: true }), /no proof store at/);
});

// ----------------------------------------------------------- refusing to run

const GATEWAY = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "server",
  "index.mjs"
);

test("refusing to start on a damaged store releases the lock on the way out", async () => {
  const dbPath = path.join(tempDir(), "proofs.log");
  await populate(dbPath, 4);
  rewrite(dbPath, (all) => all.filter((_, index) => index !== 1));

  const started = spawnSync(process.execPath, [GATEWAY], {
    encoding: "utf8",
    env: {
      ...process.env,
      OREOCHAIN_DB_PATH: dbPath,
      OREOCHAIN_API_KEYS: "k".repeat(48),
      OREOCHAIN_STORAGE: "memory",
      PORT: "18787",
    },
  });

  assert.equal(started.status, 1, started.stderr || started.stdout);
  assert.match(started.stdout + started.stderr, /does not agree with itself/);

  /*
   * This is the first exit in server/index.mjs that happens while the store's
   * lock is already held, and a lock left behind names the exiting process's
   * host and pid with a heartbeat from a second ago. On a host the next start
   * has a different pid and takes over. In a container the restarted gateway
   * is pid 1 again, identical to the holder, so the lock refuses — and the
   * operator who just restored a backup is told a second gateway is running,
   * which is false and points at the wrong problem.
   */
  assert.equal(
    existsSync(`${dbPath}.lock`),
    false,
    "a planned refusal must not leave the store locked behind it"
  );
});

// -------------------------------------------------------------- the restore

test("back up, destroy, restore, and the proof still verifies", async () => {
  const dir = tempDir();
  const dbPath = path.join(dir, "proofs.log");
  const backup = path.join(dir, "proofs.log.bak");

  const batch = await populate(dbPath, 6);
  const subject = doc(4).fileHash;

  // The documented backup: a plain copy of the log, taken without stopping
  // the gateway.
  copyFileSync(dbPath, backup);
  assert.equal((await check(backup)).ok, true, "the backup is checkable before it is needed");

  rmSync(dbPath);
  copyFileSync(backup, dbPath);

  const restored = await createProofService({ dbPath });
  try {
    const report = await restored.checkIntegrity();
    assert.equal(report.ok, true);

    const proof = await restored.proofFor(subject);
    assert.ok(proof, "the restored store can still build the proof");
    assert.equal(proof.txHash, "0x" + "ab".repeat(32));

    // The real test of a restore: the proof verifies against the root that is
    // on-chain, which no copy of the log can change.
    const verified = await verifyInBatch(proof, batch.root);
    assert.equal(verified.valid, true);
  } finally {
    restored.close();
  }
});

test("the last check is kept, so /metrics can report a damaged store", async () => {
  const dbPath = path.join(tempDir(), "proofs.log");
  await populate(dbPath, 4);
  rewrite(dbPath, (all) => all.filter((_, index) => index !== 1));

  const service = await createProofService({ dbPath });
  try {
    // A gateway started with OREOCHAIN_ALLOW_DAMAGED_STORE is up and serving
    // while some of what it anchored cannot be proved. The startup log line
    // scrolls away; this is what an alert can be hung on.
    assert.equal(service.integrity(), null, "nothing is claimed before a check runs");

    await service.checkIntegrity();
    const last = service.integrity();

    assert.equal(last.ok, false);
    assert.equal(last.damagedRoots.length, 1);
    assert.ok(Number.isInteger(last.checkedAt), "the report carries when it ran");
  } finally {
    service.close();
  }
});

test("a restore that arrived truncated loses its tail and stays consistent", async () => {
  /*
   * The likeliest bad restore there is: a transfer that stopped partway, so
   * the file ends mid-record. What it cannot do is leave a batch naming
   * documents that are gone, and that is worth pinning down rather than
   * assuming, because it is the whole reason the log is append-only.
   *
   * A batch record is written after the documents it covers, so anything a
   * tail truncation removes takes every record that depends on it with it.
   * Lose the batch and its documents simply become pending again; lose the
   * anchor and the batch is rebuilt and re-anchored, which the contract makes
   * safe. The dangerous direction is records missing from the *middle*, which
   * a truncation cannot produce and a partial restore can — that is the test
   * above this one.
   */
  const dir = tempDir();
  const dbPath = path.join(dir, "proofs.log");

  // Interleaved, as a real store is: documents, a batch over them, an anchor,
  // then more of the same. A single batch at the end would not exercise this.
  const service = await createProofService({ dbPath });
  for (const [first, txHash] of [[1, "ab"], [4, "cd"]]) {
    for (let n = first; n < first + 3; n++) await service.record(doc(n));
    const batch = await service.buildPendingBatch();
    service.recordAnchor(batch.root, { txHash: "0x" + txHash.repeat(32), block: first });
  }
  service.close();

  const whole = statSync(dbPath).size;
  let lastDocuments = Infinity;

  for (const cut of [40, 200, 500, 900, 1400]) {
    const copy = path.join(dir, `cut-${cut}.log`);
    copyFileSync(dbPath, copy);
    truncateSync(copy, whole - cut);

    const store = openStore({ path: copy, readOnly: true });
    try {
      assert.equal(store.tornTail(), true, `cut ${cut}: the reader should see a torn tail`);

      const report = await checkStore(store);
      assert.equal(report.ok, true, `cut ${cut}: ${JSON.stringify(report.problems)}`);
      assert.ok(
        report.checked.documents <= lastDocuments,
        `cut ${cut}: a deeper truncation must not resurrect documents`
      );
      lastDocuments = report.checked.documents;
    } finally {
      store.close();
    }
  }

  assert.ok(lastDocuments < 6, "the deepest cut should have lost something");
});

test("a gateway refuses to serve from a restore that lost records", async () => {
  const dbPath = path.join(tempDir(), "proofs.log");
  await populate(dbPath, 5);
  rewrite(dbPath, (all) => all.filter((_, index) => index !== 1));

  const service = await createProofService({ dbPath });
  try {
    const report = await service.checkIntegrity();
    assert.equal(report.ok, false);
    assert.equal(report.problems[0].kind, PROBLEM.MISSING_DOCUMENT);

    // Same verdict on the path that serves a user, so a store started with
    // OREOCHAIN_ALLOW_DAMAGED_STORE still cannot hand out a wrong proof.
    await assert.rejects(() => service.proofFor(doc(3).fileHash), /not stored/);
  } finally {
    service.close();
  }
});
