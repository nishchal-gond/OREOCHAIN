/**
 * Does the proof store still say what it said?
 *
 * The store is the one piece of state a deployment cannot recreate. A document
 * anchored on a public chain is provable only through the ordered document
 * list behind its batch root: lose that list, or change it, and the anchor
 * stays on-chain for ever while the proof it commits to can no longer be
 * built. There is no re-derivation, no upstream copy, no "just re-run it".
 *
 * So the log has to be checkable, not merely parseable. Reading it back into
 * an index (server/store.mjs) proves the lines are well-formed JSON in a shape
 * this version understands. It does not prove the contents still agree with
 * each other, and that is exactly what goes wrong in the cases worth catching:
 *
 *   - a backup copied mid-file, or restored short, loses whole records. The
 *     surviving lines parse perfectly; a batch simply names documents that are
 *     no longer there.
 *   - a file edited by hand — the documented reorg recovery asks an operator
 *     to delete an anchor line — takes out one line too many.
 *   - bit rot, or a partial restore from two different snapshots, leaves a
 *     batch whose stored root no longer matches the documents under it.
 *
 * Rebuilding every batch root from the stored document order is what turns all
 * three into a definite answer, because the root is a hash of exactly that
 * order. If the rebuilt root matches, the batch is byte-for-byte the batch
 * that was anchored, whatever else happened to the file. If it does not, no
 * proof from it should ever be served.
 *
 * The rebuild is the same one server/proofs.mjs does lazily on the first proof
 * request for a batch — this runs it over the whole store, on demand and at
 * startup, so damage is found by the operator rather than by the user who
 * needed the proof.
 */

import { buildBatch } from "../js/core/anchor.js";

/** What can be wrong. Kinds are stable strings: they go into logs and reports. */
export const PROBLEM = {
  /** A batch names a document that is not in the store. Records were lost. */
  MISSING_DOCUMENT: "missing_document",
  /** A batch's documents no longer hash to its recorded root. */
  ROOT_MISMATCH: "root_mismatch",
  /** A batch's documents cannot be hashed at all: malformed fields. */
  UNBUILDABLE_BATCH: "unbuildable_batch",
  /** A document is stamped into a batch the store does not have. */
  MISSING_BATCH: "missing_batch",
  /** A document's position in its batch is not where the batch lists it. */
  WRONG_BATCH_INDEX: "wrong_batch_index",
};

/** How much work to do. Full rehashes every batch; structural only cross-references. */
export const DEPTH = { FULL: "full", STRUCTURAL: "structural" };

/**
 * Check a store against itself.
 *
 * Read-only in the strongest sense: it opens nothing, writes nothing and
 * repairs nothing. A checker that "fixed" a proof store would be rewriting
 * history to match whatever survived, which is the one thing that must never
 * happen here — the recovery is a restore from backup, by a human who knows
 * which copy is good.
 *
 * @param {object} store an open store (server/store.mjs)
 * @param {object} [options]
 * @param {string} [options.depth] DEPTH.FULL or DEPTH.STRUCTURAL
 * @param {function} [options.now]
 * @returns {Promise<{ok:boolean, depth:string, checked:object, problems:Array, damagedRoots:string[], durationMs:number}>}
 */
export async function checkStore(store, { depth = DEPTH.FULL, now = () => Date.now() } = {}) {
  if (depth !== DEPTH.FULL && depth !== DEPTH.STRUCTURAL) {
    throw new Error(`unknown check depth "${depth}"`);
  }

  const startedAt = now();
  const problems = [];
  const damaged = new Set();

  const batches = store.allBatches();
  const documents = store.allDocuments();

  let anchored = 0;
  let rebuilt = 0;

  for (const batch of batches) {
    if (batch.txHash !== null) anchored += 1;

    const members = [];
    let complete = true;

    for (let position = 0; position < batch.documents.length; position++) {
      const fileHash = batch.documents[position];
      const document = store.findDocument(fileHash);
      if (!document) {
        complete = false;
        problems.push({
          kind: PROBLEM.MISSING_DOCUMENT,
          root: batch.root,
          fileHash,
          detail: `batch names document ${fileHash}, which is not in the store`,
        });
        damaged.add(batch.root);
        continue;
      }

      /*
       * The batch lists this document here; the document has to agree that it
       * is here. They come apart when one document ends up in two batch
       * records — the second stamp wins, so the first batch still lists it
       * while the document points elsewhere. Both roots then rebuild
       * perfectly, and a proof built from the first batch would be offered
       * with a position the document does not have.
       */
      if (document.batchRoot !== batch.root || document.batchIndex !== position) {
        problems.push({
          kind: PROBLEM.WRONG_BATCH_INDEX,
          root: batch.root,
          fileHash,
          detail:
            `batch lists document ${fileHash} at position ${position}, but the document ` +
            (document.batchRoot === null
              ? "is not in any batch"
              : `records itself at position ${document.batchIndex} of batch ${document.batchRoot}`),
        });
        damaged.add(batch.root);
      }

      members.push({
        fileHash: document.fileHash,
        merkleRoot: document.merkleRoot,
        fileSize: document.fileSize,
        manifestCID: document.manifestCID,
      });
    }

    // A batch missing a member cannot be rebuilt into anything meaningful:
    // hashing the survivors would produce a different root and report a
    // mismatch, which is true but hides the actual fault.
    if (!complete || depth !== DEPTH.FULL) continue;

    let candidate;
    try {
      candidate = await buildBatch(members);
    } catch (error) {
      problems.push({
        kind: PROBLEM.UNBUILDABLE_BATCH,
        root: batch.root,
        detail: `batch cannot be rebuilt: ${error.message}`,
      });
      damaged.add(batch.root);
      continue;
    }

    rebuilt += 1;
    if (candidate.root !== batch.root) {
      problems.push({
        kind: PROBLEM.ROOT_MISMATCH,
        root: batch.root,
        rebuiltRoot: candidate.root,
        detail:
          `batch rebuilds to ${candidate.root}, not the recorded ${batch.root} — ` +
          "its documents are not the documents that were anchored",
      });
      damaged.add(batch.root);
    }
  }

  /*
   * The other half of the cross-reference. A document knowing about a batch
   * the store does not have means the batch record was lost while the
   * documents it covered survived — the anchor is on-chain and the ordered
   * list that makes it provable is gone.
   *
   * The reverse direction, a batch listing a document that disagrees about
   * where it sits, is checked above: that is the side a proof is built from.
   */
  for (const document of documents) {
    if (document.batchRoot === null) continue;
    if (store.findBatch(document.batchRoot)) continue;

    problems.push({
      kind: PROBLEM.MISSING_BATCH,
      fileHash: document.fileHash,
      root: document.batchRoot,
      detail: `document is in batch ${document.batchRoot}, which is not in the store`,
    });
    damaged.add(document.batchRoot);
  }

  return {
    ok: problems.length === 0,
    depth,
    checked: {
      documents: documents.length,
      batches: batches.length,
      anchoredBatches: anchored,
      rebuiltBatches: rebuilt,
    },
    problems,
    damagedRoots: [...damaged],
    durationMs: now() - startedAt,
  };
}

/**
 * The report as lines a human reads in a terminal or a log.
 *
 * Every problem is listed rather than summarised: an operator deciding whether
 * to restore needs to see whether one batch is damaged or a thousand.
 */
export function describeReport(report) {
  const { documents, batches, anchoredBatches } = report.checked;
  const lines = [
    `${documents} document(s), ${batches} batch(es), ${anchoredBatches} anchored — ` +
      `${report.depth} check in ${report.durationMs}ms`,
  ];

  if (report.ok) {
    lines.push("no problems found");
    return lines;
  }

  lines.push(`${report.problems.length} problem(s) across ${report.damagedRoots.length} batch(es):`);
  for (const problem of report.problems) lines.push(`  [${problem.kind}] ${problem.detail}`);
  return lines;
}
