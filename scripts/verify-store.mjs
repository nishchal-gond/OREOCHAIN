#!/usr/bin/env node
/**
 * Check a proof store — or a backup of one — against itself.
 *
 *   npm run verify-store                        # $OREOCHAIN_DB_PATH
 *   npm run verify-store -- /backups/proofs.log # a restored copy
 *   npm run verify-store -- --structural        # skip the rehash
 *   npm run verify-store -- --json              # for a monitoring check
 *
 * Run it after every restore, before pointing a gateway at the result. The
 * gateway runs the same check at startup and refuses a damaged store, but by
 * then the restore has already been declared done; this is how you find out
 * while the old copy is still around.
 *
 * Safe against a live store: it takes no lock, opens no write handle and
 * repairs nothing. The worst it can see on a running gateway is a half-written
 * final line, which it reports rather than removes.
 *
 * Exit codes: 0 intact, 1 damaged, 2 could not be read.
 */

import { checkStore, describeReport } from "../server/integrity.mjs";
import { openStore } from "../server/store.mjs";

const args = process.argv.slice(2);
const json = args.includes("--json");
const depth = args.includes("--structural") ? "structural" : "full";
const paths = args.filter((arg) => !arg.startsWith("--"));

if (args.includes("--help") || args.includes("-h")) {
  console.log("usage: verify-store [path] [--structural] [--json]");
  process.exit(0);
}
if (paths.length > 1) {
  console.error("verify-store checks one store at a time");
  process.exit(2);
}

const path = paths[0] || process.env.OREOCHAIN_DB_PATH;
if (!path || path === ":memory:") {
  console.error(
    "no store to check: pass a path, or set OREOCHAIN_DB_PATH to the file the gateway uses"
  );
  process.exit(2);
}

let store;
try {
  store = openStore({ path, readOnly: true });
} catch (error) {
  console.error(`cannot read ${path}: ${error.message}`);
  process.exit(2);
}

const tornTail = store.tornTail();

let report;
try {
  report = await checkStore(store, { depth });
} finally {
  store.close();
}

if (json) {
  console.log(JSON.stringify({ path, tornTail, ...report }, null, 2));
} else {
  console.log(path);
  for (const line of describeReport(report)) console.log(line);
  if (tornTail) {
    console.log(
      "note: the last line was incomplete and was ignored. Normal for a copy taken while " +
        "the gateway was writing; the record it belonged to is not in this copy."
    );
  }
  if (!report.ok) {
    console.log("");
    console.log(
      "This store cannot prove what it claims. Restore it from a backup rather than " +
        "serving from it: the damaged batches' documents are anchored on-chain and their " +
        "proofs can only be rebuilt from the records that are missing here."
    );
  }
}

process.exit(report.ok ? 0 : 1);
