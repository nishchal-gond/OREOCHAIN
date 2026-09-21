/**
 * Durable storage for recorded documents and the batches that anchor them.
 *
 * WHY THIS EXISTS
 *
 * Everything the proof service knew used to live in `Map`s. That was fine for
 * the pending queue — losing it loses an anchor, not a document, and you can
 * re-queue. It was not fine for anything already anchored.
 *
 * A Merkle path depends on a document's *index* in its batch. Once a batch root
 * is on-chain, the ordered document list that produced the tree is the only
 * thing that can turn "this root exists" into "your document is in it". Held in
 * memory, that list did not survive a restart — so a document permanently
 * anchored on a public chain became permanently unprovable, while the receipt
 * in the user's hand went on claiming otherwise.
 *
 * WHY A LOG AND NOT SQLITE
 *
 * The plan said SQLite, and for a registry that is normally the right answer.
 * It is not available here: `better-sqlite3@13` requires Node >= 22 and
 * `node:sqlite` does not exist before 22.5, while this package supports Node 18
 * and CI proves it on 18, 20, 22 and 24. Taking SQLite means raising the floor
 * for the whole package — including the core that the browser shares — to gain
 * a query language this workload never uses.
 *
 * So: an append-only log of JSON lines with the index held in memory. It suits
 * the shape of the data exactly. Writes are appends, reads are lookups by
 * primary key, records are a couple of hundred bytes, and there is no query
 * more complicated than "which documents have no batch yet". It adds no
 * dependency and no native build step, and `npm ci` stays a download.
 *
 * The ceiling is real and worth naming: the index is in memory, so this holds
 * millions of documents rather than billions. Everything here is behind a
 * narrow interface for that reason — moving to SQLite or Postgres later means
 * reimplementing this one file, not touching the proof service.
 *
 * DURABILITY
 *
 * A record is appended and fsynced before the call returns, so a receipt is
 * never issued for a document that is not on disk. Each record is one line
 * written in a single write, and a half-written final line — the one thing a
 * crash mid-append can leave — is detected and dropped at load.
 */

import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  existsSync,
  renameSync,
  rmSync,
  truncateSync,
  writeSync,
} from "node:fs";
import { hostname } from "node:os";
import path from "node:path";

/** Bumped only if a record's meaning changes; readers check it. */
export const STORE_VERSION = 1;

const RECORD_DOCUMENT = "doc";
const RECORD_BATCH = "batch";
const RECORD_ANCHOR = "anchor";

export class StoreError extends Error {
  constructor(message) {
    super(message);
    this.name = "StoreError";
  }
}

/**
 * Raised when another process already holds this store.
 *
 * Its own class because the operator response is different from every other
 * store error: nothing here is corrupt, and there is nothing to repair. Either
 * a second replica was started, or a previous process is still running.
 */
export class StoreLockedError extends StoreError {
  constructor(message, holder) {
    super(message);
    this.name = "StoreLockedError";
    this.holder = holder;
  }
}

/**
 * How often a live holder rewrites its heartbeat, and how long a lock may go
 * unrefreshed before it is considered abandoned.
 *
 * The gap between them is five missed renewals. Shorter would risk declaring a
 * briefly stalled process dead — a long GC pause or a slow disk — and two
 * writers is the outcome this whole mechanism exists to avoid. Longer would
 * make a crashed container wait longer to reclaim its own store.
 */
const HEARTBEAT_MS = 2000;
const LEASE_MS = 10000;

/**
 * Take exclusive ownership of a store file, or refuse to start.
 *
 * WHY THIS EXISTS
 *
 * This store is a single appended file with its index in memory. Two processes
 * writing it interleave their appends and neither sees the other's records, so
 * a batch written by one names documents the other cannot produce — an
 * inclusion proof that cannot be rebuilt for a document already anchored on a
 * public chain. That is silent: both processes keep answering, and the damage
 * surfaces much later as a proof that will not verify.
 *
 * Scaling a Deployment to two replicas is a one-line change, so the failure
 * has to be loud at startup rather than discovered in the data.
 *
 * HOW IT TELLS A REPLICA FROM A RESTART
 *
 * The lock records the host and pid that took it.
 *
 * - A different host is another replica. Refuse — always, with no timeout and
 *   no takeover, because there is no safe way to tell "it crashed" from "it is
 *   busy" across machines, and guessing wrong is the corruption this exists to
 *   prevent.
 * - The same host and *our own* pid looks like our own stale lock, and a
 *   restarted container is exactly that: pid 1 again in a pod of the same
 *   name. But two live containers can also both be pid 1 with one hostname —
 *   `docker run --hostname shared` twice against one volume, or hostNetwork
 *   pods sharing an RWX volume — and from inside a PID namespace /proc/1 is
 *   *yourself*, so the neighbour is not observable at all. A dead predecessor
 *   and a live neighbour leave byte-identical lock files, and no function of
 *   identical inputs can separate them. What does separate them is a holder
 *   that keeps changing the file: see the lease below.
 * - The same host and a different pid that is still alive is another process
 *   here — someone started it twice. Refuse.
 * - The same host and a dead pid is a crash. Take it over.
 *
 * KNOWN LIMIT: this is an advisory lock built on exclusive file creation,
 * which NFS does not implement reliably. On NFS-backed storage it may not
 * catch a second replica. The durable fix for running several instances is a
 * store that supports concurrent writers, not a better lock.
 */
const heldInThisProcess = new Set();

function acquireLock(filePath, { host = hostname(), pid = process.pid, now = Date.now } = {}) {
  const lockPath = `${filePath}.lock`;
  const holder = { host, pid, since: new Date(now()).toISOString(), heartbeat: now() };

  /*
   * "Our own pid" is treated as a stale lock below, which is what makes a
   * container restart work. That reasoning does not extend to a second store
   * opened by the code that is already holding this one — same pid, both
   * alive, both appending. Tracked here because no file check can tell the two
   * apart.
   */
  if (heldInThisProcess.has(lockPath)) {
    throw new StoreLockedError(
      `${filePath} is already open in this process. Open one store per path.`,
      { host, pid }
    );
  }

  function write() {
    // wx: create, or fail if it exists. The atomicity of that is the lock, and
    // it holds across containers because it is a property of the inode.
    const fd = openSync(lockPath, "wx");
    try {
      writeSync(fd, JSON.stringify(holder) + "\n");
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }

  /**
   * Refresh the heartbeat in place.
   *
   * This is the only thing that distinguishes a live holder from a dead one
   * when identity cannot: a lock whose timestamp keeps moving is held. Written
   * whole and not fsynced — losing one beat costs nothing, and five in a row
   * is what marks the lock abandoned.
   */
  function beat() {
    try {
      // Written to a sibling and renamed: rename is atomic within a
      // filesystem, so a concurrent reader sees either the old record or the
      // new one, never a half-written line it would have to treat as
      // corruption.
      const staging = `${lockPath}.${pid}.tmp`;
      const fd = openSync(staging, "w");
      try {
        writeSync(fd, JSON.stringify({ ...holder, heartbeat: now() }) + "\n");
      } finally {
        closeSync(fd);
      }
      renameSync(staging, lockPath);
    } catch {
      // A failed beat is not worth crashing the service over; the next one may
      // succeed, and if they all fail the lock ages out, which is safe.
    }
  }

  try {
    write();
  } catch (error) {
    if (error.code !== "EEXIST") throw error;

    let existing;
    try {
      existing = JSON.parse(readFileSync(lockPath, "utf8"));
    } catch {
      // An unreadable lock is not permission to ignore it. Something holds
      // this store and we cannot tell what.
      throw new StoreLockedError(
        `${lockPath} exists but could not be read. Another process may be using ` +
          `${filePath}. Remove the lock file only if you are certain nothing else is running.`,
        null
      );
    }

    if (existing.host !== host) {
      throw new StoreLockedError(
        `${filePath} is held by host "${existing.host}" (pid ${existing.pid}, since ` +
          `${existing.since}). This store has a single writer: two instances appending to it ` +
          "corrupt each other's proofs. Run one instance, or give each its own OREOCHAIN_DB_PATH " +
          "on storage it does not share.",
        existing
      );
    }

    if (existing.pid !== pid && isRunning(existing.pid)) {
      throw new StoreLockedError(
        `${filePath} is already open by pid ${existing.pid} on this host (since ` +
          `${existing.since}). Stop it before starting another.`,
        existing
      );
    }

    /*
     * Same host, same pid. Our own crashed predecessor looks exactly like a
     * live neighbour in another PID namespace that happens to share our
     * hostname and our pid — /proc/1 is ourselves, so isRunning() answers
     * about us and tells us nothing about them.
     *
     * The heartbeat is what separates the two. A holder that is running keeps
     * rewriting it; one that died stopped. So take over only once the lease
     * has plainly lapsed.
     */
    if (existing.pid === pid) {
      if (existing.heartbeat === undefined) {
        /*
         * A lock written before heartbeats existed. It carries no evidence
         * either way, and this is the one branch where guessing wrong means
         * two writers, so it is not guessed. Only reachable once, upgrading
         * across a crash.
         */
        throw new StoreLockedError(
          `${filePath} has a lock from an older version with no heartbeat, so whether its ` +
            "holder is still running cannot be determined. Confirm nothing else is using " +
            `this store, then delete ${lockPath} and start again.`,
          existing
        );
      }

      const age = now() - (Number(existing.heartbeat) || 0);
      if (age < LEASE_MS) {
        throw new StoreLockedError(
          `${filePath} is held by a live process on "${existing.host}" sharing our pid ` +
            `${pid} — its lock was refreshed ${Math.round(age / 1000)}s ago. Two containers ` +
            "with one hostname on a shared volume look identical from inside, so this is " +
            `refused rather than guessed. If that process is gone, retry in ` +
            `${Math.ceil((LEASE_MS - age) / 1000)}s.`,
          existing
        );
      }
    }

    // A dead pid, or a lease nobody has refreshed. Take it over.
    rmSync(lockPath, { force: true });
    write();
  }

  heldInThisProcess.add(lockPath);

  // unref'd: holding the store must not by itself keep the process alive.
  const timer = setInterval(beat, HEARTBEAT_MS);
  if (typeof timer.unref === "function") timer.unref();

  return {
    path: lockPath,
    beat,
    release() {
      clearInterval(timer);
      heldInThisProcess.delete(lockPath);
      rmSync(lockPath, { force: true });
    },
  };
}

function isRunning(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;

  try {
    // Signal 0 checks for the process without touching it. EPERM means it
    // exists and belongs to someone else, which still counts as running.
    process.kill(pid, 0);
  } catch (error) {
    if (error.code !== "EPERM") return false;
    return true;
  }

  // A zombie still has a pid entry, so kill(0) succeeds for a process that has
  // already exited and is only waiting to be reaped. Without this, a
  // supervisor that restarts the gateway faster than it reaps the old one is
  // refused: measured here, a restart 0.5s after SIGKILL failed to start.
  return !isZombie(pid);
}

/** Linux only; anywhere else this cannot be determined and says "not a zombie". */
function isZombie(pid) {
  try {
    return parseProcState(readFileSync(`/proc/${pid}/stat`, "utf8")) === "Z";
  } catch {
    // No /proc, or the entry vanished between the two checks. Either way this
    // says nothing, and "not a zombie" is the conservative answer: it keeps
    // the lock held rather than letting a second writer in.
    return false;
  }
}

/**
 * The state character from a /proc/<pid>/stat line.
 *
 * The format is "pid (comm) state …" and comm is the executable name
 * *unescaped* — it can contain spaces and parentheses, which is why this
 * scans to the final ")" rather than splitting on whitespace. Getting that
 * wrong would misread the state, and reading a live process as a zombie is
 * the direction that matters: it would hand the lock to a second writer.
 */
function parseProcState(stat) {
  const end = stat.lastIndexOf(")");
  if (end === -1) return null;
  return stat.slice(end + 1).trim()[0] || null;
}

/**
 * Read a log back into an index, tolerating a torn final line.
 *
 * @returns {{documents: Map, batches: Map, order: string[], truncateTo: number|null}}
 */
function replay(text) {
  const documents = new Map();
  const batches = new Map();
  const order = [];

  let consumed = 0;
  let truncateTo = null;

  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const isLast = i === lines.length - 1;

    if (line === "") {
      if (!isLast) consumed += 1;
      continue;
    }

    let record;
    try {
      record = JSON.parse(line);
    } catch (error) {
      // Only the final line can legitimately be half-written: a crash between
      // the write and the newline. Anything earlier means the file was edited
      // or corrupted, and silently discarding records is the wrong answer for
      // a proof store.
      if (!isLast) {
        throw new StoreError(
          `log is corrupt at line ${i + 1} (${error.message}) — refusing to start rather than ` +
            "serve an incomplete proof record"
        );
      }
      truncateTo = consumed;
      break;
    }

    applyRecord(record, { documents, batches, order }, i + 1);
    consumed += Buffer.byteLength(line) + 1;
  }

  return { documents, batches, order, truncateTo };
}

function applyRecord(record, index, lineNumber) {
  if (record === null || typeof record !== "object") {
    throw new StoreError(`log line ${lineNumber} is not an object`);
  }
  if (record.v !== undefined && record.v !== STORE_VERSION) {
    throw new StoreError(
      `log line ${lineNumber} was written by store version ${record.v}, this is ${STORE_VERSION}`
    );
  }

  switch (record.t) {
    case RECORD_DOCUMENT: {
      if (!index.documents.has(record.fileHash)) index.order.push(record.fileHash);
      index.documents.set(record.fileHash, {
        fileHash: record.fileHash,
        merkleRoot: record.merkleRoot,
        fileSize: record.fileSize,
        manifestCID: record.manifestCID,
        receipt: record.receipt,
        recordedAt: record.recordedAt,
        batchRoot: null,
        batchIndex: null,
      });
      return;
    }

    case RECORD_BATCH: {
      index.batches.set(record.root, {
        root: record.root,
        size: record.documents.length,
        builtAt: record.builtAt,
        documents: record.documents,
        txHash: null,
        block: null,
      });
      // Stamping the documents here is what makes "pending" mean "has no
      // batch" rather than needing a queue of its own — there is no window in
      // which a document is in both or neither.
      record.documents.forEach((fileHash, batchIndex) => {
        const document = index.documents.get(fileHash);
        if (document) Object.assign(document, { batchRoot: record.root, batchIndex });
      });
      return;
    }

    case RECORD_ANCHOR: {
      const batch = index.batches.get(record.root);
      if (batch) Object.assign(batch, { txHash: record.txHash, block: record.block });
      return;
    }

    default:
      throw new StoreError(`log line ${lineNumber} has unknown record type "${record.t}"`);
  }
}

/**
 * Open (or create) a store.
 *
 * @param {object} options
 * @param {string} options.path log file; ":memory:" keeps everything in RAM
 * @param {boolean} [options.fsync] flush each append to disk before returning
 */
export function openStore({
  path: filePath,
  fsync = true,
  lock = true,
  readOnly = false,
  now = () => Date.now(),
} = {}) {
  const inMemory = !filePath || filePath === ":memory:";

  let documents = new Map();
  let batches = new Map();
  let order = [];
  let handle = null;
  let held = null;
  let tornTail = false;

  if (!inMemory) {
    /*
     * A reader takes no lock, creates nothing and repairs nothing.
     *
     * All three matter for the one thing that opens a store read-only: the
     * integrity checker, which has to be safe to point at a live store while
     * the gateway is writing it, and at a restored copy on a read-only mount.
     * Taking the lock would stop the gateway; truncating a torn trailing line
     * would be a write into a file the checker was only asked to look at; and
     * creating the file would turn "this backup is not where you think it is"
     * into an empty store that passes.
     */
    if (!readOnly) {
      mkdirSync(path.dirname(path.resolve(filePath)), { recursive: true });

      // Before reading a byte: this store has exactly one writer, and a second
      // one is a startup failure rather than something to discover in the data.
      if (lock) held = acquireLock(path.resolve(filePath), { now });
    } else if (!existsSync(filePath)) {
      throw new StoreError(`no proof store at ${filePath}`);
    }

    if (existsSync(filePath)) {
      const replayed = replay(readFileSync(filePath, "utf8"));
      ({ documents, batches, order } = replayed);
      tornTail = replayed.truncateTo !== null;

      // Drop a torn trailing line so the next append starts on a clean
      // boundary. Leaving it would make every subsequent read fail.
      if (!readOnly && replayed.truncateTo !== null) truncateSync(filePath, replayed.truncateTo);
    }

    if (!readOnly) handle = openSync(filePath, "a");
  }

  function refuseWrite() {
    throw new StoreError("this store is open read-only");
  }

  function append(record) {
    if (inMemory) return;
    const line = JSON.stringify({ v: STORE_VERSION, ...record }) + "\n";
    writeSync(handle, line);
    // The receipt is a promise in writing, so it must not be issued before the
    // document backing it is durable.
    if (fsync) fsyncSync(handle);
  }

  return {
    /**
     * Persist a recorded document.
     *
     * @returns {{stored: boolean, document: object}} stored is false when the
     *   document was already here — the same file registered twice is one
     *   record and one anchor.
     */
    recordDocument(document, receipt) {
      if (readOnly) refuseWrite();
      const existing = documents.get(document.fileHash);
      if (existing) return { stored: false, document: existing };

      const record = {
        t: RECORD_DOCUMENT,
        fileHash: document.fileHash,
        merkleRoot: document.merkleRoot,
        fileSize: document.fileSize,
        manifestCID: document.manifestCID,
        receipt,
        recordedAt: now(),
      };
      append(record);
      applyRecord(record, { documents, batches, order }, 0);

      return { stored: true, document: documents.get(document.fileHash) };
    },

    /** Documents with no batch yet, oldest first. */
    pendingDocuments(limit = Infinity) {
      const pending = [];
      for (const fileHash of order) {
        if (pending.length >= limit) break;
        const document = documents.get(fileHash);
        if (document && document.batchRoot === null) pending.push(document);
      }
      return pending;
    },

    /** Record a built batch and stamp its documents, in one durable append. */
    saveBatch(batch) {
      if (readOnly) refuseWrite();
      if (batches.has(batch.root)) {
        throw new StoreError(`batch ${batch.root} is already recorded`);
      }
      const record = {
        t: RECORD_BATCH,
        root: batch.root,
        builtAt: now(),
        documents: batch.documents.map((document) => document.fileHash),
      };
      append(record);
      applyRecord(record, { documents, batches, order }, 0);
      return batches.get(batch.root);
    },

    /** Note where a batch root landed on-chain. */
    anchorBatch(root, { txHash, block }) {
      if (readOnly) refuseWrite();
      if (!batches.has(root)) throw new StoreError(`no such batch ${root}`);
      const record = { t: RECORD_ANCHOR, root, txHash, block };
      append(record);
      applyRecord(record, { documents, batches, order }, 0);
      return batches.get(root);
    },

    findDocument: (fileHash) => documents.get(String(fileHash).toLowerCase()) || null,
    findBatch: (root) => batches.get(root) || null,

    /**
     * Everything, in log order, for a reader that has to walk the whole store.
     *
     * Only the integrity checker (server/integrity.mjs) needs these: nothing
     * serving a request should ever be iterating the entire log. They are
     * separate from stats() because a count cannot be cross-referenced.
     */
    allBatches: () => [...batches.values()],
    allDocuments: () => order.map((fileHash) => documents.get(fileHash)).filter(Boolean),

    /**
     * Batches that were built but never anchored, oldest first.
     *
     * The anchoring worker is a separate process and can die between building
     * a batch and submitting it. Without this, that batch would sit in the log
     * for ever: its documents are already stamped, so they never come back as
     * pending, and nothing else would ever look at it again. Insertion order
     * is log order, so the oldest unanchored batch is the first one out.
     */
    unanchoredBatches(limit = Infinity) {
      const out = [];
      for (const batch of batches.values()) {
        if (batch.txHash !== null) continue;
        out.push(batch);
        if (out.length >= limit) break;
      }
      return out;
    },

    stats() {
      let pending = 0;
      for (const document of documents.values()) if (document.batchRoot === null) pending++;
      return { documents: documents.size, batches: batches.size, pending };
    },

    /**
     * Whether the last line of the log was incomplete when it was read.
     *
     * Expected, not damage: an append is one write and a copy taken mid-write
     * catches half of it. A writer drops the fragment; a reader reports it, so
     * an operator checking a backup knows the copy is one record short rather
     * than wondering.
     */
    tornTail: () => tornTail,

    /** Refresh the lock's heartbeat now; the interval does this on its own. */
    beat() {
      if (held !== null) held.beat();
    },

    close() {
      if (handle !== null) {
        closeSync(handle);
        handle = null;
      }
      if (held !== null) {
        held.release();
        held = null;
      }
    },
  };
}

export const _internals = { replay, acquireLock, isRunning, isZombie, parseProcState, RECORD_DOCUMENT, RECORD_BATCH, RECORD_ANCHOR };
