/**
 * Write the key-derivation numbers into the documentation from the code.
 *
 *     npm run kdf-docs            rewrite the generated regions
 *     npm run kdf-docs -- --check fail if any of them is out of date
 *
 * WHY THIS EXISTS
 *
 * The Argon2id profile is defined once, in js/core/kdf.js. Before this script
 * it was also written out by hand in the example config, the worker's header
 * comment, two documents, the Readme and the test assertions — so raising it in
 * PR #7 touched twelve files, and any change that updated only kdf.js left the
 * documentation making false claims about what the code does. Prose that states
 * a security parameter wrongly is worse than prose that omits it: a reader
 * checking whether the memory cost is adequate has no reason to distrust it.
 *
 * Two ways out of that were available. A test that fails when the numbers drift
 * keeps the documentation honest but still leaves a defaults change as a
 * six-file edit, which is the thing that went wrong. Generating the numbers
 * makes it a one-place edit, and `--check` in the test suite then also covers
 * the case where someone edits the profile and forgets to run this. So: both,
 * with generation as the primary mechanism (test/docs-kdf.test.js runs the
 * check). It follows the same shape as `npm run abi`, which already generates
 * js/contract-abi.js from the Solidity source.
 *
 * WHAT IS AND IS NOT GENERATED
 *
 * Only the numbers that describe *what master ships today*. The change history
 * in docs/SEALING.md §4 is deliberately left alone: it records what each past
 * release chose, and those numbers must stay as they are however the defaults
 * move afterwards. Every generated span is marked in the source with
 * `<!-- kdf:id -->` … `<!-- /kdf:id -->`, which renders as nothing.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  ARGON2ID_DEFAULTS,
  ARGON2ID_PROFILE,
  PBKDF2_DEFAULTS,
  argon2idCost,
  _internals as kdfInternals,
} from "../js/core/kdf.js";
import { MANIFEST_LIMITS } from "../js/core/limits.js";

const ROOT = new URL("../", import.meta.url);

/** 65536 -> "64 MiB", 19456 -> "19 MiB", 2560 -> "2.5 MiB". */
function mib(kiB) {
  const value = kiB / 1024;
  return `${Number.isInteger(value) ? value : value.toFixed(1)} MiB`;
}

/** 2097152 -> "2 GiB". Used for the ceiling, which is the only limit that large. */
function gib(kiB) {
  const value = kiB / 1024 / 1024;
  return `${Number.isInteger(value) ? value : value.toFixed(1)} GiB`;
}

/**
 * 600000 -> "600,000". Matches how the documents already write these. Grouped by
 * hand rather than with toLocaleString, whose output depends on how the running
 * Node was built — the numbers in a document should not.
 */
function grouped(n) {
  return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/** "1 pass" / "2 passes" — for a table cell, where digits read better. */
function passCount(n) {
  return `${n} pass${n === 1 ? "" : "es"}`;
}

/** "one pass" / "two passes" / "17 passes" — prose, not a table cell. */
function passPhrase(n) {
  const words = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"];
  const word = words[n] ?? String(n);
  return `${word} pass${n === 1 ? "" : "es"}`;
}

/** The adjective form: "the 46 MiB single-pass profile it replaced". */
function passAdjective(n) {
  const words = ["zero", "single", "two", "three", "four", "five", "six", "seven", "eight", "nine"];
  return `${words[n] ?? n}-pass`;
}

/** "twice over", as in traversing the memory cost that many times. */
function timesPhrase(n) {
  const words = ["no times over", "once", "twice over", "three times over", "four times over"];
  return words[n] ?? `${n} times over`;
}

/** Everything the documentation is allowed to say, derived in one place. */
export function kdfFacts() {
  const { memoryKiB, iterations, parallelism } = ARGON2ID_DEFAULTS;
  const floor = ARGON2ID_PROFILE.costFloor;
  return {
    memoryKiB,
    iterations,
    parallelism,
    memory: mib(memoryKiB),
    passes: passCount(iterations),
    passesInWords: passPhrase(iterations),
    passesOver: timesPhrase(iterations),
    seconds: ARGON2ID_PROFILE.estimatedSeconds,
    keyBits: kdfInternals.KEY_BYTES * 8,
    pbkdf2Iterations: PBKDF2_DEFAULTS.iterations,
    floorMemory: mib(floor.memoryKiB),
    floorPasses: passAdjective(floor.iterations),
    floorPassPhrase: passPhrase(floor.iterations),
    /**
     * How much more an attack costs than against the floor profile. One decimal
     * place: the underlying figure is a ratio of two round numbers, and more
     * precision would imply a measurement nobody made.
     */
    costRatio: (argon2idCost(ARGON2ID_DEFAULTS) / argon2idCost(floor)).toFixed(1),
    limits: MANIFEST_LIMITS,
  };
}

/**
 * The generated spans, by file and marker id.
 *
 * A span is either inline — it must not start at the beginning of a line, or
 * the comment would open an HTML block and split the paragraph — or a whole
 * paragraph, table or fenced block with its markers on their own lines. Nothing
 * in between, because a comment in the middle of a paragraph changes how
 * Markdown renders it.
 */
export function regions() {
  const f = kdfFacts();

  return {
    "docs/SECURITY.md": {
      primitive: `Argon2id (${f.memory}, ${f.passes})`,

      profile: [
        `The shipped profile is m=${f.memoryKiB} KiB, t=${f.iterations}, p=${f.parallelism}, comfortably above OWASP's`,
        `recommended settings and roughly ${f.costRatio} times as expensive to attack as the`,
        `${f.floorMemory} ${f.floorPasses} profile it replaced. It costs about ${f.seconds}s, which is`,
        "affordable only because it runs in a dedicated worker",
        "(`js/core/kdf-worker.js`) rather than on the page's thread, so the tab stays",
        "responsive and the cost is no longer paid in visible jank — which is what makes",
        "raising these parameters practical. A server can afford more memory and should",
        "use it.",
      ].join("\n"),

      envelope: [
        "```",
        "fileKey        = 32 random bytes",
        `KEK            = Argon2id(passphrase, kdfSalt, m=${f.memoryKiB}KiB, t=${f.iterations}, p=${f.parallelism})`,
        "wrappedFileKey = AES-256-GCM(KEK, fileKey)",
        "```",
      ].join("\n"),

      wait: `${f.seconds} seconds`,

      "table-floor": `floor of ${grouped(f.limits.minArgon2MemoryKiB)} KiB enforced`,

      floor: `the Argon2id memory below ${grouped(f.limits.minArgon2MemoryKiB)} KiB`,
    },

    "docs/SEALING.md": {
      settings: [
        "| Setting | Value |",
        "|---|---|",
        "| Default KDF | `argon2id` (`DEFAULT_KDF`) |",
        `| Memory | ${f.memoryKiB} KiB (${f.memory}) |`,
        `| Passes | ${f.iterations} |`,
        `| Parallelism | ${f.parallelism} |`,
        `| Derived key | ${f.keyBits} bits |`,
        "| KDF salt | 16 random bytes, unique per file |",
        `| Cost to derive | ~${f.seconds}s in pure JavaScript on a desktop, longer on a phone |`,
        `| Legacy PBKDF2 | ${grouped(f.pbkdf2Iterations)} iterations, SHA-256 — read-only |`,
      ].join("\n"),

      oldest: `the real first profile OREOCHAIN shipped (${f.floorMemory}, ${f.floorPassPhrase})`,

      bounds: [
        "| Bound | Value | Stops |",
        "|---|---|---|",
        `| Min Argon2 memory | ${grouped(f.limits.minArgon2MemoryKiB)} KiB | A manifest setting memory to 8 KiB, making cracking as cheap as before Argon2id, with the file still opening normally |`,
        `| Max Argon2 memory | ${gib(f.limits.maxArgon2MemoryKiB)} | A manifest demanding 8 GiB to open — denial of service against the reader |`,
        `| Argon2 passes | ${f.limits.minArgon2Iterations}–${f.limits.maxArgon2Iterations} | |`,
        `| Argon2 parallelism | ${f.limits.minArgon2Parallelism}–${f.limits.maxArgon2Parallelism} | |`,
        `| PBKDF2 iterations | ${grouped(f.limits.minIterations)}–${grouped(f.limits.maxIterations)} | A legacy manifest claiming fewer than the OWASP floor |`,
      ].join("\n"),
    },

    "Readme.md": {
      memory: `${f.memory} ${f.passesOver}`,
      cost: `~${f.seconds}s`,
    },
  };
}

function markers(id) {
  return { open: `<!-- kdf:${id} -->`, close: `<!-- /kdf:${id} -->` };
}

/**
 * Replace one marked span. Missing markers are a hard error rather than a
 * silent skip: a document that lost its markers is exactly the document whose
 * numbers then rot unnoticed, which is the failure this script exists to stop.
 */
function replaceRegion(source, file, id, body) {
  const { open, close } = markers(id);
  const start = source.indexOf(open);
  if (start === -1) throw new Error(`${file}: no ${open} marker`);
  const from = start + open.length;
  const end = source.indexOf(close, from);
  if (end === -1) throw new Error(`${file}: ${open} is never closed by ${close}`);
  if (source.indexOf(open, from) !== -1) throw new Error(`${file}: ${open} appears twice`);

  // A span whose markers sit on their own lines owns whole lines, so the
  // newlines next to the markers belong to the layout, not to the content.
  const multiline = source.slice(from, end).includes("\n");
  const replacement = multiline ? `\n${body}\n` : body;
  return source.slice(0, from) + replacement + source.slice(end);
}

/**
 * Rewrite every generated span, or report which files are out of date.
 *
 * @param {{ write?: boolean }} options
 * @returns {{ stale: string[], written: string[] }}
 */
export function syncKdfDocs({ write = true } = {}) {
  const stale = [];
  const written = [];

  for (const [file, spans] of Object.entries(regions())) {
    const target = new URL(file, ROOT);
    const before = fs.readFileSync(target, "utf8");
    let after = before;
    for (const [id, body] of Object.entries(spans)) {
      after = replaceRegion(after, file, id, body);
    }
    if (after === before) continue;
    stale.push(file);
    if (write) {
      fs.writeFileSync(target, after);
      written.push(file);
    }
  }

  return { stale, written };
}

const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (invokedDirectly) {
  const check = process.argv.includes("--check");
  const { stale, written } = syncKdfDocs({ write: !check });

  if (check && stale.length > 0) {
    console.error(
      `The key-derivation numbers in ${stale.join(", ")} no longer match ` +
        "js/core/kdf.js.\nRun `npm run kdf-docs` to write them from the code."
    );
    process.exit(1);
  }
  if (check) console.log("key-derivation documentation is up to date");
  else if (written.length === 0) console.log("key-derivation documentation already up to date");
  else console.log(`wrote ${written.join(", ")}`);
}
