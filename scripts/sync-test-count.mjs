/**
 * Write the number of tests into the Readme from the test run itself.
 *
 *     npm run test-count            rewrite the counts in Readme.md
 *     npm run test-count -- --check fail if either of them is out of date
 *
 * WHY THIS EXISTS
 *
 * The Readme states the size of the suite in two places, and both are the kind
 * of number a reader takes on trust and nothing verifies. It has now gone stale
 * three times in a row, each time because a merge added tests and the prose was
 * written before the merge: it claimed 252, then 300, then 317, then 358, while
 * master carried a different number on each of those days.
 *
 * A wrong count is a small lie, but it is the sort a reader uses to judge
 * whether the project is maintained, and it costs a reviewer real time to work
 * out which of the two numbers is the true one. Counting is also exactly the
 * job a machine should have: nobody should be re-running the suite and editing
 * prose by hand to keep an integer honest.
 *
 * This follows the shape already used by `npm run abi` and `npm run kdf-docs`:
 * generate the value from the source of truth, and run `--check` in CI so that
 * generating it is not something anyone has to remember.
 *
 * WHY IT RUNS THE SUITE RATHER THAN COUNTING `test(` CALLS
 *
 * The number a reader cares about is the number the runner reports, and that is
 * not the number of top-level `test()` calls: subtests count too, and a table
 * of cases generated in a loop contributes as many tests as the table has rows.
 * Counting call sites statically would produce a second, different number that
 * disagrees with what `npm test` prints — which is the problem, not the fix.
 *
 * It cannot therefore run inside `npm test` (it would recurse), so CI runs it as
 * its own step rather than as a test case.
 */

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = new URL("../", import.meta.url);
const README = new URL("Readme.md", ROOT);

/**
 * The two places the Readme states the size of the suite. Both live inside
 * fenced code blocks, where an HTML comment marker would render as visible
 * text, so the generated spans are anchored by their surrounding text instead.
 *
 * Each pattern must match exactly once. A pattern that stops matching — because
 * the prose around it was reworded — fails loudly rather than quietly updating
 * nothing, which is the failure mode that would put this script back where the
 * hand-written numbers started.
 */
const SITES = [
  { name: "the repository map", pattern: /^(test\/\s+)(\d+)( tests,)/m },
  { name: "the Tests section", pattern: /^(npm test\s+# )(\d+)( tests)$/m },
];

/**
 * Run the suite and return the number of tests it reports.
 *
 * The file list is expanded here rather than passing the `test/` directory,
 * so that this runs the same set of files `npm test` does. Node only learned
 * to take a directory after the floor this package supports: on 18 and 20 the
 * argument is resolved as a module and the run fails outright.
 *
 * Node's test reporter also changed its prefix: 18 through 22 print
 * "# tests 387" and 24 prints "ℹ tests 387". Both are accepted, because this
 * script should not be the reason a contributor's Node version matters.
 */
function countTests() {
  const testDir = fileURLToPath(new URL("test/", ROOT));
  const files = fs
    .readdirSync(testDir)
    .filter((name) => name.endsWith(".test.js"))
    .sort()
    .map((name) => path.join("test", name));

  if (files.length === 0) throw new Error("no test files found in test/");

  const result = spawnSync(process.execPath, ["--test", ...files], {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });

  if (result.error) throw result.error;

  const output = `${result.stdout}${result.stderr}`;
  const match = output.match(/^[#ℹ]\s+tests\s+(\d+)$/m);
  const failed = output.match(/^[#ℹ]\s+fail\s+(\d+)$/m);

  if (!match) {
    throw new Error(
      "could not find a test count in the runner's output. " +
        "Run 'npm test' directly to see what it printed."
    );
  }
  // A count taken from a red run would write a number that stops being true the
  // moment the suite is fixed, so refuse rather than record it.
  if (result.status !== 0 || (failed && Number(failed[1]) > 0)) {
    throw new Error(
      `the suite is not green (${failed ? failed[1] : "?"} failing), so its size is not worth recording. ` +
        "Fix the tests first."
    );
  }

  return Number(match[1]);
}

function apply(text, count) {
  const stale = [];
  let updated = text;

  for (const site of SITES) {
    const matches = updated.match(new RegExp(site.pattern.source, "gm")) || [];
    if (matches.length !== 1) {
      throw new Error(
        `expected exactly one test count in ${site.name} of Readme.md, found ${matches.length}. ` +
          "The prose around it has changed; update scripts/sync-test-count.mjs to match."
      );
    }

    updated = updated.replace(site.pattern, (whole, before, found, after) => {
      if (Number(found) !== count) stale.push(`${site.name}: says ${found}, the suite has ${count}`);
      return `${before}${count}${after}`;
    });
  }

  return { updated, stale };
}

const check = process.argv.includes("--check");
const original = fs.readFileSync(README, "utf8");
const count = countTests();
const { updated, stale } = apply(original, count);

if (check) {
  if (stale.length > 0) {
    console.error("Readme.md states the wrong number of tests:");
    for (const line of stale) console.error(`  - ${line}`);
    console.error("\nRun 'npm run test-count' and commit the result.");
    process.exit(1);
  }
  console.log(`Readme.md test count is current (${count}).`);
} else if (updated === original) {
  console.log(`Readme.md already says ${count} tests; nothing to write.`);
} else {
  fs.writeFileSync(README, updated);
  console.log(`Readme.md updated to ${count} tests.`);
}
