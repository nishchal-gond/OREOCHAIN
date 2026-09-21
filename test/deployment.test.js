/**
 * The deployment, as opposed to the code.
 *
 * `npm test` covers the code thoroughly and cannot see any of this: whether
 * .env.example still describes the settings the gateway actually reads,
 * whether docker-compose.yml names a variable that was renamed a month ago,
 * whether the sequence in the README still works end to end against a running
 * service. Those files are documentation that executes, and they rot in
 * silence — the first person to find out is whoever follows them.
 *
 * CI rehearses the same path through Docker Compose. These run here too
 * because a Compose job is slow, needs a daemon, and is the first thing
 * skipped locally, and because a failure here names the setting rather than
 * handing back a container log.
 */

import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import path from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

import { assertSafeConfig, loadConfig } from "../server/config.mjs";
import { createHandler } from "../server/gateway.mjs";
import { createLogger } from "../server/log.mjs";
import { createMemoryBackend } from "../server/storage.mjs";
import { createProofService } from "../server/proofs.mjs";
import { createManifestVerifier } from "../server/verify.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (name) => readFileSync(path.join(ROOT, name), "utf8");

const KEY = "k".repeat(48);
const ANCHOR_KEY = "a".repeat(48);
const silent = createLogger({ level: "silent" });

/** Every OREOCHAIN_* name a file mentions, set or commented out. */
function settingsIn(text) {
  return new Set(text.match(/OREOCHAIN_[A-Z0-9_]+/g) || []);
}

// ------------------------------------------------- the documented settings

test(".env.example describes settings the gateway actually reads", () => {
  // A renamed setting leaves the old name in the example file, where it looks
  // authoritative and does nothing. Nothing else would notice.
  const documented = settingsIn(read(".env.example"));
  const code = settingsIn(
    ["server/config.mjs", "server/gateway.mjs", "server/index.mjs", "server/proofs.mjs"]
      .map(read)
      .join("\n")
  );

  // A _FILE twin never appears literally: readSecret() builds the name from
  // its base. It is documented if its base is read.
  const stale = [...documented].filter(
    (name) => !code.has(name) && !(name.endsWith("_FILE") && code.has(name.slice(0, -5)))
  );
  assert.deepEqual(stale, [], `.env.example documents settings nothing reads: ${stale}`);
});

test("docker-compose.yml sets nothing the gateway does not read", () => {
  const compose = settingsIn(read("docker-compose.yml"));
  const code = settingsIn([read("server/config.mjs"), read("server/index.mjs")].join("\n"));

  const stale = [...compose].filter(
    (name) => !code.has(name) && !(name.endsWith("_FILE") && code.has(name.slice(0, -5)))
  );
  assert.deepEqual(stale, [], `docker-compose.yml names settings nothing reads: ${stale}`);
});

test("every setting the config reads is documented somewhere an operator looks", () => {
  const code = settingsIn(read("server/config.mjs"));
  const documented = new Set([
    ...settingsIn(read(".env.example")),
    ...settingsIn(read("server/README.md")),
  ]);

  const undocumented = [...code].filter((name) => !documented.has(name));
  assert.deepEqual(
    undocumented,
    [],
    `settings with no documentation: ${undocumented}. Add them to .env.example or server/README.md.`
  );
});

test(".env.example, filled in the way the README says, starts the gateway", () => {
  /*
   * The drift that matters most: the code grows a setting it refuses to start
   * without, and the example file — which is what every deployment is copied
   * from — does not mention it. Every other check here compares names; this
   * one runs the file through the same load and validation the process does.
   */
  const env = {};
  for (const line of read(".env.example").split("\n")) {
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim());
    if (match && match[2] !== "") env[match[1]] = match[2];
  }

  // The three blanks the README tells you to fill, and the one deviation it
  // documents for a machine with no pinning account.
  env.OREOCHAIN_API_KEYS = `${KEY},${ANCHOR_KEY}`;
  env.OREOCHAIN_ANCHOR_API_KEYS = ANCHOR_KEY;
  env.OREOCHAIN_STORAGE = "memory";
  env.OREOCHAIN_DB_PATH = ":memory:";

  const warnings = [];
  const config = assertSafeConfig(loadConfig(env), { warn: (m) => warnings.push(m) });

  assert.equal(config.apiKeys.length, 2);
  assert.equal(config.anchorApiKeys.length, 1);
  // Only the one we caused by pointing the store at memory for the test.
  assert.deepEqual(
    warnings.filter((message) => !message.includes(":memory:")),
    []
  );
});

// --------------------------------------------------------- the user's path

/**
 * Run a command and collect its output.
 *
 * Asynchronous on purpose: spawnSync blocks this process's event loop, and the
 * gateway under test is listening *in* this process — so a synchronous spawn
 * deadlocks, with the child waiting on a server that cannot answer until the
 * child exits.
 */
function run(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

async function startGateway() {
  const config = assertSafeConfig(
    loadConfig({
      OREOCHAIN_API_KEYS: `${KEY},${ANCHOR_KEY}`,
      OREOCHAIN_ANCHOR_API_KEYS: ANCHOR_KEY,
      OREOCHAIN_STORAGE: "memory",
    }),
    { warn: () => {} }
  );

  const backend = createMemoryBackend();
  const proofs = await createProofService({ verifier: createManifestVerifier({ backend }) });
  const handler = createHandler(config, backend, {
    logger: silent,
    sweeper: false,
    proofs,
  });

  const server = http.createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

  return {
    url: `http://127.0.0.1:${server.address().port}`,
    stop: async () => {
      await new Promise((resolve) => server.close(resolve));
      proofs.close();
    },
  };
}

test("the smoke test drives a running gateway through the whole user path", async () => {
  /*
   * scripts/smoke.mjs is what CI points at a Compose deployment, and what an
   * operator points at their own. It is only worth that if it works, and a
   * smoke test that passes because it silently skipped its own steps is worse
   * than none — so it runs here against a real gateway, and its output is
   * checked for the steps rather than only its exit code.
   */
  const gw = await startGateway();
  try {
    const result = await run([
      path.join(ROOT, "scripts", "smoke.mjs"),
      "--url",
      gw.url,
      "--key",
      KEY,
      "--anchor-key",
      ANCHOR_KEY,
      "--size",
      "8192",
      "--chunk-size",
      "1024",
    ]);

    assert.equal(result.status, 0, result.stdout + result.stderr);

    // Named steps, so a script that stopped early cannot pass by exiting 0.
    for (const expected of [
      /the gateway is ready/,
      /packed 8192 bytes into 8 chunks/,
      /pinned 8 chunks and the manifest/,
      /the receipt verifies against the key the service publishes/,
      /restored 8192 bytes, identical to the original/,
      /batched 1 document\(s\)/,
      /the inclusion proof verifies against the batch root/,
      /All 8 step\(s\) passed/,
    ]) {
      assert.match(result.stdout, expected);
    }
  } finally {
    await gw.stop();
  }
});

test("the smoke test fails, rather than passing quietly, when it cannot get in", async () => {
  const gw = await startGateway();
  try {
    const result = await run([
      path.join(ROOT, "scripts", "smoke.mjs"),
      "--url",
      gw.url,
      "--key",
      "not-a-valid-key",
    ]);

    assert.equal(result.status, 1);
    assert.match(result.stdout + result.stderr, /401/);
  } finally {
    await gw.stop();
  }
});
