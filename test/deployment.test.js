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
import os from "node:os";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

import { assertSafeConfig, loadConfig, readSecret } from "../server/config.mjs";
import { createHandler } from "../server/gateway.mjs";
import { createLogger } from "../server/log.mjs";
import { createMemoryBackend } from "../server/storage.mjs";
import { createProofService, readSigningKey } from "../server/proofs.mjs";
import { createManifestVerifier } from "../server/verify.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (name) => readFileSync(path.join(ROOT, name), "utf8");

const KEY = "k".repeat(48);
const ANCHOR_KEY = "a".repeat(48);
const silent = createLogger({ level: "silent" });

/**
 * A receipt key pair in the shape scripts/generate-receipt-key.mjs writes.
 * readSigningKey() parses and shape-checks it without importing it, so a
 * literal keeps these checks synchronous.
 */
const RECEIPT_KEY = {
  privateJwk: { kty: "EC", crv: "P-256", d: "not-a-real-key", x: "x", y: "y", key_ops: ["sign"] },
  publicJwk: { kty: "EC", crv: "P-256", x: "x", y: "y", key_ops: ["verify"] },
};

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

/**
 * The gateway service's `environment:` block, as compose would apply it.
 *
 * Parsed by hand rather than with a YAML dependency: this is the only YAML in
 * the project, the block is four flat `KEY: value` lines, and a lenient parser
 * would defeat the point — a line it silently skipped is exactly the setting
 * that would go missing in a real deployment. So anything inside the block
 * that is not a comment, a blank, or a plain scalar assignment fails the test
 * rather than being ignored.
 */
function composeEnvironment(text) {
  const lines = text.split("\n");
  const start = lines.findIndex((line) => /^ {4}environment:\s*$/.test(line));
  assert.notEqual(start, -1, "docker-compose.yml has no gateway environment: block");

  const env = {};
  for (const line of lines.slice(start + 1)) {
    if (line.trim() === "" || /^ {6}#/.test(line)) continue;
    if (!/^ {6}\S/.test(line)) break; // dedented: the block ended
    const match = /^ {6}([A-Za-z_][A-Za-z0-9_]*): (.+)$/.exec(line);
    assert.ok(match, `unparsed line in the compose environment block: ${line}`);
    env[match[1]] = match[2].trim().replace(/^"(.*)"$/, "$1");
  }
  assert.ok(Object.keys(env).length > 0, "the compose environment block parsed as empty");
  return env;
}

test("the documented compose deployment starts the gateway, secrets and all", () => {
  /*
   * The sibling test above runs .env.example through the loader. This one runs
   * what a compose deployment actually gets: .env underneath, the service's
   * `environment:` block on top, and the two credentials arriving as mounted
   * files rather than as values.
   *
   * That last part is its own failure mode and nothing else covers it.
   * .env.example ships `PINATA_JWT=` and `OREOCHAIN_RECEIPT_KEY=` as empty
   * lines, so a compose deployment has both the base name and its `_FILE`
   * twin present at once — which is the shape readSecret() refuses as
   * ambiguous when the base holds a value. Empty has to keep reading as
   * "unset", or the documented deployment stops booting and only a container
   * would ever tell us.
   */
  const dir = mkdtempSync(path.join(os.tmpdir(), "oreochain-compose-"));
  const pinataFile = path.join(dir, "pinata_jwt");
  const receiptFile = path.join(dir, "receipt_key");
  writeFileSync(pinataFile, "placeholder-not-a-real-pinata-jwt");
  writeFileSync(receiptFile, JSON.stringify(RECEIPT_KEY));

  const env = {};
  for (const line of read(".env.example").split("\n")) {
    // Empty assignments included this time, unlike the test above: they are
    // half of what this is checking.
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim());
    if (match) env[match[1]] = match[2];
  }

  // The documented fill-in, and the one deviation .env.example itself
  // describes for a machine with no pinning account.
  env.OREOCHAIN_API_KEYS = `${KEY},${ANCHOR_KEY}`;
  env.OREOCHAIN_ANCHOR_API_KEYS = ANCHOR_KEY;
  env.OREOCHAIN_STORAGE = "memory";

  // Then compose's own block, over the top, as compose applies it.
  Object.assign(env, composeEnvironment(read("docker-compose.yml")));
  env.OREOCHAIN_DB_PATH = ":memory:"; // a test process cannot write /data
  env.PINATA_JWT_FILE = pinataFile;
  env.OREOCHAIN_RECEIPT_KEY_FILE = receiptFile;

  const warnings = [];
  const config = assertSafeConfig(loadConfig(env), { warn: (m) => warnings.push(m) });

  // Whichever layer supplies it, the effective config has to bind somewhere
  // reachable from outside the container.
  assert.equal(config.host, "0.0.0.0");
  assert.equal(config.apiKeys.length, 2);
  assert.deepEqual(
    warnings.filter((message) => !message.includes(":memory:")),
    []
  );

  // Both secrets arrive through the mount, not the environment.
  assert.equal(readSecret(env, "PINATA_JWT"), "placeholder-not-a-real-pinata-jwt");
  assert.deepEqual(readSigningKey(env).publicJwk, RECEIPT_KEY.publicJwk);
});

test("every secret docker-compose.yml reads is one it actually mounts", () => {
  /*
   * A `_FILE` pointing at a path nothing mounts fails at startup with
   * "could not be read", in a container, minutes into a deploy. The two lists
   * are twenty lines apart in the same file and drift the moment a third
   * secret is added.
   */
  const compose = read("docker-compose.yml");
  const environment = composeEnvironment(compose);

  // Compose mounts secret `foo` at /run/secrets/foo, so the path's last
  // segment is the secret's name and the two have to agree.
  const wanted = Object.entries(environment)
    .filter(([name]) => name.endsWith("_FILE"))
    .map(([name, value]) => {
      assert.match(value, /^\/run\/secrets\/[a-z0-9_]+$/, `${name} does not point into /run/secrets`);
      return value.slice("/run/secrets/".length);
    });
  assert.ok(wanted.length > 0, "no secrets are mounted, which this test cannot be right about");

  // The service's own list, and the top-level definitions it refers to.
  const granted = [...compose.matchAll(/^ {6}- ([a-z0-9_]+)$/gm)].map((m) => m[1]);
  const defined = [...compose.matchAll(/^ {2}([a-z0-9_]+):\n {4}file: (\S+)$/gm)].map((m) => m[1]);

  for (const secret of wanted) {
    assert.ok(granted.includes(secret), `${secret} is read but not granted to the gateway service`);
    assert.ok(defined.includes(secret), `${secret} is granted but has no top-level secrets: entry`);
  }
});

test("the compose stop grace period outlasts the shutdown delay", () => {
  /*
   * The gateway answers /ready with 503 for OREOCHAIN_SHUTDOWN_DELAY_MS before
   * it stops accepting, so a load balancer takes it out of rotation before
   * connections start failing. If compose's grace period is the shorter of the
   * two, that drain is killed halfway through and the delay buys nothing —
   * silently, because a killed container still stops.
   */
  const compose = read("docker-compose.yml");
  const grace = /^ {4}stop_grace_period: (\d+)s$/m.exec(compose);
  assert.ok(grace, "docker-compose.yml no longer sets stop_grace_period on the gateway");

  const delay = /^OREOCHAIN_SHUTDOWN_DELAY_MS=(\d+)$/m.exec(read(".env.example"));
  assert.ok(delay, ".env.example no longer sets OREOCHAIN_SHUTDOWN_DELAY_MS");

  assert.ok(
    Number(grace[1]) * 1000 > Number(delay[1]),
    `stop_grace_period (${grace[1]}s) must outlast OREOCHAIN_SHUTDOWN_DELAY_MS (${delay[1]}ms), ` +
      "or the drain is killed halfway"
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
