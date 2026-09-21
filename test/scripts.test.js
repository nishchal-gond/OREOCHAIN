/**
 * The one-off chain scripts: deploy the contract, authorise an exporter.
 *
 * They spend real money on a real chain, so the parts worth testing are the
 * ones that decide whether anything is sent at all — the compile, the
 * validation, and the rule that nothing happens without --confirm.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { createRequire } from "node:module";

import {
  CODE_SIZE_LIMIT,
  ROOT,
  assertAddress,
  assertContractAt,
  compileContract,
  confirmed,
  connect,
  readChainCli,
} from "../scripts/chain-tools.mjs";
import { CHUNKED_VERIFICATION_ABI } from "../js/contract-abi.js";

const require = createRequire(import.meta.url);
const haveSolc = (() => {
  try {
    require("solc");
    return true;
  } catch {
    return false;
  }
})();
const skip = haveSolc ? false : "solc not installed — run `npm install`";

const KEY = "0x" + "ab".repeat(32);

test("the deploy script compiles the same contract the tests run", { skip }, () => {
  const compiled = compileContract();

  assert.match(compiled.bytecode, /^0x[0-9a-f]+$/);
  assert.ok(compiled.deployedSize > 0);
  assert.ok(
    compiled.deployedSize <= CODE_SIZE_LIMIT,
    `deployed bytecode is ${compiled.deployedSize} bytes`
  );

  /*
   * The committed ABI is what the frontend and the anchoring worker both use.
   * A script that deployed a contract with a different interface would leave
   * every caller talking to the wrong selectors, and nothing else would
   * notice until a transaction reverted.
   */
  assert.deepEqual(
    compiled.abi,
    CHUNKED_VERIFICATION_ABI,
    "the deploy script and js/contract-abi.js disagree — run `npm run abi`"
  );
});

test("nothing is sent without --confirm", () => {
  // The whole safety model of both scripts is this one function.
  assert.equal(confirmed(["node", "deploy.mjs"]), false);
  assert.equal(confirmed(["node", "deploy.mjs", "--dry-run"]), false);
  assert.equal(confirmed(["node", "deploy.mjs", "--confirmed"]), false);
  assert.equal(confirmed(["node", "deploy.mjs", "--confirm"]), true);
  assert.equal(confirmed(["node", "add-exporter.mjs", "0xabc", "info", "--confirm"]), true);
});

test("a missing or malformed deploy key is named, not passed to web3", () => {
  assert.throws(() => readChainCli({}), /OREOCHAIN_CHAIN_RPC/);
  assert.throws(() => readChainCli({}), /OREOCHAIN_DEPLOY_KEY/);
  assert.throws(() => readChainCli({}), /2 setting\(s\) are missing/);

  assert.throws(
    () => readChainCli({ OREOCHAIN_CHAIN_RPC: "http://x", OREOCHAIN_DEPLOY_KEY: "nope" }),
    /must be a 0x-prefixed 32-byte hex private key/
  );

  assert.deepEqual(
    readChainCli({ OREOCHAIN_CHAIN_RPC: "http://x", OREOCHAIN_DEPLOY_KEY: KEY }),
    { rpcUrl: "http://x", privateKey: KEY, contractAddress: null }
  );
});

test("the deploy key can come from a file, so it stays out of shell history", () => {
  const file = path.join(ROOT, "test", `.deploy-key-${process.pid}.tmp`);
  fs.writeFileSync(file, KEY + "\n");
  try {
    assert.equal(
      readChainCli({ OREOCHAIN_CHAIN_RPC: "http://x", OREOCHAIN_DEPLOY_KEY_FILE: file })
        .privateKey,
      KEY
    );
  } finally {
    fs.rmSync(file, { force: true });
  }
});

test("an address that would waste a transaction is refused first", () => {
  assert.throws(() => assertAddress("0x123", "target"), /must be a 20-byte hex address/);
  assert.throws(() => assertAddress(undefined, "target"), /must be a 20-byte hex address/);
  // The contract reverts on this one, after the gas is spent.
  assert.throws(() => assertAddress("0x" + "0".repeat(40), "target"), /zero address/);

  assert.equal(assertAddress("0x" + "aB".repeat(20), "target"), "0x" + "aB".repeat(20));
});

test("both scripts exist, are executable, and refuse a bare invocation", () => {
  for (const name of ["deploy-contract.mjs", "add-exporter.mjs"]) {
    const file = path.join(ROOT, "scripts", name);
    assert.ok(fs.existsSync(file), `${name} is missing`);
    assert.ok(fs.statSync(file).mode & 0o111, `${name} is not executable`);

    /*
     * Actually run it. Asserting on the exported helpers leaves the case an
     * operator meets first — a bare invocation with nothing configured —
     * covered by nothing, and a script that threw on startup or, worse, got
     * far enough to send something would still pass a check of the file's
     * mode. An empty environment rather than a filtered one, so a variable
     * set on the machine running the tests cannot make this pass.
     */
    const run = spawnSync(process.execPath, [file], {
      cwd: ROOT,
      env: { PATH: process.env.PATH },
      encoding: "utf8",
    });

    assert.equal(run.status, 1, `${name} should exit 1 with nothing configured`);
    assert.match(
      run.stderr,
      /setting\(s\) are missing/,
      `${name} should name what is missing`
    );
    assert.match(run.stderr, /OREOCHAIN_CHAIN_RPC/);
    assert.match(run.stderr, /OREOCHAIN_DEPLOY_KEY/);
  }
});

/** Just enough web3 for connect() and the code check. */
function fakeWeb3({ chainId = 11155111n, balance = 0n, code = "0x" } = {}) {
  class Web3 {
    constructor() {
      this.eth = {
        accounts: {
          privateKeyToAccount: () => ({ address: "0x" + "77".repeat(20) }),
          wallet: { add: () => {} },
        },
        getChainId: async () => chainId,
        getBalance: async () => balance,
        getCode: async () => code,
      };
    }
  }
  return { Web3 };
}

test("an unfunded address is reported, not thrown, so a dry run still runs", async () => {
  /*
   * connect() used to throw on a zero balance, before either script had
   * printed a line. So the two things you go to a dry run for — which address
   * to fund, and how much gas this will take — were unavailable until after
   * you had funded it. The refusal belongs at the point of sending, which is
   * where --confirm already is.
   */
  const chain = await connect({
    rpcUrl: "http://127.0.0.1:1",
    privateKey: KEY,
    web3Module: fakeWeb3({ balance: 0n }),
  });

  assert.equal(chain.funded, false);
  assert.equal(chain.balance, "0");
  assert.equal(chain.chainId, 11155111);
  assert.match(chain.account.address, /^0x[0-9a-f]{40}$/i);

  const funded = await connect({
    rpcUrl: "http://127.0.0.1:1",
    privateKey: KEY,
    web3Module: fakeWeb3({ balance: 10n ** 18n }),
  });
  assert.equal(funded.funded, true);
});

test("an address with no contract code names the mistake instead of failing to decode", async () => {
  /*
   * The wrong-network mistake the README calls one of the two most likely.
   * The call returns empty bytes, web3 tries to decode them, and what reaches
   * the operator is "Parameter decoding error" — which names neither the
   * address, nor the network, nor what they did.
   */
  const { Web3 } = fakeWeb3({ code: "0x" });
  await assert.rejects(
    () => assertContractAt(new Web3(), "0x" + "cc".repeat(20), 11155111),
    /no contract code at 0x/
  );

  const live = fakeWeb3({ code: "0x60806040" });
  await assertContractAt(new live.Web3(), "0x" + "cc".repeat(20), 11155111);
});
