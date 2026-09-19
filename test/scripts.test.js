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
import path from "node:path";
import { createRequire } from "node:module";

import {
  CODE_SIZE_LIMIT,
  ROOT,
  assertAddress,
  compileContract,
  confirmed,
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
  }
});
