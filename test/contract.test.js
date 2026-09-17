/**
 * Cross-language verification: the Solidity Merkle implementation must produce
 * byte-identical results to the JavaScript one in js/core/chunker.js.
 *
 * If these two ever drift, on-chain chunk proofs silently stop verifying for
 * files that were registered correctly — the kind of bug that only shows up in
 * production. So the contract is compiled and executed in a real EVM here.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

import { randomBytes, to0x, toHex, utf8 } from "../js/core/bytes.js";
import { hashChunks, leafHash, merkleProof, merkleRoot } from "../js/core/chunker.js";
import { buildBatch, documentLeaf, proveInBatch } from "../js/core/anchor.js";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** These are dev-only dependencies; skip rather than fail if they are absent. */
function loadToolchain() {
  try {
    return {
      solc: require("solc"),
      evm: require("@ethereumjs/evm"),
      util: require("@ethereumjs/util"),
      keccak: require("ethereum-cryptography/keccak"),
    };
  } catch {
    return null;
  }
}

const toolchain = loadToolchain();
const skip = toolchain
  ? false
  : "solc / @ethereumjs/evm not installed — run `npm install` to enable contract tests";

function compile(solc) {
  const source = fs.readFileSync(path.join(ROOT, "Contract/ChunkedVerification.sol"), "utf8");
  const out = JSON.parse(
    solc.compile(
      JSON.stringify({
        language: "Solidity",
        sources: { "ChunkedVerification.sol": { content: source } },
        settings: {
          optimizer: { enabled: true, runs: 200 },
          // Paris keeps the bytecode free of PUSH0 so it deploys on chains
          // that have not adopted Shanghai.
          evmVersion: "paris",
          outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } },
        },
      })
    )
  );

  const errors = (out.errors || []).filter((e) => e.severity === "error");
  assert.equal(errors.length, 0, errors.map((e) => e.formattedMessage).join("\n"));
  return out.contracts["ChunkedVerification.sol"].ChunkedVerification;
}

function concat(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

async function deployed() {
  const { solc, evm: evmMod, util, keccak } = toolchain;
  const contract = compile(solc);
  const machine = await evmMod.EVM.create();

  const created = await machine.runCall({
    data: util.hexToBytes("0x" + contract.evm.bytecode.object),
  });
  assert.ok(!created.execResult.exceptionError, "contract failed to deploy");

  const code = created.execResult.returnValue;
  const address = created.createdAddress;

  const selector = (sig) => keccak.keccak256(new TextEncoder().encode(sig)).slice(0, 4);
  const word = (n) => {
    const out = new Uint8Array(32);
    const hex = BigInt(n).toString(16).padStart(2, "0");
    const bytes = util.hexToBytes("0x" + (hex.length % 2 ? "0" + hex : hex));
    out.set(bytes, 32 - bytes.length);
    return out;
  };

  async function call(data) {
    const result = await machine.runCall({ to: address, data, code });
    assert.ok(
      !result.execResult.exceptionError,
      `call reverted: ${result.execResult.exceptionError?.error}`
    );
    return result.execResult.returnValue;
  }

  return { contract, call, selector, word, code };
}

test("the contract compiles and fits within the EVM code size limit", { skip }, async () => {
  const { solc } = toolchain;
  const contract = compile(solc);
  const size = contract.evm.deployedBytecode.object.length / 2;
  assert.ok(size > 0, "no bytecode produced");
  assert.ok(size <= 24576, `deployed bytecode is ${size} bytes, over the 24576 limit`);
});

test("Solidity leafHash matches the JavaScript leaf hash", { skip }, async () => {
  const { call, selector, word } = await deployed();

  for (const size of [0, 1, 31, 32, 33, 100, 1024]) {
    const chunk = randomBytes(size);
    const padded = new Uint8Array(Math.ceil(size / 32) * 32);
    padded.set(chunk);

    const onChain = await call(
      concat(selector("leafHash(bytes)"), word(32), word(size), padded)
    );

    assert.equal(
      "0x" + toHex(onChain),
      to0x(await leafHash(chunk)),
      `leaf hash disagreed for a ${size}-byte chunk`
    );
  }
});

test("Solidity computeRoot rebuilds the JavaScript Merkle root", { skip }, async () => {
  const { call, selector, word } = await deployed();

  // Odd counts exercise the promoted-lone-node path, which is where a naive
  // Solidity port would most likely diverge.
  for (const count of [1, 2, 3, 4, 5, 7, 8, 9, 16, 17]) {
    const chunks = Array.from({ length: count }, () => randomBytes(64));
    const leaves = await hashChunks(chunks);
    const expected = to0x(await merkleRoot(leaves));

    for (let i = 0; i < count; i++) {
      const proof = await merkleProof(leaves, i);

      const onChain = await call(
        concat(
          selector("computeRoot(bytes32,bytes32[],bool[])"),
          leaves[i],
          word(96),
          word(96 + 32 + proof.length * 32),
          word(proof.length),
          ...proof.map((step) => step.hash),
          word(proof.length),
          ...proof.map((step) => word(step.side === "right" ? 1 : 0))
        )
      );

      assert.equal(
        "0x" + toHex(onChain),
        expected,
        `root disagreed proving chunk ${i} of ${count}`
      );
    }
  }
});

test("Solidity documentLeaf matches the JavaScript batch leaf", { skip }, async () => {
  const { call, selector, word } = await deployed();

  // A dynamic string argument sits after the fixed-size head, so the offset
  // accounts for fileHash, merkleRoot and fileSize.
  async function solDocumentLeaf(document) {
    const cid = utf8(document.manifestCID);
    const padded = new Uint8Array(Math.ceil(cid.length / 32) * 32);
    padded.set(cid);

    return call(
      concat(
        selector("documentLeaf(bytes32,bytes32,uint64,string)"),
        hexWord(document.fileHash),
        hexWord(document.merkleRoot),
        word(document.fileSize),
        word(4 * 32), // offset to the string data
        word(cid.length),
        padded
      )
    );
  }

  function hexWord(hex) {
    const out = new Uint8Array(32);
    const bytes = hex.slice(2).match(/../g).map((b) => parseInt(b, 16));
    out.set(bytes, 32 - bytes.length);
    return out;
  }

  const cases = [
    { fileHash: "0x" + "11".repeat(32), merkleRoot: "0x" + "22".repeat(32), fileSize: 0, manifestCID: "a" },
    { fileHash: "0x" + "ab".repeat(32), merkleRoot: "0x" + "cd".repeat(32), fileSize: 1, manifestCID: "bafyShort" },
    {
      fileHash: to0x(randomBytes(32)),
      merkleRoot: to0x(randomBytes(32)),
      fileSize: 4294967296, // beyond uint32, exercising the big-endian uint64
      manifestCID: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
    },
    {
      fileHash: to0x(randomBytes(32)),
      merkleRoot: to0x(randomBytes(32)),
      fileSize: 1099511627775,
      manifestCID: "x".repeat(70), // spans more than two 32-byte words
    },
  ];

  for (const document of cases) {
    assert.equal(
      "0x" + toHex(await solDocumentLeaf(document)),
      to0x(await documentLeaf(document)),
      `batch leaf disagreed for manifestCID of length ${document.manifestCID.length}`
    );
  }
});

test("Solidity rebuilds batch roots from JavaScript inclusion proofs", { skip }, async () => {
  const { call, selector, word } = await deployed();

  for (const count of [1, 2, 3, 5, 9, 16]) {
    const documents = Array.from({ length: count }, (_, i) => ({
      fileHash: "0x" + i.toString(16).padStart(64, "0"),
      merkleRoot: to0x(randomBytes(32)),
      fileSize: 1000 + i,
      manifestCID: `bafyBatchDoc${i}`,
    }));

    const batch = await buildBatch(documents);

    for (const document of documents) {
      const inclusion = await proveInBatch(batch, document.fileHash);
      const leaf = await documentLeaf(document);
      const proof = inclusion.proof;

      const onChain = await call(
        concat(
          selector("computeRoot(bytes32,bytes32[],bool[])"),
          leaf,
          word(96),
          word(96 + 32 + proof.length * 32),
          word(proof.length),
          ...proof.map((step) => {
            const out = new Uint8Array(32);
            out.set(step.hash.slice(2).match(/../g).map((b) => parseInt(b, 16)));
            return out;
          }),
          word(proof.length),
          ...proof.map((step) => word(step.side === "right" ? 1 : 0))
        )
      );

      assert.equal(
        "0x" + toHex(onChain),
        batch.root,
        `batch root disagreed proving document ${document.fileHash} of ${count}`
      );
    }
  }
});
