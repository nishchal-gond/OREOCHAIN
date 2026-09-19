/**
 * Content chunking and Merkle-tree commitments.
 *
 * A file is split into fixed-size chunks so that each chunk can be stored,
 * fetched and verified independently. The chunk hashes are folded into a Merkle
 * tree whose root is the single value anchored on-chain: that one 32-byte root
 * commits to every chunk, so any chunk can later be proven to belong to the
 * registered file without downloading the rest of it.
 *
 * The tree is domain-separated (leaves are prefixed 0x00, internal nodes 0x01)
 * so that a chunk's hash can never be replayed as an internal node — the
 * classic second-preimage attack on naive Merkle trees.
 */

import { concat, concatAll, equalBytes, webcrypto } from "./bytes.js";

/** 256 KiB — the same block size IPFS uses, so our chunks map cleanly onto it. */
export const DEFAULT_CHUNK_SIZE = 262144;

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

export async function sha256(bytes) {
  const digest = await webcrypto().subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

/**
 * Split bytes into fixed-size chunks. A zero-length input yields a single empty
 * chunk so that every file has at least one chunk and one Merkle leaf.
 */
export function splitIntoChunks(bytes, chunkSize = DEFAULT_CHUNK_SIZE) {
  if (!Number.isInteger(chunkSize) || chunkSize <= 0) {
    throw new Error("chunkSize must be a positive integer");
  }
  if (bytes.length === 0) return [new Uint8Array(0)];

  const chunks = [];
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    chunks.push(bytes.subarray(offset, Math.min(offset + chunkSize, bytes.length)));
  }
  return chunks;
}

/** Reverse of splitIntoChunks. */
export function joinChunks(chunks) {
  return concatAll(chunks);
}

export async function leafHash(chunk) {
  return sha256(concat(LEAF_PREFIX, chunk));
}

export async function nodeHash(left, right) {
  return sha256(concat(NODE_PREFIX, left, right));
}

/**
 * Build every level of the Merkle tree, bottom-up. A level with an odd number of
 * nodes promotes its last node unchanged to the next level (rather than hashing
 * it with a copy of itself, which would make two distinct chunk lists collide).
 */
export async function buildMerkleTree(leaves) {
  if (leaves.length === 0) throw new Error("cannot build a Merkle tree with no leaves");

  const levels = [leaves];
  let current = leaves;

  while (current.length > 1) {
    const next = [];
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 === current.length) {
        next.push(current[i]); // lone node is promoted
      } else {
        next.push(await nodeHash(current[i], current[i + 1]));
      }
    }
    levels.push(next);
    current = next;
  }

  return levels;
}

export async function merkleRoot(leaves) {
  const levels = await buildMerkleTree(leaves);
  return levels[levels.length - 1][0];
}

/** Hash every chunk and return the leaf hashes in chunk order. */
export async function hashChunks(chunks) {
  const hashes = [];
  for (const chunk of chunks) hashes.push(await leafHash(chunk));
  return hashes;
}

/**
 * The sibling path proving that the leaf at `index` is part of the tree.
 * Each step records whether the sibling sits to the left or the right, which is
 * what lets the verifier recompute the parent in the correct order.
 */
export async function merkleProof(leaves, index) {
  return merkleProofFromLevels(await buildMerkleTree(leaves), index);
}

/**
 * The same path, from a tree that has already been built.
 *
 * Proving every leaf of a tree is the common case — a batch anchor hands one
 * proof to each document it covers — and calling merkleProof() in a loop
 * rebuilds the whole tree once per leaf, which is quadratic. Build the levels
 * once with buildMerkleTree() and walk them from here instead.
 */
export function merkleProofFromLevels(levels, index) {
  const leaves = levels[0];
  if (index < 0 || index >= leaves.length) throw new Error("leaf index out of range");

  const proof = [];
  let position = index;

  for (let level = 0; level < levels.length - 1; level++) {
    const nodes = levels[level];
    const siblingIndex = position % 2 === 0 ? position + 1 : position - 1;
    if (siblingIndex < nodes.length) {
      proof.push({
        hash: nodes[siblingIndex],
        side: position % 2 === 0 ? "right" : "left",
      });
    }
    // A promoted lone node contributes no proof step; its parent is itself.
    position = Math.floor(position / 2);
  }

  return proof;
}

/**
 * The most sibling hashes any honest proof can carry.
 *
 * A proof has one step per level of the tree above the leaf, so its length is
 * bounded by log2(leaf count) — 22 steps at this project's four-million-chunk
 * ceiling, 16 for the largest batch. The bound is what makes verification
 * cheap against hostile input: a proof arrives from whoever served it, and
 * without a cap a "proof" of a million steps is a million SHA-256 invocations
 * the verifier performs before answering false. 64 is far above anything real
 * and far below anything that costs.
 */
export const MAX_PROOF_STEPS = 64;

/**
 * Recompute the root from a leaf plus its proof and compare against `root`.
 *
 * Every step is checked for shape before it is used. `side` in particular used
 * to be read as "right, or else left", so a step carrying any other value was
 * silently treated as a left sibling — a malformed proof would then be
 * evaluated rather than rejected.
 */
export async function verifyMerkleProof(leaf, proof, root, options = {}) {
  const { maxSteps = MAX_PROOF_STEPS } = options;

  if (!Array.isArray(proof)) throw new Error("a Merkle proof must be an array of steps");
  if (proof.length > maxSteps) {
    throw new Error(`Merkle proof has ${proof.length} steps, above the maximum of ${maxSteps}`);
  }

  let computed = leaf;
  for (const step of proof) {
    if (step === null || typeof step !== "object") {
      throw new Error("every Merkle proof step must be an object");
    }
    if (!(step.hash instanceof Uint8Array) || step.hash.length !== 32) {
      throw new Error("every Merkle proof step needs a 32-byte sibling hash");
    }
    if (step.side !== "left" && step.side !== "right") {
      throw new Error(`Merkle proof step has side "${step.side}", expected "left" or "right"`);
    }
    computed =
      step.side === "right"
        ? await nodeHash(computed, step.hash)
        : await nodeHash(step.hash, computed);
  }
  return equalBytes(computed, root);
}
