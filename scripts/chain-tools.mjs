/**
 * Shared pieces for the two one-off chain scripts (deploy, add-exporter).
 *
 * These are the steps the READMEs used to hand-wave as "Remix, Hardhat or
 * Foundry". The repository already carries a Solidity compiler and web3, so
 * the deployment an operator actually has to perform can be a command in this
 * repository, compiled from the same source the tests run against, rather than
 * a paste into a web IDE that may compile something subtly different.
 *
 * Both scripts spend real money on a real chain. Nothing here acts without
 * --confirm, and the dry run prints exactly what the confirmed run would do.
 */

import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

import { readSecret } from "../server/config.mjs";

const require = createRequire(import.meta.url);
export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** The deployed-bytecode ceiling every EVM chain enforces (EIP-170). */
export const CODE_SIZE_LIMIT = 24576;

/**
 * Compile Contract/ChunkedVerification.sol exactly as the tests do.
 *
 * Paris rather than the default: it keeps PUSH0 out of the bytecode, so the
 * result deploys on chains that have not adopted Shanghai. Changing this
 * silently makes the contract undeployable on some chains, which is why it is
 * spelled out in all three places rather than defaulted.
 */
export function compileContract() {
  const solc = require("solc");
  const source = fs.readFileSync(path.join(ROOT, "Contract/ChunkedVerification.sol"), "utf8");

  const output = JSON.parse(
    solc.compile(
      JSON.stringify({
        language: "Solidity",
        sources: { "ChunkedVerification.sol": { content: source } },
        settings: {
          optimizer: { enabled: true, runs: 200 },
          evmVersion: "paris",
          outputSelection: {
            "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] },
          },
        },
      })
    )
  );

  const errors = (output.errors || []).filter((entry) => entry.severity === "error");
  if (errors.length > 0) {
    throw new Error(errors.map((entry) => entry.formattedMessage).join("\n"));
  }

  const contract = output.contracts["ChunkedVerification.sol"].ChunkedVerification;
  const deployedSize = contract.evm.deployedBytecode.object.length / 2;
  if (deployedSize > CODE_SIZE_LIMIT) {
    throw new Error(
      `deployed bytecode is ${deployedSize} bytes, over the ${CODE_SIZE_LIMIT} limit — ` +
        "it would be rejected on deployment"
    );
  }

  return {
    abi: contract.abi,
    bytecode: "0x" + contract.evm.bytecode.object,
    deployedSize,
  };
}

/** `0x` + 40 hex, and not the zero address, which the contract rejects anyway. */
export function assertAddress(value, name) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new Error(`${name} must be a 20-byte hex address, got "${value}"`);
  }
  if (/^0x0{40}$/.test(value)) throw new Error(`${name} must not be the zero address`);
  return value;
}

/**
 * Read what both scripts need, and say plainly what is missing.
 *
 * The key is read with the gateway's own secret reader, so `_FILE` works here
 * too: an owner key pasted onto a command line is in the shell history of
 * whichever machine the deployment happened to be run from.
 */
export function readChainCli(env = process.env) {
  const missing = [];
  const rpcUrl = env.OREOCHAIN_CHAIN_RPC;
  if (!rpcUrl) missing.push("OREOCHAIN_CHAIN_RPC — the JSON-RPC endpoint to send through");

  const privateKey = readSecret(env, "OREOCHAIN_DEPLOY_KEY");
  if (!privateKey) {
    missing.push(
      "OREOCHAIN_DEPLOY_KEY — the private key to send from, which becomes the contract " +
        "owner (or OREOCHAIN_DEPLOY_KEY_FILE)"
    );
  }

  if (missing.length > 0) {
    throw new Error(`${missing.length} setting(s) are missing:\n  ` + missing.join("\n  "));
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) {
    throw new Error(
      `OREOCHAIN_DEPLOY_KEY must be a 0x-prefixed 32-byte hex private key (got ${privateKey.length} characters)`
    );
  }

  return { rpcUrl, privateKey, contractAddress: env.OREOCHAIN_CONTRACT_ADDRESS || null };
}

/** True only for an explicit --confirm. Everything else is a dry run. */
export function confirmed(argv = process.argv) {
  return argv.includes("--confirm");
}

/**
 * Refuse to send from an address with nothing to spend, with the amount named.
 *
 * Called at the point of sending rather than at connect, so a dry run still
 * prints the address and the gas estimate that tell you how much to send.
 */
export function assertFunded(chain, what) {
  if (chain.funded) return;
  console.error(
    `Cannot ${what}: ${chain.account.address} holds no native balance on chain ` +
      `${chain.chainId}. Fund it and re-run.`
  );
  process.exit(1);
}

/**
 * Refuse an address with no contract code at it, by name.
 *
 * The mistake this catches is pointing a script at the right address on the
 * wrong network, which the README already calls one of the two most likely.
 * Without it the call returns empty bytes, web3 tries to decode them, and the
 * operator gets "Parameter decoding error" — which names neither the address
 * nor the network nor the mistake.
 */
export async function assertContractAt(web3, address, chainId) {
  const code = await web3.eth.getCode(address);
  if (code && code !== "0x" && code !== "0x0") return;
  throw new Error(
    `no contract code at ${address} on chain ${chainId}. Either the address is wrong, ` +
      "or OREOCHAIN_CHAIN_RPC points at a different network from the one it was deployed to"
  );
}

/** Connect, and report enough that the operator can tell which chain this is. */
export async function connect({ rpcUrl, privateKey, web3Module }) {
  const { Web3 } = web3Module || (await import("web3"));
  const web3 = new Web3(rpcUrl);
  const account = web3.eth.accounts.privateKeyToAccount(privateKey);
  web3.eth.accounts.wallet.add(account);

  const [chainId, balance] = await Promise.all([
    web3.eth.getChainId(),
    web3.eth.getBalance(account.address),
  ]);

  /*
   * A zero balance is reported, not thrown.
   *
   * Throwing here meant neither script printed a line before it stopped, so
   * the one thing you go to a dry run for — which address to fund, and how
   * much gas this will take — was unavailable until after you had funded it.
   * The scripts refuse to *send* without a balance, which is where the
   * refusal belongs.
   */
  return {
    web3,
    account,
    chainId: Number(chainId),
    balance: String(balance),
    funded: BigInt(balance) > 0n,
  };
}
