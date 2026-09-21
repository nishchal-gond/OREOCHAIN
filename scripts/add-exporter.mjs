#!/usr/bin/env node
/**
 * Authorise an address to register documents and anchor batches.
 *
 *   OREOCHAIN_CHAIN_RPC=… OREOCHAIN_DEPLOY_KEY=… OREOCHAIN_CONTRACT_ADDRESS=… \
 *   node scripts/add-exporter.mjs 0x… "anchor worker" --confirm
 *
 * The key must be the contract's owner. Without --confirm it checks and
 * reports; with it, it sends.
 *
 * This is the step that is easiest to miss and hardest to diagnose: without
 * it every registration and every anchor reverts with NotAuthorisedExporter,
 * having already cost gas.
 */

import { CHUNKED_VERIFICATION_ABI } from "../js/contract-abi.js";
import {
  assertAddress,
  assertContractAt,
  assertFunded,
  confirmed,
  connect,
  readChainCli,
} from "./chain-tools.mjs";

async function main() {
  const args = process.argv.slice(2).filter((arg) => arg !== "--confirm");
  const [target, info = "exporter"] = args;

  let config;
  try {
    config = readChainCli(process.env);
    if (!config.contractAddress) {
      throw new Error("OREOCHAIN_CONTRACT_ADDRESS — the deployed ChunkedVerification");
    }
    assertAddress(config.contractAddress, "OREOCHAIN_CONTRACT_ADDRESS");
    if (!target) throw new Error("usage: add-exporter.mjs <address> [info] [--confirm]");
    assertAddress(target, "the exporter address");
  } catch (error) {
    console.error(`Cannot authorise: ${error.message}`);
    process.exit(1);
  }

  let chain;
  try {
    chain = await connect(config);
  } catch (error) {
    console.error(`Cannot authorise: ${error.message}`);
    process.exit(1);
  }

  // Before any call, so the wrong-network mistake is named rather than
  // surfacing as a decoding error on empty return bytes.
  try {
    await assertContractAt(chain.web3, config.contractAddress, chain.chainId);
  } catch (error) {
    console.error(`Cannot authorise: ${error.message}`);
    process.exit(1);
  }

  const contract = new chain.web3.eth.Contract(
    CHUNKED_VERIFICATION_ABI,
    config.contractAddress
  );
  contract.handleRevert = true;

  const owner = await contract.methods.owner().call();
  if (owner.toLowerCase() !== chain.account.address.toLowerCase()) {
    console.error(
      `Cannot authorise: ${config.contractAddress} is owned by ${owner}, and ` +
        `OREOCHAIN_DEPLOY_KEY is ${chain.account.address}. Only the owner may add an exporter.`
    );
    process.exit(1);
  }

  if (await contract.methods.isExporter(target).call()) {
    console.log(`${target} is already an authorised exporter. Nothing to do.`);
    return;
  }

  console.log(`Chain id:  ${chain.chainId}`);
  console.log(`Contract:  ${config.contractAddress}`);
  console.log(`Owner:     ${chain.account.address}`);
  console.log(`Authorise: ${target} ("${info}")`);

  const method = contract.methods.addExporter(target, info);

  let gas = null;
  try {
    gas = await method.estimateGas({ from: chain.account.address });
    console.log(`Gas:       ${gas} (about ${(Number(gas) * 2e-9).toFixed(4)} ETH at 2 gwei)`);
  } catch (error) {
    console.log(`Gas:       could not be estimated (${error.message})`);
  }

  if (!confirmed()) {
    console.log("\nDry run. Re-run with --confirm to send. Nothing was sent.");
    if (!chain.funded) {
      console.log(`\n${chain.account.address} holds nothing on chain ${chain.chainId}.`);
      console.log("Fund it with at least the gas above before re-running with --confirm.");
    }
    return;
  }

  assertFunded(chain, "authorise");
  if (gas === null) gas = await method.estimateGas({ from: chain.account.address });

  const receipt = await method.send({
    from: chain.account.address,
    gas: String(BigInt(Math.ceil(Number(gas) * 1.25))),
  });

  console.log(`\nAuthorised in ${receipt.transactionHash} (block ${receipt.blockNumber}).`);
}

main().catch((error) => {
  console.error(`Authorisation failed: ${error.message}`);
  process.exit(1);
});
