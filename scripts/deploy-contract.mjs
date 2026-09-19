#!/usr/bin/env node
/**
 * Deploy Contract/ChunkedVerification.sol.
 *
 *   OREOCHAIN_CHAIN_RPC=… OREOCHAIN_DEPLOY_KEY=… node scripts/deploy-contract.mjs
 *   …                                             node scripts/deploy-contract.mjs --confirm
 *
 * Without --confirm it compiles, connects, and prints exactly what it would
 * do. With it, it deploys. The deploying account becomes the contract owner,
 * and is the only account that can authorise exporters afterwards — so it is
 * worth using a key you can still produce in a year.
 *
 * Needs a dev checkout: solc is a devDependency, deliberately, since nothing
 * in the running service compiles Solidity.
 */

import { compileContract, confirmed, connect, readChainCli } from "./chain-tools.mjs";

async function main() {
  let config;
  try {
    config = readChainCli(process.env);
  } catch (error) {
    console.error(`Cannot deploy: ${error.message}`);
    process.exit(1);
  }

  const contract = compileContract();
  console.log(`Compiled ChunkedVerification: ${contract.deployedSize} bytes of deployed code.`);

  let chain;
  try {
    chain = await connect(config);
  } catch (error) {
    console.error(`Cannot deploy: ${error.message}`);
    process.exit(1);
  }

  console.log(`Chain id:  ${chain.chainId}`);
  console.log(`Deployer:  ${chain.account.address} (becomes the owner)`);
  console.log(`Balance:   ${chain.balance} wei`);

  if (!confirmed()) {
    console.log("\nDry run. Re-run with --confirm to deploy. Nothing was sent.");
    return;
  }

  const deployment = new chain.web3.eth.Contract(contract.abi).deploy({
    data: contract.bytecode,
  });
  const gas = await deployment.estimateGas({ from: chain.account.address });

  console.log(`\nDeploying (gas estimate ${gas})…`);
  const deployed = await deployment.send({
    from: chain.account.address,
    gas: String(BigInt(Math.ceil(Number(gas) * 1.25))),
  });

  const address = deployed.options.address;
  console.log(`\nDeployed at ${address}`);
  console.log("\nNext, and easy to forget: the owner is not an exporter, so nothing can");
  console.log("register a document or anchor a batch until you authorise it.");
  console.log(`\n  OREOCHAIN_CONTRACT_ADDRESS=${address} \\`);
  console.log("  node scripts/add-exporter.mjs <address> \"what it is\" --confirm");
  console.log("\nAuthorise your uploading wallet and the anchoring worker's address.");
}

main().catch((error) => {
  console.error(`Deployment failed: ${error.message}`);
  process.exit(1);
});
