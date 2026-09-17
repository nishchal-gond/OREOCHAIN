import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const solc = require("solc");
import fs from "node:fs";

const source = fs.readFileSync(new URL("../Contract/ChunkedVerification.sol", import.meta.url), "utf8");
const out = JSON.parse(solc.compile(JSON.stringify({
  language: "Solidity",
  sources: { "ChunkedVerification.sol": { content: source } },
  settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "paris",
    outputSelection: { "*": { "*": ["abi"] } } },
})));
const abi = out.contracts["ChunkedVerification.sol"].ChunkedVerification.abi;

const header = `/**
 * ABI for Contract/ChunkedVerification.sol.
 *
 * Regenerate after changing the contract:
 *   npm run abi
 */
export const CHUNKED_VERIFICATION_ABI = `;

fs.writeFileSync(
  new URL("../js/contract-abi.js", import.meta.url),
  header + JSON.stringify(abi, null, 2) + ";\n"
);
console.log("wrote js/contract-abi.js —", abi.filter(x => x.type === "function").length, "functions,", abi.filter(x => x.type === "event").length, "events");
