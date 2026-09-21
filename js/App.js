/**
 * Wallet session, chain helpers and exporter administration.
 *
 * The chunked upload/retrieval pipeline lives in js/chunked-app.js; this file
 * covers everything around it — connecting MetaMask, reading the chain, and the
 * owner-only exporter management used by admin.html.
 *
 * Configuration (contract address, network, storage) comes from js/config.js.
 * Nothing secret is hardcoded here: the previous version of this file embedded
 * a live Pinata API key and secret in client-side JavaScript, which meant every
 * visitor could read them out of the page source.
 */

import { CHUNKED_VERIFICATION_ABI } from "./contract-abi.js";
import { html, joinHtml, safe, toHtml } from "./core/html.js";

const CONFIG = globalThis.OREOCHAIN_CONFIG || {};
const CONTRACT = {
  address: null,
  chainId: null,
  explorer: "https://polygonscan.com",
  /**
   * A read-only JSON-RPC endpoint, so the chain can be read without a wallet.
   *
   * Reading a document's record is not a privileged act and needs no account,
   * but until this existed the only provider the app could get was the one
   * MetaMask injects. That made verification — the one thing a stranger comes
   * here to do, holding a file someone sent them — require installing a wallet
   * first. It is also what lets a document anchored by the gateway be checked
   * by someone who has no wallet at all, which is the point of that path.
   */
  rpcUrl: null,
  ...(CONFIG.contract || {}),
};

window.CONTRACT = { ...CONTRACT, abi: CHUNKED_VERIFICATION_ABI };

const CHAIN_NAMES = {
  1: "Ethereum Mainnet",
  11155111: "Sepolia Test Network",
  137: "Polygon Mainnet",
  80002: "Polygon Amoy Test Network",
  56: "BNB Smart Chain",
  42161: "Arbitrum One",
  10: "OP Mainnet",
  8453: "Base",
  1337: "Local Development Chain",
  31337: "Hardhat / Anvil",
};

// ------------------------------------------------------------------- utilities

function el(id) {
  return document.getElementById(id);
}

function note(message, tone = "info") {
  const target = el("note");
  if (target) target.innerHTML = html`<h5 class="text-${tone} text-center">${message}</h5>`.value;
}

function configured() {
  return Boolean(CONTRACT.address) && !/^0x0+$/.test(CONTRACT.address);
}

/**
 * The best chain connection this browser can make.
 *
 * A wallet is needed to *write* — registering or revoking a document, managing
 * exporters. Everything else is a read, and a read only needs an RPC endpoint.
 * Preferring the wallet when there is one keeps a signed-in user on the
 * network they chose.
 *
 * @returns {{web3: object|null, wallet: boolean}} `wallet` is whether writes
 *   are possible, which is not the same as whether reads are.
 */
function connectChain() {
  if (window.ethereum) return { web3: new Web3(window.ethereum), wallet: true };
  if (CONTRACT.rpcUrl) return { web3: new Web3(CONTRACT.rpcUrl), wallet: false };
  return { web3: null, wallet: false };
}

/**
 * Say what is missing, on the pages where it matters.
 *
 * A page that only reads is not broken by the absence of a wallet, and telling
 * its visitor to install one is both wrong and the reason they leave. Pages
 * that write are marked with `data-needs-wallet` on <body>.
 */
function chainNotice(wallet, readable) {
  const alert = document.querySelector(".alert");
  if (!alert) return;

  const needsWallet = document.body.hasAttribute("data-needs-wallet");
  const link = safe(
    '<a target="_blank" rel="noopener" href="https://metamask.io/download">MetaMask</a>'
  );

  let message = null;
  if (!wallet && needsWallet) {
    message = html`This page needs a browser wallet to sign a transaction. Install ${link}.`;
  } else if (!readable) {
    message = safe(
      "No way to reach the chain: install a wallet, or set " +
        "<code>contract.rpcUrl</code> in <code>js/config.js</code> to a read-only " +
        "RPC endpoint."
    );
  }

  alert.classList.toggle("d-none", message === null);
  if (message) alert.innerHTML = toHtml(message);
}

export function truncateAddress(address) {
  if (!address || address.length < 16) return address || "";
  return `${address.slice(0, 7)}…${address.slice(-8)}`;
}

export function getTime() {
  return new Date().toISOString().replace("T", " ").slice(0, 19);
}

/** MetaMask reports custom errors as encoded data; translate the common ones. */
function readableError(error) {
  const text = `${(error && error.message) || error}`;
  if (text.includes("NotOwner")) return "Only the contract owner can do that.";
  if (text.includes("NotAuthorisedExporter")) return "This wallet is not an authorised exporter.";
  if (text.includes("NotDocumentOwner")) return "Only the exporter that registered this document can revoke it.";
  if (text.includes("AlreadyExists")) return "That entry already exists.";
  if (text.includes("DoesNotExist")) return "No such entry.";
  if (text.includes("User denied") || text.includes("user rejected")) return "Rejected in your wallet.";
  return text;
}

// -------------------------------------------------------------- wallet session

export async function connect() {
  if (!window.ethereum) {
    const alert = document.querySelector(".alert");
    if (alert) {
      alert.innerHTML =
        'Connecting needs a browser wallet. Install <a target="_blank" rel="noopener" ' +
        'href="https://metamask.io/download">MetaMask</a>.';
      alert.classList.remove("d-none");
    }
    return;
  }
  try {
    const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
    if (!accounts || accounts.length === 0) throw new Error("No account selected.");
    window.localStorage.setItem("userAddress", accounts[0]);
    window.location.reload();
  } catch (error) {
    note(readableError(error), "danger");
  }
}

export function disconnect() {
  window.userAddress = null;
  window.localStorage.removeItem("userAddress");
  window.location.reload();
}

export async function get_ChainID() {
  if (!window.web3) return null;
  const id = Number(await window.web3.eth.getChainId());
  window.chainID = CHAIN_NAMES[id] || `Chain ID ${id}`;

  const target = el("network");
  if (target) {
    const mismatch = CONTRACT.chainId && id !== Number(CONTRACT.chainId);
    target.innerHTML = html`<i class="fa-solid fa-circle-nodes mx-2 text-${
      mismatch ? "danger" : "info"
    }"></i>${window.chainID}${mismatch ? " — wrong network for this contract" : ""}`.value;
  }
  return id;
}

export async function get_ethBalance() {
  const target = el("userBalance");
  if (!target || !window.web3 || !window.userAddress) return;
  try {
    const balance = await window.web3.eth.getBalance(window.userAddress);
    const amount = Number(window.web3.utils.fromWei(balance, "ether")).toFixed(4);
    target.innerHTML = html`<i class="fa-brands fa-gg-circle mx-2 text-danger"></i>${amount}`.value;
  } catch {
    target.innerHTML = "n/a";
  }
}

// ------------------------------------------------------------------- contract

function contract() {
  if (!window.web3) throw new Error("web3 is not loaded — install MetaMask.");
  if (!configured()) {
    throw new Error(
      "No contract address configured. Copy js/config.example.js to js/config.js and set contract.address."
    );
  }
  return new window.web3.eth.Contract(CHUNKED_VERIFICATION_ABI, CONTRACT.address);
}

export async function getExporterInfo() {
  try {
    const result = await contract().methods.getExporter(window.userAddress).call();
    window.info = result[1] || result.info || "";
    const target = el("Exporter-info");
    if (target) {
      target.innerHTML = toHtml(
        window.info
          ? html`<i class="fa-solid fa-building-columns mx-2 text-warning"></i>${window.info}`
          : html`<i class="fa-solid fa-triangle-exclamation mx-2 text-warning"></i>Not an authorised exporter`
      );
    }
    return window.info;
  } catch (error) {
    console.error(error);
    return null;
  }
}

export async function getCounters() {
  try {
    const instance = contract();
    const [documents, exporters] = await Promise.all([
      instance.methods.documentCount().call(),
      instance.methods.exporterCount().call(),
    ]);
    const docs = el("num-hashes");
    const exps = el("num-exporters");
    if (docs)
      docs.innerHTML = html`<i class="fa-solid fa-file-lines mx-2 text-warning"></i>Documents: ${documents}`.value;
    if (exps)
      exps.innerHTML = html`<i class="fa-solid fa-users mx-2 text-warning"></i>Exporters: ${exporters}`.value;
  } catch (error) {
    console.error(error);
  }
}

async function adminAction(label, build) {
  const address = el("Exporter-address")?.value.trim();
  if (!window.web3?.utils.isAddress(address)) {
    note("Enter a valid wallet address.", "danger");
    return;
  }
  el("loader")?.classList.remove("d-none");
  note(`${label} — confirm in your wallet…`);
  try {
    await build(contract(), address).send({ from: window.userAddress });
    note(`${label} confirmed.`, "success");
    await getCounters();
  } catch (error) {
    note(readableError(error), "danger");
    console.error(error);
  } finally {
    el("loader")?.classList.add("d-none");
  }
}

export function addExporter() {
  const info = el("info")?.value.trim() || "";
  if (!info) {
    note("Enter the exporter's name or label.", "danger");
    return;
  }
  return adminAction("Adding exporter", (c, address) => c.methods.addExporter(address, info));
}

export function editExporter() {
  const info = el("info")?.value.trim() || "";
  if (!info) {
    note("Enter the new name or label.", "danger");
    return;
  }
  return adminAction("Updating exporter", (c, address) => c.methods.updateExporter(address, info));
}

export function deleteExporter() {
  return adminAction("Removing exporter", (c, address) => c.methods.removeExporter(address));
}

/**
 * Revoke a document's on-chain record.
 *
 * The hash is computed from the selected file with SHA-256 over its raw bytes,
 * matching js/core/chunker.js. The previous implementation read files as UTF-8
 * text, which corrupted every non-text byte before hashing.
 */
export async function deleteHash() {
  const file = el("doc-file")?.files?.[0];
  if (!file) {
    note("Choose the document to revoke.", "danger");
    return;
  }
  el("loader")?.classList.remove("d-none");
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    const fileHash =
      "0x" + Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");

    note("Confirm the transaction in your wallet…");
    await contract().methods.revokeDocument(fileHash).send({ from: window.userAddress });
    note(
      "Record revoked on-chain. Note that chunks already pinned off-chain are not deleted.",
      "success"
    );
  } catch (error) {
    note(readableError(error), "danger");
    console.error(error);
  } finally {
    el("loader")?.classList.add("d-none");
  }
}

/** Recent registrations, read from contract events. */
export async function listen() {
  const container = document.querySelector(".transactions");
  if (!container || !configured()) return;

  const loading = document.querySelector(".loading-tx");
  loading?.classList.remove("d-none");
  try {
    const latest = Number(await window.web3.eth.getBlockNumber());
    const events = await contract().getPastEvents("DocumentRegistered", {
      fromBlock: Math.max(0, latest - 50000),
      toBlock: "latest",
    });

    el("recent-header")?.classList.remove("d-none");
    /*
     * Every value in a card came off the chain, through whatever node the
     * page is talking to. Each card is built with the tag and the cards are
     * joined as safe values, so the joining does not launder them back into
     * an ordinary string.
     */
    const cards = events
      .slice(-12)
      .reverse()
      .map((event) => {
        const { fileHash, totalChunks, encrypted } = event.returnValues;
        return html`<div class="col-lg-5 tx-card p-3 m-2">
          <div class="text-break"><i class="fa-solid fa-hashtag mx-1"></i>${truncateAddress(
            fileHash
          )}</div>
          <div><i class="fa-solid fa-layer-group mx-1"></i>${totalChunks} chunks · ${
            encrypted ? "encrypted" : "public"
          }</div>
          <div><i class="fa-solid fa-cube mx-1"></i>Block ${event.blockNumber}</div>
          <a target="_blank" rel="noopener" href="${CONTRACT.explorer}/tx/${
            event.transactionHash
          }">View transaction</a>
        </div>`;
      });
    container.innerHTML = toHtml(joinHtml(cards));
  } catch (error) {
    console.error(error);
  } finally {
    loading?.classList.add("d-none");
  }
}

// ----------------------------------------------------------------- page set-up

window.addEventListener("load", async () => {
  document.querySelector(".loader-wraper")?.classList.add("d-none");
  el("loader")?.classList.add("d-none");
  document.querySelector(".transaction-status")?.classList.add("d-none");

  if (!configured()) {
    note(
      "No contract configured yet. Copy <code>js/config.example.js</code> to <code>js/config.js</code> and set your deployed contract address.",
      "warning"
    );
  }

  const { web3, wallet } = connectChain();
  if (web3) window.web3 = web3;
  window.hasWallet = wallet;
  chainNotice(wallet, Boolean(web3));

  /*
   * A page can stop needing a wallet part-way through. On the upload page the
   * user picks how their document reaches the chain, and only one of the two
   * choices signs anything — so the notice has to be re-asked rather than
   * decided once at load and left wrong for whichever choice they make next.
   */
  window.oreochainRefreshChainNotice = () => chainNotice(wallet, Boolean(web3));

  // Signing in is a wallet affair. Without one there is nobody to sign in as,
  // but the page can still read the chain, so it carries on rather than
  // returning here as it used to.
  window.userAddress = wallet ? window.localStorage.getItem("userAddress") : null;
  const signedIn = Boolean(window.userAddress && window.userAddress.length > 10);
  el("loginButton")?.classList.toggle("d-none", !wallet || signedIn);
  el("logoutButton")?.classList.toggle("d-none", !wallet || !signedIn);

  if (!web3) return;

  if (!signedIn) {
    // Reads that do not depend on an account still belong on the page.
    await get_ChainID();
    if (configured()) await listen();
    return;
  }

  const addressField = el("userAddress");
  if (addressField) {
    const explore = `${CONTRACT.explorer}/address/${window.userAddress}`;
    addressField.innerHTML = html`<i class="fa-solid fa-address-card mx-2 text-primary"></i>${truncateAddress(
      window.userAddress
    )} <a class="text-info" target="_blank" rel="noopener" href="${explore}"><i class="fa-solid fa-square-arrow-up-right text-warning"></i></a>`.value;
  }

  await get_ChainID();
  await get_ethBalance();
  if (configured()) {
    await getExporterInfo();
    if (location.pathname.endsWith("admin.html")) await getCounters();
    await listen();
  }
});

if (window.ethereum) {
  window.ethereum.on("accountsChanged", () => {
    window.localStorage.removeItem("userAddress");
    window.location.reload();
  });
  window.ethereum.on("chainChanged", () => window.location.reload());
}

// The pages use inline handlers, so these must be globals.
Object.assign(window, {
  connect,
  disconnect,
  addExporter,
  editExporter,
  deleteExporter,
  deleteHash,
  getCounters,
  getExporterInfo,
  get_ChainID,
  get_ethBalance,
  getTime,
  listen,
  truncateAddress,
});
