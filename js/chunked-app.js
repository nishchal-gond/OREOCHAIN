/**
 * Browser controller for chunked upload and retrieval.
 *
 * All cryptography happens in this tab. Plaintext bytes, the passphrase and the
 * file key never leave the browser: what goes to the pinning service is already
 * encrypted, and what goes on-chain is two 32-byte hashes plus a manifest CID.
 *
 * Loaded as an ES module, so the handlers are published onto `window` for the
 * inline onclick/onchange attributes the pages use.
 */

import { to0x, utf8 } from "./core/bytes.js";
import { DEFAULT_CHUNK_SIZE } from "./core/chunker.js";
import { DEFAULT_KDF, describeKdf, kdfSpec } from "./core/kdf.js";
import {
  openManifest,
  packFile,
  readManifest,
  restoreFile,
  sealManifest,
} from "./core/manifest.js";
import { DEFAULT_SUITE, listSuites } from "./core/suites.js";
import { html, safe, toHtml } from "./core/html.js";
import { refusalAdvice } from "./core/refusals.js";
import { exportReceipt } from "./core/receipt.js";
import { createAdapterFromConfig, putAll } from "./storage/ipfs.js";
import { verifyInBatch } from "./core/anchor.js";
import {
  checkAnchor,
  checkReceipt,
  checkVerifyResponse,
  createProofClient,
} from "./storage/proofs.js";
import { CHUNKED_VERIFICATION_ABI } from "./contract-abi.js";

const DEFAULTS = {
  contract: {
    address: null,
    chainId: null,
    explorer: "https://polygonscan.com",
    // Read-only JSON-RPC, so retrieval and verification work without a wallet.
    // See js/App.js, which builds the provider.
    rpcUrl: null,
  },
  storage: { provider: "gateway" },
  /**
   * How a document gets onto the chain.
   *
   * "gateway" is what a user gets unless they ask otherwise: the service
   * receipts the document immediately and anchors a batch containing it in one
   * transaction it pays for. No wallet is involved anywhere in that story.
   *
   * "wallet" is the original path, kept and still offered: the user sends
   * registerDocument() themselves and pays the gas, which buys them a record
   * that names their own address and depends on no service at all.
   */
  anchoring: {
    mode: "gateway",
    /** How long the page keeps watching for the batch before saying so. */
    watchForMs: 600_000,
    pollIntervalMs: 5_000,
  },
  crypto: {
    suite: DEFAULT_SUITE,
    chunkSize: DEFAULT_CHUNK_SIZE,
    kdf: DEFAULT_KDF,
  },
};

function config() {
  const user = globalThis.OREOCHAIN_CONFIG || {};
  return {
    contract: { ...DEFAULTS.contract, ...(user.contract || {}) },
    storage: { ...DEFAULTS.storage, ...(user.storage || {}) },
    anchoring: { ...DEFAULTS.anchoring, ...(user.anchoring || {}) },
    crypto: { ...DEFAULTS.crypto, ...(user.crypto || {}) },
  };
}

// ------------------------------------------------------------------ UI helpers

function el(id) {
  return document.getElementById(id);
}

function say(message, tone = "info") {
  const note = el("note");
  if (note) note.innerHTML = html`<h5 class="text-${tone} text-center">${message}</h5>`.value;
  else console.log(`[OREOCHAIN] ${message}`);
}

function showProgress(done, total, label) {
  const bar = el("chunk-progress-bar");
  const wrap = el("chunk-progress");
  if (!bar || !wrap) return;
  wrap.classList.remove("d-none");
  const percent = total === 0 ? 0 : Math.round((done / total) * 100);
  bar.style.width = `${percent}%`;
  bar.textContent = `${label} ${done}/${total}`;
}

function hideProgress() {
  const wrap = el("chunk-progress");
  if (wrap) wrap.classList.add("d-none");
}

function busy(isBusy) {
  const loader = el("loader");
  if (loader) loader.classList.toggle("d-none", !isBusy);
  for (const id of ["chunked-upload-button", "chunked-retrieve-button", "chunked-verify-button"]) {
    const button = el(id);
    if (button) button.disabled = isBusy;
  }
}

/**
 * Hand the event loop one turn so pending DOM updates paint.
 *
 * Key derivation runs in a worker (js/core/kdf-worker.js), so the page stays
 * responsive. This remains for the fallback path — a browser without workers,
 * or a deployment where the worker script fails to load — where Argon2id runs
 * here and would otherwise freeze the tab before its own progress message had
 * a chance to render.
 */
function yieldToBrowser() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function humanSize(bytes) {
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

// ------------------------------------------------------------------- web3 glue

function contractInstance() {
  const { contract } = config();
  if (!globalThis.web3) {
    throw new Error(
      "No chain connection. Install a browser wallet, or set contract.rpcUrl in " +
        "js/config.js to a read-only RPC endpoint — reading a record needs no wallet."
    );
  }
  if (!contract.address || /^0x0+$/.test(contract.address)) {
    throw new Error(
      "No contract address configured. Copy js/config.example.js to js/config.js and set contract.address."
    );
  }
  return new globalThis.web3.eth.Contract(CHUNKED_VERIFICATION_ABI, contract.address);
}

function currentAccount() {
  const address = globalThis.userAddress;
  if (!address || address === "null" || address.length < 10) {
    throw new Error("Connect your wallet first.");
  }
  return address;
}

/** MetaMask surfaces custom errors as raw data; make the common ones readable. */
function explainChainError(error) {
  const refusal = explainRefusal(error);
  if (refusal) return refusal;

  const text = `${error && error.message}`;
  if (text.includes("NotAuthorisedExporter")) {
    return "This wallet is not an authorised exporter. Ask the contract owner to add it.";
  }
  if (text.includes("AlreadyExists")) {
    return "This exact document is already registered on-chain.";
  }
  if (text.includes("User denied") || text.includes("user rejected")) {
    return "Transaction rejected in your wallet.";
  }
  return text;
}

/**
 * What to tell the user when the gateway refused, in their terms.
 *
 * Two of these are not failures the user can do anything about by pressing the
 * button again, and saying so is the whole point: over your own allowance is a
 * wait, the service being out of budget for the day is not the user's doing at
 * all. In both cases nothing was stored and nothing is retrying quietly in the
 * background, which is the sentence people actually need.
 *
 * The wording comes from the code, never from the gateway's prose — that text
 * is written for operators and is free to change.
 */
function explainRefusal(error) {
  const advice = refusalAdvice(error && error.code);
  if (!advice) return null;

  let message = advice.message;
  if (typeof error.retryAfterMs === "number" && error.retryAfterMs > 0) {
    message += ` ${describeWait(error.retryAfterMs)}`;
  }
  return message;
}

function describeWait(ms) {
  const seconds = Math.ceil(ms / 1000);
  if (seconds < 90) return `Try again in about ${seconds} seconds.`;
  const minutes = Math.ceil(seconds / 60);
  if (minutes < 90) return `Try again in about ${minutes} minutes.`;
  return `Try again in about ${Math.ceil(minutes / 60)} hours.`;
}

// ---------------------------------------------------------------------- upload

async function readSelectedFile(inputId = "doc-file") {
  const input = el(inputId);
  const file = input && input.files && input.files[0];
  if (!file) throw new Error("Choose a file first.");
  return { file, bytes: new Uint8Array(await file.arrayBuffer()) };
}

function selectedSuite() {
  const picker = el("cipher-suite");
  return (picker && picker.value) || config().crypto.suite;
}

function selectedPassphrase(inputId = "passphrase") {
  const input = el(inputId);
  const value = input ? input.value : "";
  return value && value.length > 0 ? value : null;
}

/**
 * Which path this upload takes to the chain.
 *
 * The page offers both; the default is the one that asks nothing of the user.
 */
function anchorMode() {
  const chosen = document.querySelector('input[name="anchor-mode"]:checked');
  if (chosen && chosen.value) return chosen.value;
  return config().anchoring.mode;
}

/**
 * Chunk, encrypt and upload every chunk plus the manifest, then get the
 * document onto the chain by whichever path the user chose.
 */
export async function uploadChunked() {
  busy(true);
  try {
    const { crypto: cryptoConfig, contract: contractConfig, storage } = config();
    const mode = anchorMode();
    const { file, bytes } = await readSelectedFile();
    const passphrase = selectedPassphrase();
    const suite = selectedSuite();

    if (storage.provider !== "pinata") {
      throw new Error(
        "Uploading needs a pinning service. Set storage.provider to \"pinata\" in js/config.js."
      );
    }

    // Fail before doing the expensive part. Sealing a gigabyte and uploading
    // it, then discovering there is no wallet to register it with, wastes the
    // user's time and the service's bandwidth.
    const account = mode === "wallet" ? currentAccount() : null;
    const contract = mode === "wallet" ? contractInstance() : null;

    if (passphrase) {
      say(
        `Deriving your key with ${describeKdf(cryptoConfig.kdf)}, then encrypting ` +
          `${humanSize(bytes.length)} with ${suite}…`
      );
      // Derivation normally runs in a worker and leaves this thread free. The
      // yield only matters on the fallback path, where it lets the message
      // above paint before Argon2id takes the thread.
      await yieldToBrowser();
    } else {
      say(`Chunking ${humanSize(bytes.length)} (unencrypted — no passphrase given)…`);
    }

    const packed = await packFile(bytes, {
      fileName: file.name,
      mimeType: file.type || "application/octet-stream",
      passphrase,
      suite,
      chunkSize: cryptoConfig.chunkSize,
      kdf: cryptoConfig.kdf,
      onProgress: (done, total) => showProgress(done, total, "sealed"),
    });

    say(`Uploading ${packed.totalChunks} chunks…`);
    const adapter = createAdapterFromConfig({ storage });
    const locations = await putAll(adapter, packed.chunks, {
      concurrency: 4,
      namePrefix: `${packed.fileHashHex.slice(0, 10)}-chunk`,
      onProgress: (done, total) => showProgress(done, total, "uploaded"),
    });

    say("Uploading manifest…");
    const manifest = await sealManifest(packed, locations);
    const manifestCID = await adapter.put(
      utf8(JSON.stringify(manifest)),
      `${packed.fileHashHex.slice(0, 10)}-manifest.json`
    );

    hideProgress();

    if (mode === "wallet") {
      say("Confirm the transaction in your wallet…");
      const receipt = await contract.methods
        .registerDocument(
          packed.fileHashHex,
          packed.merkleRootHex,
          manifestCID,
          packed.totalChunks,
          packed.fileSize,
          packed.encrypted
        )
        .send({ from: account });

      renderUploadResult({ packed, manifestCID, receipt, explorer: contractConfig.explorer });
      say("Registered on-chain. Keep your passphrase safe — it cannot be recovered.", "success");
      return { manifest, manifestCID, receipt, mode };
    }

    const issued = await anchorViaGateway(packed, manifestCID);
    return { manifest, manifestCID, mode, ...issued };
  } catch (error) {
    hideProgress();
    say(explainChainError(error), "danger");
    console.error(error);
    throw error;
  } finally {
    busy(false);
  }
}

/**
 * The default path: the service receipts the document now and anchors it in a
 * batch shortly afterwards.
 *
 * The user gets something in their hand at the first step. Everything after
 * that is the page watching the chain on their behalf, and it is written so
 * that closing the tab costs them nothing — the receipt they already hold
 * names the document, and verify.html can pick the story up at any point.
 */
async function anchorViaGateway(packed, manifestCID) {
  const client = createProofClient();

  say("Getting your receipt from the service…");
  const { receipt, pending } = await client.record({
    fileHash: packed.fileHashHex,
    merkleRoot: packed.merkleRootHex,
    manifestCID,
    fileSize: packed.fileSize,
    totalChunks: packed.totalChunks,
    encrypted: packed.encrypted,
    suite: packed.encrypted ? packed.suite : null,
  });

  // Checked here, in this tab, before it is shown as anything. A receipt the
  // page displays without verifying is a picture of a receipt.
  const checked = await checkReceipt(receipt, client);

  renderReceipt({ packed, manifestCID, receipt, checked, pending });
  offerReceiptDownload(receipt, packed.fileHashHex);

  if (!checked.valid) {
    say(`The service issued a receipt this page could not verify: ${checked.reason}`, "danger");
  } else {
    say(
      "Stored and receipted. Keep your passphrase safe — it cannot be recovered.",
      "success"
    );
  }

  // Deliberately not awaited: the receipt is the deliverable and it is already
  // on screen. Anchoring takes as long as the next batch takes, and blocking
  // the button on it would make a finished upload look unfinished.
  watchForAnchor(client, receipt, packed.fileHashHex).catch((error) => {
    console.error(error);
    setAnchorState(
      "pending",
      `Could not check for the anchor: ${explainChainError(error)} Your receipt is unaffected.`
    );
  });

  return { receipt, checked };
}

/**
 * Poll until the document's batch is anchored, then verify it against the
 * chain rather than taking the gateway's word for it.
 */
async function watchForAnchor(client, receipt, fileHash) {
  const { anchoring } = config();
  const deadline = Date.now() + anchoring.watchForMs;

  while (Date.now() < deadline) {
    const inclusion = await client.inclusion(fileHash);

    // An inclusion proof with no transaction is a batch that has been built
    // but not yet sent — further along than "queued", still not anchored.
    if (inclusion && inclusion.txHash) {
      await confirmAnchor(receipt, inclusion);
      return;
    }
    if (inclusion) setAnchorState("pending", "Your document is in the next batch to be anchored.");

    await new Promise((resolve) => setTimeout(resolve, anchoring.pollIntervalMs));
  }

  setAnchorState(
    "pending",
    "Not anchored yet — batches are anchored periodically and this one is still waiting. " +
      "Your receipt already covers the document; check again on the verify page whenever you like."
  );
}

/**
 * Read the batch root from the chain and check the inclusion proof against it.
 *
 * The root has to come from the chain. Verifying the gateway's Merkle path
 * against the gateway's own root proves only that the gateway can hash.
 */
async function confirmAnchor(receipt, inclusion) {
  const { contract: contractConfig } = config();

  let onChainRoot = null;
  try {
    const batch = await contractInstance().methods.findBatch(inclusion.batchRoot).call();
    const blockNumber = Number(batch.blockNumber ?? batch[0]);
    if (blockNumber > 0) onChainRoot = String(inclusion.batchRoot).toLowerCase();
  } catch (error) {
    // No wallet and no rpcUrl, or the chain is unreachable. Say that, rather
    // than passing the gateway's claim off as a confirmation.
    console.error(error);
    setAnchorState(
      "pending",
      "The service says this document is anchored, but this page cannot reach the chain to " +
        "confirm it. Set contract.rpcUrl in js/config.js, or check it on the verify page."
    );
    return;
  }

  if (!onChainRoot) {
    setAnchorState(
      "pending",
      "The service has published an inclusion proof, but its batch root is not on the chain " +
        "yet. The transaction may still be confirming."
    );
    return;
  }

  const result = await checkAnchor(receipt, inclusion, onChainRoot);

  if (result.disputed) {
    setAnchorState(
      "disputed",
      `The anchor on-chain does not describe the document in your receipt: ${result.reason}. ` +
        `Keep your receipt — it is the evidence.`
    );
    return;
  }
  if (!result.anchored) {
    setAnchorState("pending", `The inclusion proof did not check out: ${result.reason}`);
    return;
  }

  /*
   * Built with the tag, not concatenated: a safe value survives being
   * interpolated into another safe template, and a plain string does not
   * survive being concatenated onto one. The transaction hash comes off the
   * chain and goes inside an href, which is the interpolation that most wants
   * escaping on this page.
   */
  const link = result.txHash
    ? html` <a target="_blank" rel="noopener" href="${contractConfig.explorer}/tx/${result.txHash}">View the transaction</a>`
    : "";
  setAnchorState(
    "anchored",
    html`Anchored on-chain in block ${result.block ?? "—"}, verified in this browser against the batch root read from the chain.${link}`
  );
}

/** The three states the user sees, and nothing in between. */
function setAnchorState(state, message) {
  const node = el("anchor-state");
  if (!node) return;

  const label = {
    receipted: ["Receipt issued", "info"],
    pending: ["Anchoring pending", "warning"],
    anchored: ["Anchored on-chain", "success"],
    disputed: ["Does not match", "danger"],
  }[state] || ["Anchoring pending", "warning"];

  node.className = `p-2 info alert alert-${label[1]} my-2`;
  node.dataset.state = state;
  node.innerHTML = html`<strong>${label[0]}.</strong> ${message}`.value;
}

function renderReceipt({ packed, manifestCID, receipt, checked, pending }) {
  const set = (id, markup) => {
    const node = el(id);
    if (node) node.innerHTML = toHtml(markup);
  };

  const status = document.querySelector(".transaction-status");
  if (status) status.classList.remove("d-none");

  const statement = receipt.statement;
  set("file-hash", html`<i class="fa-solid fa-hashtag mx-1"></i>${statement.fileHash}`);
  set("merkle-root", html`<i class="fa-solid fa-sitemap mx-1"></i>${statement.merkleRoot}`);
  set("manifest-cid", html`<i class="fa-solid fa-box mx-1"></i>${manifestCID}`);
  set(
    "chunk-summary",
    html`<i class="fa-solid fa-layer-group mx-1"></i>${packed.totalChunks} chunks · ${humanSize(
      packed.fileSize
    )} · ${packed.encrypted ? packed.suite : "unencrypted"}`
  );
  set("time-stamps", html`<i class="fa-solid fa-clock mx-1"></i>${statement.issuedAt}`);

  if (checked.valid) {
    /*
     * Worth one honest sentence rather than a green tick. The signature check
     * says these bytes are the ones the service signed; it does not say the
     * service is honest, and the anchor is what settles that.
     */
    const ephemeral = checked.ephemeral
      ? " This service is running with a temporary signing key, so this receipt stops being " +
        "checkable when it restarts — the anchor is what will last."
      : "";
    setAnchorState(
      "receipted",
      `The service signed for this exact document, and this page checked that signature.` +
        ` It is not yet on the chain.${ephemeral}`
    );
  } else if (checked.forged) {
    setAnchorState("disputed", checked.reason);
  } else {
    setAnchorState("pending", `Receipt issued, but not verified here: ${checked.reason}`);
  }

  if (typeof pending === "number" && pending > 0) {
    set("blockNumber", html`<i class="fa-solid fa-layer-group mx-1"></i>${pending} waiting to anchor`);
  }

  const url = `${location.origin}${location.pathname.replace(
    /[^/]*$/,
    "retrieve.html"
  )}?hash=${statement.fileHash}`;

  const share = el("share-link");
  if (share) {
    share.href = url;
    share.textContent = url;
  }

  renderShareQr(url);
}

/**
 * Hand the receipt over as a file.
 *
 * It is the user's only copy of the service's signature, and it has to outlive
 * this tab: the batch is anchored minutes later, the browser holds nothing,
 * and a receipt that exists only on screen is one refresh from gone.
 */
function offerReceiptDownload(receipt, fileHash) {
  const link = el("receipt-download");
  if (!link) return;

  const blob = new Blob([exportReceipt(receipt)], { type: "application/json" });
  if (link.href && link.href.startsWith("blob:")) URL.revokeObjectURL(link.href);
  link.href = URL.createObjectURL(blob);
  link.download = `oreochain-receipt-${fileHash.slice(2, 14)}.json`;
  link.classList.remove("d-none");
}

function renderUploadResult({ packed, manifestCID, receipt, explorer }) {
  const set = (id, markup) => {
    const node = el(id);
    if (node) node.innerHTML = toHtml(markup);
  };

  const status = document.querySelector(".transaction-status");
  if (status) status.classList.remove("d-none");

  set(
    "transaction-hash",
    html`<i class="fa fa-check-circle mx-1"></i><a target="_blank" rel="noopener" href="${explorer}/tx/${receipt.transactionHash}">${receipt.transactionHash}</a>`
  );
  set("file-hash", html`<i class="fa-solid fa-hashtag mx-1"></i>${packed.fileHashHex}`);
  set("merkle-root", html`<i class="fa-solid fa-sitemap mx-1"></i>${packed.merkleRootHex}`);
  set("manifest-cid", html`<i class="fa-solid fa-box mx-1"></i>${manifestCID}`);
  set(
    "chunk-summary",
    html`<i class="fa-solid fa-layer-group mx-1"></i>${packed.totalChunks} chunks · ${humanSize(
      packed.fileSize
    )} · ${packed.encrypted ? packed.suite : "unencrypted"}`
  );
  set("blockNumber", html`<i class="fa-solid fa-cube mx-1"></i>${receipt.blockNumber}`);
  set("time-stamps", html`<i class="fa-solid fa-clock mx-1"></i>${new Date().toISOString()}`);

  const url = `${location.origin}${location.pathname.replace(
    /[^/]*$/,
    "retrieve.html"
  )}?hash=${packed.fileHashHex}`;

  const share = el("share-link");
  if (share) {
    share.href = url;
    share.textContent = url;
  }

  renderShareQr(url);
}

/** A scannable link straight to this document's retrieval page. */
function renderShareQr(url) {
  const target = el("qrcode");
  if (!target || typeof QRCode === "undefined") return;

  target.innerHTML = "";
  new QRCode(target, {
    text: url,
    width: 180,
    height: 180,
    correctLevel: QRCode.CorrectLevel.M,
  });

  // qrcodejs renders a canvas where it can and an <img> fallback otherwise.
  const link = el("download-link");
  if (!link) return;
  const canvas = target.querySelector("canvas");
  const image = target.querySelector("img");
  const source = canvas ? canvas.toDataURL("image/png") : image && image.src;
  if (source) {
    link.href = source;
    link.classList.remove("d-none");
  }
}

// -------------------------------------------------------------------- retrieve

/**
 * Look a document up on-chain by its plaintext hash, fetch and verify every
 * chunk, decrypt, reassemble and hand the user the file.
 */
export async function retrieveChunked() {
  busy(true);
  try {
    const fileHash = (el("lookup-hash") ? el("lookup-hash").value.trim() : "").toLowerCase();
    if (!/^0x[0-9a-f]{64}$/.test(fileHash)) {
      throw new Error("Enter the document's 0x-prefixed 64-character file hash.");
    }

    const { contract: contractConfig, storage } = config();
    const contract = contractInstance();

    say("Reading the on-chain record…");
    const record = await contract.methods.findDocument(fileHash).call();
    const blockNumber = Number(record.blockNumber ?? record[0]);
    if (blockNumber === 0) {
      say("No record for that hash — this document is not registered.", "danger");
      renderRetrieveStatus(null);
      return null;
    }

    const onChain = {
      blockNumber,
      timestamp: Number(record.timestamp ?? record[1]),
      merkleRoot: (record.merkleRoot ?? record[2]).toLowerCase(),
      manifestCID: record.manifestCID ?? record[3],
      totalChunks: Number(record.totalChunks ?? record[4]),
      fileSize: Number(record.fileSize ?? record[5]),
      encrypted: Boolean(record.encrypted ?? record[6]),
      exporter: record.exporter ?? record[7],
      info: record.info ?? record[8],
    };
    renderRetrieveStatus(onChain, fileHash, contractConfig.explorer);

    const adapter = createAdapterFromConfig({ storage });

    say("Fetching manifest…");
    const manifestBytes = await adapter.get(onChain.manifestCID);
    // readManifest validates before anything trusts a field. The manifest came
    // from storage, so whoever can serve that CID wrote every value in it.
    const manifest = readManifest(manifestBytes);

    if (manifest.merkleRoot.toLowerCase() !== onChain.merkleRoot) {
      throw new Error(
        "The manifest's Merkle root does not match the on-chain record — this manifest was substituted."
      );
    }

    const passphrase = selectedPassphrase("retrieve-passphrase");
    if (manifest.encrypted && !passphrase) {
      throw new Error("This document is encrypted. Enter its passphrase.");
    }

    if (manifest.encrypted) {
      say(`Deriving your key with ${describeKdf(manifest.kdf)}…`);
      await yieldToBrowser();
    }
    const opened = await openManifest(manifest, passphrase);

    say(`Fetching and verifying ${manifest.totalChunks} chunks…`);
    const restored = await restoreFile(
      manifest,
      opened,
      (location) => adapter.get(location),
      {
        expectedMerkleRoot: onChain.merkleRoot,
        onProgress: (done, total) => showProgress(done, total, "verified"),
      }
    );

    hideProgress();
    offerDownload(restored);
    say(
      `Verified. Every one of ${manifest.totalChunks} chunks matched the root anchored on-chain.`,
      "success"
    );
    return restored;
  } catch (error) {
    hideProgress();
    say(explainChainError(error), "danger");
    console.error(error);
    throw error;
  } finally {
    busy(false);
  }
}

function renderRetrieveStatus(onChain, fileHash, explorer) {
  const set = (id, markup) => {
    const node = el(id);
    if (node) node.innerHTML = toHtml(markup);
  };
  const status = document.querySelector(".transaction-status");
  if (status) status.classList.toggle("d-none", !onChain);
  if (!onChain) return;

  set(
    "doc-status",
    html`<h3 class="text-info">Registered on-chain <i class="fa fa-check-circle"></i></h3>`
  );
  set("file-hash", html`<i class="fa-solid fa-hashtag mx-1"></i>${fileHash}`);
  set("merkle-root", html`<i class="fa-solid fa-sitemap mx-1"></i>${onChain.merkleRoot}`);
  set("manifest-cid", html`<i class="fa-solid fa-box mx-1"></i>${onChain.manifestCID}`);
  set(
    "chunk-summary",
    html`<i class="fa-solid fa-layer-group mx-1"></i>${onChain.totalChunks} chunks · ${humanSize(
      onChain.fileSize
    )} · ${onChain.encrypted ? "encrypted" : "public"}`
  );
  set("blockNumber", html`<i class="fa-solid fa-cube mx-1"></i>${onChain.blockNumber}`);
  set(
    "time-stamps",
    html`<i class="fa-solid fa-clock mx-1"></i>${new Date(onChain.timestamp * 1000).toUTCString()}`
  );
  set("college-name", html`<i class="fa-solid fa-building-columns mx-1"></i>${onChain.info}`);
  set(
    "exporter-address",
    html`<i class="fa-solid fa-user-shield mx-1"></i><a target="_blank" rel="noopener" href="${explorer}/address/${onChain.exporter}">${onChain.exporter}</a>`
  );
}

function offerDownload(restored) {
  const link = el("download-document");
  if (!link) return;
  const blob = new Blob([restored.bytes], { type: restored.mimeType });
  if (link.dataset.objectUrl) URL.revokeObjectURL(link.dataset.objectUrl);
  const url = URL.createObjectURL(blob);
  link.dataset.objectUrl = url;
  link.href = url;
  link.download = restored.fileName;
  link.textContent = `Download ${restored.fileName}`;
  link.classList.remove("d-none");
  link.style.display = "";
}

/**
 * Check whether a file is registered, without downloading anything.
 *
 * The file is hashed locally and looked up on-chain. This proves the document
 * matches a registered record; it does not need the passphrase, the manifest or
 * any chunk, so it works for encrypted documents you are not entitled to read.
 */
export async function verifyRegistration() {
  busy(true);
  try {
    let fileHash = (el("lookup-hash") ? el("lookup-hash").value.trim() : "").toLowerCase();

    if (!/^0x[0-9a-f]{64}$/.test(fileHash)) {
      const { bytes } = await readSelectedFile();
      say("Hashing the file locally…");
      const packed = await packFile(bytes, { chunkSize: config().crypto.chunkSize });
      fileHash = packed.fileHashHex;
      const field = el("lookup-hash");
      if (field) field.value = fileHash;
    }

    const { contract: contractConfig } = config();

    /*
     * No wallet and no rpcUrl: there is no chain to read, and
     * contractInstance() would throw before anything useful happened. Ask the
     * gateway for its materials instead and report exactly how far they get,
     * which is short of a verification and says so.
     */
    if (!globalThis.web3) {
      const offline = await verifyWithoutChain(createProofClient(), fileHash);
      if (offline) return offline;
      return notRegistered(fileHash);
    }

    const record = await contractInstance().methods.findDocument(fileHash).call();
    const blockNumber = Number(record.blockNumber ?? record[0]);

    if (blockNumber === 0) {
      /*
       * No per-document record — but that is only one of the two ways a
       * document reaches the chain, and it is not the default one. A document
       * anchored by the service is a leaf in a batch, so the question is
       * whether its inclusion proof reaches a batch root the chain holds.
       *
       * Without this, every document uploaded the ordinary way reads here as
       * "not registered", which is both wrong and the worst possible thing to
       * tell someone checking a document they were sent.
       */
      const batched = await verifyViaBatch(fileHash);
      if (batched) return batched;

      return notRegistered(fileHash);
    }

    renderRetrieveStatus(
      {
        blockNumber,
        timestamp: Number(record.timestamp ?? record[1]),
        merkleRoot: (record.merkleRoot ?? record[2]).toLowerCase(),
        manifestCID: record.manifestCID ?? record[3],
        totalChunks: Number(record.totalChunks ?? record[4]),
        fileSize: Number(record.fileSize ?? record[5]),
        encrypted: Boolean(record.encrypted ?? record[6]),
        exporter: record.exporter ?? record[7],
        info: record.info ?? record[8],
      },
      fileHash,
      contractConfig.explorer
    );
    say("Verified — this file matches a document registered on-chain.", "success");
    return { registered: true, fileHash };
  } catch (error) {
    say(explainChainError(error), "danger");
    console.error(error);
    throw error;
  } finally {
    busy(false);
  }
}

/**
 * Check a document against a batch anchored on-chain.
 *
 * Returns a rendered result, or null when there is nothing to show — no
 * inclusion proof, or a proof for a batch that is not on the chain yet — so
 * the caller can fall through to its own "not registered" answer.
 *
 * Every judgement here is made in this browser. The gateway supplies the
 * Merkle path and the batch root it claims; the root is then read from the
 * chain and the path checked against that. A gateway that lies about either
 * fails the check.
 */
async function verifyViaBatch(fileHash) {
  const { contract: contractConfig } = config();

  const client = createProofClient();

  /*
   * With no way to reach the chain there is nothing to check a root against,
   * so the page asks the gateway for everything it has and reports exactly
   * how far that gets — which is short of proof, and says so.
   */
  if (!globalThis.web3) return verifyWithoutChain(client, fileHash);

  let inclusion;
  try {
    inclusion = await client.inclusion(fileHash);
  } catch (error) {
    // The gateway being unreachable is not evidence of anything about the
    // document, so it must not turn into a verdict either way.
    console.error(error);
    return null;
  }
  if (!inclusion || !inclusion.txHash) return null;

  /*
   * The chain read. findBatch() is keyed on the root, so a non-zero block
   * number is the chain itself saying it holds that exact root — there is no
   * way for the gateway to name a root the chain does not have and still pass
   * here. That is what makes the Merkle check below worth anything.
   */
  const batch = await contractInstance().methods.findBatch(inclusion.batchRoot).call();
  if (Number(batch.blockNumber ?? batch[0]) === 0) return null;

  /*
   * verifyInBatch() rather than checkAnchor(): there is no receipt here. A
   * stranger checking a document they were sent holds only the file. The
   * cross-check between a receipt and an anchor needs the receipt, and
   * inventing one from the inclusion proof would compare the gateway's claim
   * against itself and call the result agreement.
   */
  const result = await verifyInBatch(inclusion, inclusion.batchRoot);
  const status = document.querySelector(".transaction-status");
  if (status) status.classList.remove("d-none");

  const set = (id, markup) => {
    const node = el(id);
    if (node) node.innerHTML = toHtml(markup);
  };
  set("file-hash", html`<i class="fa-solid fa-hashtag mx-1"></i>${fileHash}`);

  if (!result.valid) {
    set(
      "doc-status",
      safe('<h3 class="text-danger">Does not check out <i class="fa fa-times-circle"></i></h3>')
    );
    say(`An anchor exists for this hash but did not verify: ${result.reason}`, "danger");
    return { registered: false, anchored: false, fileHash, reason: result.reason };
  }

  set(
    "doc-status",
    safe('<h3 class="text-success">Anchored on-chain <i class="fa fa-check-circle"></i></h3>')
  );
  set("merkle-root", html`<i class="fa-solid fa-sitemap mx-1"></i>${inclusion.document.merkleRoot}`);
  set("manifest-cid", html`<i class="fa-solid fa-box mx-1"></i>${inclusion.document.manifestCID}`);
  set("blockNumber", html`<i class="fa-solid fa-cube mx-1"></i>${inclusion.block ?? "—"}`);
  set(
    "exporter-address",
    html`<i class="fa-solid fa-link mx-1"></i><a target="_blank" rel="noopener"
      href="${contractConfig.explorer}/tx/${inclusion.txHash}">${inclusion.txHash}</a>`
  );
  set(
    "chunk-summary",
    html`<i class="fa-solid fa-layer-group mx-1"></i>in a batch of ${Number(batch.size ?? batch[2])} documents`
  );

  say(
    "Verified — this file is committed to by a batch anchored on-chain, checked in this browser.",
    "success"
  );
  return { registered: true, anchored: true, fileHash, batchRoot: inclusion.batchRoot };
}

/**
 * The user changed how the document should reach the chain.
 *
 * Only the wallet path signs anything, so only that choice makes the page one
 * that needs a wallet. Leaving the demand up permanently is what the default
 * path exists to get rid of.
 */
export function anchorModeChanged() {
  document.body.toggleAttribute("data-needs-wallet", anchorMode() === "wallet");
  if (typeof window.oreochainRefreshChainNotice === "function") {
    window.oreochainRefreshChainNotice();
  }
}

/**
 * The plainest answer there is: nothing anywhere knows this document.
 *
 * Shared by both paths on purpose. A fallback that softens "no" into "could
 * not say" would be worse than having no fallback at all, so there is one
 * rendering of it and every path ends at the same one.
 */
function notRegistered(fileHash) {
  renderRetrieveStatus(null);
  const status = document.querySelector(".transaction-status");
  if (status) status.classList.remove("d-none");
  const label = el("doc-status");
  if (label) {
    label.innerHTML =
      '<h3 class="text-danger">Not registered <i class="fa fa-times-circle"></i></h3>';
  }
  const hashField = el("file-hash");
  if (hashField)
    hashField.innerHTML = html`<i class="fa-solid fa-hashtag mx-1"></i>${fileHash}`.value;
  say("This file does not match any registered document.", "danger");
  return { registered: false, fileHash };
}

/**
 * What can be said about a document when this page cannot read the chain.
 *
 * Less than the page would like, and the wording has to carry that. The
 * signature and the Merkle path are checked here, in this tab, and they
 * settle that the service signed for this exact document and that its own
 * records agree with themselves. They do not settle that anything was
 * anchored: the root came from the service too.
 *
 * So this never renders as verified, whatever `gatewayClaim` says. It names
 * what was checked, names what was not, and hands over the transaction to
 * look at — which is a useful answer, and an honest one.
 */
async function verifyWithoutChain(client, fileHash) {
  let body;
  try {
    body = await client.verify(fileHash);
  } catch (error) {
    console.error(error);
    return null;
  }

  const checked = await checkVerifyResponse(body, client);
  const status = checked.gatewayStatus;

  // No record anywhere is the caller's own "not registered" answer, not ours.
  if (status === "unknown" || (!body.receipt && !body.batch)) return null;

  const panel = document.querySelector(".transaction-status");
  if (panel) panel.classList.remove("d-none");
  const set = (id, markup) => {
    const node = el(id);
    if (node) node.innerHTML = toHtml(markup);
  };
  set("file-hash", html`<i class="fa-solid fa-hashtag mx-1"></i>${fileHash}`);

  // The one message on this page whose markup is deliberate. It is written
  // here, interpolates nothing, and passes through the tag intact below.
  const hint = safe(
    "This page has no read-only RPC endpoint configured, so it cannot check the chain " +
      "itself. Set <code>contract.rpcUrl</code> in <code>js/config.js</code> to get a full " +
      "verification here."
  );

  // A chain the gateway could not reach says nothing about the document, and
  // must never be shown as a document that failed to verify.
  if (status === "unavailable") {
    set("doc-status", safe('<h3 class="text-warning">Could not check <i class="fa fa-clock"></i></h3>'));
    say(
      html`The service could not reach the chain just now, so nothing is confirmed either way. ${hint}`,
      "warning"
    );
    return { registered: null, fileHash, checked };
  }

  const signatureOk = checked.receipt ? checked.receipt.valid : null;
  const pathOk = checked.inclusion ? checked.inclusion.valid : null;

  if (signatureOk === false && checked.receipt.forged) {
    set("doc-status", safe('<h3 class="text-danger">Not from this service <i class="fa fa-times-circle"></i></h3>'));
    say(checked.receipt.reason, "danger");
    return { registered: false, fileHash, checked };
  }
  if (pathOk === false || checked.consistent === false) {
    set("doc-status", safe('<h3 class="text-danger">Does not check out <i class="fa fa-times-circle"></i></h3>'));
    say(
      `The service's own records disagree about this document: ${
        checked.warnings[0] || (checked.inclusion && checked.inclusion.reason) || "unknown reason"
      }`,
      "danger"
    );
    return { registered: false, fileHash, checked };
  }

  if (checked.anchor) {
    set(
      "exporter-address",
      html`<i class="fa-solid fa-link mx-1"></i><a target="_blank" rel="noopener"
        href="${config().contract.explorer}/tx/${checked.anchor.txHash}">${checked.anchor.txHash}</a>`
    );
    set("blockNumber", html`<i class="fa-solid fa-cube mx-1"></i>${checked.anchor.block ?? "—"}`);
  }
  if (body.batch) {
    set("merkle-root", html`<i class="fa-solid fa-sitemap mx-1"></i>${body.batch.document.merkleRoot}`);
    set("manifest-cid", html`<i class="fa-solid fa-box mx-1"></i>${body.batch.document.manifestCID}`);
  }

  set("doc-status", safe('<h3 class="text-warning">Partly checked <i class="fa fa-circle-half-stroke"></i></h3>'));
  const anchored =
    checked.anchor !== null
      ? `The service says it is anchored in the transaction above; this page did not confirm that.`
      : `The service does not claim it is anchored on-chain yet.`;
  say(
    html`Checked here: the service signed for this exact file, and its inclusion proof is internally consistent. Not checked here: whether that batch is on the chain. ${anchored} ${hint}`,
    "warning"
  );
  return { registered: null, anchored: null, fileHash, checked };
}

/** Hash the selected file locally so the user can look up their own document. */
export async function hashSelectedFile() {
  try {
    const { bytes } = await readSelectedFile();
    const packed = await packFile(bytes, { chunkSize: config().crypto.chunkSize });
    const field = el("lookup-hash");
    if (field) field.value = packed.fileHashHex;
    say(`File hash: ${packed.fileHashHex}`);
    return packed.fileHashHex;
  } catch (error) {
    say(error.message, "danger");
    throw error;
  }
}

/** Fill the cipher-suite picker from the registry, so it can never drift. */
function populateSuitePicker() {
  const picker = el("cipher-suite");
  if (!picker || picker.options.length > 0) return;
  for (const suite of listSuites()) {
    const option = document.createElement("option");
    option.value = suite.name;
    option.textContent = suite.label;
    if (suite.name === config().crypto.suite) option.selected = true;
    picker.appendChild(option);
  }
}

function readHashFromUrl() {
  const hash = new URL(location.href).searchParams.get("hash");
  const field = el("lookup-hash");
  if (hash && field) {
    field.value = hash;
    return hash;
  }
  return null;
}

window.addEventListener("DOMContentLoaded", () => {
  populateSuitePicker();
  readHashFromUrl();
  // Honour a mode restored by the browser on a back-navigation, which happens
  // before any change event and would otherwise leave the notice contradicting
  // the checked radio.
  if (document.querySelector('input[name="anchor-mode"]')) anchorModeChanged();
});

// The pages use inline handlers, so publish the entry points.
Object.assign(window, {
  uploadChunked,
  retrieveChunked,
  verifyRegistration,
  hashSelectedFile,
  anchorModeChanged,
  oreochain: { config, listSuites, to0x },
});
