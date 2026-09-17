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
import { createAdapterFromConfig, putAll } from "./storage/ipfs.js";
import { CHUNKED_VERIFICATION_ABI } from "./contract-abi.js";

const DEFAULTS = {
  contract: { address: null, chainId: null, explorer: "https://polygonscan.com" },
  storage: { provider: "gateway" },
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
    crypto: { ...DEFAULTS.crypto, ...(user.crypto || {}) },
  };
}

// ------------------------------------------------------------------ UI helpers

function el(id) {
  return document.getElementById(id);
}

function say(message, tone = "info") {
  const note = el("note");
  if (note) note.innerHTML = `<h5 class="text-${tone} text-center">${message}</h5>`;
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
 * Argon2id is memory-hard by design and blocks this thread for roughly a
 * second at production settings; without this the "deriving" message would
 * only appear after the work it describes had already finished.
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
  if (!globalThis.web3) throw new Error("web3 is not loaded — is MetaMask installed?");
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
 * Chunk, encrypt, upload every chunk plus the manifest, then anchor the file
 * hash and Merkle root on-chain.
 */
export async function uploadChunked() {
  busy(true);
  try {
    const { crypto: cryptoConfig, contract: contractConfig, storage } = config();
    const { file, bytes } = await readSelectedFile();
    const passphrase = selectedPassphrase();
    const suite = selectedSuite();

    if (storage.provider !== "pinata") {
      throw new Error(
        "Uploading needs a pinning service. Set storage.provider to \"pinata\" in js/config.js."
      );
    }

    const account = currentAccount();
    const contract = contractInstance();

    if (passphrase) {
      say(
        `Deriving your key with ${describeKdf(cryptoConfig.kdf)}, then encrypting ` +
          `${humanSize(bytes.length)} with ${suite}…`
      );
      // Argon2id is deliberately slow and runs on this thread, so yield once to
      // let the message above actually render before the tab stops responding.
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
    return { manifest, manifestCID, receipt };
  } catch (error) {
    hideProgress();
    say(explainChainError(error), "danger");
    console.error(error);
    throw error;
  } finally {
    busy(false);
  }
}

function renderUploadResult({ packed, manifestCID, receipt, explorer }) {
  const set = (id, html) => {
    const node = el(id);
    if (node) node.innerHTML = html;
  };

  const status = document.querySelector(".transaction-status");
  if (status) status.classList.remove("d-none");

  set(
    "transaction-hash",
    `<i class="fa fa-check-circle mx-1"></i><a target="_blank" rel="noopener" href="${explorer}/tx/${receipt.transactionHash}">${receipt.transactionHash}</a>`
  );
  set("file-hash", `<i class="fa-solid fa-hashtag mx-1"></i>${packed.fileHashHex}`);
  set("merkle-root", `<i class="fa-solid fa-sitemap mx-1"></i>${packed.merkleRootHex}`);
  set("manifest-cid", `<i class="fa-solid fa-box mx-1"></i>${manifestCID}`);
  set(
    "chunk-summary",
    `<i class="fa-solid fa-layer-group mx-1"></i>${packed.totalChunks} chunks · ${humanSize(
      packed.fileSize
    )} · ${packed.encrypted ? packed.suite : "unencrypted"}`
  );
  set("blockNumber", `<i class="fa-solid fa-cube mx-1"></i>${receipt.blockNumber}`);
  set("time-stamps", `<i class="fa-solid fa-clock mx-1"></i>${new Date().toISOString()}`);

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
  const set = (id, html) => {
    const node = el(id);
    if (node) node.innerHTML = html;
  };
  const status = document.querySelector(".transaction-status");
  if (status) status.classList.toggle("d-none", !onChain);
  if (!onChain) return;

  set(
    "doc-status",
    `<h3 class="text-info">Registered on-chain <i class="fa fa-check-circle"></i></h3>`
  );
  set("file-hash", `<i class="fa-solid fa-hashtag mx-1"></i>${fileHash}`);
  set("merkle-root", `<i class="fa-solid fa-sitemap mx-1"></i>${onChain.merkleRoot}`);
  set("manifest-cid", `<i class="fa-solid fa-box mx-1"></i>${onChain.manifestCID}`);
  set(
    "chunk-summary",
    `<i class="fa-solid fa-layer-group mx-1"></i>${onChain.totalChunks} chunks · ${humanSize(
      onChain.fileSize
    )} · ${onChain.encrypted ? "encrypted" : "public"}`
  );
  set("blockNumber", `<i class="fa-solid fa-cube mx-1"></i>${onChain.blockNumber}`);
  set(
    "time-stamps",
    `<i class="fa-solid fa-clock mx-1"></i>${new Date(onChain.timestamp * 1000).toUTCString()}`
  );
  set("college-name", `<i class="fa-solid fa-building-columns mx-1"></i>${onChain.info}`);
  set(
    "exporter-address",
    `<i class="fa-solid fa-user-shield mx-1"></i><a target="_blank" rel="noopener" href="${explorer}/address/${onChain.exporter}">${onChain.exporter}</a>`
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
    const record = await contractInstance().methods.findDocument(fileHash).call();
    const blockNumber = Number(record.blockNumber ?? record[0]);

    if (blockNumber === 0) {
      renderRetrieveStatus(null);
      const status = document.querySelector(".transaction-status");
      if (status) status.classList.remove("d-none");
      const label = el("doc-status");
      if (label) {
        label.innerHTML =
          '<h3 class="text-danger">Not registered <i class="fa fa-times-circle"></i></h3>';
      }
      const hashField = el("file-hash");
      if (hashField) hashField.innerHTML = `<i class="fa-solid fa-hashtag mx-1"></i>${fileHash}`;
      say("This file does not match any registered document.", "danger");
      return { registered: false, fileHash };
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
});

// The pages use inline handlers, so publish the entry points.
Object.assign(window, {
  uploadChunked,
  retrieveChunked,
  verifyRegistration,
  hashSelectedFile,
  oreochain: { config, listSuites, to0x },
});
