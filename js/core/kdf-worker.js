/**
 * Key-derivation worker.
 *
 * Argon2id is memory-hard by design, which means it is also slow by design:
 * roughly 2 seconds of solid computation at the shipped parameters. Run on
 * the main thread that freezes the tab — no scrolling, no clicking, no
 * repainting — and the freeze gets worse on exactly the low-end phones where a
 * user is most likely to be uploading something important.
 *
 * Moving it here keeps the page responsive, and because the cost is no longer
 * paid in visible jank, stronger parameters become affordable.
 *
 * This file runs in a browser Worker and in Node's worker_threads, which have
 * different message APIs. Supporting both is not incidental: it is what lets
 * test/kdf-worker.test.js execute this exact script in a real thread. Module
 * resolution inside a worker is the part most likely to be quietly broken, and
 * it cannot be checked any other way.
 */

import { handleKdfRequest } from "./kdf.js";

async function respond(post, request) {
  const response = await handleKdfRequest(request);
  // The derived key is transferred rather than copied, so no second copy of
  // key material is left behind in this thread's heap.
  post(response, response.ok && response.key ? [response.key] : []);
}

if (typeof self !== "undefined" && typeof self.postMessage === "function") {
  // Browser worker.
  self.onmessage = (event) => {
    respond((message, transfer) => self.postMessage(message, transfer), event.data);
  };
} else {
  // Node worker_threads.
  const { parentPort } = await import("node:worker_threads");
  if (parentPort) {
    parentPort.on("message", (data) => {
      respond((message, transfer) => parentPort.postMessage(message, transfer), data);
    });
  }
}
