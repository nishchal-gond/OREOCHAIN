/**
 * Everything the browser test needs standing up: a gateway serving the real
 * pages, a chain serving the real contract, and a Chromium page wired to both.
 *
 * The substitutions are deliberate and there are exactly two. `js/config.js`
 * is gitignored — it is a deployment's own settings file — so the test
 * supplies the same object it would define. And there is no MetaMask in a
 * headless browser, so `window.ethereum` is an EIP-1193 provider backed by
 * test/e2e/chain.mjs. Everything downstream of those two is the shipped code:
 * the same web3.js build the pages load, the same ABI, the same sealing core,
 * the same gateway.
 */

import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

import { assertSafeConfig, loadConfig } from "../../server/config.mjs";
import { createHandler } from "../../server/gateway.mjs";
import { createMemoryBackend } from "../../server/storage.mjs";
import { createLogger } from "../../server/log.mjs";
import { createProofService } from "../../server/proofs.mjs";
import { openKeyring } from "../../server/keyring.mjs";
import { openStore } from "../../server/store.mjs";
import { generateSigningKey } from "../../js/core/receipt.js";
import { createManifestVerifier } from "../../server/verify.mjs";

import { Web3 } from "web3";

import { startChain } from "./chain.mjs";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

/**
 * Playwright is not a dependency of this package: it is a browser download,
 * and three of the four Node versions in CI never run this suite. Resolve it
 * from wherever it happens to be installed, and let the caller skip when it
 * is nowhere.
 */
export function loadPlaywright() {
  for (const specifier of ["playwright", "playwright-core", "@playwright/test"]) {
    try {
      const module = require(specifier);
      if (module && module.chromium) return module;
    } catch {
      /* try the next one */
    }
  }
  try {
    // A globally installed playwright is the common case on a dev machine.
    const globalRoot = require("node:child_process")
      .execFileSync("npm", ["root", "-g"], { encoding: "utf8" })
      .trim();
    const module = require(path.join(globalRoot, "playwright"));
    if (module && module.chromium) return module;
  } catch {
    /* fall through */
  }
  return null;
}

/**
 * Start the gateway on an ephemeral port, serving the repository's pages.
 *
 * Anonymous, because the browser is the client here and giving a page an API
 * key would mean shipping a credential to every visitor — which is the bug
 * this repository already shipped once. It also means the test needs no
 * OREOCHAIN_ANCHOR_API_KEYS entry if it ever reaches the anchoring routes,
 * which are key-scoped; today nothing in the frontend calls them.
 */
export async function startGateway(envOverrides = {}) {
  const config = assertSafeConfig(
    loadConfig({
      OREOCHAIN_STORAGE: "memory",
      OREOCHAIN_ALLOW_ANONYMOUS: "true",
      OREOCHAIN_SERVE_STATIC: "true",
      OREOCHAIN_DB_PATH: ":memory:",
      ...envOverrides,
    }),
    { warn: () => {} }
  );

  /*
   * Wired the way server/index.mjs wires it, including the manifest verifier
   * that `OREOCHAIN_VERIFY_MANIFESTS` turns on by default. That matters here:
   * without it a receipt only repeats what the browser claimed, and the test
   * would be checking a signature over an unchecked assertion. With it, the
   * gateway fetches the manifest the browser just uploaded and confirms the
   * document against it before signing — so the receipt this suite verifies
   * is the one a deployment issues.
   */
  const backend = createMemoryBackend();

  /*
   * The store and the keyring outlive the proof service that uses them, which
   * is what makes a rotation expressible here. A deployment rotates by
   * restarting the gateway with a new OREOCHAIN_RECEIPT_KEY: the proofs and
   * the ring on disk are the same afterwards, only the signing key is
   * different. Holding both out here and building a second service over them
   * is that, without the restart — and without the restart the browser's
   * origin does not move, which a test that has a page open needs.
   */
  const keyring = openKeyring({ path: ":memory:" });
  const store = openStore({ path: ":memory:" });
  const verifier = config.verifyManifests ? createManifestVerifier({ backend }) : null;

  const signingKey = await generateSigningKey();
  let proofs = await createProofService({
    keyring,
    store,
    verifier,
    privateJwk: signingKey.exported.privateJwk,
    publicJwk: signingKey.exported.publicJwk,
  });

  const buildHandler = () =>
    createHandler(config, backend, {
      logger: createLogger({ level: "silent" }),
      sweeper: false,
      staticRoot: ROOT,
      proofs,
    });

  let handler = buildHandler();

  const server = http.createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  return {
    origin: `http://127.0.0.1:${port}`,
    /*
     * The proof service itself, for the test to drive as the operator does.
     *
     * Anchoring is deliberately not something the browser can reach: those
     * routes are scoped to the anchoring worker's key, and the worker holds a
     * funded account this process has no business holding. So a test that
     * needs a batch anchored builds it here, out of band, exactly where the
     * worker would.
     */
    get proofs() {
      return proofs;
    },

    /**
     * Rotate the receipt signing key, as an operator does.
     *
     * Returns the kid that was signing before and the one signing now, so a
     * test can assert on the receipt it already holds rather than on whatever
     * the gateway happens to report afterwards.
     *
     * The point of the exercise is what does *not* change: the keyring keeps
     * the old public key and marks it retired, so a receipt issued before the
     * rotation still verifies. A gateway that lost it would turn every
     * receipt already in someone's hands into something indistinguishable
     * from a forgery, which is the failure this is here to catch.
     */
    async rotateReceiptKey() {
      const before = proofs.kid;
      const next = await generateSigningKey();
      proofs = await createProofService({
        keyring,
        store,
        verifier,
        privateJwk: next.exported.privateJwk,
        publicJwk: next.exported.publicJwk,
      });
      handler = buildHandler();
      return { before, after: proofs.kid };
    },

    async stop() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

/**
 * The shipped Argon2id profile, by name, so this suite runs what a user runs.
 * Lowering it here would be the one substitution that could hide a real
 * failure: the manifest reader enforces a memory floor, and a suite that
 * sealed below it would pass while every real file failed to open.
 */
export const TEST_KDF = "argon2id";

/**
 * Anchor a batch the way the operator's worker does.
 *
 * Three steps, in the order they really happen: the gateway builds a batch
 * from what is pending, someone with a funded key sends anchorBatch(), and the
 * transaction is reported back to the gateway so it can serve inclusion
 * proofs that point at it. Nothing here goes through the browser, because
 * nothing about anchoring is the browser's business.
 */
export async function anchorPending(gateway, chain) {
  const batch = await gateway.proofs.buildPendingBatch();
  if (!batch) return null;

  const abiCoder = new Web3().eth.abi;
  const txHash = await chain.request({
    method: "eth_sendTransaction",
    params: [
      {
        from: chain.accounts[0],
        to: chain.address,
        data: abiCoder.encodeFunctionCall(
          chain.abi.find((entry) => entry.type === "function" && entry.name === "anchorBatch"),
          [batch.root, batch.size, ""]
        ),
      },
    ],
  });

  const receipt = await chain.request({ method: "eth_getTransactionReceipt", params: [txHash] });
  const block = Number(receipt.blockNumber);

  gateway.proofs.recordAnchor(batch.root, { txHash, block });
  return { ...batch, txHash, block };
}

/**
 * Boot gateway, chain and browser.
 *
 * `newPage()` opens a page already wired to both, and collects the console
 * errors, uncaught exceptions and failed same-origin requests it produces. A
 * test that passes while the console fills with Content-Security-Policy
 * violations has not proven the site works, so those are assertable rather
 * than merely printed.
 */
export async function openApp(options = {}) {
  const playwright = loadPlaywright();
  if (!playwright) throw new Error("playwright is not installed");

  const gateway = await startGateway(options.env);
  const chain = await startChain();

  const browser = await playwright.chromium.launch({
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });

  /**
   * Where a page with no wallet reaches the chain.
   *
   * It has to be https and it cannot be a local port: the gateway serves
   * `connect-src 'self' https:`, so the browser refuses an http:// RPC
   * outright. Rather than run a TLS server with a self-signed certificate —
   * and a private key that the no-secrets CI job would rightly object to — the
   * URL is intercepted and answered from the same in-process chain.
   */
  const RPC_URL = "https://rpc.oreochain.test/";

  function pageConfig({ rpcUrl = null } = {}) {
    return {
      contract: {
        address: chain.address,
        chainId: chain.chainId,
        explorer: "https://example.invalid",
        rpcUrl,
      },
      storage: {
        // "pinata" in backend mode means "POST to my own server", which is
        // exactly what the gateway is. The browser sees no credential.
        provider: "pinata",
        mode: "backend",
        endpoint: "/api/storage/pin",
        gateways: ["/api/storage/"],
        retry: { maxAttempts: 2, backoffBaseMs: 50 },
      },
      crypto: {
        suite: options.suite || "aes-256-gcm",
        chunkSize: options.chunkSize || 65536,
        kdf: options.kdf || TEST_KDF,
      },
    };
  }

  /**
   * A browser context, with or without a wallet in it.
   *
   * These are separate contexts rather than separate pages because both the
   * injected provider and the config are set by an init script, which is a
   * property of the context.
   */
  async function newContext({ wallet = true, rpcUrl = true } = {}) {
    const context = await browser.newContext({ acceptDownloads: true });

    if (wallet) {
      // Playwright marshals through JSON, so the provider hands back a string.
      await context.exposeFunction("__oreochainRpc", async (payload) => {
        const { method, params } = JSON.parse(payload);
        try {
          return JSON.stringify({ result: await chain.request({ method, params }) });
        } catch (error) {
          return JSON.stringify({ error: { message: error.message, code: error.code || -32603 } });
        }
      });

      await context.addInitScript(
        ({ config, account }) => {
          window.OREOCHAIN_CONFIG = config;

          /** The EIP-1193 surface web3.js and js/App.js actually use. */
          window.ethereum = {
            isMetaMask: true,
            selectedAddress: account,
            async request({ method, params }) {
              const raw = await window.__oreochainRpc(
                JSON.stringify({ method, params: params || [] })
              );
              const response = JSON.parse(raw);
              if (response.error) {
                const error = new Error(response.error.message);
                error.code = response.error.code;
                throw error;
              }
              return response.result;
            },
            on() {},
            removeListener() {},
          };

          // js/App.js reads the connected account from localStorage and
          // renders the signed-in view only when it is there. MetaMask's
          // approval popup has no headless equivalent, so the session starts
          // already connected.
          try {
            window.localStorage.setItem("userAddress", account);
          } catch {
            /* the first navigation may be about:blank */
          }
        },
        { account: chain.accounts[0], config: pageConfig() }
      );

      return context;
    }

    // No wallet at all: no window.ethereum, only a read-only RPC endpoint.
    await context.route(RPC_URL, async (route) => {
      const body = JSON.parse(route.request().postData() || "{}");
      const calls = Array.isArray(body) ? body : [body];

      const answers = await Promise.all(
        calls.map(async (call) => {
          try {
            return {
              jsonrpc: "2.0",
              id: call.id,
              result: await chain.request({ method: call.method, params: call.params || [] }),
            };
          } catch (error) {
            return {
              jsonrpc: "2.0",
              id: call.id,
              error: { code: error.code || -32603, message: error.message },
            };
          }
        })
      );

      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(Array.isArray(body) ? answers : answers[0]),
      });
    });

    await context.addInitScript((config) => {
      window.OREOCHAIN_CONFIG = config;
    }, pageConfig({ rpcUrl: rpcUrl ? RPC_URL : null }));

    return context;
  }

  const context = await newContext({ wallet: true });

  /**
   * js/config.js is a deployment's own gitignored settings file, so a checkout
   * does not have one and the pages 404 on it by design. Every other
   * same-origin request failing is a real problem.
   */
  function isExpectedFailure(url) {
    if (!url.startsWith(gateway.origin)) return true;
    if (url.endsWith("/js/config.js")) return true;
    /*
     * A document with no inclusion proof yet is the ordinary state between
     * upload and the next batch, and the endpoint says so with a 404. The page
     * polls it on purpose; treating that as a page fault would make the
     * default path untestable.
     */
    if (url.includes("/api/proofs/inclusion/")) return true;
    /*
     * The verify endpoint answers 404 for a document it has never seen and
     * 503 when it could not reach the chain. Both are answers the page
     * renders, not faults.
     */
    if (url.includes("/api/proofs/verify/")) return true;
    return false;
  }

  async function newPage({ wallet = true, rpcUrl = true } = {}) {
    const surface =
      wallet && rpcUrl ? context : await newContext({ wallet, rpcUrl });
    const page = await surface.newPage();
    const problems = [];

    page.on("console", (message) => {
      if (message.type() !== "error") return;
      const text = message.text();
      // A failed third-party CDN or font is the sandbox's network, not a bug,
      // and the MIME-type complaint is the missing js/config.js again.
      if (/Failed to load resource/.test(text)) return;
      if (/js\/config\.js/.test(text)) return;
      problems.push(`console: ${text}`);
    });
    page.on("pageerror", (error) => problems.push(`uncaught: ${error.message}`));
    page.on("requestfailed", (request) => {
      if (isExpectedFailure(request.url())) return;
      problems.push(`request failed: ${request.method()} ${request.url()}`);
    });
    page.on("response", (response) => {
      if (response.status() < 400 || isExpectedFailure(response.url())) return;
      problems.push(`HTTP ${response.status()} ${response.url()}`);
    });

    return { page, problems };
  }

  return {
    newPage,
    context,
    browser,
    chain,
    gateway,
    async close() {
      await browser.close();
      await gateway.stop();
    },
  };
}
