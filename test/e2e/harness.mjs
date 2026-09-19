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

  const handler = createHandler(config, createMemoryBackend(), {
    logger: createLogger({ level: "silent" }),
    sweeper: false,
    staticRoot: ROOT,
    proofs: await createProofService({ dbPath: ":memory:" }),
  });

  const server = http.createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  return {
    origin: `http://127.0.0.1:${port}`,
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
  const context = await browser.newContext({ acceptDownloads: true });

  // The page's only route to the chain. Playwright marshals through JSON, so
  // the provider on the other side hands back a string.
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
          const raw = await window.__oreochainRpc(JSON.stringify({ method, params: params || [] }));
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

      // js/App.js reads the connected account from localStorage and renders
      // the signed-in view only when it is there. MetaMask's approval popup
      // has no headless equivalent, so the session starts already connected.
      try {
        window.localStorage.setItem("userAddress", account);
      } catch {
        /* the first navigation may be about:blank */
      }
    },
    {
      account: chain.accounts[0],
      config: {
        contract: {
          address: chain.address,
          chainId: chain.chainId,
          explorer: "https://example.invalid",
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
      },
    }
  );

  /**
   * js/config.js is a deployment's own gitignored settings file, so a checkout
   * does not have one and the pages 404 on it by design. Every other
   * same-origin request failing is a real problem.
   */
  function isExpectedFailure(url) {
    return !url.startsWith(gateway.origin) || url.endsWith("/js/config.js");
  }

  async function newPage() {
    const page = await context.newPage();
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
