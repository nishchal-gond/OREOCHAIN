/**
 * Static checks on the shipped pages.
 *
 * The browser suite (test/e2e/) is the real proof, but it needs Playwright
 * and a Chromium download, so it does not run on every Node version and will
 * not run at all on a contributor's machine that has neither. These are the
 * same failures caught by reading the files, so they run everywhere `npm
 * test` runs.
 *
 * Each one is a bug that shipped: the pages were served by a gateway whose
 * Content-Security-Policy forbids inline script, so every `onclick` handler
 * was silently refused and no button on the site did anything; and the
 * chunking core imported @noble through node_modules, whose ESM uses package
 * specifiers that no browser can resolve, so the module graph never loaded.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { _internals as gateway } from "../server/gateway.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const PAGES = fs
  .readdirSync(ROOT)
  .filter((name) => name.endsWith(".html"))
  .sort();

function read(relative) {
  return fs.readFileSync(path.join(ROOT, relative), "utf8");
}

/** Commented-out markup is not served, so it is not a finding. */
function withoutComments(html) {
  return html.replace(/<!--[\s\S]*?-->/g, "");
}

test("the pages are found", () => {
  assert.ok(PAGES.length >= 6, `expected the site's pages, found ${PAGES.join(", ")}`);
});

test("no page uses an inline event handler", () => {
  // `script-src 'self'` covers event-handler attributes, so one of these is a
  // button that does nothing when the site is served by its own gateway.
  const offenders = [];
  for (const page of PAGES) {
    for (const match of withoutComments(read(page)).matchAll(/\son[a-z]+\s*=\s*"[^"]*"/gi)) {
      offenders.push(`${page}: ${match[0].trim()}`);
    }
  }
  assert.deepEqual(
    offenders,
    [],
    "use data-action and js/ui.js instead — inline handlers are blocked by the CSP"
  );
});

test("no page carries an inline script", () => {
  const offenders = [];
  for (const page of PAGES) {
    const html = withoutComments(read(page));
    // An import map would be inline script too, which is why js/vendor exists.
    for (const match of html.matchAll(/<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)) {
      if (match[1].trim().length > 0) offenders.push(`${page}: ${match[1].trim().slice(0, 60)}…`);
    }
  }
  assert.deepEqual(offenders, [], "move it to a file under js/ — inline script is blocked by the CSP");
});

test("every data-action names a handler the page publishes", () => {
  const published = ["js/App.js", "js/chunked-app.js", "js/script.js"].map(read).join("\n");

  for (const page of PAGES) {
    for (const match of withoutComments(read(page)).matchAll(/data-action="([^"]+)"/g)) {
      const name = match[1];
      assert.match(
        published,
        new RegExp(`\\b${name}\\b`),
        `${page} calls ${name}, which no loaded script defines`
      );
    }
  }
});

test("every page that dispatches an action loads js/ui.js", () => {
  for (const page of PAGES) {
    const html = read(page);
    if (!html.includes("data-action=")) continue;
    assert.match(html, /<script src="\.\/js\/ui\.js"><\/script>/, `${page} loads no dispatcher`);
  }
});

test("the browser code never imports through node_modules", () => {
  // node_modules layout is a package manager's business, and @noble's ESM
  // there is not loadable by a browser at all. js/vendor holds the copies
  // that are.
  const offenders = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(path.join(ROOT, directory), { withFileTypes: true })) {
      const relative = `${directory}/${entry.name}`;
      if (entry.isDirectory()) {
        if (entry.name !== "vendor") walk(relative);
      } else if (entry.name.endsWith(".js") && !entry.name.endsWith(".min.js")) {
        if (/["']\.{0,2}[^"']*node_modules/.test(read(relative))) offenders.push(relative);
      }
    }
  };
  walk("js");
  assert.deepEqual(offenders, [], "import from js/vendor instead — see scripts/vendor-noble.mjs");
});

test("no vendored module imports a bare package specifier", () => {
  // This is the exact failure: `import … from '@noble/hashes/crypto'` in a
  // browser is "Failed to resolve module specifier", and it takes the whole
  // module graph down, not just that import.
  const offenders = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(path.join(ROOT, directory), { withFileTypes: true })) {
      const relative = `${directory}/${entry.name}`;
      if (entry.isDirectory()) {
        walk(relative);
        continue;
      }
      if (!entry.name.endsWith(".js")) continue;
      for (const match of read(relative).matchAll(/\bfrom\s*['"]([^'"]+)['"]/g)) {
        const specifier = match[1];
        if (specifier.startsWith(".") || specifier.startsWith("/")) continue;
        offenders.push(`${relative}: ${specifier}`);
      }
    }
  };
  walk("js/vendor");
  assert.deepEqual(offenders, [], "re-run `npm run vendor`");
});

test("js/vendor is what scripts/vendor-noble.mjs generates", (t) => {
  if (!fs.existsSync(path.join(ROOT, "node_modules/@noble/hashes/esm"))) {
    return t.skip("@noble is not installed");
  }

  const before = snapshot();
  execFileSync(process.execPath, [path.join(ROOT, "scripts/vendor-noble.mjs")], { cwd: ROOT });
  const after = snapshot();

  assert.deepEqual(
    after,
    before,
    "js/vendor is stale — run `npm run vendor` and commit the result"
  );

  function snapshot() {
    const files = {};
    const walk = (directory) => {
      for (const entry of fs.readdirSync(path.join(ROOT, directory), { withFileTypes: true })) {
        const relative = `${directory}/${entry.name}`;
        if (entry.isDirectory()) walk(relative);
        else files[relative] = read(relative);
      }
    };
    walk("js/vendor");
    return files;
  }
});

test("every local asset a page references exists and the gateway will serve it", () => {
  // Two different ways to ship a page with a hole in it: reference a file
  // that is not there, or reference one the gateway's static allowlist will
  // not serve. Both render as a missing image or an unstyled page, and
  // neither fails anything else.
  const missingFile = [];
  const notServable = [];

  for (const page of PAGES) {
    const html = withoutComments(read(page));
    for (const match of html.matchAll(/(?:src|href)="([^"]+)"/g)) {
      const reference = match[1];
      if (/^(https?:|data:|mailto:|#|\/\/)/.test(reference)) continue;

      const relative = reference.replace(/^\.\//, "").split(/[?#]/)[0];
      if (relative === "" || relative.endsWith(".html")) continue;

      if (!fs.existsSync(path.join(ROOT, relative))) {
        // js/config.js is a deployment's own settings file and is gitignored.
        if (relative !== "js/config.js") missingFile.push(`${page}: ${reference}`);
        continue;
      }
      if (!gateway.isServablePath(relative)) notServable.push(`${page}: ${reference}`);
    }
  }

  assert.deepEqual(missingFile, []);
  assert.deepEqual(
    notServable,
    [],
    "the gateway serves only STATIC_DIRECTORIES — see server/gateway.mjs"
  );
});
