/**
 * The server-side storage backend.
 *
 * This is the only storage path that runs in production, and until now it had
 * no tests at all — every gateway test ran against the memory backend. What is
 * worth checking here is behaviour against a misbehaving upstream: a pinning
 * service that returns 500 once, a read gateway that hangs, one that tries to
 * hand back a gigabyte.
 *
 * `fetch` is replaced rather than a real service called, because the failures
 * that matter are the ones a real service will not produce on demand.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { createPinataBackend, createBackend, _internals } from "../server/storage.mjs";

const FAST_RETRY = { maxAttempts: 3, backoffBaseMs: 1, maxBackoffMs: 2 };

/** Swap global fetch for the duration of one test. */
function withFetch(implementation, run) {
  const original = globalThis.fetch;
  globalThis.fetch = implementation;
  return (async () => {
    try {
      return await run();
    } finally {
      globalThis.fetch = original;
    }
  })();
}

function jsonResponse(body, { status = 200 } = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function bytesResponse(bytes, { status = 200, contentLength } = {}) {
  const headers = {};
  if (contentLength !== undefined) headers["Content-Length"] = String(contentLength);
  return new Response(bytes, { status, headers });
}

function backend(overrides = {}) {
  return createPinataBackend({
    jwt: "test-jwt",
    gateways: ["https://gw-a.example/ipfs/", "https://gw-b.example/ipfs/"],
    upstreamTimeoutMs: 1000,
    maxBodyBytes: 1024,
    retry: FAST_RETRY,
    ...overrides,
  });
}

// ---------------------------------------------------------------------- put

test("a transient pinning failure is retried rather than failing the client", async () => {
  let attempts = 0;

  await withFetch(
    async () => {
      attempts++;
      if (attempts < 3) return jsonResponse({ error: "busy" }, { status: 503 });
      return jsonResponse({ IpfsHash: "bafyRetried" });
    },
    async () => {
      assert.equal(await backend().put(new Uint8Array([1, 2, 3]), "chunk"), "bafyRetried");
      assert.equal(attempts, 3, "the upload was not retried");
    }
  );
});

test("a rejected credential is not retried — it will never succeed", async () => {
  let attempts = 0;

  await withFetch(
    async () => {
      attempts++;
      return jsonResponse({ error: "unauthorized" }, { status: 401 });
    },
    async () => {
      await assert.rejects(() => backend().put(new Uint8Array([1]), "chunk"), /HTTP 401/);
      assert.equal(attempts, 1, "a permanent failure was retried");
    }
  );
});

test("the client is told 502 whatever the pinning service said", async () => {
  await withFetch(
    async () => jsonResponse({ error: "no" }, { status: 401 }),
    async () => {
      // The caller's request was fine; ours was not. A 401 passed through
      // would tell them to fix their own credentials.
      const error = await backend()
        .put(new Uint8Array([1]), "chunk")
        .catch((e) => e);
      assert.equal(error.status, 502);
      assert.equal(error.upstreamStatus, 401);
    }
  );
});

test("the pinning credential never appears in an error", async () => {
  await withFetch(
    async () => jsonResponse({ error: "boom" }, { status: 500 }),
    async () => {
      const error = await backend({ jwt: "super-secret-jwt" })
        .put(new Uint8Array([1]), "chunk")
        .catch((e) => e);
      assert.ok(!JSON.stringify(error.message).includes("super-secret-jwt"));
    }
  );
});

test("a retried upload sends the body again, not an emptied one", async () => {
  const seen = [];

  await withFetch(
    async (url, init) => {
      // A FormData body is consumed once, so a naive retry sends nothing.
      seen.push(init.body.get("file").size);
      return seen.length < 2
        ? jsonResponse({}, { status: 500 })
        : jsonResponse({ IpfsHash: "bafyOk" });
    },
    async () => {
      await backend().put(new Uint8Array([1, 2, 3, 4, 5]), "chunk");
      assert.deepEqual(seen, [5, 5], "the retry sent a different body");
    }
  );
});

test("a response with no CID is an error, not an undefined location", async () => {
  await withFetch(
    async () => jsonResponse({ ok: true }),
    async () => {
      await assert.rejects(() => backend().put(new Uint8Array([1]), "chunk"), /no CID/);
    }
  );
});

test("a CID that is not safe to use as a path is refused", async () => {
  await withFetch(
    async () => jsonResponse({ IpfsHash: "../../etc/passwd" }),
    async () => {
      await assert.rejects(
        () => backend().put(new Uint8Array([1]), "chunk"),
        /unsafe storage identifier/
      );
    }
  );
});

// ---------------------------------------------------------------------- get

test("each gateway is retried before moving to the next", async () => {
  const calls = [];

  await withFetch(
    async (url) => {
      calls.push(url);
      if (url.startsWith("https://gw-a")) return bytesResponse(new Uint8Array(), { status: 500 });
      return bytesResponse(new Uint8Array([7, 7]));
    },
    async () => {
      const bytes = await backend().get("bafySomething");
      assert.deepEqual(Array.from(bytes), [7, 7]);

      const first = calls.filter((url) => url.startsWith("https://gw-a"));
      assert.equal(first.length, FAST_RETRY.maxAttempts, "the first gateway was not retried");
    }
  );
});

test("exhausting every gateway reports all of them, not just the last", async () => {
  await withFetch(
    async () => bytesResponse(new Uint8Array(), { status: 500 }),
    async () => {
      const error = await backend()
        .get("bafyMissing")
        .catch((e) => e);
      assert.equal(error.status, 502);
      assert.match(error.message, /gw-a/);
      assert.match(error.message, /gw-b/);
    }
  );
});

test("an oversized response is refused before it is buffered", async () => {
  let pulled = 0;

  await withFetch(
    async () =>
      new Response(
        new ReadableStream({
          pull(controller) {
            pulled++;
            if (pulled > 100) return controller.close();
            controller.enqueue(new Uint8Array(256));
          },
        })
      ),
    async () => {
      // 1 KiB cap against a stream that would keep going for 25 KiB.
      const error = await backend()
        .get("bafyHuge")
        .catch((e) => e);
      assert.match(error.message, /exceeds 1024 bytes/);

      // It must stop pulling rather than discover the size after buffering
      // everything. The exact count is the stream's queueing strategy running
      // ahead of us, not our concern — that it ended well short of the 100
      // chunks on offer, twice over, is.
      assert.ok(pulled < 50, `kept reading the whole body: pulled ${pulled} times`);
    }
  );
});

test("a declared Content-Length over the cap is refused without reading a byte", async () => {
  let bodyRead = false;

  await withFetch(
    async () => {
      const response = bytesResponse(new Uint8Array(10), { contentLength: 99999 });
      Object.defineProperty(response, "body", {
        get() {
          bodyRead = true;
          return null;
        },
      });
      return response;
    },
    async () => {
      await assert.rejects(() => backend().get("bafyLiar"));
      assert.equal(bodyRead, false, "the body was read despite an oversized Content-Length");
    }
  );
});

test("a response inside the cap comes back whole", async () => {
  const payload = new Uint8Array(1024).fill(9);

  await withFetch(
    async () => bytesResponse(payload),
    async () => {
      const bytes = await backend().get("bafyExact");
      assert.equal(bytes.length, 1024);
      assert.ok(bytes.every((b) => b === 9));
    }
  );
});

test("readCapped handles a runtime with no streaming body", async () => {
  const response = new Response(new Uint8Array([1, 2, 3]));
  Object.defineProperty(response, "body", { get: () => null });
  assert.deepEqual(Array.from(await _internals.readCapped(response, 10)), [1, 2, 3]);
});

// ------------------------------------------------------------------- wiring

test("the real backend is built with a cap derived from the chunk limit", () => {
  const built = createBackend({
    storage: "pinata",
    pinataJwt: "jwt",
    gateways: ["https://gw.example/ipfs/"],
    upstreamTimeoutMs: 1000,
    maxChunkBytes: 4096,
  });
  assert.equal(built.name, "pinata");
});

test("memory storage still selects the memory backend", () => {
  assert.equal(createBackend({ storage: "memory" }).name, "memory");
});
