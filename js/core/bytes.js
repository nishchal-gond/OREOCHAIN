/**
 * Byte / encoding helpers shared by the OREOCHAIN core modules.
 *
 * Everything here is dependency-free and works unchanged in a browser and in
 * Node (>=18), so the same code can back the web UI today and a server later.
 */

const HEX = "0123456789abcdef";

export function toHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += HEX[bytes[i] >> 4] + HEX[bytes[i] & 15];
  }
  return out;
}

const HEX_ONLY = /^[0-9a-fA-F]*$/;

/**
 * Strict hex decoding.
 *
 * parseInt() is not a validator: parseInt("1z", 16) is 1, not NaN, so a
 * per-pair parseInt silently accepts "0x1z" and returns a byte nobody wrote.
 * Every caller here is decoding a hash or a proof step that arrived from
 * storage or from a peer, and a decoder that invents bytes for malformed input
 * turns "this digest is malformed" into "this digest did not match" — or worse,
 * into a match. Reject the whole string instead.
 */
export function fromHex(hex) {
  if (typeof hex !== "string") throw new Error("hex must be a string");
  const clean = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("hex string has odd length");
  if (!HEX_ONLY.test(clean)) throw new Error("invalid hex string");

  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Hex with the 0x prefix the smart contract and explorers expect. */
export function to0x(bytes) {
  return "0x" + toHex(bytes);
}

export function toBase64(bytes) {
  // btoa chokes on very long argument lists, so build the binary string in slices.
  let binary = "";
  const SLICE = 0x8000;
  for (let i = 0; i < bytes.length; i += SLICE) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + SLICE));
  }
  return btoa(binary);
}

export function fromBase64(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * base64url, for values a person copies and pastes.
 *
 * Recipient keys and identities travel through URLs, shell arguments, chat
 * messages and HTML inputs, where the `+` and `/` of standard base64 are
 * variously escaped, split on, or silently mangled — and padding invites a
 * trailing `=` being dropped by one hop and not the next. The URL-safe
 * alphabet with padding stripped survives all of that unchanged.
 */
export function toBase64Url(bytes) {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const BASE64URL_ONLY = /^[A-Za-z0-9_-]*$/;

export function fromBase64Url(text) {
  if (typeof text !== "string") throw new Error("base64url input must be a string");
  if (!BASE64URL_ONLY.test(text)) throw new Error("invalid base64url string");
  // A length of 4n+1 encodes no whole number of bytes: it is malformed rather
  // than merely unpadded, and padding it out would hand back bytes nobody wrote.
  if (text.length % 4 === 1) throw new Error("invalid base64url string");
  const padding = "=".repeat((4 - (text.length % 4)) % 4);
  return fromBase64(text.replace(/-/g, "+").replace(/_/g, "/") + padding);
}

export function utf8(str) {
  return new TextEncoder().encode(str);
}

export function fromUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

export function concat(...arrays) {
  return concatAll(arrays);
}

/**
 * concat() for a list that may be long.
 *
 * `concat(...chunks)` spreads the array onto the call stack, and a stack has a
 * ceiling: a few hundred thousand arguments overflow it. A file restored at a
 * small chunk size reaches that number comfortably within the limits this
 * project already enforces, so the assembly step has to take an array rather
 * than an argument list.
 */
export function concatAll(arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/** Constant-time comparison — never leaks where two digests diverge. */
export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * The WebCrypto implementation, in a browser or in Node.
 *
 * Node only exposed Web Crypto as `globalThis.crypto` from v19. On v18 the same
 * implementation exists but has to be taken off `node:crypto`, so resolve it
 * once here rather than failing at the first hash. The dynamic import is
 * reached only when a Node runtime is detected, so a browser never evaluates it.
 */
let cryptoImpl = globalThis.crypto;

if (
  (!cryptoImpl || !cryptoImpl.subtle) &&
  typeof process !== "undefined" &&
  process.versions &&
  process.versions.node
) {
  cryptoImpl = (await import("node:crypto")).webcrypto;
}

export function webcrypto() {
  if (!cryptoImpl || !cryptoImpl.subtle) {
    throw new Error(
      "WebCrypto is unavailable. Use a browser on a secure origin (HTTPS or localhost), or Node 18 or newer."
    );
  }
  return cryptoImpl;
}

export function randomBytes(length) {
  const out = new Uint8Array(length);
  webcrypto().getRandomValues(out);
  return out;
}
