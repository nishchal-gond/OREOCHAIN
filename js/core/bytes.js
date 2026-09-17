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

export function fromHex(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("hex string has odd length");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(clean.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) throw new Error("invalid hex string");
    out[i] = byte;
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

export function utf8(str) {
  return new TextEncoder().encode(str);
}

export function fromUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

export function concat(...arrays) {
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

/** The WebCrypto implementation, in a browser or in Node. */
export function webcrypto() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error(
      "WebCrypto is unavailable. Use a modern browser over HTTPS (or localhost), or Node 18+."
    );
  }
  return c;
}

export function randomBytes(length) {
  const out = new Uint8Array(length);
  webcrypto().getRandomValues(out);
  return out;
}
