// SPDX-License-Identifier: MIT

// E2E encryption using Web Crypto API (X25519 + AES-256-GCM).

const PROTOCOL_VERSION = 1;

export interface DerivedKeys {
  senderToReceiver: CryptoKey;
  receiverToSender: CryptoKey;
  confirm: Uint8Array;
  verifyCode: string;
}

// Generate an X25519 key pair.
export async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey("X25519", true, [
    "deriveBits",
  ]) as Promise<CryptoKeyPair>;
}

// Export the public key as raw bytes.
export async function exportPublicKey(key: CryptoKey): Promise<Uint8Array> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return new Uint8Array(raw);
}

// Import a peer's public key from raw bytes.
export async function importPublicKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, "X25519", true, []);
}

// Perform X25519 DH and derive all session keys.
export async function deriveKeys(
  myPrivateKey: CryptoKey,
  theirPublicKey: CryptoKey,
  seed: Uint8Array,
  sessionId: string,
  senderPub: Uint8Array,
  receiverPub: Uint8Array
): Promise<DerivedKeys> {
  // X25519 DH shared secret.
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "X25519", public: theirPublicKey },
    myPrivateKey,
    256
  );
  const shared = new Uint8Array(sharedBits);

  // Validate: reject all-zero shared secret.
  if (shared.every((b) => b === 0)) {
    throw new Error("Invalid DH shared secret (low-order point)");
  }

  // HKDF-Extract: PRK = HMAC-SHA256(seed, shared)
  const prkKey = await crypto.subtle.importKey(
    "raw",
    seed,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const prkBuf = await crypto.subtle.sign("HMAC", prkKey, shared);
  const prk = new Uint8Array(prkBuf);

  // Build info prefix for transcript binding:
  // "sp2p-v1" || sessionId || senderPub || receiverPub
  const versionTag = new TextEncoder().encode("sp2p-v1");
  const sessionBytes = new TextEncoder().encode(sessionId);
  const infoPrefix = new Uint8Array(versionTag.length + sessionBytes.length + senderPub.length + receiverPub.length);
  infoPrefix.set(versionTag, 0);
  infoPrefix.set(sessionBytes, versionTag.length);
  infoPrefix.set(senderPub, versionTag.length + sessionBytes.length);
  infoPrefix.set(receiverPub, versionTag.length + sessionBytes.length + senderPub.length);

  // Derive directional keys and confirmation key.
  const s2r = await hkdfExpand(prk, infoPrefix, "sender-to-receiver", 32);
  const r2s = await hkdfExpand(prk, infoPrefix, "receiver-to-sender", 32);
  const confirmBytes = await hkdfExpand(prk, infoPrefix, "key-confirm", 32);
  const verifyBytes = await hkdfExpand(prk, infoPrefix, "sp2p-verify", 4);

  // Import as AES-GCM keys.
  const senderToReceiver = await crypto.subtle.importKey(
    "raw",
    s2r,
    "AES-GCM",
    false,
    ["encrypt", "decrypt"]
  );
  const receiverToSender = await crypto.subtle.importKey(
    "raw",
    r2s,
    "AES-GCM",
    false,
    ["encrypt", "decrypt"]
  );

  const verifyCode = Array.from(verifyBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return {
    senderToReceiver,
    receiverToSender,
    confirm: confirmBytes,
    verifyCode,
  };
}

// HKDF-Expand using HMAC-SHA256.
async function hkdfExpand(
  prk: Uint8Array,
  infoPrefix: Uint8Array,
  label: string,
  length: number
): Promise<Uint8Array> {
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    prk,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const labelBytes = new TextEncoder().encode(label);
  const info = new Uint8Array(infoPrefix.length + labelBytes.length);
  info.set(infoPrefix, 0);
  info.set(labelBytes, infoPrefix.length);
  const result = new Uint8Array(length);
  let prev = new Uint8Array(0);
  let offset = 0;
  let counter = 1;

  while (offset < length) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev, 0);
    input.set(info, prev.length);
    input[prev.length + info.length] = counter;

    const block = new Uint8Array(
      await crypto.subtle.sign("HMAC", hmacKey, input)
    );
    const needed = Math.min(block.length, length - offset);
    result.set(block.subarray(0, needed), offset);
    offset += needed;
    prev = block;
    counter++;
  }

  return result;
}

// Compute key confirmation HMAC.
export async function computeConfirmation(
  confirmKey: Uint8Array,
  role: string,
  senderPub: Uint8Array,
  receiverPub: Uint8Array
): Promise<Uint8Array> {
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    confirmKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const roleBytes = new TextEncoder().encode(role);
  const data = new Uint8Array(
    roleBytes.length + senderPub.length + receiverPub.length
  );
  data.set(roleBytes, 0);
  data.set(senderPub, roleBytes.length);
  data.set(receiverPub, roleBytes.length + senderPub.length);

  return new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, data));
}

// Build a 96-bit nonce from a counter.
function buildNonce(counter: number): Uint8Array {
  const nonce = new Uint8Array(12);
  const view = new DataView(nonce.buffer);
  // Put counter in the last 8 bytes (big-endian).
  // JS numbers are safe up to 2^53, which is plenty.
  view.setUint32(4, Math.floor(counter / 0x100000000));
  view.setUint32(8, counter >>> 0);
  return nonce;
}

// Build AAD: [type][seq (8 bytes)][version]
function buildAAD(msgType: number, seq: number): Uint8Array {
  const aad = new Uint8Array(10);
  aad[0] = msgType;
  const view = new DataView(aad.buffer);
  view.setUint32(1, Math.floor(seq / 0x100000000));
  view.setUint32(5, seq >>> 0);
  aad[9] = PROTOCOL_VERSION;
  return aad;
}

// Encrypted frame reader/writer matching Go's crypto.EncryptedStream wire format.
export class EncryptedChannel {
  private writeKey: CryptoKey;
  private readKey: CryptoKey;
  private writeSeq = 0;
  private readSeq = 0;

  constructor(writeKey: CryptoKey, readKey: CryptoKey) {
    this.writeKey = writeKey;
    this.readKey = readKey;
  }

  // Encrypt a frame. Returns the full wire bytes:
  // [4 len][1 type][8 seq][ciphertext]
  async encryptFrame(
    msgType: number,
    data: Uint8Array
  ): Promise<Uint8Array> {
    if (this.writeSeq >= 0x100000000) {
      throw new Error("Nonce counter exhausted — transfer too large");
    }
    const seq = this.writeSeq++;
    const nonce = buildNonce(seq);
    const aad = buildAAD(msgType, seq);

    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad },
        this.writeKey,
        data
      )
    );

    const framePayloadLen = 1 + 8 + ciphertext.length;
    const frame = new Uint8Array(4 + framePayloadLen);
    const view = new DataView(frame.buffer);
    view.setUint32(0, framePayloadLen);
    frame[4] = msgType;
    view.setUint32(5, Math.floor(seq / 0x100000000));
    view.setUint32(9, seq >>> 0);
    frame.set(ciphertext, 13);

    return frame;
  }

  // Decrypt a frame from wire bytes (after length prefix is stripped).
  // Input: [1 type][8 seq][ciphertext]
  async decryptFrame(
    payload: Uint8Array
  ): Promise<{ msgType: number; data: Uint8Array }> {
    // Check nonce exhaustion before decrypting. Nonces 0 through 2^32-1 are valid.
    if (this.readSeq >= 0x100000000) {
      throw new Error("Nonce counter exhausted — transfer too large");
    }

    if (payload.length < 9) {
      throw new Error("Frame too small");
    }

    const msgType = payload[0];
    const view = new DataView(payload.buffer, payload.byteOffset);
    const seqHi = view.getUint32(1);
    const seqLo = view.getUint32(5);
    const seq = seqHi * 0x100000000 + seqLo;
    const ciphertext = payload.subarray(9);

    if (seq !== this.readSeq) {
      throw new Error(
        `Sequence mismatch: got ${seq}, expected ${this.readSeq}`
      );
    }

    const nonce = buildNonce(seq);
    const aad = buildAAD(msgType, seq);

    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad },
        this.readKey,
        ciphertext
      )
    );

    this.readSeq++;
    return { msgType, data: plaintext };
  }
}

// Generate a 128-bit encryption seed, returns base62 encoded and raw.
const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

export function generateSeed(): { encoded: string; raw: Uint8Array } {
  const raw = crypto.getRandomValues(new Uint8Array(16));
  const encoded = base62Encode(raw);
  return { encoded, raw };
}

export function decodeSeed(encoded: string): Uint8Array {
  return base62Decode(encoded, 16);
}

export function base62Encode(data: Uint8Array): string {
  let n = 0n;
  for (const b of data) {
    n = (n << 8n) | BigInt(b);
  }
  if (n === 0n) return "0";

  let result = "";
  const base = 62n;
  while (n > 0n) {
    result = BASE62[Number(n % base)] + result;
    n = n / base;
  }
  return result;
}

export function base62Decode(s: string, targetLen: number): Uint8Array {
  let n = 0n;
  const base = 62n;
  for (const c of s) {
    const idx = BASE62.indexOf(c);
    if (idx < 0) throw new Error(`Invalid base62 character: ${c}`);
    n = n * base + BigInt(idx);
  }

  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n = n >> 8n;
  }

  if (bytes.length > targetLen) {
    throw new Error(`Decoded seed too large: ${bytes.length} bytes, expected at most ${targetLen}`);
  }
  // Pad with leading zeros.
  while (bytes.length < targetLen) {
    bytes.unshift(0);
  }
  return new Uint8Array(bytes);
}

// Base64 encode/decode for Go []byte JSON interop.
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Encrypt file metadata with an AES-256-GCM key derived from the seed.
// Returns nonce || ciphertext (including GCM tag).
export async function encryptFileInfo(
  seed: Uint8Array,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  const key = await deriveFileInfoKey(seed);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      key,
      plaintext
    )
  );
  const out = new Uint8Array(nonce.length + ciphertext.length);
  out.set(nonce, 0);
  out.set(ciphertext, nonce.length);
  return out;
}

// Decrypt file metadata encrypted by encryptFileInfo.
export async function decryptFileInfo(
  seed: Uint8Array,
  encrypted: Uint8Array
): Promise<Uint8Array> {
  const key = await deriveFileInfoKey(seed);
  const nonce = encrypted.slice(0, 12);
  const ciphertext = encrypted.slice(12);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      key,
      ciphertext
    )
  );
}

// Derive AES-256-GCM key from seed for file-info encryption.
async function deriveFileInfoKey(seed: Uint8Array): Promise<CryptoKey> {
  // HKDF-Extract: PRK = HMAC-SHA256(salt="sp2p-file-info", ikm=seed)
  const salt = new TextEncoder().encode("sp2p-file-info");
  const prkKey = await crypto.subtle.importKey(
    "raw",
    salt,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const prk = new Uint8Array(await crypto.subtle.sign("HMAC", prkKey, seed));

  // HKDF-Expand with label "sp2p-v1-file-info-key"
  const keyBytes = await hkdfExpand(
    prk,
    new Uint8Array(0),
    "sp2p-v1-file-info-key",
    32
  );
  return crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

// Parse a transfer code into sessionId and seed.
export function parseCode(code: string): { sessionId: string; seed: string } {
  const idx = code.indexOf("-");
  if (idx < 1 || idx >= code.length - 1) {
    throw new Error("Invalid transfer code format");
  }
  return {
    sessionId: code.substring(0, idx),
    seed: code.substring(idx + 1),
  };
}
