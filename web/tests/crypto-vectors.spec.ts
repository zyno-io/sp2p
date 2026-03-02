import { readFileSync } from "fs";
import { join } from "path";
import { test, expect } from "./fixtures";

const vectorsPath = join(__dirname, "../../testdata/crypto_vectors.json");
const VECTORS = JSON.parse(readFileSync(vectorsPath, "utf-8"));

// Helper: load the crypto test bundle into the page.
// Uses a URL (served by the embedded file server) to comply with CSP.
async function loadCryptoBundle(page: any) {
  await page.addScriptTag({ url: "/crypto-test.js" });
}

// ── Base62 ─────────────────────────────────────────────────────────────────────

test("base62 encode/decode matches Go", async ({ page }) => {
  await page.goto("/");
  await loadCryptoBundle(page);

  const result = await page.evaluate(
    (vectors: typeof VECTORS.base62) => {
      const { base62Encode, base62Decode } = (window as any).__cryptoTest;

      function hexToBytes(hex: string): Uint8Array {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
      }

      function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
          if (a[i] !== b[i]) return false;
        }
        return true;
      }

      const errors: string[] = [];
      for (const v of vectors) {
        const raw = hexToBytes(v.rawHex);
        const encoded = base62Encode(raw);
        if (encoded !== v.encoded) {
          errors.push(
            `encode(${v.rawHex}): got "${encoded}", want "${v.encoded}"`
          );
        }
        const decoded = base62Decode(v.encoded, raw.length);
        if (!bytesEqual(decoded, raw)) {
          errors.push(
            `decode("${v.encoded}"): mismatch`
          );
        }
      }
      return errors.length === 0 ? "ok" : errors.join("; ");
    },
    VECTORS.base62
  );

  expect(result).toBe("ok");
});

// ── Key Derivation ─────────────────────────────────────────────────────────────

test("HKDF key derivation matches Go", async ({ page }) => {
  await page.goto("/");
  await loadCryptoBundle(page);

  const result = await page.evaluate(
    async (kd: typeof VECTORS.keyDerivation) => {
      const { deriveKeys, importPublicKey, EncryptedChannel } =
        (window as any).__cryptoTest;

      function hexToBytes(hex: string): Uint8Array {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
      }

      function bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
          .map((b: number) => b.toString(16).padStart(2, "0"))
          .join("");
      }

      function hexToBase64url(hex: string): string {
        const bytes = hexToBytes(hex);
        let binary = "";
        for (const b of bytes) binary += String.fromCharCode(b);
        return btoa(binary)
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=+$/, "");
      }

      const errors: string[] = [];

      // Import sender's private key via JWK (required for X25519 private keys).
      const senderPrivKey = await crypto.subtle.importKey(
        "jwk",
        {
          kty: "OKP",
          crv: "X25519",
          d: hexToBase64url(kd.senderPrivateHex),
          x: hexToBase64url(kd.senderPublicHex),
        },
        "X25519",
        true,
        ["deriveBits"]
      );

      // Import receiver's public key.
      const receiverPub = hexToBytes(kd.receiverPublicHex);
      const receiverPubKey = await importPublicKey(receiverPub);

      // Derive keys.
      const seed = hexToBytes(kd.seedHex);
      const senderPub = hexToBytes(kd.senderPublicHex);
      const keys = await deriveKeys(
        senderPrivKey,
        receiverPubKey,
        seed,
        kd.sessionId,
        senderPub,
        receiverPub
      );

      // Verify confirm key (raw Uint8Array).
      if (bytesToHex(keys.confirm) !== kd.expected.confirmHex) {
        errors.push(
          `confirm: got ${bytesToHex(keys.confirm)}, want ${kd.expected.confirmHex}`
        );
      }

      // Verify code.
      if (keys.verifyCode !== kd.expected.verifyCode) {
        errors.push(
          `verifyCode: got ${keys.verifyCode}, want ${kd.expected.verifyCode}`
        );
      }

      // Verify s2r key by encrypting a known frame.
      const s2rChannel = new EncryptedChannel(
        keys.senderToReceiver,
        keys.receiverToSender
      );
      const s2rPlain = hexToBytes(kd.s2rFrameTest.plaintextHex);
      const s2rFrame = await s2rChannel.encryptFrame(
        kd.s2rFrameTest.msgType,
        s2rPlain
      );
      if (bytesToHex(s2rFrame) !== kd.s2rFrameTest.expectedFrameHex) {
        errors.push(
          `s2r frame: got ${bytesToHex(s2rFrame)}, want ${kd.s2rFrameTest.expectedFrameHex}`
        );
      }

      // Verify r2s key by encrypting a known frame.
      const r2sChannel = new EncryptedChannel(
        keys.receiverToSender,
        keys.senderToReceiver
      );
      const r2sPlain = hexToBytes(kd.r2sFrameTest.plaintextHex);
      const r2sFrame = await r2sChannel.encryptFrame(
        kd.r2sFrameTest.msgType,
        r2sPlain
      );
      if (bytesToHex(r2sFrame) !== kd.r2sFrameTest.expectedFrameHex) {
        errors.push(
          `r2s frame: got ${bytesToHex(r2sFrame)}, want ${kd.r2sFrameTest.expectedFrameHex}`
        );
      }

      return errors.length === 0 ? "ok" : errors.join("; ");
    },
    VECTORS.keyDerivation
  );

  expect(result).toBe("ok");
});

// ── Key Confirmation ───────────────────────────────────────────────────────────

test("HMAC key confirmation matches Go", async ({ page }) => {
  await page.goto("/");
  await loadCryptoBundle(page);

  const result = await page.evaluate(
    async (c: typeof VECTORS.confirmation) => {
      const { computeConfirmation } = (window as any).__cryptoTest;

      function hexToBytes(hex: string): Uint8Array {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
      }

      function bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
          .map((b: number) => b.toString(16).padStart(2, "0"))
          .join("");
      }

      const errors: string[] = [];
      const confirmKey = hexToBytes(c.confirmKeyHex);
      const senderPub = hexToBytes(c.senderPubHex);
      const receiverPub = hexToBytes(c.receiverPubHex);

      const senderMAC = await computeConfirmation(
        confirmKey,
        "sender",
        senderPub,
        receiverPub
      );
      if (bytesToHex(senderMAC) !== c.expectedSenderHex) {
        errors.push(
          `sender: got ${bytesToHex(senderMAC)}, want ${c.expectedSenderHex}`
        );
      }

      const receiverMAC = await computeConfirmation(
        confirmKey,
        "receiver",
        senderPub,
        receiverPub
      );
      if (bytesToHex(receiverMAC) !== c.expectedReceiverHex) {
        errors.push(
          `receiver: got ${bytesToHex(receiverMAC)}, want ${c.expectedReceiverHex}`
        );
      }

      return errors.length === 0 ? "ok" : errors.join("; ");
    },
    VECTORS.confirmation
  );

  expect(result).toBe("ok");
});

// ── Encrypted Frames ───────────────────────────────────────────────────────────

test("AES-GCM encrypted frames match Go", async ({ page }) => {
  await page.goto("/");
  await loadCryptoBundle(page);

  const result = await page.evaluate(
    async (frames: typeof VECTORS.encryptedFrames) => {
      const { EncryptedChannel } = (window as any).__cryptoTest;

      function hexToBytes(hex: string): Uint8Array {
        if (hex === "") return new Uint8Array(0);
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
      }

      function bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
          .map((b: number) => b.toString(16).padStart(2, "0"))
          .join("");
      }

      const errors: string[] = [];

      // Group by key (all frames in the vector use the same key).
      // Create one EncryptedChannel per key and encrypt sequentially.
      let currentKeyHex = "";
      let channel: any = null;

      for (let i = 0; i < frames.length; i++) {
        const fv = frames[i];

        if (fv.keyHex !== currentKeyHex) {
          // Import key and create a new channel.
          const keyBytes = hexToBytes(fv.keyHex);
          const aesKey = await crypto.subtle.importKey(
            "raw",
            keyBytes,
            "AES-GCM",
            false,
            ["encrypt", "decrypt"]
          );
          // Both write and read key are the same for standalone tests.
          channel = new EncryptedChannel(aesKey, aesKey);
          currentKeyHex = fv.keyHex;
        }

        const plaintext = hexToBytes(fv.plaintextHex);
        const frame = await channel.encryptFrame(fv.msgType, plaintext);
        if (bytesToHex(frame) !== fv.expectedFrameHex) {
          errors.push(
            `frame ${i} (type=${fv.msgType}, seq=${fv.sequence}): got ${bytesToHex(frame)}, want ${fv.expectedFrameHex}`
          );
        }
      }

      return errors.length === 0 ? "ok" : errors.join("; ");
    },
    VECTORS.encryptedFrames
  );

  expect(result).toBe("ok");
});

// ── SHA-256 ───────────────────────────────────────────────────────────────────

test("incremental SHA-256 matches NIST vectors", async ({ page }) => {
  await page.goto("/");
  await loadCryptoBundle(page);

  const result = await page.evaluate(async () => {
    const { SHA256 } = (window as any).__cryptoTest;

    function bytesToHex(bytes: Uint8Array): string {
      return Array.from(bytes)
        .map((b: number) => b.toString(16).padStart(2, "0"))
        .join("");
    }

    const errors: string[] = [];

    // NIST test vectors.
    const vectors = [
      {
        input: "",
        expected:
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      },
      {
        input: "abc",
        expected:
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      },
      {
        input: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        expected:
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
      },
    ];

    for (const v of vectors) {
      const h = new SHA256();
      h.update(new TextEncoder().encode(v.input));
      const got = bytesToHex(h.digest());
      if (got !== v.expected) {
        errors.push(`SHA-256("${v.input}"): got ${got}, want ${v.expected}`);
      }
    }

    // Test incremental hashing: split "abc" across multiple updates.
    const h = new SHA256();
    h.update(new TextEncoder().encode("a"));
    h.update(new TextEncoder().encode("b"));
    h.update(new TextEncoder().encode("c"));
    const got = bytesToHex(h.digest());
    const want =
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    if (got !== want) {
      errors.push(`incremental SHA-256("a"+"b"+"c"): got ${got}, want ${want}`);
    }

    // Cross-check against Web Crypto.
    const data = new TextEncoder().encode("SP2P integrity check test data");
    const h2 = new SHA256();
    h2.update(data);
    const jsHash = bytesToHex(h2.digest());
    const webCryptoDigest = await crypto.subtle.digest("SHA-256", data);
    const webCryptoHash = bytesToHex(new Uint8Array(webCryptoDigest));
    if (jsHash !== webCryptoHash) {
      errors.push(
        `JS vs WebCrypto mismatch: ${jsHash} vs ${webCryptoHash}`
      );
    }

    return errors.length === 0 ? "ok" : errors.join("; ");
  });

  expect(result).toBe("ok");
});

// ── File Info Encryption ─────────────────────────────────────────────────────

test("file-info decrypt matches Go-encrypted blob", async ({ page }) => {
  await page.goto("/");
  await loadCryptoBundle(page);

  const result = await page.evaluate(
    async (fi: typeof VECTORS.fileInfo) => {
      const { decryptFileInfo } = (window as any).__cryptoTest;

      function hexToBytes(hex: string): Uint8Array {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
      }

      function bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
          .map((b: number) => b.toString(16).padStart(2, "0"))
          .join("");
      }

      const errors: string[] = [];
      const seed = hexToBytes(fi.seedHex);
      const encrypted = hexToBytes(fi.encryptedHex);

      // Decrypt the Go-generated blob.
      const plaintext = await decryptFileInfo(seed, encrypted);
      if (bytesToHex(plaintext) !== fi.plaintextHex) {
        errors.push(
          `decrypt: got ${bytesToHex(plaintext)}, want ${fi.plaintextHex}`
        );
      }

      // Verify the decrypted JSON parses correctly.
      const parsed = JSON.parse(new TextDecoder().decode(plaintext));
      if (parsed.name !== "test.txt") {
        errors.push(`name: got ${parsed.name}, want test.txt`);
      }
      if (parsed.size !== 12345) {
        errors.push(`size: got ${parsed.size}, want 12345`);
      }

      return errors.length === 0 ? "ok" : errors.join("; ");
    },
    VECTORS.fileInfo
  );

  expect(result).toBe("ok");
});

test("file-info round-trip: TS encrypt → TS decrypt", async ({ page }) => {
  await page.goto("/");
  await loadCryptoBundle(page);

  const result = await page.evaluate(
    async (fi: typeof VECTORS.fileInfo) => {
      const { encryptFileInfo, decryptFileInfo } = (window as any).__cryptoTest;

      function hexToBytes(hex: string): Uint8Array {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
      }

      function bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
          .map((b: number) => b.toString(16).padStart(2, "0"))
          .join("");
      }

      const errors: string[] = [];
      const seed = hexToBytes(fi.seedHex);
      const plaintext = hexToBytes(fi.plaintextHex);

      // Encrypt, then decrypt.
      const encrypted = await encryptFileInfo(seed, plaintext);
      const decrypted = await decryptFileInfo(seed, encrypted);
      if (bytesToHex(decrypted) !== fi.plaintextHex) {
        errors.push(
          `round-trip: got ${bytesToHex(decrypted)}, want ${fi.plaintextHex}`
        );
      }

      // Ensure TS-encrypted blob cannot be decrypted with wrong seed.
      const wrongSeed = new Uint8Array(seed.length);
      wrongSeed.set(seed);
      wrongSeed[0] ^= 0xff;
      try {
        await decryptFileInfo(wrongSeed, encrypted);
        errors.push("expected decryption with wrong seed to fail");
      } catch {
        // Expected.
      }

      return errors.length === 0 ? "ok" : errors.join("; ");
    },
    VECTORS.fileInfo
  );

  expect(result).toBe("ok");
});

// ── Cross-decryption ───────────────────────────────────────────────────────────

test("TypeScript can decrypt Go-encrypted frames", async ({ page }) => {
  await page.goto("/");
  await loadCryptoBundle(page);

  const result = await page.evaluate(
    async (frames: typeof VECTORS.encryptedFrames) => {
      const { EncryptedChannel } = (window as any).__cryptoTest;

      function hexToBytes(hex: string): Uint8Array {
        if (hex === "") return new Uint8Array(0);
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
      }

      function bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
          .map((b: number) => b.toString(16).padStart(2, "0"))
          .join("");
      }

      const errors: string[] = [];

      let currentKeyHex = "";
      let channel: any = null;

      for (let i = 0; i < frames.length; i++) {
        const fv = frames[i];

        if (fv.keyHex !== currentKeyHex) {
          const keyBytes = hexToBytes(fv.keyHex);
          const aesKey = await crypto.subtle.importKey(
            "raw",
            keyBytes,
            "AES-GCM",
            false,
            ["encrypt", "decrypt"]
          );
          channel = new EncryptedChannel(aesKey, aesKey);
          currentKeyHex = fv.keyHex;
        }

        // Parse the Go-generated frame and decrypt.
        const frameBytes = hexToBytes(fv.expectedFrameHex);
        // Strip 4-byte length prefix to get the payload.
        const payload = frameBytes.subarray(4);

        const { msgType, data } = await channel.decryptFrame(payload);
        if (msgType !== fv.msgType) {
          errors.push(`frame ${i}: msgType got ${msgType}, want ${fv.msgType}`);
        }
        const expectedPlain = hexToBytes(fv.plaintextHex);
        if (bytesToHex(data) !== bytesToHex(expectedPlain)) {
          errors.push(
            `frame ${i}: plaintext got ${bytesToHex(data)}, want ${fv.plaintextHex}`
          );
        }
      }

      return errors.length === 0 ? "ok" : errors.join("; ");
    },
    VECTORS.encryptedFrames
  );

  expect(result).toBe("ok");
});
