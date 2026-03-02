// SPDX-License-Identifier: MIT

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// vectorsPath returns the path to the shared test vectors JSON.
func vectorsPath() string {
	return filepath.Join("..", "..", "testdata", "crypto_vectors.json")
}

// --- JSON schema ---

type TestVectors struct {
	Base62        []Base62Vector      `json:"base62"`
	KeyDerivation KeyDerivationVector `json:"keyDerivation"`
	Confirmation  ConfirmationVector  `json:"confirmation"`
	EncFrames     []FrameVector       `json:"encryptedFrames"`
	FileInfo      FileInfoVector      `json:"fileInfo"`
}

type FileInfoVector struct {
	SeedHex       string `json:"seedHex"`
	PlaintextHex  string `json:"plaintextHex"`
	EncryptedHex  string `json:"encryptedHex"`  // Go-encrypted blob (nonce || ciphertext)
	DerivedKeyHex string `json:"derivedKeyHex"` // for verifying key derivation matches
}

type Base62Vector struct {
	RawHex  string `json:"rawHex"`
	Encoded string `json:"encoded"`
}

type KeyDerivationVector struct {
	SenderPrivateHex   string `json:"senderPrivateHex"`
	SenderPublicHex    string `json:"senderPublicHex"`
	ReceiverPrivateHex string `json:"receiverPrivateHex"`
	ReceiverPublicHex  string `json:"receiverPublicHex"`
	SeedHex            string `json:"seedHex"`
	SessionID          string `json:"sessionId"`
	Expected           struct {
		SharedSecretHex     string `json:"sharedSecretHex"`
		SenderToReceiverHex string `json:"senderToReceiverHex"`
		ReceiverToSenderHex string `json:"receiverToSenderHex"`
		ConfirmHex          string `json:"confirmHex"`
		VerifyCode          string `json:"verifyCode"`
	} `json:"expected"`
	// Frame tests use derived keys so TypeScript can verify non-extractable CryptoKeys.
	S2RFrameTest FrameTest `json:"s2rFrameTest"`
	R2SFrameTest FrameTest `json:"r2sFrameTest"`
}

type FrameTest struct {
	MsgType          int    `json:"msgType"`
	Sequence         int    `json:"sequence"`
	PlaintextHex     string `json:"plaintextHex"`
	ExpectedFrameHex string `json:"expectedFrameHex"`
}

type ConfirmationVector struct {
	ConfirmKeyHex       string `json:"confirmKeyHex"`
	SenderPubHex        string `json:"senderPubHex"`
	ReceiverPubHex      string `json:"receiverPubHex"`
	ExpectedSenderHex   string `json:"expectedSenderHex"`
	ExpectedReceiverHex string `json:"expectedReceiverHex"`
}

type FrameVector struct {
	KeyHex           string `json:"keyHex"`
	MsgType          int    `json:"msgType"`
	Sequence         int    `json:"sequence"`
	PlaintextHex     string `json:"plaintextHex"`
	ExpectedFrameHex string `json:"expectedFrameHex"`
}

// --- Generation ---

func encryptFrameRaw(key []byte, msgType byte, seq uint64, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := buildNonce(seq)
	aad := buildAAD(msgType, seq)
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	framePayloadLen := 1 + 8 + len(ciphertext)
	frame := make([]byte, 4+framePayloadLen)
	binary.BigEndian.PutUint32(frame[0:4], uint32(framePayloadLen))
	frame[4] = msgType
	binary.BigEndian.PutUint64(frame[5:13], seq)
	copy(frame[13:], ciphertext)

	return frame
}

func TestGenerateVectors(t *testing.T) {
	if os.Getenv("GENERATE_VECTORS") == "" {
		t.Skip("Set GENERATE_VECTORS=1 to regenerate test vectors")
	}

	v := TestVectors{}

	// --- Base62 ---
	base62Cases := [][]byte{
		hexDec("000102030405060708090a0b0c0d0e0f"),
		hexDec("deadbeefcafebabe0123456789abcdef"),
		hexDec("ffffffffffffffffffffffffffffffff"),
	}
	for _, raw := range base62Cases {
		v.Base62 = append(v.Base62, Base62Vector{
			RawHex:  hex.EncodeToString(raw),
			Encoded: base62Encode(raw),
		})
	}

	// --- Key Derivation ---
	senderPriv := sha256Sum("sp2p-test-sender-private")
	receiverPriv := sha256Sum("sp2p-test-receiver-private")

	senderPub, err := curve25519.X25519(senderPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	receiverPub, err := curve25519.X25519(receiverPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}

	seedFull := sha256Sum("sp2p-test-seed")
	seed := seedFull[:SeedBytes]
	sessionID := "test1234"

	// Compute shared secret for the vector (sender's priv × receiver's pub).
	shared, err := curve25519.X25519(senderPriv, receiverPub)
	if err != nil {
		t.Fatal(err)
	}

	keys, err := DeriveKeys(senderPriv, receiverPub, seed, sessionID, senderPub, receiverPub)
	if err != nil {
		t.Fatal(err)
	}

	v.KeyDerivation = KeyDerivationVector{
		SenderPrivateHex:   hex.EncodeToString(senderPriv),
		SenderPublicHex:    hex.EncodeToString(senderPub),
		ReceiverPrivateHex: hex.EncodeToString(receiverPriv),
		ReceiverPublicHex:  hex.EncodeToString(receiverPub),
		SeedHex:            hex.EncodeToString(seed),
		SessionID:          sessionID,
	}
	v.KeyDerivation.Expected.SharedSecretHex = hex.EncodeToString(shared)
	v.KeyDerivation.Expected.SenderToReceiverHex = hex.EncodeToString(keys.SenderToReceiver)
	v.KeyDerivation.Expected.ReceiverToSenderHex = hex.EncodeToString(keys.ReceiverToSender)
	v.KeyDerivation.Expected.ConfirmHex = hex.EncodeToString(keys.Confirm)
	v.KeyDerivation.Expected.VerifyCode = keys.VerifyCode

	// Encryption tests using derived keys (for TypeScript to verify non-extractable keys).
	s2rPlain := []byte("Hello from sender")
	v.KeyDerivation.S2RFrameTest = FrameTest{
		MsgType:          2,
		Sequence:         0,
		PlaintextHex:     hex.EncodeToString(s2rPlain),
		ExpectedFrameHex: hex.EncodeToString(encryptFrameRaw(keys.SenderToReceiver, 2, 0, s2rPlain)),
	}

	r2sPlain := []byte("Hello from receiver")
	v.KeyDerivation.R2SFrameTest = FrameTest{
		MsgType:          3,
		Sequence:         0,
		PlaintextHex:     hex.EncodeToString(r2sPlain),
		ExpectedFrameHex: hex.EncodeToString(encryptFrameRaw(keys.ReceiverToSender, 3, 0, r2sPlain)),
	}

	// --- Confirmation ---
	// Use a distinct confirm key to test independently from key derivation.
	confirmKey := sha256Sum("sp2p-test-confirm-key")
	confirmSenderPub := sha256Sum("sp2p-test-confirm-sender-pub")
	confirmReceiverPub := sha256Sum("sp2p-test-confirm-receiver-pub")

	v.Confirmation = ConfirmationVector{
		ConfirmKeyHex:       hex.EncodeToString(confirmKey),
		SenderPubHex:        hex.EncodeToString(confirmSenderPub),
		ReceiverPubHex:      hex.EncodeToString(confirmReceiverPub),
		ExpectedSenderHex:   hex.EncodeToString(ComputeConfirmation(confirmKey, "sender", confirmSenderPub, confirmReceiverPub)),
		ExpectedReceiverHex: hex.EncodeToString(ComputeConfirmation(confirmKey, "receiver", confirmSenderPub, confirmReceiverPub)),
	}

	// --- Encrypted Frames (standalone, known key) ---
	frameKey := sha256Sum("sp2p-test-frame-key")

	v.EncFrames = []FrameVector{
		{
			KeyHex:           hex.EncodeToString(frameKey),
			MsgType:          1,
			Sequence:         0,
			PlaintextHex:     hex.EncodeToString([]byte("Hello")),
			ExpectedFrameHex: hex.EncodeToString(encryptFrameRaw(frameKey, 1, 0, []byte("Hello"))),
		},
		{
			KeyHex:           hex.EncodeToString(frameKey),
			MsgType:          2,
			Sequence:         1,
			PlaintextHex:     hex.EncodeToString(makeSeqBytes(64)),
			ExpectedFrameHex: hex.EncodeToString(encryptFrameRaw(frameKey, 2, 1, makeSeqBytes(64))),
		},
		{
			KeyHex:           hex.EncodeToString(frameKey),
			MsgType:          4,
			Sequence:         2,
			PlaintextHex:     "", // empty payload
			ExpectedFrameHex: hex.EncodeToString(encryptFrameRaw(frameKey, 4, 2, nil)),
		},
	}

	// --- File Info ---
	fileInfoSeed := sha256Sum("sp2p-test-fileinfo-seed")[:SeedBytes]
	fileInfoPlaintext := []byte(`{"name":"test.txt","size":12345,"isFolder":false,"fileCount":0}`)
	fileInfoEncrypted, err := EncryptFileInfo(fileInfoSeed, fileInfoPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	fileInfoKey, err := deriveFileInfoKey(fileInfoSeed)
	if err != nil {
		t.Fatal(err)
	}
	v.FileInfo = FileInfoVector{
		SeedHex:       hex.EncodeToString(fileInfoSeed),
		PlaintextHex:  hex.EncodeToString(fileInfoPlaintext),
		EncryptedHex:  hex.EncodeToString(fileInfoEncrypted),
		DerivedKeyHex: hex.EncodeToString(fileInfoKey),
	}

	// Write JSON.
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorsPath(), data, 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("Wrote vectors to %s", vectorsPath())
}

// --- Verification ---

func TestVerifyVectors(t *testing.T) {
	data, err := os.ReadFile(vectorsPath())
	if err != nil {
		t.Fatalf("reading vectors: %v (run with GENERATE_VECTORS=1 first)", err)
	}

	var v TestVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parsing vectors: %v", err)
	}

	t.Run("base62", func(t *testing.T) {
		for i, tc := range v.Base62 {
			raw := hexDec(tc.RawHex)

			encoded := base62Encode(raw)
			if encoded != tc.Encoded {
				t.Errorf("case %d: encode(%s) = %q, want %q", i, tc.RawHex, encoded, tc.Encoded)
			}

			decoded, err := base62Decode(tc.Encoded)
			if err != nil {
				t.Errorf("case %d: decode(%q) error: %v", i, tc.Encoded, err)
				continue
			}
			// Pad to match original length.
			if len(decoded) < len(raw) {
				padded := make([]byte, len(raw))
				copy(padded[len(raw)-len(decoded):], decoded)
				decoded = padded
			}
			if !bytes.Equal(decoded, raw) {
				t.Errorf("case %d: decode(%q) = %x, want %x", i, tc.Encoded, decoded, raw)
			}
		}
	})

	t.Run("keyDerivation", func(t *testing.T) {
		kd := v.KeyDerivation
		senderPriv := hexDec(kd.SenderPrivateHex)
		receiverPub := hexDec(kd.ReceiverPublicHex)
		senderPub := hexDec(kd.SenderPublicHex)
		seed := hexDec(kd.SeedHex)

		// Verify public key derivation.
		computedSenderPub, err := curve25519.X25519(senderPriv, curve25519.Basepoint)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(computedSenderPub, senderPub) {
			t.Error("sender public key mismatch")
		}

		computedReceiverPub, err := curve25519.X25519(hexDec(kd.ReceiverPrivateHex), curve25519.Basepoint)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(computedReceiverPub, receiverPub) {
			t.Error("receiver public key mismatch")
		}

		// Verify shared secret.
		shared, err := curve25519.X25519(senderPriv, receiverPub)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(shared) != kd.Expected.SharedSecretHex {
			t.Errorf("shared secret: got %x, want %s", shared, kd.Expected.SharedSecretHex)
		}

		// Verify key derivation.
		keys, err := DeriveKeys(senderPriv, receiverPub, seed, kd.SessionID, senderPub, receiverPub)
		if err != nil {
			t.Fatal(err)
		}

		if hex.EncodeToString(keys.SenderToReceiver) != kd.Expected.SenderToReceiverHex {
			t.Errorf("s2r key mismatch: got %x", keys.SenderToReceiver)
		}
		if hex.EncodeToString(keys.ReceiverToSender) != kd.Expected.ReceiverToSenderHex {
			t.Errorf("r2s key mismatch: got %x", keys.ReceiverToSender)
		}
		if hex.EncodeToString(keys.Confirm) != kd.Expected.ConfirmHex {
			t.Errorf("confirm key mismatch: got %x", keys.Confirm)
		}
		if keys.VerifyCode != kd.Expected.VerifyCode {
			t.Errorf("verify code mismatch: got %s, want %s", keys.VerifyCode, kd.Expected.VerifyCode)
		}

		// Verify frame encryption with derived keys.
		t.Run("s2r_frame", func(t *testing.T) {
			ft := kd.S2RFrameTest
			plain := hexDec(ft.PlaintextHex)
			frame := encryptFrameRaw(keys.SenderToReceiver, byte(ft.MsgType), uint64(ft.Sequence), plain)
			if hex.EncodeToString(frame) != ft.ExpectedFrameHex {
				t.Errorf("s2r frame mismatch:\n  got  %x\n  want %s", frame, ft.ExpectedFrameHex)
			}
		})

		t.Run("r2s_frame", func(t *testing.T) {
			ft := kd.R2SFrameTest
			plain := hexDec(ft.PlaintextHex)
			frame := encryptFrameRaw(keys.ReceiverToSender, byte(ft.MsgType), uint64(ft.Sequence), plain)
			if hex.EncodeToString(frame) != ft.ExpectedFrameHex {
				t.Errorf("r2s frame mismatch:\n  got  %x\n  want %s", frame, ft.ExpectedFrameHex)
			}
		})
	})

	t.Run("confirmation", func(t *testing.T) {
		c := v.Confirmation
		confirmKey := hexDec(c.ConfirmKeyHex)
		senderPub := hexDec(c.SenderPubHex)
		receiverPub := hexDec(c.ReceiverPubHex)

		senderMAC := ComputeConfirmation(confirmKey, "sender", senderPub, receiverPub)
		if hex.EncodeToString(senderMAC) != c.ExpectedSenderHex {
			t.Errorf("sender confirmation mismatch: got %x", senderMAC)
		}

		receiverMAC := ComputeConfirmation(confirmKey, "receiver", senderPub, receiverPub)
		if hex.EncodeToString(receiverMAC) != c.ExpectedReceiverHex {
			t.Errorf("receiver confirmation mismatch: got %x", receiverMAC)
		}

		// Cross-verification should fail.
		if VerifyConfirmation(confirmKey, "sender", senderPub, receiverPub, receiverMAC) {
			t.Error("sender MAC should not verify with receiver role")
		}
	})

	t.Run("encryptedFrames", func(t *testing.T) {
		for i, fv := range v.EncFrames {
			key := hexDec(fv.KeyHex)
			plain := hexDec(fv.PlaintextHex)
			frame := encryptFrameRaw(key, byte(fv.MsgType), uint64(fv.Sequence), plain)
			if hex.EncodeToString(frame) != fv.ExpectedFrameHex {
				t.Errorf("frame %d mismatch:\n  got  %x\n  want %s", i, frame, fv.ExpectedFrameHex)
			}

			// Also verify round-trip through EncryptedStream.
			var buf bytes.Buffer
			stream, err := NewEncryptedStream(&buf, key, key)
			if err != nil {
				t.Fatal(err)
			}
			// Advance write nonce to the expected sequence.
			stream.writeNonce = uint64(fv.Sequence)
			if err := stream.WriteFrame(byte(fv.MsgType), plain); err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(buf.Bytes()) != fv.ExpectedFrameHex {
				t.Errorf("frame %d EncryptedStream mismatch:\n  got  %x\n  want %s", i, buf.Bytes(), fv.ExpectedFrameHex)
			}
		}
	})

	t.Run("fileInfo", func(t *testing.T) {
		fi := v.FileInfo
		seed := hexDec(fi.SeedHex)
		expectedPlaintext := hexDec(fi.PlaintextHex)
		encrypted := hexDec(fi.EncryptedHex)

		// Verify key derivation.
		key, err := deriveFileInfoKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(key) != fi.DerivedKeyHex {
			t.Errorf("derived key mismatch: got %x, want %s", key, fi.DerivedKeyHex)
		}

		// Verify decryption of the Go-generated blob.
		plaintext, err := DecryptFileInfo(seed, encrypted)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(plaintext, expectedPlaintext) {
			t.Errorf("plaintext mismatch:\n  got  %x\n  want %s", plaintext, fi.PlaintextHex)
		}

		// Verify round-trip: encrypt then decrypt.
		reEncrypted, err := EncryptFileInfo(seed, expectedPlaintext)
		if err != nil {
			t.Fatalf("re-encrypt: %v", err)
		}
		reDecrypted, err := DecryptFileInfo(seed, reEncrypted)
		if err != nil {
			t.Fatalf("re-decrypt: %v", err)
		}
		if !bytes.Equal(reDecrypted, expectedPlaintext) {
			t.Error("round-trip mismatch")
		}
	})
}

// --- Helpers ---

func hexDec(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func sha256Sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func makeSeqBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}
