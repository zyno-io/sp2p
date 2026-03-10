// SPDX-License-Identifier: MIT

package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	KeySize    = 32 // X25519 / AES-256
	NonceSize  = 12 // AES-GCM nonce
	TagSize    = 16 // AES-GCM tag
	VerifySize = 4  // Verification code bytes
)

// KeyPair holds an X25519 key pair.
type KeyPair struct {
	Private []byte
	Public  []byte
}

// DerivedKeys holds all keys derived from the key exchange.
type DerivedKeys struct {
	SenderToReceiver []byte // k_s2r: sender→receiver data key
	ReceiverToSender []byte // k_r2s: receiver→sender data key
	Confirm          []byte // k_confirm: key confirmation MAC key
	VerifyCode       string // 8 hex chars for optional visual verification
}

// GenerateKeyPair generates a new X25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	priv := make([]byte, KeySize)
	if _, err := rand.Read(priv); err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("computing public key: %w", err)
	}

	return &KeyPair{Private: priv, Public: pub}, nil
}

// ComputeSharedSecret performs X25519 DH and returns the raw shared secret.
// This is the same computation as the first step of DeriveKeys, exposed
// separately so callers can use it for deriving parallel stream keys.
func ComputeSharedSecret(myPrivate, theirPublic []byte) ([]byte, error) {
	shared, err := curve25519.X25519(myPrivate, theirPublic)
	if err != nil {
		return nil, fmt.Errorf("X25519 failed: %w", err)
	}

	allZero := true
	for _, b := range shared {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, fmt.Errorf("invalid DH shared secret (low-order point)")
	}
	return shared, nil
}

// DeriveKeys performs X25519 DH and derives all session keys using HKDF.
//
// Parameters:
//   - myPrivate: our X25519 private key
//   - theirPublic: peer's X25519 public key
//   - seed: raw encryption seed (16 bytes)
//   - sessionID: the session identifier
//   - senderPub: sender's public key (for transcript binding)
//   - receiverPub: receiver's public key (for transcript binding)
func DeriveKeys(myPrivate, theirPublic, seed []byte, sessionID string, senderPub, receiverPub []byte) (*DerivedKeys, error) {
	// Compute DH shared secret.
	shared, err := curve25519.X25519(myPrivate, theirPublic)
	if err != nil {
		return nil, fmt.Errorf("X25519 failed: %w", err)
	}

	// Validate: reject all-zero shared secret (low-order point attack).
	allZero := true
	for _, b := range shared {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, fmt.Errorf("invalid DH shared secret (low-order point)")
	}

	// HKDF-Extract: prk = HKDF-Extract(salt=seed, ikm=shared)
	prk := hkdf.Extract(sha256.New, shared, seed)

	// Build info prefix for transcript binding:
	// "sp2p-v1" || session_id || sender_pubkey || receiver_pubkey
	infoPrefix := make([]byte, 0, 7+len(sessionID)+len(senderPub)+len(receiverPub))
	infoPrefix = append(infoPrefix, "sp2p-v1"...)
	infoPrefix = append(infoPrefix, []byte(sessionID)...)
	infoPrefix = append(infoPrefix, senderPub...)
	infoPrefix = append(infoPrefix, receiverPub...)

	keys := &DerivedKeys{}

	// k_s2r = HKDF-Expand(prk, info_prefix || "sender-to-receiver", 32)
	keys.SenderToReceiver, err = hkdfExpand(prk, infoPrefix, "sender-to-receiver", KeySize)
	if err != nil {
		return nil, err
	}

	// k_r2s = HKDF-Expand(prk, info_prefix || "receiver-to-sender", 32)
	keys.ReceiverToSender, err = hkdfExpand(prk, infoPrefix, "receiver-to-sender", KeySize)
	if err != nil {
		return nil, err
	}

	// k_confirm = HKDF-Expand(prk, info_prefix || "key-confirm", 32)
	keys.Confirm, err = hkdfExpand(prk, infoPrefix, "key-confirm", KeySize)
	if err != nil {
		return nil, err
	}

	// verify = HKDF-Expand(prk, info_prefix || "sp2p-verify", 4) → 8 hex chars
	verifyBytes, err := hkdfExpand(prk, infoPrefix, "sp2p-verify", VerifySize)
	if err != nil {
		return nil, err
	}
	keys.VerifyCode = fmt.Sprintf("%x", verifyBytes)

	return keys, nil
}

func hkdfExpand(prk, infoPrefix []byte, label string, length int) ([]byte, error) {
	// Defensive copy: append to infoPrefix would mutate the underlying array
	// if it ever had spare capacity.
	info := make([]byte, len(infoPrefix)+len(label))
	copy(info, infoPrefix)
	copy(info[len(infoPrefix):], label)

	r := hkdf.Expand(sha256.New, prk, info)
	out := make([]byte, length)
	if _, err := r.Read(out); err != nil {
		return nil, fmt.Errorf("HKDF-Expand(%s): %w", label, err)
	}
	return out, nil
}

// ComputeConfirmation computes the key confirmation HMAC.
// role is "sender" or "receiver", pubkeys are both public keys concatenated.
func ComputeConfirmation(confirmKey []byte, role string, senderPub, receiverPub []byte) []byte {
	mac := hmac.New(sha256.New, confirmKey)
	mac.Write([]byte(role))
	mac.Write(senderPub)
	mac.Write(receiverPub)
	return mac.Sum(nil)
}

// VerifyConfirmation checks a key confirmation HMAC.
func VerifyConfirmation(confirmKey []byte, role string, senderPub, receiverPub, expected []byte) bool {
	computed := ComputeConfirmation(confirmKey, role, senderPub, receiverPub)
	return subtle.ConstantTimeCompare(computed, expected) == 1
}
