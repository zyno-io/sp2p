// SPDX-License-Identifier: MIT

package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveParallelKeys(t *testing.T) {
	sharedSecret := bytes.Repeat([]byte{0x42}, 32)
	seed := bytes.Repeat([]byte{0x01}, 16)
	sessionID := "test-session"
	senderPub := bytes.Repeat([]byte{0xAA}, 32)
	receiverPub := bytes.Repeat([]byte{0xBB}, 32)

	// Derive keys for index 1.
	writeKey1, readKey1, err := DeriveParallelKeys(sharedSecret, seed, 1, sessionID, senderPub, receiverPub)
	if err != nil {
		t.Fatalf("DeriveParallelKeys(1): %v", err)
	}
	if len(writeKey1) != KeySize || len(readKey1) != KeySize {
		t.Fatalf("unexpected key sizes: %d, %d", len(writeKey1), len(readKey1))
	}

	// Write and read keys should be different.
	if bytes.Equal(writeKey1, readKey1) {
		t.Fatal("write and read keys should differ")
	}

	// Derive keys for index 2 — should differ from index 1.
	writeKey2, readKey2, err := DeriveParallelKeys(sharedSecret, seed, 2, sessionID, senderPub, receiverPub)
	if err != nil {
		t.Fatalf("DeriveParallelKeys(2): %v", err)
	}
	if bytes.Equal(writeKey1, writeKey2) {
		t.Fatal("different indices should produce different write keys")
	}
	if bytes.Equal(readKey1, readKey2) {
		t.Fatal("different indices should produce different read keys")
	}

	// Same inputs should be deterministic.
	writeKey1b, readKey1b, err := DeriveParallelKeys(sharedSecret, seed, 1, sessionID, senderPub, receiverPub)
	if err != nil {
		t.Fatalf("DeriveParallelKeys(1) again: %v", err)
	}
	if !bytes.Equal(writeKey1, writeKey1b) || !bytes.Equal(readKey1, readKey1b) {
		t.Fatal("derivation should be deterministic")
	}

	// Index 0 should error.
	_, _, err = DeriveParallelKeys(sharedSecret, seed, 0, sessionID, senderPub, receiverPub)
	if err == nil {
		t.Fatal("expected error for index 0")
	}

	// Different session ID should produce different keys.
	writeKey1c, _, err := DeriveParallelKeys(sharedSecret, seed, 1, "different-session", senderPub, receiverPub)
	if err != nil {
		t.Fatalf("DeriveParallelKeys different session: %v", err)
	}
	if bytes.Equal(writeKey1, writeKey1c) {
		t.Fatal("different session IDs should produce different keys")
	}

	// Different public keys should produce different keys.
	writeKey1d, _, err := DeriveParallelKeys(sharedSecret, seed, 1, sessionID, receiverPub, senderPub)
	if err != nil {
		t.Fatalf("DeriveParallelKeys swapped pubkeys: %v", err)
	}
	if bytes.Equal(writeKey1, writeKey1d) {
		t.Fatal("different public keys should produce different keys")
	}
}

func TestDeriveParallelToken(t *testing.T) {
	sharedSecret := bytes.Repeat([]byte{0x42}, 32)
	seed := bytes.Repeat([]byte{0x01}, 16)
	sessionID := "test-session"
	senderPub := bytes.Repeat([]byte{0xAA}, 32)
	receiverPub := bytes.Repeat([]byte{0xBB}, 32)

	token1, err := DeriveParallelToken(sharedSecret, seed, sessionID, senderPub, receiverPub)
	if err != nil {
		t.Fatalf("DeriveParallelToken: %v", err)
	}

	// Should be deterministic.
	token2, err := DeriveParallelToken(sharedSecret, seed, sessionID, senderPub, receiverPub)
	if err != nil {
		t.Fatalf("DeriveParallelToken again: %v", err)
	}
	if token1 != token2 {
		t.Fatal("token derivation should be deterministic")
	}

	// Different secret should produce different token.
	differentSecret := bytes.Repeat([]byte{0x43}, 32)
	token3, err := DeriveParallelToken(differentSecret, seed, sessionID, senderPub, receiverPub)
	if err != nil {
		t.Fatalf("DeriveParallelToken different secret: %v", err)
	}
	if token1 == token3 {
		t.Fatal("different secrets should produce different tokens")
	}

	// Different session should produce different token.
	token4, err := DeriveParallelToken(sharedSecret, seed, "other-session", senderPub, receiverPub)
	if err != nil {
		t.Fatalf("DeriveParallelToken different session: %v", err)
	}
	if token1 == token4 {
		t.Fatal("different sessions should produce different tokens")
	}
}

func TestComputeSharedSecret(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	ss1, err := ComputeSharedSecret(kp1.Private, kp2.Public)
	if err != nil {
		t.Fatalf("ComputeSharedSecret(1→2): %v", err)
	}
	ss2, err := ComputeSharedSecret(kp2.Private, kp1.Public)
	if err != nil {
		t.Fatalf("ComputeSharedSecret(2→1): %v", err)
	}

	if !bytes.Equal(ss1, ss2) {
		t.Fatal("shared secrets should be equal")
	}
}
