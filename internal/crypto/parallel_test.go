// SPDX-License-Identifier: MIT

package crypto

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"
)

type replayedLaneCandidate struct {
	*bytes.Reader
}

func (*replayedLaneCandidate) Write(p []byte) (int, error) { return len(p), nil }
func (*replayedLaneCandidate) SetDeadline(time.Time) error { return nil }

func TestWebRTCLaneRejectsReplayedCandidateProof(t *testing.T) {
	keys, err := DeriveWebRTCLaneKeys(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	senderPub, receiverPub := []byte("sender"), []byte("receiver")
	oldSenderNonce, oldReceiverNonce := bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32)
	for _, sender := range []bool{true, false} {
		// Replay a valid challenge/proof from a previous candidate with the
		// same lane keys. The fresh local challenge must invalidate that proof.
		role, peerNonce := "receiver", oldReceiverNonce
		if !sender {
			role, peerNonce = "sender", oldSenderNonce
		}
		mac := hmac.New(sha256.New, keys.Confirm)
		mac.Write([]byte("sp2p/v3/candidate/" + role))
		mac.Write(senderPub)
		mac.Write(receiverPub)
		mac.Write(oldSenderNonce)
		mac.Write(oldReceiverNonce)
		transcript := append(append([]byte(nil), peerNonce...), mac.Sum(nil)...)
		peer := &replayedLaneCandidate{Reader: bytes.NewReader(transcript)}
		_, err := AuthenticateCandidate(context.Background(), peer, keys, senderPub, receiverPub, sender)
		if err == nil || !strings.Contains(err.Error(), "candidate authentication failed") {
			t.Fatalf("sender=%v accepted replay or failed for another reason: %v", sender, err)
		}
	}
}

func TestWebRTCLaneProofRejectsCrossLaneSetupAndSession(t *testing.T) {
	for _, mismatch := range []string{"lane", "setup", "session"} {
		t.Run(mismatch, func(t *testing.T) {
			confirm, nonce := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
			correct, err := DeriveWebRTCLaneKeys(confirm, nonce, 1)
			if err != nil {
				t.Fatal(err)
			}
			id := 1
			switch mismatch {
			case "lane":
				id = 2
			case "setup":
				nonce[0]++
			case "session":
				confirm[0]++
			}
			wrong, err := DeriveWebRTCLaneKeys(confirm, nonce, id)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			result := make(chan error, 1)
			go func() {
				_, err := AuthenticateCandidate(ctx, b, wrong, []byte("sender"), []byte("receiver"), false)
				result <- err
			}()
			_, err = AuthenticateCandidate(ctx, a, correct, []byte("sender"), []byte("receiver"), true)
			if err == nil {
				t.Fatal("sender accepted a mismatched lane proof")
			}
			if err := <-result; err == nil {
				t.Fatal("receiver accepted a mismatched lane proof")
			}
		})
	}
}

func TestWebRTCLaneKeys(t *testing.T) {
	confirm, nonce := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	keys, err := DeriveWebRTCLaneKeys(confirm, nonce, 1)
	if err != nil {
		t.Fatal(err)
	}
	for label, item := range map[string]struct {
		key []byte
		hex string
	}{
		"s2r":     {keys.SenderToReceiver, "2a568d4490c34636cc13bcc236026d5135067ad6d405e522efe9b35c6793f8c6"},
		"r2s":     {keys.ReceiverToSender, "013df1f1091470737a0de0f5e9de22f3231189f7720413d0e828304101a5c4ab"},
		"confirm": {keys.Confirm, "1db671558ed2f9c7812d62608c2dad77c2174caa7fc00ac3c3cbc6865abe010b"},
	} {
		if hex.EncodeToString(item.key) != item.hex {
			t.Fatalf("%s differs from browser vector", label)
		}
	}
	for _, id := range []int{0, 4, -1} {
		if _, err := DeriveWebRTCLaneKeys(confirm, nonce, id); err == nil {
			t.Fatalf("accepted lane %d", id)
		}
	}
	if _, err := DeriveWebRTCLaneKeys(confirm[:31], nonce, 1); err == nil {
		t.Fatal("accepted short key")
	}
	if _, err := DeriveWebRTCLaneKeys(confirm, nonce[:31], 1); err == nil {
		t.Fatal("accepted short nonce")
	}
	other, _ := DeriveWebRTCLaneKeys(confirm, nonce, 2)
	if bytes.Equal(other.Confirm, keys.Confirm) {
		t.Fatal("lane not bound")
	}
	nonce[0]++
	other, _ = DeriveWebRTCLaneKeys(confirm, nonce, 1)
	if bytes.Equal(other.Confirm, keys.Confirm) {
		t.Fatal("setup nonce not bound")
	}
	confirm[0]++
	third, _ := DeriveWebRTCLaneKeys(confirm, nonce, 1)
	if bytes.Equal(third.Confirm, other.Confirm) {
		t.Fatal("session not bound")
	}
}

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
