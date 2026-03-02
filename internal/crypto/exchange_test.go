// SPDX-License-Identifier: MIT

package crypto

import (
	"testing"
)

func TestKeyPairGeneration(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(kp.Private) != KeySize {
		t.Fatalf("expected %d byte private key, got %d", KeySize, len(kp.Private))
	}
	if len(kp.Public) != KeySize {
		t.Fatalf("expected %d byte public key, got %d", KeySize, len(kp.Public))
	}
}

func TestDeriveKeys(t *testing.T) {
	sender, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	_, seedRaw, err := GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}

	sessionID := "test1234"

	// Sender derives keys.
	senderKeys, err := DeriveKeys(sender.Private, receiver.Public, seedRaw, sessionID, sender.Public, receiver.Public)
	if err != nil {
		t.Fatal(err)
	}

	// Receiver derives keys.
	receiverKeys, err := DeriveKeys(receiver.Private, sender.Public, seedRaw, sessionID, sender.Public, receiver.Public)
	if err != nil {
		t.Fatal(err)
	}

	// Verify directional keys match.
	assertBytesEqual(t, "SenderToReceiver", senderKeys.SenderToReceiver, receiverKeys.SenderToReceiver)
	assertBytesEqual(t, "ReceiverToSender", senderKeys.ReceiverToSender, receiverKeys.ReceiverToSender)
	assertBytesEqual(t, "Confirm", senderKeys.Confirm, receiverKeys.Confirm)

	if senderKeys.VerifyCode != receiverKeys.VerifyCode {
		t.Fatalf("verify codes don't match: %s != %s", senderKeys.VerifyCode, receiverKeys.VerifyCode)
	}

	// Verify directional keys are different from each other.
	if bytesEqual(senderKeys.SenderToReceiver, senderKeys.ReceiverToSender) {
		t.Fatal("directional keys should be different")
	}
}

func TestKeyConfirmation(t *testing.T) {
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()
	_, seedRaw, _ := GenerateSeed()
	sessionID := "test1234"

	keys, _ := DeriveKeys(sender.Private, receiver.Public, seedRaw, sessionID, sender.Public, receiver.Public)

	// Compute confirmations.
	senderConfirm := ComputeConfirmation(keys.Confirm, "sender", sender.Public, receiver.Public)
	receiverConfirm := ComputeConfirmation(keys.Confirm, "receiver", sender.Public, receiver.Public)

	// Verify.
	if !VerifyConfirmation(keys.Confirm, "sender", sender.Public, receiver.Public, senderConfirm) {
		t.Fatal("sender confirmation should verify")
	}
	if !VerifyConfirmation(keys.Confirm, "receiver", sender.Public, receiver.Public, receiverConfirm) {
		t.Fatal("receiver confirmation should verify")
	}

	// Wrong role should fail.
	if VerifyConfirmation(keys.Confirm, "receiver", sender.Public, receiver.Public, senderConfirm) {
		t.Fatal("wrong role should fail verification")
	}
}

func TestDeriveKeysDifferentSeed(t *testing.T) {
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()
	_, seed1, _ := GenerateSeed()
	_, seed2, _ := GenerateSeed()
	sessionID := "test1234"

	keys1, _ := DeriveKeys(sender.Private, receiver.Public, seed1, sessionID, sender.Public, receiver.Public)
	keys2, _ := DeriveKeys(sender.Private, receiver.Public, seed2, sessionID, sender.Public, receiver.Public)

	if bytesEqual(keys1.SenderToReceiver, keys2.SenderToReceiver) {
		t.Fatal("different seeds should produce different keys")
	}
}

func assertBytesEqual(t *testing.T, name string, a, b []byte) {
	t.Helper()
	if !bytesEqual(a, b) {
		t.Fatalf("%s: bytes don't match", name)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
