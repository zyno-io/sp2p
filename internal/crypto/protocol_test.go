// SPDX-License-Identifier: MIT

package crypto

import (
	"bytes"
	"testing"
)

func TestTransferProtocolNegotiation(t *testing.T) {
	for _, senderV3 := range []bool{false, true} {
		for _, receiverV3 := range []bool{false, true} {
			sender, err := GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			if sender.Public[31]&0x80 != 0 || receiver.Public[31]&0x80 != 0 {
				t.Fatal("legacy public key must be canonical")
			}
			canonical := append([]byte(nil), receiver.Public...)
			if senderV3 {
				sender.Public[31] |= 0x80
			}
			if receiverV3 {
				receiver.Public[31] |= 0x80
			}
			version, err := TransferProtocol(sender.Public, receiver.Public)
			want := 2
			if senderV3 && receiverV3 {
				want = 3
			}
			if err != nil || version != want {
				t.Fatalf("version: %d, %v", version, err)
			}
			// RFC 7748 decoding preserves the same DH result for old libraries.
			original, err := ComputeSharedSecret(sender.Private, canonical)
			if err != nil {
				t.Fatal(err)
			}
			marked, err := ComputeSharedSecret(sender.Private, receiver.Public)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(original, marked) {
				t.Fatal("marker changed DH")
			}
			seed := bytes.Repeat([]byte{7}, 16)
			sk, err := DeriveKeys(sender.Private, receiver.Public, seed, "session1", sender.Public, receiver.Public)
			if err != nil {
				t.Fatal(err)
			}
			rk, err := DeriveKeys(receiver.Private, sender.Public, seed, "session1", sender.Public, receiver.Public)
			if err != nil {
				t.Fatal(err)
			}
			proof := ComputeConfirmation(sk.Confirm, "sender", sender.Public, receiver.Public)
			if !VerifyConfirmation(rk.Confirm, "sender", sender.Public, receiver.Public, proof) {
				t.Fatal("honest negotiation failed confirmation")
			}
		}
	}
	for _, length := range []int{0, 31, 33, 64} {
		if _, err := TransferProtocol(make([]byte, length), make([]byte, 32)); err == nil {
			t.Fatal("accepted invalid sender key length")
		}
		if _, err := TransferProtocol(make([]byte, 32), make([]byte, length)); err == nil {
			t.Fatal("accepted invalid receiver key length")
		}
	}
}

func TestTransferCapabilityTamperingFailsConfirmation(t *testing.T) {
	// Cover removal, addition, and bidirectional removal/addition. Keeping only
	// the DH point is not enough: the two ends must bind the exact sent bytes.
	for _, initiallyV3 := range []bool{false, true} {
		for _, mask := range []int{1, 2, 3} {
			sender, err := GenerateTransferKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := GenerateTransferKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			if !initiallyV3 {
				sender.Public[31] &= 0x7f
				receiver.Public[31] &= 0x7f
			}
			seenSender := append([]byte(nil), sender.Public...)
			seenReceiver := append([]byte(nil), receiver.Public...)
			if mask&1 != 0 {
				seenSender[31] ^= 0x80
			}
			if mask&2 != 0 {
				seenReceiver[31] ^= 0x80
			}
			seed := bytes.Repeat([]byte{7}, 16)
			sk, err := DeriveKeys(sender.Private, seenReceiver, seed, "session1", sender.Public, seenReceiver)
			if err != nil {
				t.Fatal(err)
			}
			rk, err := DeriveKeys(receiver.Private, seenSender, seed, "session1", seenSender, receiver.Public)
			if err != nil {
				t.Fatal(err)
			}
			proof := ComputeConfirmation(sk.Confirm, "sender", sender.Public, seenReceiver)
			if VerifyConfirmation(rk.Confirm, "sender", seenSender, receiver.Public, proof) {
				t.Fatalf("accepted marker tampering: v3=%v mask=%d", initiallyV3, mask)
			}
			if bytes.Equal(sk.SenderToReceiver, rk.SenderToReceiver) {
				t.Fatal("tampering did not change traffic keys")
			}
		}
	}
}
