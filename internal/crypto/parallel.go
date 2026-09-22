// SPDX-License-Identifier: MIT

package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"

	"golang.org/x/crypto/hkdf"
)

// DeriveWebRTCLaneKeys domain-separates each additional WebRTC connection from
// both the primary stream and parallel TCP. Confirm already binds the session
// and both public keys. A fresh, encrypted setup nonce additionally binds the
// keys to this one negotiation; indices are the original lane IDs, not the
// positions of surviving lanes after partial setup.
func DeriveWebRTCLaneKeys(confirm, setupNonce []byte, index int) (*DerivedKeys, error) {
	if len(confirm) != 32 || len(setupNonce) != 32 || index < 1 || index > 3 {
		return nil, fmt.Errorf("invalid WebRTC lane key parameters")
	}
	derive := func(label string) ([]byte, error) {
		info := []byte("sp2p/v3/webrtc/lane/" + strconv.Itoa(index) + "/" + label)
		out := make([]byte, 32)
		_, err := io.ReadFull(hkdf.New(sha256.New, confirm, setupNonce, info), out)
		return out, err
	}
	s2r, err := derive("sender-to-receiver")
	if err != nil {
		return nil, err
	}
	r2s, err := derive("receiver-to-sender")
	if err != nil {
		return nil, err
	}
	proof, err := derive("key-confirm")
	if err != nil {
		return nil, err
	}
	return &DerivedKeys{SenderToReceiver: s2r, ReceiverToSender: r2s, Confirm: proof}, nil
}

// DeriveParallelKeys derives a write/read key pair for a secondary parallel
// TCP stream at the given index. Stream 0 (primary) uses the original keys;
// this function is for indices 1..N-1.
//
// Keys are derived from the shared HKDF PRK (not the session keys themselves)
// using distinct labels per stream index with transcript binding (session ID
// and public keys in the HKDF info), ensuring cryptographic independence and
// session binding consistent with DeriveKeys.
func DeriveParallelKeys(sharedSecret, seed []byte, index int, sessionID string, senderPub, receiverPub []byte) (s2rKey, r2sKey []byte, err error) {
	if index < 1 {
		return nil, nil, fmt.Errorf("parallel key index must be >= 1, got %d", index)
	}

	// Extract PRK from shared secret + seed, same as DeriveKeys does.
	prk := hkdf.Extract(sha256.New, sharedSecret, seed)

	// Build info prefix for transcript binding, matching DeriveKeys:
	// "sp2p-v1" || session_id || sender_pubkey || receiver_pubkey
	infoPrefix := make([]byte, 0, 7+len(sessionID)+len(senderPub)+len(receiverPub))
	infoPrefix = append(infoPrefix, "sp2p-v1"...)
	infoPrefix = append(infoPrefix, []byte(sessionID)...)
	infoPrefix = append(infoPrefix, senderPub...)
	infoPrefix = append(infoPrefix, receiverPub...)

	suffix := strconv.Itoa(index)

	s2rKey, err = hkdfExpand(prk, infoPrefix, "s2r-parallel-"+suffix, KeySize)
	if err != nil {
		return nil, nil, err
	}
	r2sKey, err = hkdfExpand(prk, infoPrefix, "r2s-parallel-"+suffix, KeySize)
	if err != nil {
		return nil, nil, err
	}
	return s2rKey, r2sKey, nil
}

// DeriveParallelToken derives a 16-byte HKDF token for authenticating
// secondary TCP connections to a specific session. Includes session
// binding via sessionID and public keys, consistent with DeriveParallelKeys.
func DeriveParallelToken(sharedSecret, seed []byte, sessionID string, senderPub, receiverPub []byte) ([16]byte, error) {
	prk := hkdf.Extract(sha256.New, sharedSecret, seed)

	// Build info prefix for transcript binding, matching DeriveParallelKeys.
	infoPrefix := make([]byte, 0, 7+len(sessionID)+len(senderPub)+len(receiverPub))
	infoPrefix = append(infoPrefix, "sp2p-v1"...)
	infoPrefix = append(infoPrefix, []byte(sessionID)...)
	infoPrefix = append(infoPrefix, senderPub...)
	infoPrefix = append(infoPrefix, receiverPub...)

	data, err := hkdfExpand(prk, infoPrefix, "parallel-tcp", 16)
	if err != nil {
		return [16]byte{}, err
	}
	var token [16]byte
	copy(token[:], data)
	return token, nil
}
