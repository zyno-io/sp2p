// SPDX-License-Identifier: MIT

package crypto

import (
	"crypto/sha256"
	"fmt"
	"strconv"

	"golang.org/x/crypto/hkdf"
)

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
