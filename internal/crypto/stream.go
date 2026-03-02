// SPDX-License-Identifier: MIT

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/zyno-io/sp2p/internal/transfer"
)

// EncryptedStream wraps a ReadWriter with AES-256-GCM encryption.
// It uses directional keys: one for writing, one for reading.
// Nonces are sequential counters starting at 0.
//
// Wire format per encrypted frame:
//
//	[4 bytes: total payload length, big-endian uint32]
//	[1 byte:  msg type (cleartext, also authenticated via AAD)]
//	[8 bytes: sequence number (big-endian uint64)]
//	[N bytes: AEAD ciphertext of msg data, with AAD = type || seq || version]
type EncryptedStream struct {
	raw io.ReadWriter

	writeAEAD  cipher.AEAD
	writeNonce uint64
	writeMu    sync.Mutex

	readAEAD  cipher.AEAD
	readNonce uint64
	readMu    sync.Mutex
}

// NewEncryptedStream creates an encrypted stream using directional keys.
// writeKey is used for outgoing data, readKey for incoming data.
func NewEncryptedStream(raw io.ReadWriter, writeKey, readKey []byte) (*EncryptedStream, error) {
	writeBlock, err := aes.NewCipher(writeKey)
	if err != nil {
		return nil, fmt.Errorf("creating write cipher: %w", err)
	}
	writeAEAD, err := cipher.NewGCM(writeBlock)
	if err != nil {
		return nil, fmt.Errorf("creating write GCM: %w", err)
	}

	readBlock, err := aes.NewCipher(readKey)
	if err != nil {
		return nil, fmt.Errorf("creating read cipher: %w", err)
	}
	readAEAD, err := cipher.NewGCM(readBlock)
	if err != nil {
		return nil, fmt.Errorf("creating read GCM: %w", err)
	}

	return &EncryptedStream{
		raw:       raw,
		writeAEAD: writeAEAD,
		readAEAD:  readAEAD,
	}, nil
}

// buildNonce creates a 96-bit nonce from a sequential counter.
func buildNonce(counter uint64) []byte {
	nonce := make([]byte, NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// buildAAD constructs Additional Authenticated Data: type || seq || version.
func buildAAD(msgType byte, seq uint64) []byte {
	aad := make([]byte, 10)
	aad[0] = msgType
	binary.BigEndian.PutUint64(aad[1:9], seq)
	aad[9] = 1 // protocol version
	return aad
}

// WriteFrame encrypts and writes a framed message.
func (s *EncryptedStream) WriteFrame(msgType byte, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	seq := s.writeNonce
	if seq >= 1<<32 {
		return fmt.Errorf("nonce counter exhausted — transfer too large")
	}

	nonce := buildNonce(seq)
	aad := buildAAD(msgType, seq)

	// Encrypt only the data payload; msg type is in cleartext header + AAD.
	ciphertext := s.writeAEAD.Seal(nil, nonce, data, aad)
	s.writeNonce++

	// Frame: [4 len] [1 type] [8 seq] [ciphertext]
	framePayloadLen := 1 + 8 + len(ciphertext)
	if framePayloadLen > transfer.MaxFrameSize {
		return fmt.Errorf("encrypted frame too large: %d", framePayloadLen)
	}

	// Build the full frame in one buffer to minimize writes.
	frame := make([]byte, 4+framePayloadLen)
	binary.BigEndian.PutUint32(frame[0:4], uint32(framePayloadLen))
	frame[4] = msgType
	binary.BigEndian.PutUint64(frame[5:13], seq)
	copy(frame[13:], ciphertext)

	if _, err := writeAll(s.raw, frame); err != nil {
		return err
	}
	return nil
}

// ReadFrame reads and decrypts a framed message.
// Returns the message type and decrypted data.
func (s *EncryptedStream) ReadFrame() (byte, []byte, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	// Check nonce exhaustion before reading. Nonces 0 through 2^32-1 are valid.
	if s.readNonce >= 1<<32 {
		return 0, nil, fmt.Errorf("nonce counter exhausted — transfer too large")
	}

	// Read length header.
	var hdr [4]byte
	if _, err := io.ReadFull(s.raw, hdr[:]); err != nil {
		return 0, nil, err
	}

	payloadLen := binary.BigEndian.Uint32(hdr[:])
	if payloadLen < 9 { // minimum: 1 type + 8 seq
		return 0, nil, fmt.Errorf("frame too small: %d", payloadLen)
	}
	if payloadLen > uint32(transfer.MaxFrameSize) {
		return 0, nil, fmt.Errorf("frame too large: %d", payloadLen)
	}

	// Read full payload.
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(s.raw, payload); err != nil {
		return 0, nil, err
	}

	msgType := payload[0]
	seq := binary.BigEndian.Uint64(payload[1:9])
	ciphertext := payload[9:]

	// Verify sequence order.
	if seq != s.readNonce {
		return 0, nil, fmt.Errorf("sequence mismatch: got %d, expected %d (possible replay/reorder)", seq, s.readNonce)
	}

	// Reconstruct nonce and AAD.
	nonce := buildNonce(seq)
	aad := buildAAD(msgType, seq)

	plaintext, err := s.readAEAD.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return 0, nil, fmt.Errorf("data integrity check failed — connection may be compromised: %w", err)
	}

	s.readNonce++
	return msgType, plaintext, nil
}

// writeAll writes all of p to w, handling short writes.
func writeAll(w io.Writer, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := w.Write(p[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
