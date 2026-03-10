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

// buildNonce writes a 96-bit nonce from a sequential counter into dst.
func buildNonce(dst []byte, counter uint64) {
	_ = dst[NonceSize-1] // bounds check hint
	dst[0] = 0
	dst[1] = 0
	dst[2] = 0
	dst[3] = 0
	binary.BigEndian.PutUint64(dst[4:], counter)
}

// buildAAD writes Additional Authenticated Data (type || seq || version) into dst.
func buildAAD(dst []byte, msgType byte, seq uint64) {
	_ = dst[9] // bounds check hint
	dst[0] = msgType
	binary.BigEndian.PutUint64(dst[1:9], seq)
	dst[9] = 1 // protocol version
}

// PrepareFrame encrypts a message and returns the complete wire-format frame
// without writing it. The returned bytes can later be written with WriteRawFrame.
// This enables pipelining encryption and I/O in separate goroutines.
// PrepareFrame is safe for concurrent use; it serializes nonce assignment internally.
func (s *EncryptedStream) PrepareFrame(msgType byte, data []byte) ([]byte, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	seq := s.writeNonce
	if seq >= 1<<32 {
		return nil, fmt.Errorf("nonce counter exhausted — transfer too large")
	}

	var nonce [NonceSize]byte
	buildNonce(nonce[:], seq)
	var aad [10]byte
	buildAAD(aad[:], msgType, seq)

	// Frame layout: [4 len] [1 type] [8 seq] [ciphertext]
	// Encrypt directly into the frame buffer to avoid a separate
	// ciphertext allocation and copy.
	overhead := s.writeAEAD.Overhead()
	ciphertextLen := len(data) + overhead
	framePayloadLen := 1 + 8 + ciphertextLen
	if framePayloadLen > transfer.MaxFrameSize {
		return nil, fmt.Errorf("encrypted frame too large: %d", framePayloadLen)
	}

	frame := make([]byte, 13, 4+framePayloadLen)
	binary.BigEndian.PutUint32(frame[0:4], uint32(framePayloadLen))
	frame[4] = msgType
	binary.BigEndian.PutUint64(frame[5:13], seq)
	// Seal appends ciphertext to frame[13:13], extending to full capacity.
	frame = s.writeAEAD.Seal(frame, nonce[:], data, aad[:])

	s.writeNonce++
	return frame, nil
}

// ReserveWriteSeq reserves and returns the next write sequence number.
// The caller can then use PrepareFrameAt to encrypt a frame with this
// sequence number from any goroutine. Nonces must be reserved in order.
func (s *EncryptedStream) ReserveWriteSeq() (uint64, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	seq := s.writeNonce
	if seq >= 1<<32 {
		return 0, fmt.Errorf("nonce counter exhausted — transfer too large")
	}
	s.writeNonce++
	return seq, nil
}

// PrepareFrameAt encrypts a frame using a pre-reserved sequence number.
// Unlike PrepareFrame, this is safe for concurrent use with different
// sequence numbers — multiple goroutines can encrypt in parallel.
// This relies on cipher.AEAD.Seal being stateless and goroutine-safe,
// which holds for Go's standard library AES-GCM implementation (the only
// AEAD used here). This is NOT a general cipher.AEAD guarantee.
// Callers must ensure frames are written in sequence order via WriteRawFrame.
func (s *EncryptedStream) PrepareFrameAt(msgType byte, data []byte, seq uint64) ([]byte, error) {
	var nonce [NonceSize]byte
	buildNonce(nonce[:], seq)
	var aad [10]byte
	buildAAD(aad[:], msgType, seq)

	overhead := s.writeAEAD.Overhead()
	ciphertextLen := len(data) + overhead
	framePayloadLen := 1 + 8 + ciphertextLen
	if framePayloadLen > transfer.MaxFrameSize {
		return nil, fmt.Errorf("encrypted frame too large: %d", framePayloadLen)
	}

	frame := make([]byte, 13, 4+framePayloadLen)
	binary.BigEndian.PutUint32(frame[0:4], uint32(framePayloadLen))
	frame[4] = msgType
	binary.BigEndian.PutUint64(frame[5:13], seq)
	frame = s.writeAEAD.Seal(frame, nonce[:], data, aad[:])

	return frame, nil
}

// WriteRawFrame writes a pre-built frame (from PrepareFrame) to the underlying connection.
func (s *EncryptedStream) WriteRawFrame(frame []byte) error {
	_, err := writeAll(s.raw, frame)
	return err
}

// WriteFrame encrypts and writes a framed message.
func (s *EncryptedStream) WriteFrame(msgType byte, data []byte) error {
	frame, err := s.PrepareFrame(msgType, data)
	if err != nil {
		return err
	}
	return s.WriteRawFrame(frame)
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
	var nonce [NonceSize]byte
	buildNonce(nonce[:], seq)
	var aad [10]byte
	buildAAD(aad[:], msgType, seq)

	plaintext, err := s.readAEAD.Open(nil, nonce[:], ciphertext, aad[:])
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
