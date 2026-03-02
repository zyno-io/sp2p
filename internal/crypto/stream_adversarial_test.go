// SPDX-License-Identifier: MIT

package crypto

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/zyno-io/sp2p/internal/transfer"
)

// TestTamperedCiphertext verifies that modifying ciphertext causes decryption failure.
func TestTamperedCiphertext(t *testing.T) {
	writeKey := make([]byte, KeySize)
	readKey := make([]byte, KeySize)
	copy(writeKey, bytes.Repeat([]byte{0xAA}, KeySize))
	copy(readKey, bytes.Repeat([]byte{0xBB}, KeySize))

	var buf bytes.Buffer

	writer, err := NewEncryptedStream(&buf, writeKey, readKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := writer.WriteFrame(transfer.MsgData, []byte("secret data")); err != nil {
		t.Fatal(err)
	}

	// Tamper with the ciphertext (last byte before end).
	raw := buf.Bytes()
	raw[len(raw)-2] ^= 0xFF

	reader, err := NewEncryptedStream(bytes.NewBuffer(raw), readKey, writeKey)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = reader.ReadFrame()
	if err == nil {
		t.Fatal("expected decryption failure on tampered ciphertext")
	}
}

// TestTamperedMsgType verifies that modifying the message type in the cleartext header
// is caught by AAD verification.
func TestTamperedMsgType(t *testing.T) {
	writeKey := bytes.Repeat([]byte{0xCC}, KeySize)
	readKey := bytes.Repeat([]byte{0xDD}, KeySize)

	var buf bytes.Buffer

	writer, err := NewEncryptedStream(&buf, writeKey, readKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := writer.WriteFrame(transfer.MsgData, []byte("test")); err != nil {
		t.Fatal(err)
	}

	raw := buf.Bytes()
	// The message type is at byte offset 4 (after 4-byte length header).
	raw[4] = transfer.MsgMetadata // Change type from MsgData to MsgMetadata

	reader, err := NewEncryptedStream(bytes.NewBuffer(raw), readKey, writeKey)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = reader.ReadFrame()
	if err == nil {
		t.Fatal("expected decryption failure on tampered message type (AAD mismatch)")
	}
}

// TestTamperedSequenceNumber verifies that modifying the sequence number
// is caught by sequence validation.
func TestTamperedSequenceNumber(t *testing.T) {
	writeKey := bytes.Repeat([]byte{0x11}, KeySize)
	readKey := bytes.Repeat([]byte{0x22}, KeySize)

	var buf bytes.Buffer

	writer, err := NewEncryptedStream(&buf, writeKey, readKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := writer.WriteFrame(transfer.MsgData, []byte("test")); err != nil {
		t.Fatal(err)
	}

	raw := buf.Bytes()
	// Sequence number is at bytes 5-12. Set it to 1 instead of 0.
	binary.BigEndian.PutUint64(raw[5:13], 1)

	reader, err := NewEncryptedStream(bytes.NewBuffer(raw), readKey, writeKey)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = reader.ReadFrame()
	if err == nil {
		t.Fatal("expected failure on wrong sequence number")
	}
}

// TestReplayAttack verifies that replaying a frame is detected.
func TestReplayAttack(t *testing.T) {
	writeKey := bytes.Repeat([]byte{0x33}, KeySize)
	readKey := bytes.Repeat([]byte{0x44}, KeySize)

	var buf bytes.Buffer

	writer, err := NewEncryptedStream(&buf, writeKey, readKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := writer.WriteFrame(transfer.MsgData, []byte("frame0")); err != nil {
		t.Fatal(err)
	}

	frame0 := make([]byte, buf.Len())
	copy(frame0, buf.Bytes())

	// Write a second frame.
	buf.Reset()
	if err := writer.WriteFrame(transfer.MsgData, []byte("frame1")); err != nil {
		t.Fatal(err)
	}

	// Build a stream with frame0, then frame0 again (replay).
	var replay bytes.Buffer
	replay.Write(frame0)
	replay.Write(frame0) // replayed frame

	reader, err := NewEncryptedStream(&replay, readKey, writeKey)
	if err != nil {
		t.Fatal(err)
	}

	// First read should succeed.
	_, _, err = reader.ReadFrame()
	if err != nil {
		t.Fatalf("first read should succeed: %v", err)
	}

	// Second read is a replay (seq 0 again, but reader expects seq 1).
	_, _, err = reader.ReadFrame()
	if err == nil {
		t.Fatal("expected replay detection (sequence mismatch)")
	}
}

// TestWrongDecryptionKey verifies that using the wrong key fails.
func TestWrongDecryptionKey(t *testing.T) {
	writeKey := bytes.Repeat([]byte{0x55}, KeySize)
	readKey := bytes.Repeat([]byte{0x66}, KeySize)
	wrongKey := bytes.Repeat([]byte{0x77}, KeySize)

	var buf bytes.Buffer

	writer, err := NewEncryptedStream(&buf, writeKey, readKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := writer.WriteFrame(transfer.MsgData, []byte("secret")); err != nil {
		t.Fatal(err)
	}

	// Reader uses wrong key.
	reader, err := NewEncryptedStream(bytes.NewBuffer(buf.Bytes()), readKey, wrongKey)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = reader.ReadFrame()
	if err == nil {
		t.Fatal("expected decryption failure with wrong key")
	}
}

// TestTruncatedFrame verifies that a truncated frame is detected.
func TestTruncatedFrame(t *testing.T) {
	writeKey := bytes.Repeat([]byte{0x88}, KeySize)
	readKey := bytes.Repeat([]byte{0x99}, KeySize)

	var buf bytes.Buffer

	writer, err := NewEncryptedStream(&buf, writeKey, readKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := writer.WriteFrame(transfer.MsgData, []byte("test data")); err != nil {
		t.Fatal(err)
	}

	// Truncate the frame (remove last 5 bytes).
	raw := buf.Bytes()
	truncated := raw[:len(raw)-5]

	reader, err := NewEncryptedStream(bytes.NewBuffer(truncated), readKey, writeKey)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = reader.ReadFrame()
	if err == nil {
		t.Fatal("expected error on truncated frame")
	}
}

// TestFrameTooSmall verifies that a frame with payload too small is rejected.
func TestFrameTooSmall(t *testing.T) {
	// Write a frame header claiming payload of 4 bytes (less than minimum 9).
	var buf bytes.Buffer
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, 4)
	buf.Write(header)
	buf.Write([]byte{0x01, 0x02, 0x03, 0x04})

	readKey := bytes.Repeat([]byte{0xAA}, KeySize)
	writeKey := bytes.Repeat([]byte{0xBB}, KeySize)

	reader, err := NewEncryptedStream(&buf, writeKey, readKey)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = reader.ReadFrame()
	if err == nil {
		t.Fatal("expected error for frame too small")
	}
}

// TestNonceExhaustion verifies that the nonce counter cap at 2^32 is enforced.
func TestNonceExhaustion(t *testing.T) {
	writeKey := bytes.Repeat([]byte{0xEE}, KeySize)
	readKey := bytes.Repeat([]byte{0xFF}, KeySize)

	writer, err := NewEncryptedStream(&discardWriter{}, writeKey, readKey)
	if err != nil {
		t.Fatal(err)
	}

	// Advance write nonce to just below the limit.
	writer.writeNonce = (1 << 32) - 1

	// This write should succeed (nonce = 2^32 - 1).
	if err := writer.WriteFrame(transfer.MsgData, []byte("last")); err != nil {
		t.Fatalf("last valid nonce should succeed: %v", err)
	}

	// This write should fail (nonce = 2^32).
	err = writer.WriteFrame(transfer.MsgData, []byte("overflow"))
	if err == nil {
		t.Fatal("expected nonce exhaustion error")
	}
}

// TestReadNonceExhaustion verifies the read nonce cap.
// Reading at nonce 2^32-1 should succeed (it's the last valid nonce).
// The NEXT read should fail with nonce exhaustion.
func TestReadNonceExhaustion(t *testing.T) {
	writeKey := bytes.Repeat([]byte{0xAB}, KeySize)
	readKey := bytes.Repeat([]byte{0xCD}, KeySize)

	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	writer, err := NewEncryptedStream(&duplexPipe{r: rr, w: sw}, writeKey, readKey)
	if err != nil {
		t.Fatal(err)
	}
	writer.writeNonce = (1 << 32) - 1

	reader, err := NewEncryptedStream(&duplexPipe{r: sr, w: rw}, readKey, writeKey)
	if err != nil {
		t.Fatal(err)
	}
	reader.readNonce = (1 << 32) - 1

	errCh := make(chan error, 2)

	go func() {
		errCh <- writer.WriteFrame(transfer.MsgData, []byte("boundary"))
	}()

	go func() {
		_, _, err := reader.ReadFrame()
		errCh <- err
	}()

	// Both write and read at nonce 2^32-1 should succeed.
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("expected success at nonce 2^32-1: %v", err)
		}
	}

	// The next read should fail with nonce exhaustion (readNonce is now 2^32).
	_, _, err = reader.ReadFrame()
	if err == nil {
		t.Fatal("expected nonce exhaustion error on next read")
	}
}

// TestEmptyPayload verifies that encrypting/decrypting an empty payload works.
func TestEmptyPayload(t *testing.T) {
	writeKey := bytes.Repeat([]byte{0x01}, KeySize)
	readKey := bytes.Repeat([]byte{0x02}, KeySize)

	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	writer, err := NewEncryptedStream(&duplexPipe{r: rr, w: sw}, writeKey, readKey)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewEncryptedStream(&duplexPipe{r: sr, w: rw}, readKey, writeKey)
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 2)

	go func() {
		errCh <- writer.WriteFrame(transfer.MsgMetadata, []byte{})
	}()

	go func() {
		msgType, data, err := reader.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		if msgType != transfer.MsgMetadata {
			t.Errorf("expected MsgMetadata, got 0x%02x", msgType)
		}
		if len(data) != 0 {
			t.Errorf("expected empty data, got %d bytes", len(data))
		}
		errCh <- nil
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}

type discardWriter struct{}

func (d *discardWriter) Read(p []byte) (int, error)  { return 0, io.EOF }
func (d *discardWriter) Write(p []byte) (int, error) { return len(p), nil }
