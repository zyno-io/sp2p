// SPDX-License-Identifier: MIT

package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
)

// TestEmptyFileTransfer verifies that transferring a zero-byte file works.
func TestEmptyFileTransfer(t *testing.T) {
	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	meta := &Metadata{
		Name: "empty.txt",
		Size: 0,
		Type: "text/plain",
	}

	errCh := make(chan error, 2)
	var receivedMeta *Metadata
	var receivedData bytes.Buffer

	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}
		recv := NewReceiver(frw)
		var err error
		receivedMeta, err = recv.Receive(context.Background(), &receivedData, nil)
		errCh <- err
	}()

	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
		sender := NewSender(frw, meta)
		errCh <- sender.Send(context.Background(), bytes.NewReader(nil), nil)
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}

	if receivedMeta.Name != "empty.txt" {
		t.Fatalf("name mismatch: %s", receivedMeta.Name)
	}
	if receivedData.Len() != 0 {
		t.Fatalf("expected 0 bytes, got %d", receivedData.Len())
	}
}

// TestVerificationMismatch verifies that sender detects count mismatch from receiver.
func TestVerificationMismatch(t *testing.T) {
	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	errCh := make(chan error, 2)

	// Fake receiver that sends wrong Complete counts.
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}

		// Read metadata.
		msgType, _, err := frw.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		if msgType != MsgMetadata {
			errCh <- nil
			return
		}

		// Read data chunks.
		totalBytes := uint64(0)
		for {
			mt, data, err := frw.ReadFrame()
			if err != nil {
				errCh <- err
				return
			}
			if mt == MsgData {
				totalBytes += uint64(len(data))
			} else if mt == MsgDone {
				break
			}
		}

		// Send wrong complete (mismatched bytes).
		WriteComplete(frw, &Complete{
			TotalBytes: totalBytes + 100, // intentionally wrong
			ChunkCount: 999,
		})
		errCh <- nil
	}()

	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
		sender := NewSender(frw, &Metadata{Name: "test.bin", Size: 10})
		err := sender.Send(context.Background(), bytes.NewReader([]byte("0123456789")), nil)
		errCh <- err
	}()

	// One goroutine will return nil (fake receiver), the sender should error.
	var senderErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			senderErr = err
		}
	}

	if senderErr == nil {
		t.Fatal("expected verification mismatch error from sender")
	}
}

// TestReceiverGetsError verifies that the receiver handles error messages from sender.
func TestReceiverGetsError(t *testing.T) {
	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	errCh := make(chan error, 2)

	// Sender sends metadata then an error.
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
		meta := &Metadata{Name: "test.bin", Size: 100}
		WriteMetadata(frw, meta)
		// Send some data then an error.
		WriteData(frw, []byte("partial"))
		WriteError(frw, "disk read failed")
		errCh <- nil
	}()

	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}
		recv := NewReceiver(frw)
		_, err := recv.Receive(context.Background(), io.Discard, nil)
		errCh <- err
	}()

	var recvErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			recvErr = err
		}
	}

	if recvErr == nil {
		t.Fatal("expected receiver to get error message")
	}
}

// TestSenderGetsError verifies that the sender handles error messages from receiver.
func TestSenderGetsError(t *testing.T) {
	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	errCh := make(chan error, 2)

	// Fake receiver that sends an error instead of complete.
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}

		// Read metadata.
		frw.ReadFrame()

		// Read all data + done.
		for {
			mt, _, err := frw.ReadFrame()
			if err != nil {
				errCh <- err
				return
			}
			if mt == MsgDone {
				break
			}
		}

		// Send error instead of complete.
		WriteError(frw, "receiver out of space")
		errCh <- nil
	}()

	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
		sender := NewSender(frw, &Metadata{Name: "test.bin", Size: 5})
		err := sender.Send(context.Background(), bytes.NewReader([]byte("hello")), nil)
		errCh <- err
	}()

	var senderErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			senderErr = err
		}
	}

	if senderErr == nil {
		t.Fatal("expected sender to get error from receiver")
	}
}

// TestUnexpectedMessageType verifies that unexpected message types are rejected.
func TestUnexpectedMessageType(t *testing.T) {
	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	errCh := make(chan error, 2)

	// Sender sends metadata then an unexpected type (0xFF).
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
		WriteMetadata(frw, &Metadata{Name: "test.bin", Size: 100})
		frw.WriteFrame(0xFF, []byte("bogus"))
		errCh <- nil
	}()

	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}
		recv := NewReceiver(frw)
		_, err := recv.Receive(context.Background(), io.Discard, nil)
		errCh <- err
	}()

	var recvErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			recvErr = err
		}
	}

	if recvErr == nil {
		t.Fatal("expected error on unexpected message type")
	}
}

// TestProgressCallback verifies that the progress callback is called during transfer.
func TestProgressCallback(t *testing.T) {
	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	fileData := bytes.Repeat([]byte("x"), 200*1024) // 200 KB → multiple chunks
	meta := &Metadata{
		Name: "progress.bin",
		Size: uint64(len(fileData)),
		Type: "application/octet-stream",
	}

	errCh := make(chan error, 2)
	var senderProgress, receiverProgress []uint64

	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}
		recv := NewReceiver(frw)
		_, err := recv.Receive(context.Background(), io.Discard, func(bytesRecv uint64) {
			receiverProgress = append(receiverProgress, bytesRecv)
		})
		errCh <- err
	}()

	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
		sender := NewSender(frw, meta)
		err := sender.Send(context.Background(), bytes.NewReader(fileData), func(bytesSent uint64) {
			senderProgress = append(senderProgress, bytesSent)
		})
		errCh <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}

	if len(senderProgress) == 0 {
		t.Fatal("sender progress callback was never called")
	}
	if len(receiverProgress) == 0 {
		t.Fatal("receiver progress callback was never called")
	}

	// Last progress value should equal total size.
	if senderProgress[len(senderProgress)-1] != uint64(len(fileData)) {
		t.Fatalf("sender final progress: %d, expected %d", senderProgress[len(senderProgress)-1], len(fileData))
	}
	if receiverProgress[len(receiverProgress)-1] != uint64(len(fileData)) {
		t.Fatalf("receiver final progress: %d, expected %d", receiverProgress[len(receiverProgress)-1], len(fileData))
	}
}

// TestFrameTooLarge verifies that writing a frame larger than MaxFrameSize is rejected.
func TestFrameTooLarge(t *testing.T) {
	var buf bytes.Buffer
	frw := &PlaintextFrameRW{RW: &buf}

	hugeData := make([]byte, MaxFrameSize) // payload + 1 byte type = MaxFrameSize+1 > MaxFrameSize
	err := frw.WriteFrame(MsgData, hugeData)
	if err == nil {
		t.Fatal("expected error for frame too large")
	}
}

// TestWriteHelpers verifies WriteMetadata, WriteData, WriteDone, WriteComplete, WriteError.
func TestWriteHelpers(t *testing.T) {
	tests := []struct {
		name    string
		write   func(frw FrameReadWriter) error
		msgType byte
	}{
		{
			name: "WriteData",
			write: func(frw FrameReadWriter) error {
				return WriteData(frw, []byte("chunk"))
			},
			msgType: MsgData,
		},
		{
			name: "WriteDone",
			write: func(frw FrameReadWriter) error {
				return WriteDone(frw, &Done{TotalBytes: 100, ChunkCount: 2})
			},
			msgType: MsgDone,
		},
		{
			name: "WriteComplete",
			write: func(frw FrameReadWriter) error {
				return WriteComplete(frw, &Complete{TotalBytes: 100, ChunkCount: 2})
			},
			msgType: MsgComplete,
		},
		{
			name: "WriteError",
			write: func(frw FrameReadWriter) error {
				return WriteError(frw, "something went wrong")
			},
			msgType: MsgError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			frw := &PlaintextFrameRW{RW: &buf}

			if err := tt.write(frw); err != nil {
				t.Fatal(err)
			}

			readFrw := &PlaintextFrameRW{RW: &buf}
			msgType, data, err := readFrw.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			if msgType != tt.msgType {
				t.Fatalf("expected type 0x%02x, got 0x%02x", tt.msgType, msgType)
			}
			if len(data) == 0 {
				t.Fatal("expected non-empty data")
			}

			// Verify JSON is valid for control messages.
			if tt.msgType != MsgData {
				var m map[string]interface{}
				if err := json.Unmarshal(data, &m); err != nil {
					t.Fatalf("invalid JSON: %v", err)
				}
			}
		})
	}
}

// TestReceiverVerificationMismatch verifies that the receiver detects when
// the Done message's counts don't match what was actually received.
func TestReceiverVerificationMismatch(t *testing.T) {
	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	errCh := make(chan error, 2)

	// Sender sends metadata, one chunk, but Done claims more.
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
		WriteMetadata(frw, &Metadata{Name: "test.bin", Size: 5})
		WriteData(frw, []byte("hello"))
		WriteDone(frw, &Done{
			TotalBytes: 999, // wrong
			ChunkCount: 42,  // wrong
		})
		// Read the error from receiver (so pipes don't deadlock).
		frw.ReadFrame()
		errCh <- nil
	}()

	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}
		recv := NewReceiver(frw)
		_, err := recv.Receive(context.Background(), io.Discard, nil)
		errCh <- err
	}()

	var recvErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			recvErr = err
		}
	}

	if recvErr == nil {
		t.Fatal("expected receiver to detect verification mismatch")
	}
}
