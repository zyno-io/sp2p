// SPDX-License-Identifier: MIT

package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
)

func TestPlaintextFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	frw := &PlaintextFrameRW{RW: &buf}

	data := []byte("hello world")
	if err := frw.WriteFrame(MsgData, data); err != nil {
		t.Fatal(err)
	}

	readFrw := &PlaintextFrameRW{RW: &buf}
	msgType, payload, err := readFrw.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}

	if msgType != MsgData {
		t.Fatalf("expected type 0x%02x, got 0x%02x", MsgData, msgType)
	}
	if !bytes.Equal(payload, data) {
		t.Fatalf("payload mismatch")
	}
}

func TestMultipleFrames(t *testing.T) {
	var buf bytes.Buffer
	frw := &PlaintextFrameRW{RW: &buf}

	frames := []struct {
		msgType byte
		data    []byte
	}{
		{MsgMetadata, []byte(`{"name":"test.txt","size":100}`)},
		{MsgData, bytes.Repeat([]byte("A"), 1024)},
		{MsgData, bytes.Repeat([]byte("B"), 512)},
		{MsgDone, []byte(`{"totalBytes":1536,"chunkCount":2}`)},
	}

	for _, f := range frames {
		if err := frw.WriteFrame(f.msgType, f.data); err != nil {
			t.Fatal(err)
		}
	}

	readFrw := &PlaintextFrameRW{RW: &buf}
	for i, expected := range frames {
		msgType, data, err := readFrw.ReadFrame()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if msgType != expected.msgType {
			t.Fatalf("frame %d: expected type 0x%02x, got 0x%02x", i, expected.msgType, msgType)
		}
		if !bytes.Equal(data, expected.data) {
			t.Fatalf("frame %d: data mismatch", i)
		}
	}
}

func TestSendReceiveFile(t *testing.T) {
	// Two pipes for bidirectional communication:
	// sender writes to sw, receiver reads from sr (same pipe)
	// receiver writes to rw, sender reads from rr (same pipe)
	sr, sw := io.Pipe() // sender → receiver
	rr, rw := io.Pipe() // receiver → sender

	fileData := bytes.Repeat([]byte("test data "), 10000) // ~100KB
	meta := &Metadata{
		Name: "test.bin",
		Size: uint64(len(fileData)),
		Type: "application/octet-stream",
	}

	errCh := make(chan error, 2)
	var receivedMeta *Metadata
	var receivedData bytes.Buffer

	// Receiver goroutine.
	go func() {
		// Receiver reads from sr (sender's output), writes to rw (back to sender).
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}
		recv := NewReceiver(frw)
		var err error
		receivedMeta, err = recv.Receive(context.Background(), &receivedData, nil)
		errCh <- err
	}()

	// Sender: writes to sw (to receiver), reads from rr (receiver's output).
	senderFrw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
	sender := NewSender(senderFrw, meta)
	errCh <- sender.Send(context.Background(), bytes.NewReader(fileData), nil)

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}

	if receivedMeta.Name != meta.Name {
		t.Fatalf("name mismatch: %s != %s", receivedMeta.Name, meta.Name)
	}
	if !bytes.Equal(receivedData.Bytes(), fileData) {
		t.Fatalf("data mismatch: got %d bytes, expected %d", receivedData.Len(), len(fileData))
	}
}

// duplexRW combines separate reader/writer.
type duplexRW struct {
	r io.Reader
	w io.Writer
}

func (rw *duplexRW) Read(p []byte) (int, error)  { return rw.r.Read(p) }
func (rw *duplexRW) Write(p []byte) (int, error) { return rw.w.Write(p) }

func TestHelperFunctions(t *testing.T) {
	var buf bytes.Buffer
	frw := &PlaintextFrameRW{RW: &buf}

	meta := &Metadata{Name: "test.txt", Size: 100, Type: "text/plain"}
	if err := WriteMetadata(frw, meta); err != nil {
		t.Fatal(err)
	}

	readFrw := &PlaintextFrameRW{RW: &buf}
	msgType, data, err := readFrw.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if msgType != MsgMetadata {
		t.Fatalf("expected MsgMetadata, got 0x%02x", msgType)
	}

	var decoded Metadata
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Name != "test.txt" {
		t.Fatalf("expected name 'test.txt', got '%s'", decoded.Name)
	}
}
