// SPDX-License-Identifier: MIT

package crypto

import (
	"bytes"
	"io"
	"testing"

	"github.com/zyno-io/sp2p/internal/transfer"
)

func TestEncryptedStreamRoundTrip(t *testing.T) {
	// Generate keys.
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()
	_, seedRaw, _ := GenerateSeed()
	sessionID := "test1234"

	senderKeys, _ := DeriveKeys(sender.Private, receiver.Public, seedRaw, sessionID, sender.Public, receiver.Public)
	receiverKeys, _ := DeriveKeys(receiver.Private, sender.Public, seedRaw, sessionID, sender.Public, receiver.Public)

	// Two pipes for bidirectional communication.
	sr, sw := io.Pipe() // sender → receiver
	rr, rw := io.Pipe() // receiver → sender

	// Create encrypted streams with directional keys.
	senderStream, err := NewEncryptedStream(
		&duplexPipe{r: rr, w: sw},
		senderKeys.SenderToReceiver,
		senderKeys.ReceiverToSender,
	)
	if err != nil {
		t.Fatal(err)
	}

	receiverStream, err := NewEncryptedStream(
		&duplexPipe{r: sr, w: rw},
		receiverKeys.ReceiverToSender,
		receiverKeys.SenderToReceiver,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Test sending data from sender to receiver.
	testData := []byte("hello encrypted world")

	errCh := make(chan error, 2)

	go func() {
		errCh <- senderStream.WriteFrame(transfer.MsgData, testData)
	}()

	go func() {
		msgType, data, err := receiverStream.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		if msgType != transfer.MsgData {
			t.Errorf("expected MsgData, got 0x%02x", msgType)
		}
		if !bytes.Equal(data, testData) {
			t.Errorf("data mismatch")
		}
		errCh <- nil
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}

func TestEncryptedStreamMultipleFrames(t *testing.T) {
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()
	_, seedRaw, _ := GenerateSeed()

	keys, _ := DeriveKeys(sender.Private, receiver.Public, seedRaw, "sess1", sender.Public, receiver.Public)

	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	senderStream, _ := NewEncryptedStream(
		&duplexPipe{r: rr, w: sw},
		keys.SenderToReceiver,
		keys.ReceiverToSender,
	)

	receiverStream, _ := NewEncryptedStream(
		&duplexPipe{r: sr, w: rw},
		keys.ReceiverToSender,
		keys.SenderToReceiver,
	)

	frames := []struct {
		msgType byte
		data    []byte
	}{
		{transfer.MsgMetadata, []byte(`{"name":"test.txt"}`)},
		{transfer.MsgData, bytes.Repeat([]byte("A"), 64*1024)},
		{transfer.MsgData, bytes.Repeat([]byte("B"), 32*1024)},
		{transfer.MsgDone, []byte(`{"totalBytes":98304,"chunkCount":2}`)},
	}

	errCh := make(chan error, 2)

	go func() {
		for _, f := range frames {
			if err := senderStream.WriteFrame(f.msgType, f.data); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()

	go func() {
		for _, expected := range frames {
			msgType, data, err := receiverStream.ReadFrame()
			if err != nil {
				errCh <- err
				return
			}
			if msgType != expected.msgType {
				t.Errorf("type mismatch: 0x%02x != 0x%02x", msgType, expected.msgType)
			}
			if !bytes.Equal(data, expected.data) {
				t.Errorf("data mismatch for type 0x%02x", expected.msgType)
			}
		}
		errCh <- nil
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}

type duplexPipe struct {
	r io.Reader
	w io.Writer
}

func (d *duplexPipe) Read(p []byte) (int, error)  { return d.r.Read(p) }
func (d *duplexPipe) Write(p []byte) (int, error) { return d.w.Write(p) }
