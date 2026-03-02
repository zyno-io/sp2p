// SPDX-License-Identifier: MIT

package transfer

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// TestSenderGetsMalformedError verifies that when the receiver sends a MsgError
// frame with invalid JSON, the sender returns an error containing "malformed".
func TestSenderGetsMalformedError(t *testing.T) {
	sr, sw := io.Pipe() // sender -> receiver
	rr, rw := io.Pipe() // receiver -> sender

	errCh := make(chan error, 2)

	// Fake receiver: reads metadata, data, done, then sends a malformed error.
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}

		// Read metadata.
		mt, _, err := frw.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		if mt != MsgMetadata {
			errCh <- nil
			return
		}

		// Read data chunks until done.
		for {
			mt, _, err = frw.ReadFrame()
			if err != nil {
				errCh <- err
				return
			}
			if mt == MsgDone {
				break
			}
		}

		// Send a MsgError with invalid JSON instead of Complete.
		frw.WriteFrame(MsgError, []byte("not json at all"))
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
		t.Fatal("expected sender to get an error")
	}
	if !strings.Contains(senderErr.Error(), "malformed") {
		t.Fatalf("expected error to contain 'malformed', got: %s", senderErr.Error())
	}
	if !strings.Contains(senderErr.Error(), "not json at all") {
		t.Fatalf("expected error to contain the raw payload, got: %s", senderErr.Error())
	}
}

// TestReceiverGetsMalformedError verifies that when the sender sends a MsgError
// frame with invalid JSON, the receiver returns an error containing "malformed".
func TestReceiverGetsMalformedError(t *testing.T) {
	sr, sw := io.Pipe() // sender -> receiver
	rr, rw := io.Pipe() // receiver -> sender

	errCh := make(chan error, 2)

	// Fake sender: sends metadata, then a MsgError with invalid JSON.
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
		WriteMetadata(frw, &Metadata{Name: "test.bin", Size: 100})
		frw.WriteFrame(MsgError, []byte("{{bad json}}"))
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
		t.Fatal("expected receiver to get an error")
	}
	if !strings.Contains(recvErr.Error(), "malformed") {
		t.Fatalf("expected error to contain 'malformed', got: %s", recvErr.Error())
	}
	if !strings.Contains(recvErr.Error(), "{{bad json}}") {
		t.Fatalf("expected error to contain the raw payload, got: %s", recvErr.Error())
	}
}

// TestSenderGetsValidError verifies that when the receiver sends a well-formed
// MsgError with a JSON TransferError, the sender returns the error message.
func TestSenderGetsValidError(t *testing.T) {
	sr, sw := io.Pipe() // sender -> receiver
	rr, rw := io.Pipe() // receiver -> sender

	errCh := make(chan error, 2)

	// Fake receiver: reads metadata, data, done, then sends a valid error.
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}

		// Read metadata.
		mt, _, err := frw.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		if mt != MsgMetadata {
			errCh <- nil
			return
		}

		// Read data chunks until done.
		for {
			mt, _, err = frw.ReadFrame()
			if err != nil {
				errCh <- err
				return
			}
			if mt == MsgDone {
				break
			}
		}

		// Send a valid MsgError with proper JSON.
		WriteError(frw, "disk full")
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
		t.Fatal("expected sender to get an error")
	}
	if !strings.Contains(senderErr.Error(), "disk full") {
		t.Fatalf("expected error to contain 'disk full', got: %s", senderErr.Error())
	}
	if strings.Contains(senderErr.Error(), "malformed") {
		t.Fatalf("valid error should not contain 'malformed', got: %s", senderErr.Error())
	}
}

// TestReceiverGetsValidError verifies that when the sender sends a well-formed
// MsgError with a JSON TransferError, the receiver returns the error message.
func TestReceiverGetsValidError(t *testing.T) {
	sr, sw := io.Pipe() // sender -> receiver
	rr, rw := io.Pipe() // receiver -> sender

	errCh := make(chan error, 2)

	// Fake sender: sends metadata, some data, then a valid error.
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
		WriteMetadata(frw, &Metadata{Name: "test.bin", Size: 100})
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
		t.Fatal("expected receiver to get an error")
	}
	if !strings.Contains(recvErr.Error(), "disk read failed") {
		t.Fatalf("expected error to contain 'disk read failed', got: %s", recvErr.Error())
	}
	if strings.Contains(recvErr.Error(), "malformed") {
		t.Fatalf("valid error should not contain 'malformed', got: %s", recvErr.Error())
	}
}
