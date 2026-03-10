// SPDX-License-Identifier: MIT

package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"
	"time"
)

func TestHeartbeatTimeoutFiresWithoutTouch(t *testing.T) {
	hb := &Heartbeat{
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	// Set lastRecv far in the past to trigger immediate timeout.
	hb.lastRecv.Store(time.Now().Add(-HeartbeatTimeout - time.Second).UnixNano())
	go hb.watchLoop()
	defer hb.Stop()

	select {
	case <-hb.Done():
		// Expected.
	case <-time.After(HeartbeatInterval + time.Second):
		t.Fatal("heartbeat timeout did not fire")
	}
}

func TestHeartbeatTouchPreventsTimeout(t *testing.T) {
	hb := StartHeartbeat()
	defer hb.Stop()

	// Touch repeatedly — Done should not close.
	for i := 0; i < 3; i++ {
		hb.Touch()
		time.Sleep(HeartbeatInterval / 2)
	}

	select {
	case <-hb.Done():
		t.Fatal("heartbeat fired despite regular touches")
	default:
		// Expected — still alive.
	}
}

func TestHeartbeatStopPreventsTimeout(t *testing.T) {
	hb := &Heartbeat{
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	hb.lastRecv.Store(time.Now().Add(-HeartbeatTimeout - time.Second).UnixNano())
	go hb.watchLoop()

	// Stop before watchLoop checks.
	hb.Stop()
	time.Sleep(HeartbeatInterval + 500*time.Millisecond)

	select {
	case <-hb.Done():
		t.Fatal("heartbeat should not fire after Stop()")
	default:
		// Expected.
	}
}

func TestHeartbeatFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	frw := &PlaintextFrameRW{RW: &buf}

	if err := WriteHeartbeat(frw); err != nil {
		t.Fatal(err)
	}

	readFrw := &PlaintextFrameRW{RW: &buf}
	msgType, data, err := readFrw.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if msgType != MsgHeartbeat {
		t.Fatalf("expected MsgHeartbeat (0x%02x), got 0x%02x", MsgHeartbeat, msgType)
	}
	if len(data) != 0 {
		t.Fatalf("expected empty data, got %d bytes", len(data))
	}
}

func TestCancelFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	frw := &PlaintextFrameRW{RW: &buf}

	if err := WriteCancel(frw, CancelUserAbort); err != nil {
		t.Fatal(err)
	}

	readFrw := &PlaintextFrameRW{RW: &buf}
	msgType, data, err := readFrw.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if msgType != MsgCancel {
		t.Fatalf("expected MsgCancel (0x%02x), got 0x%02x", MsgCancel, msgType)
	}
	if len(data) != 1 || data[0] != CancelUserAbort {
		t.Fatalf("expected CancelUserAbort reason, got %v", data)
	}
}

func TestReceiverHandlesHeartbeatDuringTransfer(t *testing.T) {
	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	fileData := []byte("hello heartbeat world")
	meta := &Metadata{Name: "hb.txt", Size: uint64(len(fileData)), Type: "text/plain"}

	errCh := make(chan error, 2)
	var receivedData bytes.Buffer

	// Receiver goroutine.
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}
		recv := NewReceiver(frw)
		_, err := recv.Receive(context.Background(), &receivedData, nil)
		errCh <- err
	}()

	// Sender: manually interleave heartbeats with data.
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}

		WriteMetadata(frw, meta)
		WriteHeartbeat(frw)
		WriteData(frw, fileData)
		WriteHeartbeat(frw)
		WriteDone(frw, &Done{
			TotalBytes: uint64(len(fileData)),
			ChunkCount: 1,
			SHA256:     testSHA256(fileData),
		})

		// Read complete.
		msgType, _, err := frw.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		if msgType != MsgComplete {
			errCh <- nil
			return
		}
		WriteFinAck(frw)
		errCh <- nil
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}

	if !bytes.Equal(receivedData.Bytes(), fileData) {
		t.Fatalf("data mismatch: got %d bytes, expected %d", receivedData.Len(), len(fileData))
	}
}

func TestReceiverHandlesCancelDuringTransfer(t *testing.T) {
	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	meta := &Metadata{Name: "cancel.txt", Size: 1000, Type: "text/plain"}
	errCh := make(chan error, 1)

	// Receiver goroutine.
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}
		recv := NewReceiver(frw)
		var buf bytes.Buffer
		_, err := recv.Receive(context.Background(), &buf, nil)
		errCh <- err
	}()

	// Sender: send metadata, one chunk, then cancel.
	senderFrw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
	WriteMetadata(senderFrw, meta)
	WriteData(senderFrw, []byte("partial"))
	WriteCancel(senderFrw, CancelUserAbort)

	err := <-errCh
	if err == nil {
		t.Fatal("expected error from cancel, got nil")
	}
	if err.Error() != "peer cancelled transfer" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSenderHandlesCancelDuringWaitForComplete(t *testing.T) {
	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	fileData := []byte("tiny")
	meta := &Metadata{Name: "tiny.txt", Size: uint64(len(fileData)), Type: "text/plain"}

	errCh := make(chan error, 1)

	// Sender goroutine.
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
		sender := NewSender(frw, meta)
		errCh <- sender.Send(context.Background(), bytes.NewReader(fileData), nil)
	}()

	// Fake receiver: read metadata + data + done, then send cancel.
	recvFrw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}

	// Drain all frames until done, skipping heartbeats.
	for {
		msgType, _, err := recvFrw.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if msgType == MsgHeartbeat {
			continue
		}
		if msgType == MsgDone {
			break
		}
	}

	// Send cancel instead of complete.
	WriteCancel(recvFrw, CancelUserAbort)

	senderErr := <-errCh
	if senderErr == nil {
		t.Fatal("expected error from cancel, got nil")
	}
	if senderErr.Error() != "peer cancelled transfer" {
		t.Fatalf("unexpected error: %v", senderErr)
	}
}

func TestSenderSkipsHeartbeatsWhileWaitingForComplete(t *testing.T) {
	sr, sw := io.Pipe()
	rr, rw := io.Pipe()

	fileData := []byte("data")
	meta := &Metadata{Name: "hb-skip.txt", Size: uint64(len(fileData)), Type: "text/plain"}

	errCh := make(chan error, 2)
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: rr, w: sw}}
		sender := NewSender(frw, meta)
		errCh <- sender.Send(context.Background(), bytes.NewReader(fileData), nil)
	}()

	// Fake receiver: read all, send heartbeats before complete.
	go func() {
		frw := &PlaintextFrameRW{RW: &duplexRW{r: sr, w: rw}}

		// Drain metadata + data + done, skipping heartbeats.
		for {
			msgType, _, err := frw.ReadFrame()
			if err != nil {
				errCh <- err
				return
			}
			if msgType == MsgHeartbeat {
				continue
			}
			if msgType == MsgDone {
				break
			}
		}

		// Send some heartbeats to make the sender skip them.
		WriteHeartbeat(frw)
		WriteHeartbeat(frw)

		// Now send complete.
		checksum := testSHA256(fileData)
		WriteComplete(frw, &Complete{
			TotalBytes: uint64(len(fileData)),
			ChunkCount: 1,
			SHA256:     checksum,
		})

		// Read FinAck (best-effort).
		frw.ReadFrame()
		errCh <- nil
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}

func testSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
