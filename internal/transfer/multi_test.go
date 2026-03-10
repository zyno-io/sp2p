// SPDX-License-Identifier: MIT

package transfer

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

// mockFrameRW is a FrameReadWriter backed by channels for testing.
type mockFrameRW struct {
	readCh  chan mockFrame
	writeCh chan mockFrame
	closed  bool
	mu      sync.Mutex
}

type mockFrame struct {
	msgType byte
	data    []byte
}

func newMockFrameRWPair() (*mockFrameRW, *mockFrameRW) {
	ch1 := make(chan mockFrame, 64)
	ch2 := make(chan mockFrame, 64)
	a := &mockFrameRW{readCh: ch1, writeCh: ch2}
	b := &mockFrameRW{readCh: ch2, writeCh: ch1}
	return a, b
}

func (m *mockFrameRW) WriteFrame(msgType byte, data []byte) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return fmt.Errorf("closed")
	}
	m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.writeCh <- mockFrame{msgType: msgType, data: cp}
	return nil
}

func (m *mockFrameRW) ReadFrame() (byte, []byte, error) {
	f, ok := <-m.readCh
	if !ok {
		return 0, nil, io.EOF
	}
	return f.msgType, f.data, nil
}

func (m *mockFrameRW) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.writeCh)
	}
	return nil
}

func (m *mockFrameRW) SetDeadline(t time.Time) error { return nil }

// TestMultiStreamSingleStream verifies MultiStream works with a single stream
// (degenerate case: N=1).
func TestMultiStreamSingleStream(t *testing.T) {
	a, b := newMockFrameRWPair()

	msA := NewMultiStream(
		[]FrameReadWriter{a},
		[]MultiStreamConn{a},
	)
	msB := NewMultiStream(
		[]FrameReadWriter{b},
		[]MultiStreamConn{b},
	)
	defer msA.Close()
	defer msB.Close()

	// Send metadata (control frame).
	if err := msA.WriteFrame(MsgMetadata, []byte(`{"name":"test"}`)); err != nil {
		t.Fatalf("WriteFrame metadata: %v", err)
	}

	msgType, data, err := msB.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if msgType != MsgMetadata {
		t.Fatalf("expected MsgMetadata, got 0x%02x", msgType)
	}
	if string(data) != `{"name":"test"}` {
		t.Fatalf("unexpected data: %s", data)
	}

	// Send data frames.
	for i := 0; i < 5; i++ {
		payload := []byte(fmt.Sprintf("chunk-%d", i))
		if err := msA.WriteFrame(MsgData, payload); err != nil {
			t.Fatalf("WriteFrame data %d: %v", i, err)
		}
	}

	for i := 0; i < 5; i++ {
		msgType, data, err := msB.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame data %d: %v", i, err)
		}
		if msgType != MsgData {
			t.Fatalf("expected MsgData, got 0x%02x", msgType)
		}
		expected := fmt.Sprintf("chunk-%d", i)
		if string(data) != expected {
			t.Fatalf("expected %q, got %q", expected, string(data))
		}
	}
}

// TestMultiStreamRoundTrip verifies data frames are reassembled in order
// across multiple streams.
func TestMultiStreamRoundTrip(t *testing.T) {
	const numStreams = 3
	const numChunks = 30

	// Create N pairs of connected mock streams.
	senderStreams := make([]FrameReadWriter, numStreams)
	receiverStreams := make([]FrameReadWriter, numStreams)
	senderConns := make([]MultiStreamConn, numStreams)
	receiverConns := make([]MultiStreamConn, numStreams)

	for i := range numStreams {
		a, b := newMockFrameRWPair()
		senderStreams[i] = a
		receiverStreams[i] = b
		senderConns[i] = a
		receiverConns[i] = b
	}

	msSender := NewMultiStream(senderStreams, senderConns)
	msReceiver := NewMultiStream(receiverStreams, receiverConns)
	defer msSender.Close()
	defer msReceiver.Close()

	// Sender: write data chunks in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		for i := range numChunks {
			payload := []byte(fmt.Sprintf("data-%03d", i))
			if err := msSender.WriteFrame(MsgData, payload); err != nil {
				errCh <- fmt.Errorf("WriteFrame data %d: %w", i, err)
				return
			}
		}
		errCh <- nil
	}()

	// Receiver: read and verify order.
	for i := range numChunks {
		msgType, data, err := msReceiver.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame data %d: %v", i, err)
		}
		if msgType != MsgData {
			t.Fatalf("chunk %d: expected MsgData, got 0x%02x", i, msgType)
		}
		expected := fmt.Sprintf("data-%03d", i)
		if string(data) != expected {
			t.Fatalf("chunk %d: expected %q, got %q", i, expected, string(data))
		}
	}

	// Wait for sender to finish.
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

// TestMultiStreamControlAfterData verifies that control frames sent after
// data frames are delivered after all data frames.
func TestMultiStreamControlAfterData(t *testing.T) {
	a, b := newMockFrameRWPair()

	msSender := NewMultiStream(
		[]FrameReadWriter{a},
		[]MultiStreamConn{a},
	)
	msReceiver := NewMultiStream(
		[]FrameReadWriter{b},
		[]MultiStreamConn{b},
	)
	defer msSender.Close()
	defer msReceiver.Close()

	// Write some data, then a control frame.
	for i := range 5 {
		if err := msSender.WriteFrame(MsgData, []byte(fmt.Sprintf("d%d", i))); err != nil {
			t.Fatalf("WriteFrame data: %v", err)
		}
	}
	if err := msSender.WriteFrame(MsgDone, []byte("{}")); err != nil {
		t.Fatalf("WriteFrame done: %v", err)
	}

	// Read all — data should come before Done.
	for i := range 5 {
		msgType, data, err := msReceiver.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame %d: %v", i, err)
		}
		if msgType != MsgData {
			t.Fatalf("frame %d: expected MsgData, got 0x%02x (data=%q)", i, msgType, data)
		}
	}
	msgType, _, err := msReceiver.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame done: %v", err)
	}
	if msgType != MsgDone {
		t.Fatalf("expected MsgDone, got 0x%02x", msgType)
	}
}

// TestReassemblerOrdering verifies the reassembler delivers frames in order
// even when inserted out of order.
func TestReassemblerOrdering(t *testing.T) {
	r := newReassembler()

	ctx := context.Background()

	// Insert out of order: 2, 0, 1
	r.insert(ctx, 2, []byte("two"))
	r.insert(ctx, 0, []byte("zero"))
	r.insert(ctx, 1, []byte("one"))

	data, ok := r.tryDeliver()
	if !ok || string(data) != "zero" {
		t.Fatalf("expected 'zero', got %q (ok=%v)", data, ok)
	}
	data, ok = r.tryDeliver()
	if !ok || string(data) != "one" {
		t.Fatalf("expected 'one', got %q (ok=%v)", data, ok)
	}
	data, ok = r.tryDeliver()
	if !ok || string(data) != "two" {
		t.Fatalf("expected 'two', got %q (ok=%v)", data, ok)
	}
	_, ok = r.tryDeliver()
	if ok {
		t.Fatal("expected empty")
	}
}

// TestReassemblerAbort verifies abort signals waiting goroutines.
func TestReassemblerAbort(t *testing.T) {
	r := newReassembler()
	r.abort(fmt.Errorf("test error"))

	// Signal channel should be notified.
	select {
	case <-r.signal():
	case <-time.After(time.Second):
		t.Fatal("expected signal after abort")
	}
}

// TestMultiStreamCancel verifies cancel frames bypass reassembly.
func TestMultiStreamCancel(t *testing.T) {
	a, b := newMockFrameRWPair()

	msSender := NewMultiStream(
		[]FrameReadWriter{a},
		[]MultiStreamConn{a},
	)
	msReceiver := NewMultiStream(
		[]FrameReadWriter{b},
		[]MultiStreamConn{b},
	)
	defer msSender.Close()
	defer msReceiver.Close()

	// Send a cancel frame.
	if err := msSender.WriteFrame(MsgCancel, []byte{CancelUserAbort}); err != nil {
		t.Fatalf("WriteFrame cancel: %v", err)
	}

	msgType, data, err := msReceiver.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if msgType != MsgCancel {
		t.Fatalf("expected MsgCancel, got 0x%02x", msgType)
	}
	if len(data) != 1 || data[0] != CancelUserAbort {
		t.Fatalf("unexpected cancel data: %v", data)
	}
}

// TestMultiStreamGlobalSeqPrefix verifies the global sequence prefix is
// correctly prepended and stripped for data frames.
func TestMultiStreamGlobalSeqPrefix(t *testing.T) {
	a, b := newMockFrameRWPair()

	msSender := NewMultiStream(
		[]FrameReadWriter{a},
		[]MultiStreamConn{a},
	)

	// Write a data frame via MultiStream.
	if err := msSender.WriteFrame(MsgData, []byte("hello")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	msSender.Close()

	// Read the raw frame from the underlying mock to verify prefix.
	f, ok := <-b.readCh
	if !ok {
		t.Fatal("expected frame on channel")
	}
	if f.msgType != MsgData {
		t.Fatalf("expected MsgData, got 0x%02x", f.msgType)
	}
	if len(f.data) < globalSeqSize {
		t.Fatalf("data too short: %d", len(f.data))
	}
	seq := binary.BigEndian.Uint64(f.data[:globalSeqSize])
	if seq != 0 {
		t.Fatalf("expected global seq 0, got %d", seq)
	}
	payload := f.data[globalSeqSize:]
	if !bytes.Equal(payload, []byte("hello")) {
		t.Fatalf("expected 'hello', got %q", payload)
	}
}

// TestMultiFrameRouting verifies the multiFrame wrapper for PrepareFrameAt routing.
func TestMultiFrameRouting(t *testing.T) {
	frame := []byte("test-frame-data")
	wrapped := multiFrameToBytes(2, frame)

	mf, ok := multiFrameFromBytes(wrapped)
	if !ok {
		t.Fatal("expected valid multiFrame")
	}
	if mf.streamIdx != 2 {
		t.Fatalf("expected stream 2, got %d", mf.streamIdx)
	}
	if !bytes.Equal(mf.frame, frame) {
		t.Fatalf("frame mismatch")
	}

	// Non-multiFrame data should return false.
	_, ok = multiFrameFromBytes([]byte{0x00, 0x01, 0x02, 0x03, 0x04})
	if ok {
		t.Fatal("expected false for non-multiFrame")
	}
}

// TestMultiStreamReadFrameDrainsBeforeError verifies that ReadFrame delivers
// buffered data and control frames before returning an error from a closed stream.
func TestMultiStreamReadFrameDrainsBeforeError(t *testing.T) {
	a, b := newMockFrameRWPair()

	msSender := NewMultiStream(
		[]FrameReadWriter{a},
		[]MultiStreamConn{a},
	)
	msReceiver := NewMultiStream(
		[]FrameReadWriter{b},
		[]MultiStreamConn{b},
	)
	defer msSender.Close()

	// Write data + done, then close the sender stream to trigger EOF.
	if err := msSender.WriteFrame(MsgData, []byte("payload")); err != nil {
		t.Fatalf("WriteFrame data: %v", err)
	}
	if err := msSender.WriteFrame(MsgDone, []byte(`{"totalBytes":7}`)); err != nil {
		t.Fatalf("WriteFrame done: %v", err)
	}
	msSender.Close() // causes EOF on the receiver's readLoop

	// Give readLoop time to process all frames and the EOF.
	time.Sleep(50 * time.Millisecond)

	// ReadFrame should deliver data first, then Done, then the error.
	msgType, data, err := msReceiver.ReadFrame()
	if err != nil {
		t.Fatalf("expected data frame, got error: %v", err)
	}
	if msgType != MsgData || string(data) != "payload" {
		t.Fatalf("expected MsgData 'payload', got 0x%02x %q", msgType, data)
	}

	msgType, _, err = msReceiver.ReadFrame()
	if err != nil {
		t.Fatalf("expected Done frame, got error: %v", err)
	}
	if msgType != MsgDone {
		t.Fatalf("expected MsgDone, got 0x%02x", msgType)
	}

	// Now should get the error.
	_, _, err = msReceiver.ReadFrame()
	if err == nil {
		t.Fatal("expected error after draining, got nil")
	}
	msReceiver.Close()
}

// TestMultiStreamStreamCount verifies StreamCount returns the correct value.
func TestMultiStreamStreamCount(t *testing.T) {
	const n = 3
	streams := make([]FrameReadWriter, n)
	conns := make([]MultiStreamConn, n)
	for i := range n {
		a, _ := newMockFrameRWPair()
		streams[i] = a
		conns[i] = a
	}
	ms := NewMultiStream(streams, conns)
	defer ms.Close()

	if ms.StreamCount() != n {
		t.Fatalf("expected StreamCount()=%d, got %d", n, ms.StreamCount())
	}
}

// TestMaxRawFrameSize verifies that WriteRawFrame rejects oversized frames.
func TestMaxRawFrameSize(t *testing.T) {
	a, _ := newMockFrameRWPair()
	ms := NewMultiStream([]FrameReadWriter{a}, []MultiStreamConn{a})
	defer ms.Close()

	// Create an oversized frame.
	huge := make([]byte, maxRawFrameSize+1)
	err := ms.WriteRawFrame(huge)
	if err == nil {
		t.Fatal("expected error for oversized raw frame")
	}
}
