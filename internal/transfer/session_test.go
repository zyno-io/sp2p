// SPDX-License-Identifier: MIT

package transfer

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSessionCreditTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, b := net.Pipe()
	s := NewSession(ctx, &PlaintextFrameRW{RW: a}, a, true)
	defer s.Close()
	r := NewSession(ctx, &PlaintextFrameRW{RW: b}, b, false)
	defer r.Close()
	data := bytes.Repeat([]byte("bounded"), 800000)
	var output bytes.Buffer
	result := make(chan error, 1)
	go func() { _, err := NewReceiver(r).Receive(r.Context(), &output, nil); result <- err }()
	if err := NewSender(s, &Metadata{Name: "data", Size: uint64(len(data))}).Send(s.Context(), bytes.NewReader(data), nil); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, output.Bytes()) {
		t.Fatal("data mismatch")
	}
}

func TestSessionCancellationUnblocksIdleInput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a, b := net.Pipe()
	s := NewSession(ctx, &PlaintextFrameRW{RW: a}, a, true)
	defer s.Close()
	r := NewSession(ctx, &PlaintextFrameRW{RW: b}, b, false)
	defer r.Close()
	input, writer := io.Pipe()
	defer writer.Close()
	result := make(chan error, 1)
	go func() {
		result <- NewSender(s, &Metadata{Name: "stdin", StreamMode: true}).Send(s.Context(), input, nil)
	}()
	if kind, _, err := r.ReadFrame(); err != nil || kind != MsgMetadata {
		t.Fatalf("metadata: %x %v", kind, err)
	}
	r.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("idle input did not unblock")
	}
}

func TestSessionRejectsOverCredit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a, b := net.Pipe()
	defer a.Close()
	r := NewSession(ctx, &PlaintextFrameRW{RW: b}, b, false)
	defer r.Close()
	peer := &PlaintextFrameRW{RW: a}
	for i := uint64(0); i < CreditWindow+1; i++ {
		if err := peer.WriteFrame(MsgData, []byte{1}); err != nil {
			break
		}
	}
	select {
	case <-r.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("over-credit peer was not disconnected")
	}
}

func TestSessionPeerErrorUnblocksIdleInput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a, b := net.Pipe()
	defer b.Close()
	s := NewSession(ctx, &PlaintextFrameRW{RW: a}, a, true)
	defer s.Close()
	input, writer := io.Pipe()
	defer writer.Close()
	result := make(chan error, 1)
	go func() {
		result <- NewSender(s, &Metadata{Name: "stdin", StreamMode: true}).Send(s.Context(), input, nil)
	}()
	peer := &PlaintextFrameRW{RW: b}
	if _, _, err := peer.ReadFrame(); err != nil {
		t.Fatal(err)
	}
	if err := WriteError(peer, "destination failed"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "destination failed") {
			t.Fatalf("lost peer failure: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer error did not cancel input")
	}
}

func TestSessionParallelCompressedTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var sf, rf []FrameReadWriter
	var sc, rc []MultiStreamConn
	for i := 0; i < 3; i++ {
		a, b := net.Pipe()
		sf = append(sf, &PlaintextFrameRW{RW: a})
		rf = append(rf, &PlaintextFrameRW{RW: b})
		sc = append(sc, a)
		rc = append(rc, b)
	}
	ms, mr := NewMultiStream(sf, sc), NewMultiStream(rf, rc)
	s, r := NewSession(ctx, ms, ms, true), NewSession(ctx, mr, mr, false)
	defer s.Close()
	defer r.Close()
	data := bytes.Repeat([]byte("parallel and bounded"), 1000000)
	var output bytes.Buffer
	result := make(chan error, 1)
	go func() { _, err := NewReceiver(r).Receive(r.Context(), &output, nil); result <- err }()
	sender := NewSender(s, &Metadata{Name: "file", Size: uint64(len(data))})
	if err := sender.SetCompression(3); err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(s.Context(), bytes.NewReader(data), nil); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), data) {
		t.Fatal("out-of-order compression or parallel output")
	}
}

func TestAsyncMultiWriterDoesNotBlockOtherStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a0, b0 := net.Pipe()
	a1, b1 := net.Pipe()
	defer b0.Close()
	defer b1.Close()
	ms := NewMultiStream([]FrameReadWriter{&PlaintextFrameRW{RW: a0}, &PlaintextFrameRW{RW: a1}}, []MultiStreamConn{a0, a1})
	defer ms.Close()
	// No reader on stream 1. Stream 0 must still deliver its next data frame.
	for i := 0; i < 3; i++ {
		if err := ms.WriteSessionFrame(ctx, MsgData, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	peer := &PlaintextFrameRW{RW: b0}
	b0.SetReadDeadline(time.Now().Add(time.Second))
	for i := 0; i < 2; i++ {
		if kind, _, err := peer.ReadFrame(); err != nil || kind != MsgData {
			t.Fatalf("primary blocked: %x %v", kind, err)
		}
	}
}
