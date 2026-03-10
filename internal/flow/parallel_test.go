// SPDX-License-Identifier: MIT

package flow

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/crypto"
	"github.com/zyno-io/sp2p/internal/transfer"
)

// mockP2PConn wraps a net.Conn to satisfy conn.P2PConn.
type mockP2PConn struct {
	net.Conn
}

func (m *mockP2PConn) SetDeadline(t time.Time) error {
	return m.Conn.SetDeadline(t)
}

// setupNegotiationPair creates a connected sender/receiver pair with
// encrypted streams over a real TCP connection, suitable for testing
// the full negotiation protocol.
func setupNegotiationPair(t *testing.T) (
	senderStream *crypto.EncryptedStream,
	senderConn conn.P2PConn,
	receiverStream *crypto.EncryptedStream,
	receiverConn conn.P2PConn,
	sharedSecret, seed []byte,
	senderPub, receiverPub []byte,
	senderTCPResult, receiverTCPResult *conn.TCPResult,
) {
	t.Helper()

	// Create primary connection pair via real TCP so we get kernel
	// send/receive buffers (net.Pipe is unbuffered and would deadlock
	// when both sides write-then-read simultaneously).
	primaryLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen primary: %v", err)
	}
	primaryAddr := primaryLn.Addr().String()
	acceptCh := make(chan net.Conn, 1)
	go func() {
		c, err := primaryLn.Accept()
		if err != nil {
			t.Errorf("primary accept: %v", err)
			return
		}
		acceptCh <- c
	}()
	c1, err := net.Dial("tcp", primaryAddr)
	if err != nil {
		t.Fatalf("primary dial: %v", err)
	}
	c2 := <-acceptCh
	primaryLn.Close()

	senderConn = &mockP2PConn{c1}
	receiverConn = &mockP2PConn{c2}

	// Generate key pairs and shared secret.
	senderKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair sender: %v", err)
	}
	receiverKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair receiver: %v", err)
	}

	sharedSecret, err = crypto.ComputeSharedSecret(senderKP.Private, receiverKP.Public)
	if err != nil {
		t.Fatalf("ComputeSharedSecret: %v", err)
	}

	seed = make([]byte, 16)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	senderPub = senderKP.Public
	receiverPub = receiverKP.Public

	// Create encrypted streams with directional keys.
	s2rKey := make([]byte, 32)
	r2sKey := make([]byte, 32)
	for i := range s2rKey {
		s2rKey[i] = byte(i + 0x10)
		r2sKey[i] = byte(i + 0x20)
	}

	senderStream, err = crypto.NewEncryptedStream(senderConn, s2rKey, r2sKey)
	if err != nil {
		t.Fatalf("NewEncryptedStream sender: %v", err)
	}
	receiverStream, err = crypto.NewEncryptedStream(receiverConn, r2sKey, s2rKey)
	if err != nil {
		t.Fatalf("NewEncryptedStream receiver: %v", err)
	}

	// Create TCP listener for secondary connections.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	addr := ln.Addr().String()

	// Mock AcceptStopped — already stopped.
	acceptStopped := make(chan struct{})
	close(acceptStopped)

	senderTCPResult = &conn.TCPResult{
		Conn:          senderConn,
		PeerAddr:      addr,
		WeDialed:      true,
		AcceptStopped: acceptStopped,
	}
	receiverTCPResult = &conn.TCPResult{
		Conn:          receiverConn,
		Listener:      ln,
		WeDialed:      false,
		AcceptStopped: acceptStopped,
	}

	return
}

type negotiateResult struct {
	frw transfer.FrameReadWriter
	ds  transfer.DeadlineSetter
	err error
}

// TestNegotiateIntegration_ForcedParallel tests the full negotiation protocol
// with a forced parallel count to ensure multi-stream setup works end-to-end.
func TestNegotiateIntegration_ForcedParallel(t *testing.T) {
	senderStream, senderConn, receiverStream, receiverConn,
		sharedSecret, seed, senderPub, receiverPub,
		senderTCP, receiverTCP := setupNegotiationPair(t)
	t.Cleanup(func() {
		senderConn.Close()
		receiverConn.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sessionID := "test-session-parallel"
	fileSize := uint64(128 * 1024 * 1024) // above parallelMinFileSize

	senderCh := make(chan negotiateResult, 1)
	receiverCh := make(chan negotiateResult, 1)

	// Force parallel=2 on both sides to guarantee multi-stream.
	go func() {
		frw, ds, err := negotiateSender(ctx, senderStream, senderConn, senderTCP,
			sharedSecret, seed, fileSize, 2,
			sessionID, senderPub, receiverPub, nil)
		senderCh <- negotiateResult{frw, ds, err}
	}()

	go func() {
		frw, ds, err := negotiateReceiver(ctx, receiverStream, receiverConn, receiverTCP,
			sharedSecret, seed, 2,
			sessionID, senderPub, receiverPub, nil)
		receiverCh <- negotiateResult{frw, ds, err}
	}()

	senderRes := <-senderCh
	receiverRes := <-receiverCh

	if senderRes.err != nil {
		t.Fatalf("sender negotiation error: %v", senderRes.err)
	}
	if receiverRes.err != nil {
		t.Fatalf("receiver negotiation error: %v", receiverRes.err)
	}

	// Both should return MultiStream.
	senderMS, ok := senderRes.frw.(*transfer.MultiStream)
	if !ok {
		t.Fatal("sender should return MultiStream")
	}
	defer senderMS.Close()

	receiverMS, ok := receiverRes.frw.(*transfer.MultiStream)
	if !ok {
		t.Fatal("receiver should return MultiStream")
	}
	defer receiverMS.Close()

	if senderMS.StreamCount() != 2 {
		t.Fatalf("sender stream count = %d, want 2", senderMS.StreamCount())
	}
	if receiverMS.StreamCount() != 2 {
		t.Fatalf("receiver stream count = %d, want 2", receiverMS.StreamCount())
	}

	// Verify data can be sent and received through the MultiStream.
	const numFrames = 5
	errCh := make(chan error, 1)
	go func() {
		for i := range numFrames {
			msgType, data, err := receiverMS.ReadFrame()
			if err != nil {
				errCh <- err
				return
			}
			if msgType != transfer.MsgData {
				errCh <- fmt.Errorf("unexpected message")
				return
			}
			expected := byte(i)
			if len(data) != 1 || data[0] != expected {
				errCh <- fmt.Errorf("unexpected message")
				return
			}
		}
		errCh <- nil
	}()

	for i := range numFrames {
		if err := senderMS.WriteFrame(transfer.MsgData, []byte{byte(i)}); err != nil {
			t.Fatalf("sender WriteFrame %d: %v", i, err)
		}
	}

	if err := <-errCh; err != nil {
		t.Fatalf("receiver ReadFrame error: %v", err)
	}
}

// TestNegotiateIntegration_SmallFile tests that a small file skips probes
// and both sides agree on single-stream.
func TestNegotiateIntegration_SmallFile(t *testing.T) {
	senderStream, senderConn, receiverStream, receiverConn,
		sharedSecret, seed, senderPub, receiverPub,
		senderTCP, receiverTCP := setupNegotiationPair(t)
	t.Cleanup(func() {
		senderConn.Close()
		receiverConn.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sessionID := "test-session-small"
	fileSize := uint64(1024) // well below parallelMinFileSize

	senderCh := make(chan negotiateResult, 1)
	receiverCh := make(chan negotiateResult, 1)

	go func() {
		frw, ds, err := negotiateSender(ctx, senderStream, senderConn, senderTCP,
			sharedSecret, seed, fileSize, 0,
			sessionID, senderPub, receiverPub, nil)
		senderCh <- negotiateResult{frw, ds, err}
	}()

	go func() {
		frw, ds, err := negotiateReceiver(ctx, receiverStream, receiverConn, receiverTCP,
			sharedSecret, seed, 0,
			sessionID, senderPub, receiverPub, nil)
		receiverCh <- negotiateResult{frw, ds, err}
	}()

	senderRes := <-senderCh
	receiverRes := <-receiverCh

	if senderRes.err != nil {
		t.Fatalf("sender error: %v", senderRes.err)
	}
	if receiverRes.err != nil {
		t.Fatalf("receiver error: %v", receiverRes.err)
	}

	// Both should fall back to the original encrypted stream (single connection).
	if senderRes.frw != senderStream {
		t.Fatal("sender should return original encrypted stream for small file")
	}
	if receiverRes.frw != receiverStream {
		t.Fatal("receiver should return original encrypted stream for small file")
	}
}

// TestNegotiateIntegration_ForcedSingle tests that parallel=1 forces single-stream
// even for a large file.
func TestNegotiateIntegration_ForcedSingle(t *testing.T) {
	senderStream, senderConn, receiverStream, receiverConn,
		sharedSecret, seed, senderPub, receiverPub,
		senderTCP, receiverTCP := setupNegotiationPair(t)
	t.Cleanup(func() {
		senderConn.Close()
		receiverConn.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sessionID := "test-session-forced-single"
	fileSize := uint64(256 * 1024 * 1024) // large file

	senderCh := make(chan negotiateResult, 1)
	receiverCh := make(chan negotiateResult, 1)

	// Sender forces parallel=1
	go func() {
		frw, ds, err := negotiateSender(ctx, senderStream, senderConn, senderTCP,
			sharedSecret, seed, fileSize, 1,
			sessionID, senderPub, receiverPub, nil)
		senderCh <- negotiateResult{frw, ds, err}
	}()

	go func() {
		frw, ds, err := negotiateReceiver(ctx, receiverStream, receiverConn, receiverTCP,
			sharedSecret, seed, 0,
			sessionID, senderPub, receiverPub, nil)
		receiverCh <- negotiateResult{frw, ds, err}
	}()

	senderRes := <-senderCh
	receiverRes := <-receiverCh

	if senderRes.err != nil {
		t.Fatalf("sender error: %v", senderRes.err)
	}
	if receiverRes.err != nil {
		t.Fatalf("receiver error: %v", receiverRes.err)
	}

	// Both should fall back to single stream since sender requested count=1.
	if senderRes.frw != senderStream {
		t.Fatal("sender should return original stream when parallel=1")
	}
	if receiverRes.frw != receiverStream {
		t.Fatal("receiver should return original stream when sender requested count=1")
	}
}

// TestNegotiateIntegration_SmallFileStreamUsable verifies that after
// small-file negotiation falls back to single-stream, the encrypted stream
// is still usable and no frames were consumed by the negotiation protocol.
func TestNegotiateIntegration_SmallFileStreamUsable(t *testing.T) {
	senderStream, senderConn, receiverStream, receiverConn,
		sharedSecret, seed, senderPub, receiverPub,
		senderTCP, receiverTCP := setupNegotiationPair(t)
	t.Cleanup(func() {
		senderConn.Close()
		receiverConn.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sessionID := "test-stream-usable"
	fileSize := uint64(1024) // small file → single stream

	senderCh := make(chan negotiateResult, 1)
	receiverCh := make(chan negotiateResult, 1)

	go func() {
		frw, ds, err := negotiateSender(ctx, senderStream, senderConn, senderTCP,
			sharedSecret, seed, fileSize, 0,
			sessionID, senderPub, receiverPub, nil)
		senderCh <- negotiateResult{frw, ds, err}
	}()

	go func() {
		frw, ds, err := negotiateReceiver(ctx, receiverStream, receiverConn, receiverTCP,
			sharedSecret, seed, 0,
			sessionID, senderPub, receiverPub, nil)
		receiverCh <- negotiateResult{frw, ds, err}
	}()

	senderRes := <-senderCh
	receiverRes := <-receiverCh

	if senderRes.err != nil {
		t.Fatalf("sender error: %v", senderRes.err)
	}
	if receiverRes.err != nil {
		t.Fatalf("receiver error: %v", receiverRes.err)
	}

	// After fallback, the stream should be clean — write metadata-like frame
	// from sender and verify receiver gets it intact (no consumed frames).
	payload := []byte(`{"name":"test.txt","size":1024}`)
	errCh := make(chan error, 1)
	go func() {
		msgType, data, err := receiverRes.frw.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		if msgType != transfer.MsgMetadata {
			errCh <- fmt.Errorf("expected MsgMetadata (0x%02x), got 0x%02x", transfer.MsgMetadata, msgType)
			return
		}
		if string(data) != string(payload) {
			errCh <- fmt.Errorf("expected %q, got %q", payload, data)
			return
		}
		errCh <- nil
	}()

	if err := senderRes.frw.WriteFrame(transfer.MsgMetadata, payload); err != nil {
		t.Fatalf("sender WriteFrame: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("receiver: %v", err)
	}
}

// TestParallelCountForRTT verifies RTT → connection count mapping.
func TestParallelCountForRTT(t *testing.T) {
	tests := []struct {
		rtt   time.Duration
		count int
	}{
		{1 * time.Millisecond, 1},
		{4 * time.Millisecond, 1},
		{5 * time.Millisecond, 2},
		{15 * time.Millisecond, 2},
		{20 * time.Millisecond, 3},
		{49 * time.Millisecond, 3},
		{50 * time.Millisecond, 4},
		{99 * time.Millisecond, 4},
		{100 * time.Millisecond, 6},
		{500 * time.Millisecond, 6},
	}
	for _, tt := range tests {
		got := parallelCountForRTT(tt.rtt)
		if got != tt.count {
			t.Errorf("parallelCountForRTT(%v) = %d, want %d", tt.rtt, got, tt.count)
		}
	}
}

// TestResolveParallelCount verifies override vs auto behavior.
func TestResolveParallelCount(t *testing.T) {
	// With override.
	if got := resolveParallelCount(3, 100*time.Millisecond); got != 3 {
		t.Errorf("resolveParallelCount(3, 100ms) = %d, want 3", got)
	}
	// Without override, uses RTT.
	if got := resolveParallelCount(0, 100*time.Millisecond); got != 6 {
		t.Errorf("resolveParallelCount(0, 100ms) = %d, want 6", got)
	}
	// Override of 1 forces single.
	if got := resolveParallelCount(1, 100*time.Millisecond); got != 1 {
		t.Errorf("resolveParallelCount(1, 100ms) = %d, want 1", got)
	}
}
