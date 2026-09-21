// SPDX-License-Identifier: MIT

package stream

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/zyno-io/sp2p/internal/crypto"
)

type closerOnly struct{ io.Closer }

type blockingDrainCloser struct {
	io.Closer
	started chan struct{}
	release chan struct{}
}

type gatedWriteReturnConn struct {
	net.Conn
	mu        sync.Mutex
	armed     bool
	delivered chan struct{}
	release   chan struct{}
}

func (c *gatedWriteReturnConn) arm() {
	c.mu.Lock()
	c.armed = true
	c.mu.Unlock()
}

func (c *gatedWriteReturnConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	armed := c.armed
	c.armed = false
	c.mu.Unlock()
	n, err := c.Conn.Write(p)
	if armed {
		close(c.delivered)
		<-c.release
	}
	return n, err
}

func (c *blockingDrainCloser) Drain(ctx context.Context) error {
	close(c.started)
	select {
	case <-c.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newPair(t *testing.T) (*Stream, *Stream, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	left, right, closePair := newPairContext(t, ctx)
	return left, right, func() { cancel(); closePair() }
}

func newPairContext(t *testing.T, ctx context.Context) (*Stream, *Stream, func()) {
	t.Helper()
	left, right := net.Pipe()
	firstKey := bytes.Repeat([]byte{1}, 32)
	secondKey := bytes.Repeat([]byte{2}, 32)
	leftFrames, err := crypto.NewEncryptedStream(left, firstKey, secondKey)
	if err != nil {
		t.Fatal(err)
	}
	rightFrames, err := crypto.NewEncryptedStream(right, secondKey, firstKey)
	if err != nil {
		t.Fatal(err)
	}
	return New(ctx, leftFrames, left), New(ctx, rightFrames, right), func() { left.Close(); right.Close() }
}

func newRawPeer(t *testing.T) (*Stream, *crypto.EncryptedStream, func()) {
	s, raw, _, cleanup := newRawPeerTransport(t)
	return s, raw, cleanup
}

func newRawPeerTransport(t *testing.T) (*Stream, *crypto.EncryptedStream, func() error, func()) {
	t.Helper()
	left, right := net.Pipe()
	firstKey := bytes.Repeat([]byte{1}, 32)
	secondKey := bytes.Repeat([]byte{2}, 32)
	leftFrames, err := crypto.NewEncryptedStream(left, firstKey, secondKey)
	if err != nil {
		t.Fatal(err)
	}
	rightFrames, err := crypto.NewEncryptedStream(right, secondKey, firstKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return New(ctx, leftFrames, left), rightFrames, right.Close, func() { cancel(); left.Close(); right.Close() }
}

func completeRawFins(t *testing.T, s *Stream, raw *crypto.EncryptedStream) {
	t.Helper()
	if err := raw.WriteFrame(msgFin, nil); err != nil {
		t.Fatal(err)
	}
	typ, _, err := raw.ReadFrame()
	if err != nil || typ != msgFinAck {
		t.Fatalf("fin ack: %x %v", typ, err)
	}
	closeErr := make(chan error, 1)
	go func() { closeErr <- s.CloseWrite() }()
	typ, _, err = raw.ReadFrame()
	if err != nil || typ != msgFin {
		t.Fatalf("fin: %x %v", typ, err)
	}
	if err := <-closeErr; err != nil {
		t.Fatal(err)
	}
	if err := raw.WriteFrame(msgFinAck, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(s); err != nil {
		t.Fatal(err)
	}
}

func handshakeRawPeer(t *testing.T, s *Stream, raw *crypto.EncryptedStream) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Handshake(context.Background(), Config{Service: "tunnel", Mode: "serve", ExpectedService: "tunnel", ExpectedMode: "connect"})
	}()
	typ, _, err := raw.ReadFrame()
	if err != nil || typ != msgHello {
		t.Fatalf("read hello: type=%x err=%v", typ, err)
	}
	peer := hello{Protocol: protocolName, Service: "tunnel", Mode: "connect", MaxData: maxDataSize, MaxOutstanding: maxFrames}
	if err := raw.WriteFrame(msgHello, mustJSON(peer)); err != nil {
		t.Fatal(err)
	}
	typ, _, err = raw.ReadFrame()
	if err != nil || typ != msgHandshakeAck {
		t.Fatalf("read handshake ack: type=%x err=%v", typ, err)
	}
	if err := raw.WriteFrame(msgHandshakeAck, mustJSON(peer)); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("handshake: %v", err)
	}
	readyErr := make(chan error, 1)
	go func() { readyErr <- s.Ready() }()
	typ, _, err = raw.ReadFrame()
	if err != nil || typ != msgReady {
		t.Fatalf("read ready: type=%x err=%v", typ, err)
	}
	if err := <-readyErr; err != nil {
		t.Fatal(err)
	}
	if err := raw.WriteFrame(msgReady, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.WaitReady(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func handshakePair(t *testing.T, left, right *Stream) {
	t.Helper()
	var leftErr, rightErr error
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		leftErr = left.Handshake(context.Background(), Config{Service: "tunnel", Mode: "serve", ExpectedService: "tunnel", ExpectedMode: "connect"})
	}()
	go func() {
		defer wait.Done()
		rightErr = right.Handshake(context.Background(), Config{Service: "tunnel", Mode: "connect", ExpectedService: "tunnel", ExpectedMode: "serve"})
	}()
	wait.Wait()
	if leftErr != nil || rightErr != nil {
		t.Fatalf("handshake errors: left=%v right=%v", leftErr, rightErr)
	}
	if err := left.Ready(); err != nil {
		t.Fatal(err)
	}
	if err := right.Ready(); err != nil {
		t.Fatal(err)
	}
	if err := left.WaitReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := right.WaitReady(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStreamFullDuplexBoundedPressureAndCompletion(t *testing.T) {
	left, right, closePair := newPair(t)
	defer closePair()
	handshakePair(t, left, right)
	leftPayload := bytes.Repeat([]byte("left"), 300000)
	rightPayload := bytes.Repeat([]byte("right"), 300000)
	type result struct {
		data []byte
		err  error
	}
	leftRead := make(chan result, 1)
	rightRead := make(chan result, 1)
	go func() { data, err := io.ReadAll(left); leftRead <- result{data, err} }()
	go func() { data, err := io.ReadAll(right); rightRead <- result{data, err} }()
	var write sync.WaitGroup
	write.Add(2)
	go func() {
		defer write.Done()
		if n, err := left.Write(leftPayload); err != nil || n != len(leftPayload) {
			t.Errorf("left write = %d, %v", n, err)
		}
		if err := left.CloseWrite(); err != nil {
			t.Errorf("left close write: %v", err)
		}
	}()
	go func() {
		defer write.Done()
		if n, err := right.Write(rightPayload); err != nil || n != len(rightPayload) {
			t.Errorf("right write = %d, %v", n, err)
		}
		if err := right.CloseWrite(); err != nil {
			t.Errorf("right close write: %v", err)
		}
	}()
	write.Wait()
	gotLeft, gotRight := <-leftRead, <-rightRead
	if gotLeft.err != nil || !bytes.Equal(gotLeft.data, rightPayload) {
		t.Fatalf("left read: len=%d err=%v", len(gotLeft.data), gotLeft.err)
	}
	if gotRight.err != nil || !bytes.Equal(gotRight.data, leftPayload) {
		t.Fatalf("right read: len=%d err=%v", len(gotRight.data), gotRight.err)
	}
	var finish sync.WaitGroup
	finish.Add(2)
	go func() {
		defer finish.Done()
		if err := left.Finish(nil); err != nil {
			t.Errorf("left finish: %v", err)
		}
	}()
	go func() {
		defer finish.Done()
		if err := right.Finish(nil); err != nil {
			t.Errorf("right finish: %v", err)
		}
	}()
	finish.Wait()
	if sent, received := left.Stats(); sent != uint64(len(leftPayload)) || received != uint64(len(rightPayload)) {
		t.Fatalf("left stats = %d/%d", sent, received)
	}
}

func TestStreamHalfCloseKeepsResponseDirectionOpen(t *testing.T) {
	left, right, closePair := newPair(t)
	defer closePair()
	handshakePair(t, left, right)
	request := []byte("request")
	response := []byte("response after request EOF")
	if _, err := left.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := left.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	gotRequest, err := io.ReadAll(right)
	if err != nil || !bytes.Equal(gotRequest, request) {
		t.Fatalf("request = %q, %v", gotRequest, err)
	}
	if _, err := right.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := right.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	gotResponse, err := io.ReadAll(left)
	if err != nil || !bytes.Equal(gotResponse, response) {
		t.Fatalf("response = %q, %v", gotResponse, err)
	}
	results := make(chan error, 2)
	go func() { results <- left.Finish(nil) }()
	go func() { results <- right.Finish(nil) }()
	if err := <-results; err != nil {
		t.Fatal(err)
	}
	if err := <-results; err != nil {
		t.Fatal(err)
	}
}

func TestStreamHandshakeMismatchAndCancellation(t *testing.T) {
	left, right, closePair := newPair(t)
	defer closePair()
	result := make(chan error, 2)
	go func() {
		result <- left.Handshake(context.Background(), Config{Service: "tunnel", Mode: "serve", ExpectedService: "tunnel", ExpectedMode: "connect"})
	}()
	go func() {
		result <- right.Handshake(context.Background(), Config{Service: "rsync", Mode: "recv", ExpectedService: "rsync", ExpectedMode: "send"})
	}()
	if err := <-result; err == nil {
		t.Fatal("first mismatched handshake succeeded")
	}
	if err := <-result; err == nil {
		t.Fatal("second mismatched handshake succeeded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := left.Wait(ctx); err == nil {
		t.Fatal("Wait succeeded after handshake abort")
	}
}

func TestStreamReadyAndRemoteFailure(t *testing.T) {
	left, right, closePair := newPair(t)
	defer closePair()
	handshakePair(t, left, right)
	if err := left.Ready(); err == nil {
		t.Fatal("duplicate Ready succeeded")
	}
	failure := errors.New("target dial failed")
	if err := left.Finish(failure); !errors.Is(err, failure) {
		t.Fatalf("Finish failure = %v", err)
	}
	if err := right.Wait(context.Background()); err == nil || err.Error() != failure.Error() {
		t.Fatalf("remote failure = %v", err)
	}
}

func TestStreamFailureDrainsTransportBeforeReturning(t *testing.T) {
	left, right := net.Pipe()
	firstKey := bytes.Repeat([]byte{1}, 32)
	secondKey := bytes.Repeat([]byte{2}, 32)
	leftFrames, err := crypto.NewEncryptedStream(left, firstKey, secondKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := crypto.NewEncryptedStream(right, secondKey, firstKey)
	if err != nil {
		t.Fatal(err)
	}
	closer := &blockingDrainCloser{Closer: left, started: make(chan struct{}), release: make(chan struct{})}
	s := New(context.Background(), leftFrames, closer)
	defer func() {
		s.Close()
		right.Close()
	}()
	handshakeRawPeer(t, s, raw)

	failure := errors.New("target dial failed")
	finished := make(chan error, 1)
	go func() { finished <- s.Finish(failure) }()
	typ, data, err := raw.ReadFrame()
	if err != nil || typ != msgStatus {
		t.Fatalf("failure status: type=%x data=%q err=%v", typ, data, err)
	}
	select {
	case <-closer.started:
	case <-time.After(time.Second):
		t.Fatal("Finish did not drain the failure status")
	}
	select {
	case err := <-finished:
		t.Fatalf("Finish returned before transport drain completed: %v", err)
	default:
	}
	close(closer.release)
	if err := <-finished; !errors.Is(err, failure) {
		t.Fatalf("Finish failure = %v, want %v", err, failure)
	}
}

func TestStreamAbortReachesPeerBeforeTransportClose(t *testing.T) {
	left, right, closePair := newPair(t)
	defer closePair()
	handshakePair(t, left, right)
	abortErr := errors.New("local endpoint failed")
	if err := left.Abort(abortErr); err == nil {
		t.Fatal("Abort succeeded without reporting the local failure")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := right.Wait(ctx)
	if err == nil || err.Error() != "peer aborted stream: local endpoint failed" {
		t.Fatalf("peer abort error = %v", err)
	}
}

func TestStreamRejectsControlAfterTerminalStatus(t *testing.T) {
	s, raw, closePair := newRawPeer(t)
	defer closePair()
	handshakeRawPeer(t, s, raw)
	if err := raw.WriteFrame(msgFin, nil); err != nil {
		t.Fatal(err)
	}
	typ, _, err := raw.ReadFrame()
	if err != nil || typ != msgFinAck {
		t.Fatalf("fin ack: %x %v", typ, err)
	}
	closeWriteErr := make(chan error, 1)
	go func() { closeWriteErr <- s.CloseWrite() }()
	typ, _, err = raw.ReadFrame()
	if err != nil || typ != msgFin {
		t.Fatalf("fin: %x %v", typ, err)
	}
	if err := <-closeWriteErr; err != nil {
		t.Fatal(err)
	}
	if err := raw.WriteFrame(msgFinAck, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(s); err != nil {
		t.Fatal(err)
	}
	if err := raw.WriteFrame(msgStatus, mustJSON(status{OK: true})); err != nil {
		t.Fatal(err)
	}
	if err := raw.WriteFrame(msgAbort, []byte("ignored after status")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("stream did not observe terminal transport failure")
	}
	if err := s.Wait(context.Background()); err == nil {
		t.Fatal("post-status control frame was accepted as successful completion")
	}
}

func TestStreamFinishRequiresStatusAcknowledgements(t *testing.T) {
	t.Run("premature-peer-close-fails", func(t *testing.T) {
		s, raw, closePeer, cleanup := newRawPeerTransport(t)
		defer cleanup()
		handshakeRawPeer(t, s, raw)
		completeRawFins(t, s, raw)
		finished := make(chan error, 1)
		go func() { finished <- s.Finish(nil) }()
		typ, _, err := raw.ReadFrame()
		if err != nil || typ != msgStatus {
			t.Fatalf("status: %x %v", typ, err)
		}
		if err := raw.WriteFrame(msgStatus, mustJSON(status{OK: true})); err != nil {
			t.Fatal(err)
		}
		if err := closePeer(); err != nil {
			t.Fatal(err)
		}
		if err := <-finished; err == nil {
			t.Fatal("Finish succeeded without peer status acknowledgement")
		}
	})
	t.Run("late-close-after-both-acks-succeeds", func(t *testing.T) {
		s, raw, closePeer, cleanup := newRawPeerTransport(t)
		defer cleanup()
		handshakeRawPeer(t, s, raw)
		completeRawFins(t, s, raw)
		finished := make(chan error, 1)
		go func() { finished <- s.Finish(nil) }()
		typ, _, err := raw.ReadFrame()
		if err != nil || typ != msgStatus {
			t.Fatalf("status: %x %v", typ, err)
		}
		if err := raw.WriteFrame(msgStatus, mustJSON(status{OK: true})); err != nil {
			t.Fatal(err)
		}
		typ, _, err = raw.ReadFrame()
		if err != nil || typ != msgStatusAck {
			t.Fatalf("status ack: %x %v", typ, err)
		}
		if err := raw.WriteFrame(msgStatusAck, nil); err != nil {
			t.Fatal(err)
		}
		select {
		case <-s.localStatAckCh:
		case <-time.After(time.Second):
			t.Fatal("stream did not receive peer status acknowledgement")
		}
		if err := closePeer(); err != nil {
			t.Fatal(err)
		}
		if err := <-finished; err != nil {
			t.Fatalf("Finish lost authenticated terminal proof: %v", err)
		}
	})
	t.Run("waits-for-physical-status-ack-write", func(t *testing.T) {
		s, raw, _, cleanup := newRawPeerTransport(t)
		defer cleanup()
		handshakeRawPeer(t, s, raw)
		completeRawFins(t, s, raw)
		finished := make(chan error, 1)
		go func() { finished <- s.Finish(nil) }()
		typ, _, err := raw.ReadFrame()
		if err != nil || typ != msgStatus {
			t.Fatalf("status: %x %v", typ, err)
		}
		if err := raw.WriteFrame(msgStatus, mustJSON(status{OK: true})); err != nil {
			t.Fatal(err)
		}
		if err := raw.WriteFrame(msgStatusAck, nil); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-finished:
			t.Fatalf("Finish returned before its status ACK was written: %v", err)
		case <-time.After(25 * time.Millisecond):
		}
		typ, _, err = raw.ReadFrame()
		if err != nil || typ != msgStatusAck {
			t.Fatalf("status ack: %x %v", typ, err)
		}
		if err := <-finished; err != nil {
			t.Fatalf("Finish after physical status ACK: %v", err)
		}
	})
	t.Run("peer-close-joins-delivered-status-ack-write", func(t *testing.T) {
		left, right := net.Pipe()
		gated := &gatedWriteReturnConn{
			Conn: left, delivered: make(chan struct{}), release: make(chan struct{}),
		}
		firstKey := bytes.Repeat([]byte{1}, 32)
		secondKey := bytes.Repeat([]byte{2}, 32)
		leftFrames, err := crypto.NewEncryptedStream(gated, firstKey, secondKey)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := crypto.NewEncryptedStream(right, secondKey, firstKey)
		if err != nil {
			t.Fatal(err)
		}
		s := New(context.Background(), leftFrames, gated)
		defer func() {
			s.Close()
			right.Close()
		}()
		handshakeRawPeer(t, s, raw)
		completeRawFins(t, s, raw)

		finished := make(chan error, 1)
		go func() { finished <- s.Finish(nil) }()
		typ, _, err := raw.ReadFrame()
		if err != nil || typ != msgStatus {
			t.Fatalf("status: %x %v", typ, err)
		}
		gated.arm()
		if err := raw.WriteFrame(msgStatus, mustJSON(status{OK: true})); err != nil {
			t.Fatal(err)
		}
		typ, _, err = raw.ReadFrame()
		if err != nil || typ != msgStatusAck {
			t.Fatalf("status ack: %x %v", typ, err)
		}
		select {
		case <-gated.delivered:
		case <-time.After(time.Second):
			t.Fatal("status acknowledgement was not delivered")
		}
		if err := raw.WriteFrame(msgStatusAck, nil); err != nil {
			t.Fatal(err)
		}
		select {
		case <-s.localStatAckCh:
		case <-time.After(time.Second):
			t.Fatal("stream did not receive peer status acknowledgement")
		}
		if err := right.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-s.Context().Done():
		case <-time.After(time.Second):
			t.Fatal("stream did not observe peer close")
		}
		select {
		case err := <-finished:
			t.Fatalf("Finish returned before the delivered ACK write completed: %v", err)
		default:
		}
		close(gated.release)
		if err := <-finished; err != nil {
			t.Fatalf("Finish lost the delivered terminal ACK: %v", err)
		}
	})
	t.Run("peer-close-joins-delivered-status-write", func(t *testing.T) {
		left, right := net.Pipe()
		gated := &gatedWriteReturnConn{
			Conn: left, delivered: make(chan struct{}), release: make(chan struct{}),
		}
		firstKey := bytes.Repeat([]byte{1}, 32)
		secondKey := bytes.Repeat([]byte{2}, 32)
		leftFrames, err := crypto.NewEncryptedStream(gated, firstKey, secondKey)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := crypto.NewEncryptedStream(right, secondKey, firstKey)
		if err != nil {
			t.Fatal(err)
		}
		s := New(context.Background(), leftFrames, gated)
		defer func() {
			s.Close()
			right.Close()
		}()
		handshakeRawPeer(t, s, raw)
		completeRawFins(t, s, raw)

		if err := raw.WriteFrame(msgStatus, mustJSON(status{OK: true})); err != nil {
			t.Fatal(err)
		}
		typ, _, err := raw.ReadFrame()
		if err != nil || typ != msgStatusAck {
			t.Fatalf("status ack: %x %v", typ, err)
		}
		gated.arm()
		finished := make(chan error, 1)
		go func() { finished <- s.Finish(nil) }()
		typ, _, err = raw.ReadFrame()
		if err != nil || typ != msgStatus {
			t.Fatalf("status: %x %v", typ, err)
		}
		select {
		case <-gated.delivered:
		case <-time.After(time.Second):
			t.Fatal("status was not delivered")
		}
		if err := raw.WriteFrame(msgStatusAck, nil); err != nil {
			t.Fatal(err)
		}
		select {
		case <-s.localStatAckCh:
		case <-time.After(time.Second):
			t.Fatal("stream did not receive peer status acknowledgement")
		}
		if err := right.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-s.Context().Done():
		case <-time.After(time.Second):
			t.Fatal("stream did not observe peer close")
		}
		select {
		case err := <-finished:
			t.Fatalf("Finish returned before the delivered status write completed: %v", err)
		default:
		}
		close(gated.release)
		if err := <-finished; err != nil {
			t.Fatalf("Finish lost the delivered terminal status: %v", err)
		}
	})
}

func TestStreamRejectsMalformedControls(t *testing.T) {
	invalidCredit := make([]byte, 8)
	binary.BigEndian.PutUint64(invalidCredit, 1)
	cases := []struct {
		name string
		send func(t *testing.T, raw *crypto.EncryptedStream)
	}{
		{"empty-data", func(t *testing.T, raw *crypto.EncryptedStream) {
			if err := raw.WriteFrame(msgData, nil); err != nil {
				t.Fatal(err)
			}
		}},
		{"unearned-credit", func(t *testing.T, raw *crypto.EncryptedStream) {
			if err := raw.WriteFrame(msgCredit, invalidCredit); err != nil {
				t.Fatal(err)
			}
		}},
		{"data-after-fin", func(t *testing.T, raw *crypto.EncryptedStream) {
			if err := raw.WriteFrame(msgFin, nil); err != nil {
				t.Fatal(err)
			}
			typ, _, err := raw.ReadFrame()
			if err != nil || typ != msgFinAck {
				t.Fatalf("fin ack: %x %v", typ, err)
			}
			if err := raw.WriteFrame(msgData, []byte("late")); err != nil {
				t.Fatal(err)
			}
		}},
		{"duplicate-fin", func(t *testing.T, raw *crypto.EncryptedStream) {
			if err := raw.WriteFrame(msgFin, nil); err != nil {
				t.Fatal(err)
			}
			typ, _, err := raw.ReadFrame()
			if err != nil || typ != msgFinAck {
				t.Fatalf("fin ack: %x %v", typ, err)
			}
			if err := raw.WriteFrame(msgFin, nil); err != nil {
				t.Fatal(err)
			}
		}},
		{"unexpected-status-ack", func(t *testing.T, raw *crypto.EncryptedStream) {
			if err := raw.WriteFrame(msgStatusAck, nil); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			s, raw, closePair := newRawPeer(t)
			defer closePair()
			handshakeRawPeer(t, s, raw)
			test.send(t, raw)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := s.Wait(ctx); err == nil {
				t.Fatal("malformed frame did not fail stream")
			}
		})
	}
}

func TestStreamHandshakeDeadlineClosesNonDeadlineTransport(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	keyA, keyB := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	frames, err := crypto.NewEncryptedStream(left, keyA, keyB)
	if err != nil {
		t.Fatal(err)
	}
	s := New(context.Background(), frames, closerOnly{left})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := s.Handshake(ctx, Config{Service: "tunnel", Mode: "serve"}); err == nil {
		t.Fatal("handshake unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("handshake timeout took %v", elapsed)
	}
}

func TestStreamReadyGateRejectsDataButAllowsSetupFailure(t *testing.T) {
	for _, test := range []struct {
		name      string
		typ       byte
		data      []byte
		wantError bool
	}{
		{"data-before-ready", msgData, []byte("early"), true},
		{"failure-status-before-ready", msgStatus, mustJSON(status{OK: false, Error: "target unavailable"}), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, raw, closePair := newRawPeer(t)
			defer closePair()
			errCh := make(chan error, 1)
			go func() {
				errCh <- s.Handshake(context.Background(), Config{Service: "tunnel", Mode: "serve", ExpectedService: "tunnel", ExpectedMode: "connect"})
			}()
			typ, _, err := raw.ReadFrame()
			if err != nil || typ != msgHello {
				t.Fatalf("hello: %x %v", typ, err)
			}
			peer := hello{Protocol: protocolName, Service: "tunnel", Mode: "connect", MaxData: maxDataSize, MaxOutstanding: maxFrames}
			if err := raw.WriteFrame(msgHello, mustJSON(peer)); err != nil {
				t.Fatal(err)
			}
			typ, _, err = raw.ReadFrame()
			if err != nil || typ != msgHandshakeAck {
				t.Fatalf("ack: %x %v", typ, err)
			}
			if err := raw.WriteFrame(msgHandshakeAck, mustJSON(peer)); err != nil {
				t.Fatal(err)
			}
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}
			if _, err := s.Write([]byte("local early")); err == nil {
				t.Fatal("local write before ready succeeded")
			}
			if err := raw.WriteFrame(test.typ, test.data); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = s.Wait(ctx)
			if test.wantError && err == nil {
				t.Fatal("data before ready did not fail")
			}
			if !test.wantError && (err == nil || err.Error() != "target unavailable") {
				t.Fatalf("setup failure = %v", err)
			}
		})
	}
}

func TestStreamCreditWaitUnblocksOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	left, right, closePair := newPairContext(t, ctx)
	defer closePair()
	handshakePair(t, left, right)
	if got, want := cap(left.writeCh), maxFrames+16; got != want {
		t.Fatalf("write queue cap = %d, want %d", got, want)
	}
	result := make(chan error, 1)
	go func() {
		_, err := left.Write(bytes.Repeat([]byte{'x'}, maxDataSize*(maxFrames+1)))
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("write escaped credit window: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("credit wait succeeded after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("credit wait remained blocked after cancellation")
	}
}

func TestStreamPhysicalWriteTimeout(t *testing.T) {
	oldTimeout := physicalWriteTimeout
	physicalWriteTimeout = 20 * time.Millisecond
	defer func() { physicalWriteTimeout = oldTimeout }()
	s, raw, closePair := newRawPeer(t)
	defer closePair()
	handshakeRawPeer(t, s, raw)
	started := time.Now()
	if _, err := s.Write([]byte("blocked")); err == nil {
		t.Fatal("write unexpectedly succeeded without peer read")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("physical write timeout took %v", elapsed)
	}
}
