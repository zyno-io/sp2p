// SPDX-License-Identifier: MIT

package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestSessionSurvivesIdleInputAndSlowFinalization(t *testing.T) {
	for _, slowFinalize := range []bool{false, true} {
		t.Run(fmt.Sprintf("slow-finalize=%v", slowFinalize), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := net.Pipe()
				s := NewSession(context.Background(), &PlaintextFrameRW{RW: a}, a, true)
				r := NewSession(context.Background(), &PlaintextFrameRW{RW: b}, b, false)
				defer s.Close()
				defer r.Close()
				input, writer := io.Pipe()
				defer writer.Close()
				sender := NewSender(s, &Metadata{Name: "stdin", StreamMode: true})
				receiver := NewReceiver(r)
				// Match the production flows, including their legacy timeout setup.
				sender.SetIdleTimeout(a, 2*time.Minute)
				receiver.SetIdleTimeout(b, 2*time.Minute)
				if slowFinalize {
					receiver.Finalize = func() error { time.Sleep(3 * time.Minute); return nil }
				}
				var output bytes.Buffer
				sent, received := make(chan error, 1), make(chan error, 1)
				go func() { sent <- sender.Send(s.Context(), input, nil) }()
				go func() { _, err := receiver.Receive(r.Context(), &output, nil); received <- err }()
				if !slowFinalize {
					time.Sleep(3 * time.Minute)
					synctest.Wait()
					if s.Context().Err() != nil || r.Context().Err() != nil {
						t.Fatalf("healthy idle session closed: sender=%v receiver=%v", context.Cause(s.Context()), context.Cause(r.Context()))
					}
				}
				if _, err := writer.Write([]byte("still alive")); err != nil {
					t.Fatal(err)
				}
				writer.Close()
				if err := <-sent; err != nil {
					t.Fatal(err)
				}
				if err := <-received; err != nil {
					t.Fatal(err)
				}
				if output.String() != "still alive" {
					t.Fatal("output mismatch")
				}
			})
		})
	}
}

func TestSessionWriteTimeoutDespiteLivePeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		defer b.Close()
		s := NewSession(context.Background(), &PlaintextFrameRW{RW: a}, a, true)
		defer s.Close()
		// Expire before the local heartbeat attempts the writer mutex: mutex
		// contention is not durably blocked under synctest's fake clock.
		const writeTimeout = 2 * time.Second
		s.SetWriteTimeout(writeTimeout)
		peer := &PlaintextFrameRW{RW: b}
		go func() {
			for {
				if err := peer.WriteFrame(MsgHeartbeat, nil); err != nil {
					return
				}
				select {
				case <-s.Context().Done():
					return
				case <-time.After(100 * time.Millisecond):
				}
			}
		}()
		start := time.Now()
		// Peer writes heartbeats but never reads this frame.
		err := s.WriteFrame(MsgMetadata, []byte("{}"))
		if err == nil || !strings.Contains(err.Error(), "network write timed out") {
			t.Fatalf("write: %v", err)
		}
		if elapsed := time.Since(start); elapsed != writeTimeout {
			t.Fatalf("write timeout after %v", elapsed)
		}
	})
}

func TestSessionSecondaryWriteTimeoutDespiteLivePrimary(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a0, b0 := net.Pipe()
		a1, b1 := net.Pipe()
		defer b0.Close()
		defer b1.Close()
		ms := NewMultiStream([]FrameReadWriter{&PlaintextFrameRW{RW: a0}, &PlaintextFrameRW{RW: a1}}, []MultiStreamConn{a0, a1})
		s := NewSession(context.Background(), ms, ms, true)
		defer s.Close()
		peer := &PlaintextFrameRW{RW: b0}
		go func() {
			for {
				if _, _, err := peer.ReadFrame(); err != nil {
					return
				}
			}
		}()
		go func() {
			for {
				if err := peer.WriteFrame(MsgHeartbeat, nil); err != nil {
					return
				}
				select {
				case <-s.Context().Done():
					return
				case <-time.After(HeartbeatInterval):
				}
			}
		}()
		for i := 0; i < 2; i++ {
			if err := s.WriteFrame(MsgData, []byte{1}); err != nil {
				t.Fatal(err)
			}
		}
		<-s.Context().Done()
		if cause := context.Cause(s.Context()); !strings.Contains(cause.Error(), "network write timed out") {
			t.Fatal(cause)
		}
	})
}

func TestSessionFinAckWaitIsBoundedWithHeartbeats(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		s := NewSession(context.Background(), &PlaintextFrameRW{RW: a}, a, true)
		r := NewSession(context.Background(), &PlaintextFrameRW{RW: b}, b, false)
		defer s.Close()
		defer r.Close()
		received := make(chan error, 1)
		go func() { _, err := NewReceiver(r).Receive(r.Context(), io.Discard, nil); received <- err }()
		if err := WriteMetadata(s, &Metadata{Name: "empty"}); err != nil {
			t.Fatal(err)
		}
		if err := WriteDone(s, &Done{SHA256: fmt.Sprintf("%x", sha256.Sum256(nil))}); err != nil {
			t.Fatal(err)
		}
		if kind, _, err := s.ReadFrame(); err != nil || kind != MsgComplete {
			t.Fatalf("complete: %x %v", kind, err)
		}
		start := time.Now()
		if err := <-received; err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed != CompletionAckTimeout {
			t.Fatalf("ack wait: %v", elapsed)
		}
		if r.Context().Err() != nil {
			t.Fatal("ack timeout cancelled verified session")
		}
	})
}

// A peer can receive Complete and close before the local WriteFrame returns.
// Keep that write in flight until the read loop and its cancellation callbacks
// have processed EOF, so the completion race is deterministic.
type delayedCompleteFrameRW struct {
	FrameReadWriter
	release <-chan struct{}
}

func (f *delayedCompleteFrameRW) WriteFrame(kind byte, data []byte) error {
	err := f.FrameReadWriter.WriteFrame(kind, data)
	if kind == MsgComplete && err == nil {
		<-f.release
	}
	return err
}

func TestSessionWriteTimeoutAfterPhysicalWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		release := make(chan struct{})
		s := NewSession(context.Background(), &delayedCompleteFrameRW{
			FrameReadWriter: &PlaintextFrameRW{RW: b}, release: release,
		}, b, false)
		defer s.Close()
		const timeout = 2 * time.Second
		s.SetWriteTimeout(timeout)
		written := make(chan error, 1)
		go func() { written <- s.WriteFrame(MsgComplete, nil) }()
		peer := &PlaintextFrameRW{RW: a}
		if kind, _, err := peer.ReadFrame(); err != nil || kind != MsgComplete {
			t.Fatalf("complete: %x %v", kind, err)
		}
		// The bytes arrived, but the physical write has not returned by its
		// own deadline. Unlike a peer close, this must remain a timeout.
		time.Sleep(timeout)
		<-s.Context().Done()
		synctest.Wait()
		close(release)
		if err := <-written; err == nil || !strings.Contains(err.Error(), "network write timed out") {
			t.Fatalf("write: %v", err)
		}
	})
}

func TestSessionCompleteWriteSurvivesPeerClose(t *testing.T) {
	for _, tt := range []struct {
		streams int
		ack     bool
	}{{1, false}, {1, true}, {3, false}, {3, true}} {
		t.Run(fmt.Sprintf("streams=%d/fin-ack=%v", tt.streams, tt.ack), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				var peerFrames, receiverFrames []FrameReadWriter
				var peerConns, receiverConns []MultiStreamConn
				for i := 0; i < tt.streams; i++ {
					a, b := net.Pipe()
					peerFrames = append(peerFrames, &PlaintextFrameRW{RW: a})
					receiverFrames = append(receiverFrames, &delayedCompleteFrameRW{
						FrameReadWriter: &PlaintextFrameRW{RW: b}, release: release,
					})
					peerConns = append(peerConns, a)
					receiverConns = append(receiverConns, b)
				}
				peer, receiverIO := peerFrames[0], receiverFrames[0]
				var peerCloser, receiverCloser io.Closer = peerConns[0], receiverConns[0]
				if tt.streams > 1 {
					peerMulti := NewMultiStream(peerFrames, peerConns)
					receiverMulti := NewMultiStream(receiverFrames, receiverConns)
					peer, peerCloser = peerMulti, peerMulti
					receiverIO, receiverCloser = receiverMulti, receiverMulti
				}
				defer peerCloser.Close()
				r := NewSession(context.Background(), receiverIO, receiverCloser, false)
				defer r.Close()
				payload := []byte("verified before completion")
				var output bytes.Buffer
				finalized := false
				receiver := NewReceiver(r)
				receiver.Finalize = func() error { finalized = true; return nil }
				received := make(chan error, 1)
				go func() {
					_, err := receiver.Receive(r.Context(), &output, nil)
					received <- err
				}()
				if err := WriteMetadata(peer, &Metadata{Name: "file", Size: uint64(len(payload))}); err != nil {
					t.Fatal(err)
				}
				if err := WriteData(peer, payload); err != nil {
					t.Fatal(err)
				}
				if kind, _, err := peer.ReadFrame(); err != nil || kind != MsgCredit {
					t.Fatalf("credit: %x %v", kind, err)
				}
				if err := WriteDone(peer, &Done{
					TotalBytes: uint64(len(payload)), ChunkCount: 1,
					SHA256: fmt.Sprintf("%x", sha256.Sum256(payload)),
				}); err != nil {
					t.Fatal(err)
				}
				if kind, _, err := peer.ReadFrame(); err != nil || kind != MsgComplete {
					t.Fatalf("complete: %x %v", kind, err)
				}
				if tt.ack {
					if err := WriteFinAck(peer); err != nil {
						t.Fatal(err)
					}
				}
				peerCloser.Close()
				<-r.Context().Done()
				synctest.Wait()
				close(release)
				if err := <-received; err != nil {
					t.Fatalf("verified transfer failed after Complete was written: %v", err)
				}
				if !finalized || !bytes.Equal(output.Bytes(), payload) {
					t.Fatal("output was not verified and finalized")
				}
			})
		})
	}
}
