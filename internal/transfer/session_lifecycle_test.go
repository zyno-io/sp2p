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
