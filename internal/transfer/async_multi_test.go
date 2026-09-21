// SPDX-License-Identifier: MIT

package transfer

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type recordingFrameRW struct {
	FrameReadWriter
	started chan byte
}

type delayedAsyncFrameRW struct {
	FrameReadWriter
	kind      byte
	delivered chan struct{}
	release   <-chan struct{}
}

func (f *delayedAsyncFrameRW) WriteFrame(kind byte, data []byte) error {
	err := f.FrameReadWriter.WriteFrame(kind, data)
	if kind == f.kind && err == nil {
		close(f.delivered)
		<-f.release
	}
	return err
}

func (f *recordingFrameRW) WriteFrame(kind byte, data []byte) error {
	f.started <- kind
	return f.FrameReadWriter.WriteFrame(kind, data)
}

func TestAsyncMultiWriterCancellationAbandonsQueuedControl(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, peer := net.Pipe()
		defer peer.Close()
		frw := &recordingFrameRW{
			FrameReadWriter: &PlaintextFrameRW{RW: local},
			started:         make(chan byte, 2),
		}
		multi := NewMultiStream([]FrameReadWriter{frw}, []MultiStreamConn{local})
		defer multi.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Data writes are asynchronous. With no peer reader, this one occupies
		// the sole worker while the following control remains queued.
		if err := multi.WriteSessionFrame(ctx, MsgData, []byte("blocked")); err != nil {
			t.Fatal(err)
		}
		if kind := <-frw.started; kind != MsgData {
			t.Fatalf("started frame = %x, want data", kind)
		}
		result := make(chan error, 1)
		go func() { result <- multi.WriteSessionFrame(ctx, MsgComplete, nil) }()
		synctest.Wait()
		if queued := len(multi.asyncWriter.queues[0]); queued != 1 {
			t.Fatalf("queued writes = %d, want 1", queued)
		}

		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("queued control result = %v, want context cancellation", err)
		}
		if err := multi.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case kind := <-frw.started:
			t.Fatalf("canceled queued frame was written: %x", kind)
		default:
		}
	})
}

func TestAsyncMultiWriterPreservesPhysicalTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, peer := net.Pipe()
		defer peer.Close()
		release := make(chan struct{})
		frw := &delayedAsyncFrameRW{
			FrameReadWriter: &PlaintextFrameRW{RW: local},
			kind:            MsgComplete,
			delivered:       make(chan struct{}),
			release:         release,
		}
		multi := NewMultiStream([]FrameReadWriter{frw}, []MultiStreamConn{local})
		session := NewSession(context.Background(), multi, multi, false)
		defer session.Close()
		const timeout = 2 * time.Second
		session.SetWriteTimeout(timeout)

		written := make(chan error, 1)
		go func() { written <- session.WriteFrame(MsgComplete, nil) }()
		peerFrames := &PlaintextFrameRW{RW: peer}
		if kind, _, err := peerFrames.ReadFrame(); err != nil || kind != MsgComplete {
			t.Fatalf("complete: %x %v", kind, err)
		}
		<-frw.delivered
		time.Sleep(timeout)
		<-session.Context().Done()
		synctest.Wait()
		close(release)
		if err := <-written; err == nil || !strings.Contains(err.Error(), "network write timed out") {
			t.Fatalf("write = %v, want physical timeout", err)
		}
	})
}
