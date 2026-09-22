// SPDX-License-Identifier: MIT

package transfer

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
)

func TestWebRTCReassemblyBounds(t *testing.T) {
	newBounded := func() *reassembler {
		r := newReassembler()
		r.strict, r.maxAhead, r.maxBytes = true, 64, 8*1024*1024
		return r
	}
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		seq  uint64
		size int
	}{
		{"empty", 0, 0}, {"oversize", 0, MaxFrameSize + 1}, {"ahead", 64, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := newBounded().insert(ctx, tc.seq, make([]byte, tc.size)); err == nil {
				t.Fatal("accepted invalid frame")
			}
		})
	}
	r := newBounded()
	for i := uint64(0); i < 16; i++ {
		if err := r.insert(ctx, i, make([]byte, MaxFrameSize)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.insert(ctx, 16, []byte{1}); err == nil {
		t.Fatal("exceeded aggregate byte budget")
	}
	if _, ok := r.tryDeliver(); !ok {
		t.Fatal("missing first frame")
	}
	if err := r.insert(ctx, 16, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := r.insert(ctx, 16, []byte{1}); err == nil {
		t.Fatal("accepted duplicate")
	}
	if err := r.insert(ctx, 0, []byte{1}); err == nil {
		t.Fatal("accepted stale sequence")
	}
}

type loadedConn struct {
	net.Conn
	buffered uint64
}

func (c loadedConn) BufferedAmount() uint64 { return c.buffered }

func TestWebRTCAsyncSchedulingAvoidsCongestedLane(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, peerA := net.Pipe()
		b, peerB := net.Pipe()
		defer peerA.Close()
		defer peerB.Close()
		ms := NewWebRTCMultiStream([]FrameReadWriter{&PlaintextFrameRW{RW: a}, &PlaintextFrameRW{RW: b}},
			[]MultiStreamConn{loadedConn{a, 2 * 1024 * 1024}, loadedConn{b, 0}})
		defer ms.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := ms.WriteSessionFrame(ctx, MsgData, []byte{7}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if ms.asyncWriter.queuedBytes[0].Load() != 0 || ms.asyncWriter.queuedBytes[1].Load() != 9 {
			t.Fatal("did not route the whole chunk to the available lane")
		}
		peer := &PlaintextFrameRW{RW: peerB}
		kind, data, err := peer.ReadFrame()
		if err != nil || kind != MsgData || len(data) != 9 || data[8] != 7 {
			t.Fatalf("frame: %x %x %v", kind, data, err)
		}
		synctest.Wait()
		if ms.asyncWriter.queuedBytes[1].Load() != 0 {
			t.Fatal("completed write retained queue bytes")
		}
	})
}
