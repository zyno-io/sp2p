// SPDX-License-Identifier: MIT

package transfer

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func windowReceiver(t *testing.T, profile uint32) (*Session, *PlaintextFrameRW) {
	t.Helper()
	a, b := net.Pipe()
	s := NewSession(context.Background(), &PlaintextFrameRW{RW: b}, b, false)
	t.Cleanup(func() { s.Close(); a.Close() })
	a.SetDeadline(time.Now().Add(5 * time.Second))
	peer := &PlaintextFrameRW{RW: a}
	if err := WriteMetadata(peer, &Metadata{Name: "file", Size: 8 * 1024 * 1024, ReceiveWindow: profile}); err != nil {
		t.Fatal(err)
	}
	if profile == ReceiveWindowVersion {
		kind, grant, err := peer.ReadFrame()
		if err != nil || kind != MsgReceiveWindow || len(grant) != 12 {
			t.Fatalf("grant: %x %x %v", kind, grant, err)
		}
		if binary.BigEndian.Uint32(grant[0:4]) != 1 || binary.BigEndian.Uint32(grant[4:8]) != 64 || binary.BigEndian.Uint32(grant[8:12]) != 65536 {
			t.Fatalf("invalid grant: %x", grant)
		}
	}
	if kind, _, err := s.ReadFrame(); err != nil || kind != MsgMetadata {
		t.Fatalf("metadata: %x %v", kind, err)
	}
	return s, peer
}

func TestReceiveWindowGrantAndCumulativeCredits(t *testing.T) {
	s, peer := windowReceiver(t, 1)
	for i := 0; i < 64; i++ {
		if err := WriteData(peer, make([]byte, 65536)); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
	}
	if _, _, err := s.ReadFrame(); err != nil {
		t.Fatal(err)
	}
	credited := make(chan error, 1)
	go func() { credited <- s.ConsumeData() }()
	kind, data, err := peer.ReadFrame()
	if err != nil || kind != MsgCredit || len(data) != 8 || binary.BigEndian.Uint64(data) != 1 {
		t.Fatalf("credit: %x %x %v", kind, data, err)
	}
	if err := <-credited; err != nil {
		t.Fatal(err)
	}
	if err := WriteData(peer, []byte{1}); err != nil {
		t.Fatal(err)
	}
	// Reading frames does not acknowledge them; a further send exceeds 64.
	_ = WriteData(peer, []byte{1})
	select {
	case <-s.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("over-credit sender not rejected")
	}
}

func TestReceiveWindowRejectsOversizedData(t *testing.T) {
	s, peer := windowReceiver(t, 1)
	_ = WriteData(peer, make([]byte, 65537))
	select {
	case <-s.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("oversized chunk not rejected")
	}
}

func TestReceiveWindowLegacyAndUnknownProfiles(t *testing.T) {
	for _, profile := range []uint32{0, 2} {
		s, peer := windowReceiver(t, profile)
		for i := 0; i < 17; i++ {
			_ = WriteData(peer, []byte{1})
		}
		select {
		case <-s.Context().Done():
		case <-time.After(time.Second):
			t.Fatalf("profile %d exceeded original credit limit", profile)
		}
	}
}
