// SPDX-License-Identifier: MIT

package transfer

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestBufferedMetadataPrecedesData(t *testing.T) {
	r := newReassembler()
	if err := r.insert(context.Background(), 0, []byte("data")); err != nil {
		t.Fatal(err)
	}
	ms := &MultiStream{reassembly: r, controlCh: make(chan controlFrame, 2)}
	ms.controlCh <- controlFrame{msgType: MsgMetadata, data: []byte(`{"name":"file"}`)}
	ms.ExpectMetadata()
	typ, _, err := ms.ReadFrame()
	if err != nil || typ != MsgMetadata {
		t.Fatalf("first read: %x, %v", typ, err)
	}
	typ, data, err := ms.ReadFrame()
	if err != nil || typ != MsgData || string(data) != "data" {
		t.Fatalf("data: %x %q %v", typ, data, err)
	}
}

func TestReassemblyRejectsStaleAndDuplicate(t *testing.T) {
	r := newReassembler()
	ctx := context.Background()
	if err := r.insert(ctx, 0, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := r.insert(ctx, 0, []byte("x")); err == nil {
		t.Fatal("accepted duplicate")
	}
	r.tryDeliver()
	if err := r.insert(ctx, 0, []byte("x")); err == nil {
		t.Fatal("accepted stale sequence")
	}
	if r.bytes != 0 || len(r.buffer) != 0 {
		t.Fatal("retained consumed data")
	}
}

func TestReceiverFinalizeFailurePreventsComplete(t *testing.T) {
	a, b := newMockFrameRWPair()
	defer a.Close()
	defer b.Close()
	WriteMetadata(a, &Metadata{Name: "empty"})
	WriteDone(a, &Done{SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"})
	recv := NewReceiver(b)
	failure := errors.New("disk full")
	recv.Finalize = func() error { return failure }
	_, err := recv.Receive(context.Background(), io.Discard, nil)
	if !errors.Is(err, failure) {
		t.Fatalf("lost finalization error: %v", err)
	}
	typ, _, err := a.ReadFrame()
	if err != nil || typ != MsgError {
		t.Fatalf("expected error, got %x %v", typ, err)
	}
}

func TestOversizedZstdHeaderRejectedBeforeDecode(t *testing.T) {
	a, b := newMockFrameRWPair()
	defer a.Close()
	defer b.Close()
	WriteMetadata(a, &Metadata{Name: "bomb", Compression: "zstd"})
	// Single-segment frame advertising 8 GiB, but containing no data blocks.
	header := []byte{0x28, 0xb5, 0x2f, 0xfd, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint64(header[5:], 8<<30)
	WriteData(a, header)
	_, err := NewReceiver(b).Receive(context.Background(), io.Discard, nil)
	if err == nil {
		t.Fatal("accepted oversized frame")
	}
}

func TestEmptyMetadataRejectsData(t *testing.T) {
	a, b := newMockFrameRWPair()
	defer a.Close()
	defer b.Close()
	WriteMetadata(a, &Metadata{Name: "empty", Size: 0})
	WriteData(a, []byte("not empty"))
	_, err := NewReceiver(b).Receive(context.Background(), io.Discard, nil)
	if err == nil {
		t.Fatal("accepted data for a declared empty file")
	}
}
