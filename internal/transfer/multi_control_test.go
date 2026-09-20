// SPDX-License-Identifier: MIT

package transfer

import "testing"

func TestMultiStreamDrainsControlsOnlyToPendingCapacity(t *testing.T) {
	ms := &MultiStream{
		controlCh:  make(chan controlFrame, maxPendingControls),
		reassembly: newReassembler(),
		readCancel: func() {},
		readDone:   make(chan struct{}),
	}

	// A credit window can leave 15 controls waiting for an application's next
	// ReadFrame. Heartbeat and Complete are both valid following controls. The
	// reader must deliver a pending control before consuming both and exceeding
	// the pending-control bound.
	for range maxPendingControls - 1 {
		ms.pendingControls = append(ms.pendingControls, controlFrame{msgType: MsgCredit})
	}
	ms.controlCh <- controlFrame{msgType: MsgHeartbeat}
	ms.controlCh <- controlFrame{msgType: MsgComplete}

	for i := 0; i < maxPendingControls-1; i++ {
		msgType, _, err := ms.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame credit %d: %v", i, err)
		}
		if msgType != MsgCredit {
			t.Fatalf("credit %d: got 0x%02x, want MsgCredit", i, msgType)
		}
	}

	for _, want := range []byte{MsgHeartbeat, MsgComplete} {
		msgType, _, err := ms.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame control 0x%02x: %v", want, err)
		}
		if msgType != want {
			t.Fatalf("got control 0x%02x, want 0x%02x", msgType, want)
		}
	}

	if err := ms.readErr.Load(); err != nil {
		t.Fatalf("valid control burst set a read error: %v", *err)
	}
}

func TestMultiStreamDrainsFullControlChannelBeforeDelivery(t *testing.T) {
	ms := &MultiStream{
		controlCh:  make(chan controlFrame, maxPendingControls),
		reassembly: newReassembler(),
		readCancel: func() {},
		readDone:   make(chan struct{}),
	}
	for range maxPendingControls {
		ms.controlCh <- controlFrame{msgType: MsgCredit}
	}

	msgType, _, err := ms.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if msgType != MsgCredit {
		t.Fatalf("got 0x%02x, want MsgCredit", msgType)
	}
	if got := len(ms.pendingControls); got != maxPendingControls-1 {
		t.Fatalf("pending controls = %d, want %d after one delivery", got, maxPendingControls-1)
	}
	if got := len(ms.controlCh); got != 0 {
		t.Fatalf("controls left in channel = %d, want 0", got)
	}
}
