// SPDX-License-Identifier: MIT

package conn

import "testing"

func TestWebRTCReceiveBudgetIsAggregate(t *testing.T) {
	b := &webRTCReceiveBudget{parallel: true}
	if !b.reserve(4*1024*1024) || !b.reserve(4*1024*1024) {
		t.Fatal("valid bounded allocation rejected")
	}
	if b.reserve(1) {
		t.Fatal("exceeded shared byte limit")
	}
	b.release(4*1024*1024, true)
	if !b.reserve(1) {
		t.Fatal("consumption did not release capacity")
	}
	b.release(1, true)
	b.release(4*1024*1024, true)
	for range 256 {
		if !b.reserve(1) {
			t.Fatal("valid frame count rejected")
		}
	}
	if b.reserve(1) {
		t.Fatal("exceeded shared frame limit")
	}
	for range 256 {
		b.release(1, true)
	}
	if b.bytes != 0 || b.messages != 0 {
		t.Fatal("budget leaked")
	}
}

func TestSingleWebRTCPreservesChannelBackpressureUntilParallelSetup(t *testing.T) {
	b := &webRTCReceiveBudget{}
	// A single pre-existing channel, not this accounting object, applies the
	// original 256-message queue backpressure to uncredited legacy senders.
	if !b.reserve(9 * 1024 * 1024) {
		t.Fatal("changed legacy backpressure")
	}
	if b.enableParallel() {
		t.Fatal("enabled lanes over the shared limit")
	}
	b.release(9*1024*1024, true)
	if !b.enableParallel() {
		t.Fatal("could not enable empty shared budget")
	}
	if b.reserve(9 * 1024 * 1024) {
		t.Fatal("parallel bound not enforced")
	}
}

func TestDiscardUnusedWebRTCLaneReleasesSharedBudget(t *testing.T) {
	b := &webRTCReceiveBudget{}
	c := &WebRTCConn{readBuf: make(chan []byte, 2), closed: make(chan struct{}), receiveBudget: b}
	b.reserve(5)
	c.readBuf <- []byte("hello")
	b.reserve(5)
	c.readBuf <- []byte("world")
	var first [2]byte
	if n, err := c.Read(first[:]); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	close(c.closed)
	c.DiscardSetupInput()
	if b.bytes != 0 || b.messages != 0 || len(c.readLeft) != 0 {
		t.Fatal("unused lane retained receive budget")
	}
}
