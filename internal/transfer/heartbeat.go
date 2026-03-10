// SPDX-License-Identifier: MIT

package transfer

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	// HeartbeatInterval is how often to check peer liveness and send
	// heartbeats during idle periods.
	HeartbeatInterval = 5 * time.Second
	// HeartbeatTimeout is how long to wait for any frame before assuming
	// the peer is gone.
	HeartbeatTimeout = 15 * time.Second
)

// Heartbeat monitors peer liveness by tracking when the last frame was
// received. Call Touch() on every received frame to reset the timeout.
// When the peer is unresponsive for HeartbeatTimeout, the Done channel
// is closed.
//
// Heartbeat does NOT send heartbeat frames itself to avoid concurrent
// writes to the FrameReadWriter. During active transfer, data frames
// serve as implicit heartbeats. During idle periods (e.g. waiting for
// Complete), the caller should call SendHeartbeat() from its own write
// goroutine.
type Heartbeat struct {
	lastRecv atomic.Int64 // unix nanos of last received frame
	stopCh   chan struct{}
	doneCh   chan struct{} // closed when peer timeout detected
	once     sync.Once
}

// StartHeartbeat begins monitoring for peer liveness.
// The returned Heartbeat must be stopped by calling Stop().
func StartHeartbeat() *Heartbeat {
	hb := &Heartbeat{
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	hb.lastRecv.Store(time.Now().UnixNano())
	go hb.watchLoop()
	return hb
}

// Touch records that a frame was received from the peer.
// Call this for every frame read (data, control, heartbeat, etc.).
func (hb *Heartbeat) Touch() {
	hb.lastRecv.Store(time.Now().UnixNano())
}

// Done returns a channel that is closed when the peer is detected as unresponsive.
func (hb *Heartbeat) Done() <-chan struct{} {
	return hb.doneCh
}

// Stop terminates the heartbeat goroutine.
func (hb *Heartbeat) Stop() {
	hb.once.Do(func() { close(hb.stopCh) })
}

func (hb *Heartbeat) watchLoop() {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			last := time.Unix(0, hb.lastRecv.Load())
			if time.Since(last) > HeartbeatTimeout {
				close(hb.doneCh)
				return
			}
		case <-hb.stopCh:
			return
		}
	}
}
