// SPDX-License-Identifier: MIT

package conn

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

// WebRTCLane is an untrusted candidate until the caller authenticates it with
// session- and lane-specific keys. Its SDP is exchanged over the authenticated
// primary, never through the signaling server. Reuse only the primary's ICE
// configuration so opening extra lanes cannot implicitly authorize TURN.
type WebRTCLane struct {
	Conn  *WebRTCConn
	ready chan struct{}
}

func (primary *WebRTCConn) NewLane(sender bool) (*WebRTCLane, error) {
	if !primary.receiveBudget.enableParallel() {
		return nil, fmt.Errorf("primary input exceeds parallel receive budget")
	}
	se := webrtc.SettingEngine{}
	se.SetSCTPMaxMessageSize(sctpMaxMsgSize)
	se.SetSCTPMaxReceiveBufferSize(2 * 1024 * 1024)
	pc, err := newOfferPeerConnection(se, primary.pc.GetConfiguration(), primary.browserPeer, sender)
	if err != nil {
		return nil, fmt.Errorf("creating WebRTC lane: %w", err)
	}
	c := &WebRTCConn{pc: pc, readBuf: make(chan []byte, 256), closed: make(chan struct{}), receiveBudget: primary.receiveBudget, browserPeer: primary.browserPeer}
	c.flowCond = sync.NewCond(&c.flowMu)
	lane := &WebRTCLane{Conn: c, ready: make(chan struct{})}
	var once sync.Once
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			go c.Close()
		}
	})
	if sender {
		dc, err := pc.CreateDataChannel(dataChannelLabel, nil)
		if err != nil {
			pc.Close()
			return nil, err
		}
		c.setDataChannel(dc)
		setupDataChannel(dc, c, lane.ready, &once)
	} else {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			if dc.Label() != dataChannelLabel || !dc.Ordered() || dc.MaxRetransmits() != nil || dc.MaxPacketLifeTime() != nil {
				go c.Close()
				return
			}
			// Exactly one channel is permitted per independent connection.
			if !c.setDataChannel(dc) {
				go c.Close()
				return
			}
			setupDataChannel(dc, c, lane.ready, &once)
		})
	}
	return lane, nil
}

func (c *WebRTCConn) dataChannel() *webrtc.DataChannel {
	c.dcMu.RLock()
	defer c.dcMu.RUnlock()
	return c.dc
}

func (c *WebRTCConn) setDataChannel(dc *webrtc.DataChannel) bool {
	c.dcMu.Lock()
	defer c.dcMu.Unlock()
	if c.dc != nil {
		return false
	}
	c.dc = dc
	return true
}

// DiscardSetupInput is called only after lane setup readers have been joined
// and the unused connection closed. Do not use it for live/terminal transfer
// reads, which must still drain a buffered Complete after peer EOF.
func (c *WebRTCConn) DiscardSetupInput() {
	c.enqueueMu.Lock()
	defer c.enqueueMu.Unlock()
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.readLeft) > 0 {
		c.receiveBudget.release(len(c.readLeft), true)
		c.readLeft = nil
	}
	for {
		select {
		case data := <-c.readBuf:
			c.receiveBudget.release(len(data), true)
		default:
			return
		}
	}
}

// A single raw receive budget is shared by the primary and every extra lane.
// Lane-local SCTP buffers are additionally bounded by Pion; decoded frames use
// the multiplexer/Session's separate aggregate reassembly and credit limits.
type webRTCReceiveBudget struct {
	mu              sync.Mutex
	bytes, messages int
	parallel        bool
}

// Legacy v2 has no receiver credits: preserve its existing bounded-channel
// backpressure instead of disconnecting a valid sender when the sink pauses.
// Switch to the shared fail-closed budget only for opted-in v3 lane setup.
func (b *webRTCReceiveBudget) enableParallel() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.bytes > 8*1024*1024 || b.messages > 256 {
		return false
	}
	b.parallel = true
	return true
}

func (b *webRTCReceiveBudget) reserve(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.parallel && (n > 8*1024*1024-b.bytes || b.messages >= 256) {
		return false
	}
	b.bytes += n
	b.messages++
	return true
}
func (b *webRTCReceiveBudget) release(n int, complete bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bytes -= n
	if complete {
		b.messages--
	}
}

func (l *WebRTCLane) Description(ctx context.Context, offer bool) (string, error) {
	var desc webrtc.SessionDescription
	var err error
	if offer {
		desc, err = l.Conn.pc.CreateOffer(nil)
	} else {
		desc, err = l.Conn.pc.CreateAnswer(nil)
	}
	if err != nil {
		return "", err
	}
	complete := webrtc.GatheringCompletePromise(l.Conn.pc)
	if err = l.Conn.pc.SetLocalDescription(desc); err != nil {
		return "", err
	}
	// Include the candidates gathered so far even if a STUN service is slow.
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case <-complete:
	case <-timer.C:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	return l.Conn.pc.LocalDescription().SDP, nil
}

func (l *WebRTCLane) SetDescription(sdp string, offer bool) error {
	if len(sdp) == 0 || len(sdp) > 12*1024 {
		return fmt.Errorf("invalid WebRTC lane SDP size")
	}
	kind := webrtc.SDPTypeAnswer
	if offer {
		kind = webrtc.SDPTypeOffer
	}
	return l.Conn.pc.SetRemoteDescription(webrtc.SessionDescription{Type: kind, SDP: sdp})
}

func (l *WebRTCLane) Wait(ctx context.Context) error {
	select {
	case <-l.ready:
		return nil
	case <-l.Conn.closed:
		return fmt.Errorf("WebRTC lane closed during setup")
	case <-ctx.Done():
		return ctx.Err()
	}
}
