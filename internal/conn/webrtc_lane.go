// SPDX-License-Identifier: MIT

package conn

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

// ErrLaneClosed is returned by Wait when the lane closed (self-closed or the
// peer connection failed) before its DataChannel opened. Classification code
// elsewhere matches on this sentinel rather than the message text.
var ErrLaneClosed = fmt.Errorf("WebRTC lane closed during setup")

// LaneTraceEvent is one address-free state transition recorded for an extra
// WebRTC lane: a millisecond offset from the lane's creation (the start of
// its auth phase) and a short event name such as "ice=connected",
// "dtls=connecting", "conn=failed", "dc=open", or "close=budget_exceeded".
// Never includes IPs, ports, ICE ufrags/pwds, or SDP.
type LaneTraceEvent struct {
	MS    int64  `json:"ms"`
	Event string `json:"event"`
}

// WebRTCLane is an untrusted candidate until the caller authenticates it with
// session- and lane-specific keys. Its SDP is exchanged over the authenticated
// primary, never through the signaling server. Reuse only the primary's ICE
// configuration so opening extra lanes cannot implicitly authorize TURN.
type WebRTCLane struct {
	Conn  *WebRTCConn
	ready chan struct{}

	start   time.Time
	traceMu sync.Mutex
	trace   []LaneTraceEvent
}

// record appends an address-free trace event with its offset from the
// lane's creation. Safe to call from any pion callback goroutine.
func (l *WebRTCLane) record(event string) {
	l.traceMu.Lock()
	l.trace = append(l.trace, LaneTraceEvent{MS: time.Since(l.start).Milliseconds(), Event: event})
	l.traceMu.Unlock()
}

// closeSelf records why this lane is closing itself (never the peer's
// choice) and closes it. reason is one of a small fixed vocabulary:
// "label_rejected", "budget_exceeded", or "peer_connection_failed".
func (l *WebRTCLane) closeSelf(reason string) {
	l.record("close=" + reason)
	go l.Conn.Close()
}

// Trace returns the lane's address-free state trace recorded so far:
// connection, ICE, and DTLS transport transitions, DataChannel open/close,
// and — if the lane closed itself — why. Never includes IPs, ports, ICE
// ufrags/pwds, or SDP.
func (l *WebRTCLane) Trace() []LaneTraceEvent {
	l.traceMu.Lock()
	defer l.traceMu.Unlock()
	out := make([]LaneTraceEvent, len(l.trace))
	copy(out, l.trace)
	return out
}

// PairTypes returns the selected ICE candidate pair's types only, e.g.
// "host/prflx" (local/remote) — never addresses, ports, or ufrags. Empty if
// no pair has been selected yet.
func (l *WebRTCLane) PairTypes() string {
	sctp := l.Conn.pc.SCTP()
	if sctp == nil {
		return ""
	}
	dtls := sctp.Transport()
	if dtls == nil {
		return ""
	}
	ice := dtls.ICETransport()
	if ice == nil {
		return ""
	}
	pair, err := ice.GetSelectedCandidatePair()
	if err != nil || pair == nil || pair.Local == nil || pair.Remote == nil {
		return ""
	}
	return pair.Local.Typ.String() + "/" + pair.Remote.Typ.String()
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
	lane := &WebRTCLane{Conn: c, ready: make(chan struct{}), start: time.Now()}

	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		lane.record("ice=" + state.String())
	})
	if dtls := pc.SCTP().Transport(); dtls != nil {
		dtls.OnStateChange(func(state webrtc.DTLSTransportState) {
			lane.record("dtls=" + state.String())
		})
	}

	var once sync.Once
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		lane.record("conn=" + state.String())
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			lane.closeSelf("peer_connection_failed")
		}
	})
	if sender {
		dc, err := pc.CreateDataChannel(dataChannelLabel, nil)
		if err != nil {
			pc.Close()
			return nil, err
		}
		c.setDataChannel(dc)
		setupDataChannel(dc, c, lane.ready, &once, lane.record)
	} else {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			if dc.Label() != dataChannelLabel || !dc.Ordered() || dc.MaxRetransmits() != nil || dc.MaxPacketLifeTime() != nil {
				lane.closeSelf("label_rejected")
				return
			}
			// Exactly one channel is permitted per independent connection.
			if !c.setDataChannel(dc) {
				lane.closeSelf("label_rejected")
				return
			}
			setupDataChannel(dc, c, lane.ready, &once, lane.record)
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
		return ErrLaneClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}
