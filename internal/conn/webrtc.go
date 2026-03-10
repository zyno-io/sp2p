// SPDX-License-Identifier: MIT

package conn

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"

	"github.com/zyno-io/sp2p/internal/signal"
)

const (
	dataChannelLabel  = "sp2p"
	dataChannelBuffer = 64 * 1024 * 1024  // 64 MB buffered amount
	sctpMaxMsgSize    = 256 * 1024        // 256 KiB SCTP message size — browser DataChannels typically cap at 256 KiB
)

// WebRTCConfig holds configuration for WebRTC connections.
type WebRTCConfig struct {
	STUNServers    []string
	TURNServers    []TURNServer
	IsSender       bool
	PeerClientType string // "cli", "browser", or "" — used to disable features incompatible with browsers
	OnStatus       StatusCallback
	OnLog          func(string)
}

// TURNServer describes a TURN relay server with credentials.
type TURNServer struct {
	URLs       []string
	Username   string
	Credential string
}

// DefaultSTUNServers returns common public STUN servers.
func DefaultSTUNServers() []string {
	return []string{
		"stun:stun.l.google.com:19302",
		"stun:stun1.l.google.com:19302",
	}
}

// WebRTCConn wraps a WebRTC DataChannel as a P2PConn.
type WebRTCConn struct {
	pc *webrtc.PeerConnection
	dc *webrtc.DataChannel

	readBuf  chan []byte
	readLeft []byte
	readMu   sync.Mutex

	writeMu       sync.Mutex
	flowMu        sync.Mutex
	flowCond      *sync.Cond
	closed        chan struct{}
	closeOnce     sync.Once
	deadlineMu    sync.Mutex
	deadlineTimer *time.Timer
}

// EstablishWebRTC creates a WebRTC connection using the signaling client.
// It handles SDP offer/answer exchange and ICE candidate gathering.
func EstablishWebRTC(ctx context.Context, sigClient *signal.Client, cfg WebRTCConfig) (*WebRTCConn, error) {
	if cfg.OnStatus != nil {
		cfg.OnStatus(MethodStatus{Method: "WebRTC", State: "trying", Detail: "STUN gathering..."})
	}
	logVerbose(cfg.OnLog, "WebRTC: %d STUN servers, %d TURN servers", len(cfg.STUNServers), len(cfg.TURNServers))

	iceServers := make([]webrtc.ICEServer, 0, len(cfg.STUNServers)+len(cfg.TURNServers))
	for _, s := range cfg.STUNServers {
		iceServers = append(iceServers, webrtc.ICEServer{URLs: []string{s}})
	}
	for _, t := range cfg.TURNServers {
		iceServers = append(iceServers, webrtc.ICEServer{
			URLs:           t.URLs,
			Username:       t.Username,
			Credential:     t.Credential,
			CredentialType: webrtc.ICECredentialTypePassword,
		})
	}

	// Tune the SCTP transport for high-throughput bulk transfers.
	se := webrtc.SettingEngine{}
	se.SetSCTPMaxMessageSize(sctpMaxMsgSize)
	// Increase the receive buffer from the 1 MB default so the receiver
	// can advertise a larger window, preventing the sender's congestion
	// window from being capped by the receiver's RWND.
	se.SetSCTPMaxReceiveBufferSize(8 * 1024 * 1024) // 8 MB
	// Skip SCTP checksums — DTLS already provides integrity, so the
	// per-packet CRC32c is redundant overhead. Only enable for CLI↔CLI
	// connections; browsers may not support RFC 8261 zero-checksum.
	if cfg.PeerClientType != "browser" {
		se.EnableSCTPZeroChecksum(true)
	}
	api := webrtc.NewAPI(webrtc.WithSettingEngine(se))

	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: iceServers,
	})
	if err != nil {
		reportFailed(cfg.OnStatus, "WebRTC", err)
		return nil, fmt.Errorf("creating peer connection: %w", err)
	}

	conn := &WebRTCConn{
		pc:      pc,
		readBuf: make(chan []byte, 256),
		closed:  make(chan struct{}),
	}
	conn.flowCond = sync.NewCond(&conn.flowMu)

	// Close the connection when the peer disconnects (e.g. browser tab closed).
	// Run in a goroutine to avoid deadlocking pion's internal locks.
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		logVerbose(cfg.OnLog, "WebRTC: connection state → %s", state.String())
		switch state {
		case webrtc.PeerConnectionStateDisconnected,
			webrtc.PeerConnectionStateFailed,
			webrtc.PeerConnectionStateClosed:
			go conn.Close()
		}
	})

	// Set up ICE candidate sending (trickle ICE — best-effort since
	// the full SDP already includes gathered candidates).
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		logVerbose(cfg.OnLog, "WebRTC: local ICE candidate: %s %s", c.Typ.String(), c.Address)
		init := c.ToJSON()
		if err := sigClient.Send(ctx, signal.TypeCandidate, signal.Candidate{
			Candidate:     init.Candidate,
			SDPMid:        deref(init.SDPMid),
			SDPMLineIndex: derefU16(init.SDPMLineIndex),
		}); err != nil {
			log.Printf("warning: failed to send ICE candidate: %v", err)
		}
	})

	dcReady := make(chan struct{})
	var dcOnce sync.Once

	if cfg.IsSender {
		// Sender creates the data channel and offer.
		dc, err := pc.CreateDataChannel(dataChannelLabel, nil)
		if err != nil {
			pc.Close()
			reportFailed(cfg.OnStatus, "WebRTC", err)
			return nil, fmt.Errorf("creating data channel: %w", err)
		}
		conn.dc = dc
		setupDataChannel(dc, conn, dcReady, &dcOnce)

		offer, err := pc.CreateOffer(nil)
		if err != nil {
			pc.Close()
			reportFailed(cfg.OnStatus, "WebRTC", err)
			return nil, fmt.Errorf("creating offer: %w", err)
		}
		if err := pc.SetLocalDescription(offer); err != nil {
			pc.Close()
			reportFailed(cfg.OnStatus, "WebRTC", err)
			return nil, fmt.Errorf("setting local description: %w", err)
		}

		// Wait for ICE gathering to complete for a more complete SDP.
		gatherDone := webrtc.GatheringCompletePromise(pc)
		select {
		case <-gatherDone:
		case <-ctx.Done():
			pc.Close()
			return nil, ctx.Err()
		}

		// Send the offer with ICE candidates included.
		localDesc := pc.LocalDescription()
		logVerbose(cfg.OnLog, "WebRTC: sending SDP offer:\n%s", localDesc.SDP)
		if err := sigClient.Send(ctx, signal.TypeOffer, signal.SDP{
			SDP:  localDesc.SDP,
			Type: localDesc.Type.String(),
		}); err != nil {
			pc.Close()
			reportFailed(cfg.OnStatus, "WebRTC", err)
			return nil, fmt.Errorf("sending offer: %w", err)
		}
	} else {
		// Receiver waits for data channel.
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			conn.dc = dc
			setupDataChannel(dc, conn, dcReady, &dcOnce)
		})
	}

	// Process signaling messages for SDP and ICE.
	// Pass dcReady so the receiver can also exit when the data channel opens
	// directly, in case the peer's "connected" signal fails to arrive.
	if err := processSignaling(ctx, sigClient, pc, cfg.IsSender, dcReady, cfg.OnLog); err != nil {
		pc.Close()
		reportFailed(cfg.OnStatus, "WebRTC", err)
		return nil, err
	}

	// Wait for data channel to open.
	select {
	case <-dcReady:
	case <-ctx.Done():
		pc.Close()
		return nil, ctx.Err()
	}

	// Log the selected ICE candidate pair so verbose output shows
	// whether the connection is direct (host/srflx) or relayed (relay).
	if pair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair(); err == nil && pair != nil {
		logVerbose(cfg.OnLog, "WebRTC: selected candidate pair: local %s %s:%d ↔ remote %s %s:%d",
			pair.Local.Typ.String(), pair.Local.Address, pair.Local.Port,
			pair.Remote.Typ.String(), pair.Remote.Address, pair.Remote.Port)
	}

	if cfg.OnStatus != nil {
		cfg.OnStatus(MethodStatus{Method: "WebRTC", State: "connected"})
	}

	// Signal connected via signaling server (best-effort — the data channel
	// is already open, and the receiver also watches dcReady as a fallback).
	if err := sigClient.Send(ctx, signal.TypeConnected, signal.Connected{}); err != nil {
		log.Printf("warning: failed to send connected signal: %v", err)
	}

	return conn, nil
}

func processSignaling(ctx context.Context, sigClient *signal.Client, pc *webrtc.PeerConnection, isSender bool, dcReady <-chan struct{}, onLog func(string)) error {
	for {
		select {
		case env := <-sigClient.Incoming:
			if env == nil {
				return fmt.Errorf("signaling connection lost")
			}
			switch env.Type {
			case signal.TypeOffer:
				if isSender {
					continue // sender shouldn't get offers
				}
				var sdp signal.SDP
				if err := env.ParsePayload(&sdp); err != nil {
					return fmt.Errorf("parsing offer: %w", err)
				}
				logVerbose(onLog, "WebRTC: received SDP offer:\n%s", sdp.SDP)
				if err := pc.SetRemoteDescription(webrtc.SessionDescription{
					Type: webrtc.SDPTypeOffer,
					SDP:  sdp.SDP,
				}); err != nil {
					return fmt.Errorf("setting remote offer: %w", err)
				}

				answer, err := pc.CreateAnswer(nil)
				if err != nil {
					return fmt.Errorf("creating answer: %w", err)
				}
				if err := pc.SetLocalDescription(answer); err != nil {
					return fmt.Errorf("setting local description: %w", err)
				}

				// Wait for ICE gathering.
				gatherDone := webrtc.GatheringCompletePromise(pc)
				select {
				case <-gatherDone:
				case <-ctx.Done():
					return ctx.Err()
				}

				localDesc := pc.LocalDescription()
				logVerbose(onLog, "WebRTC: sending SDP answer:\n%s", localDesc.SDP)
				if err := sigClient.Send(ctx, signal.TypeAnswer, signal.SDP{
					SDP:  localDesc.SDP,
					Type: localDesc.Type.String(),
				}); err != nil {
					return fmt.Errorf("sending answer: %w", err)
				}

			case signal.TypeAnswer:
				if !isSender {
					continue
				}
				var sdp signal.SDP
				if err := env.ParsePayload(&sdp); err != nil {
					return fmt.Errorf("parsing answer: %w", err)
				}
				logVerbose(onLog, "WebRTC: received SDP answer:\n%s", sdp.SDP)
				if err := pc.SetRemoteDescription(webrtc.SessionDescription{
					Type: webrtc.SDPTypeAnswer,
					SDP:  sdp.SDP,
				}); err != nil {
					return fmt.Errorf("setting remote answer: %w", err)
				}
				return nil // SDP exchange complete for sender

			case signal.TypeCandidate:
				var cand signal.Candidate
				if err := env.ParsePayload(&cand); err != nil {
					continue
				}
				logVerbose(onLog, "WebRTC: received remote ICE candidate: %s", cand.Candidate)
				sdpMid := cand.SDPMid
				sdpMLineIndex := cand.SDPMLineIndex
				pc.AddICECandidate(webrtc.ICECandidateInit{
					Candidate:     cand.Candidate,
					SDPMid:        &sdpMid,
					SDPMLineIndex: &sdpMLineIndex,
				})

			case signal.TypeConnected:
				if !isSender {
					return nil // receiver done after peer signals connected
				}

			case signal.TypePeerLeft:
				return fmt.Errorf("peer disconnected")

			case signal.TypeError:
				var errMsg signal.Error
				env.ParsePayload(&errMsg)
				return fmt.Errorf("signaling error: %s", errMsg.Message)
			}

		case <-dcReady:
			// Data channel opened directly — no need to wait for "connected" signal.
			// This handles the case where the peer's connected signal fails to arrive.
			if !isSender {
				return nil
			}

		case <-sigClient.Done():
			return fmt.Errorf("signaling connection closed")

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func setupDataChannel(dc *webrtc.DataChannel, conn *WebRTCConn, ready chan struct{}, closeOnce *sync.Once) {
	dc.SetBufferedAmountLowThreshold(dataChannelBuffer / 2)

	dc.OnBufferedAmountLow(func() {
		conn.flowCond.Broadcast()
	})

	dc.OnOpen(func() {
		closeOnce.Do(func() { close(ready) })
	})

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		data := make([]byte, len(msg.Data))
		copy(data, msg.Data)
		select {
		case conn.readBuf <- data:
		case <-conn.closed:
		}
	})

	dc.OnClose(func() {
		conn.closeOnce.Do(func() {
			close(conn.closed)
			conn.flowCond.Broadcast()
		})
	})
}

func (c *WebRTCConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Drain leftover from previous read.
	if len(c.readLeft) > 0 {
		n := copy(p, c.readLeft)
		c.readLeft = c.readLeft[n:]
		return n, nil
	}

	// Prioritize draining buffered data so that a closed channel
	// doesn't cause us to return EOF while data remains.
	select {
	case data := <-c.readBuf:
		n := copy(p, data)
		if n < len(data) {
			c.readLeft = data[n:]
		}
		return n, nil
	default:
	}

	// No data immediately available; block until data or close.
	select {
	case data := <-c.readBuf:
		n := copy(p, data)
		if n < len(data) {
			c.readLeft = data[n:]
		}
		return n, nil
	case <-c.closed:
		// One final drain attempt.
		select {
		case data := <-c.readBuf:
			n := copy(p, data)
			if n < len(data) {
				c.readLeft = data[n:]
			}
			return n, nil
		default:
			return 0, io.EOF
		}
	}
}

// BufferedAmount returns the number of bytes queued in the DataChannel's
// send buffer that have not yet been transmitted to the peer.
func (c *WebRTCConn) BufferedAmount() uint64 {
	return c.dc.BufferedAmount()
}

func (c *WebRTCConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// WebRTC DataChannel has a max message size. Send in chunks.
	const maxMsg = sctpMaxMsgSize
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxMsg {
			chunk = p[:maxMsg]
		}

		// Wait until the DataChannel buffer drains below the threshold
		// to avoid unbounded memory growth.
		c.flowMu.Lock()
		for c.dc.BufferedAmount() > uint64(dataChannelBuffer) {
			select {
			case <-c.closed:
				c.flowMu.Unlock()
				return total, io.ErrClosedPipe
			default:
			}
			c.flowCond.Wait()
		}
		c.flowMu.Unlock()

		if err := c.dc.Send(chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *WebRTCConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.flowCond.Broadcast()
	})
	if c.dc != nil {
		c.dc.Close()
	}
	return c.pc.Close()
}

func (c *WebRTCConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	if c.deadlineTimer != nil {
		c.deadlineTimer.Stop()
		c.deadlineTimer = nil
	}

	if t.IsZero() {
		return nil
	}

	d := time.Until(t)
	if d <= 0 {
		c.Close()
		return nil
	}

	c.deadlineTimer = time.AfterFunc(d, func() {
		c.Close()
	})
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefU16(v *uint16) uint16 {
	if v == nil {
		return 0
	}
	return *v
}

func reportFailed(cb StatusCallback, method string, err error) {
	if cb != nil {
		cb(MethodStatus{Method: method, State: "failed", Detail: err.Error()})
	}
}
