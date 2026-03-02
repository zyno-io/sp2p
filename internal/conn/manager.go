// SPDX-License-Identifier: MIT

package conn

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/zyno-io/sp2p/internal/signal"
)

// P2PConn is the common interface produced by all connection methods.
type P2PConn interface {
	io.ReadWriteCloser
	SetDeadline(t time.Time) error
}

// MethodStatus reports the state of a connection method.
type MethodStatus struct {
	Method string // "WebRTC", "TCP"
	State  string // "trying", "connected", "failed", "skipped"
	Detail string // e.g., "STUN gathering...", "port 48291 mapped"
}

// StatusCallback is called when a connection method changes state.
type StatusCallback func(MethodStatus)

// ConnectConfig holds configuration for establishing a P2P connection.
type ConnectConfig struct {
	SignalClient   *signal.Client
	IsSender       bool
	STUNServers    []string
	TURNServers    []TURNServer
	PeerClientType string         // "cli", "browser", or "" — used to skip TCP for browsers
	DevMode        bool           // when true, allow dialing loopback/link-local addresses
	OnStatus       StatusCallback
	OnLog          func(string) // verbose diagnostic logging (nil = disabled)
}

func logVerbose(f func(string), msg string, args ...any) {
	if f != nil {
		f(fmt.Sprintf(msg, args...))
	}
}

// Establish races multiple connection methods and returns the first to succeed.
func Establish(ctx context.Context, cfg ConnectConfig) (P2PConn, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return establish(attemptCtx, cfg)
}

// establish races multiple connection methods and returns the first to succeed.
// The caller is responsible for setting timeouts on ctx.
func establish(ctx context.Context, cfg ConnectConfig) (P2PConn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		conn   P2PConn
		method string
		err    error
	}

	// Skip TCP when the peer is a browser (browsers can't do raw TCP).
	skipTCP := cfg.PeerClientType == "browser"
	methodCount := 2
	if skipTCP {
		methodCount = 1
		logVerbose(cfg.OnLog, "peer is browser, skipping TCP — WebRTC only (isSender=%v)", cfg.IsSender)
	} else {
		logVerbose(cfg.OnLog, "starting connection race: WebRTC + TCP (isSender=%v)", cfg.IsSender)
	}

	results := make(chan result, methodCount)

	// Method 1: WebRTC (always attempted).
	go func() {
		conn, err := EstablishWebRTC(ctx, cfg.SignalClient, WebRTCConfig{
			STUNServers: cfg.STUNServers,
			TURNServers: cfg.TURNServers,
			IsSender:    cfg.IsSender,
			OnStatus:    cfg.OnStatus,
			OnLog:       cfg.OnLog,
		})
		results <- result{conn: conn, method: "WebRTC", err: err}
	}()

	// Method 2: Symmetric TCP (LAN + UPnP, both sides listen and connect).
	if !skipTCP {
		go func() {
			conn, err := tryTCP(ctx, cfg)
			results <- result{conn: conn, method: "TCP", err: err}
		}()
	} else if cfg.OnStatus != nil {
		cfg.OnStatus(MethodStatus{Method: "TCP", State: "skipped", Detail: "peer is browser"})
	}

	// Collect results — first success wins.
	var firstErr error
	remaining := methodCount

	for remaining > 0 {
		select {
		case r := <-results:
			remaining--
			if r.err == nil && r.conn != nil {
				logVerbose(cfg.OnLog, "%s won the connection race", r.method)
				// Winner! Cancel other attempts and close losers in background.
				cancel()
				go func(n int) {
					for i := 0; i < n; i++ {
						res := <-results
						if res.err == nil && res.conn != nil {
							res.conn.Close()
						}
					}
				}(remaining)
				return r.conn, nil
			}
			if r.err != nil {
				logVerbose(cfg.OnLog, "%s failed: %v", r.method, r.err)
			}
			if firstErr == nil && r.err != nil {
				firstErr = r.err
			}
		case <-ctx.Done():
			// Drain remaining goroutines in background to clean up.
			go func(n int) {
				for i := 0; i < n; i++ {
					res := <-results
					if res.err == nil && res.conn != nil {
						res.conn.Close()
					}
				}
			}(remaining)
			if firstErr != nil {
				return nil, firstErr
			}
			return nil, ctx.Err()
		}
	}

	if firstErr != nil {
		return nil, fmt.Errorf("all connection methods failed: %w", firstErr)
	}
	return nil, fmt.Errorf("could not establish P2P connection")
}

// tcpMagic is the handshake byte exchanged to ensure both peers converge
// on the same TCP connection when both sides dial simultaneously.
const tcpMagic = byte(0x53)

// maxDirectAddrs caps how many peer TCP addresses we'll attempt to dial.
const maxDirectAddrs = 8

// drainRawConns closes any connections buffered in the channel.
func drainRawConns(ch chan net.Conn) {
	for {
		select {
		case c := <-ch:
			c.Close()
		default:
			return
		}
	}
}

// tryTCP implements symmetric TCP connection establishment. Both sides:
// 1. Listen on a random TCP port
// 2. Immediately trickle all LAN addresses via TypeDirect
// 3. In background, attempt UPnP mapping; on success, send external address
// 4. Subscribe to TypeDirect and try connecting to every peer address
// 5. Accept inbound connections on the listener
// 6. Handshake: sender writes magic byte, receiver reads it and acks
// 7. First successfully handshaken connection wins
func tryTCP(ctx context.Context, cfg ConnectConfig) (P2PConn, error) {
	if cfg.OnStatus != nil {
		cfg.OnStatus(MethodStatus{Method: "TCP", State: "trying", Detail: "starting..."})
	}

	// Listen on a random TCP port.
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		reportFailed(cfg.OnStatus, "TCP", err)
		return nil, err
	}

	localPort := ln.Addr().(*net.TCPAddr).Port
	logVerbose(cfg.OnLog, "TCP: listening on port %d", localPort)

	// Subscribe to direct endpoint messages from peer.
	directCh := cfg.SignalClient.Subscribe(signal.TypeDirect)

	// Track cleanup resources.
	var mapping *UPnPMapping
	var mappingMu sync.Mutex
	var cleaned bool

	cleanup := func() {
		ln.Close()
		cfg.SignalClient.Unsubscribe(signal.TypeDirect, directCh)
		mappingMu.Lock()
		cleaned = true
		if mapping != nil {
			mapping.RemoveMapping()
		}
		mappingMu.Unlock()
	}

	// Immediately trickle all LAN addresses.
	localIPs := GetLocalIPs()
	logVerbose(cfg.OnLog, "TCP: local IPs: %v", localIPs)
	for _, ip := range localIPs {
		addr := fmt.Sprintf("%s:%d", ip, localPort)
		if err := cfg.SignalClient.Send(ctx, signal.TypeDirect, signal.DirectEndpoint{TCP: addr}); err != nil {
			logVerbose(cfg.OnLog, "TCP: failed to send LAN address %s: %v", addr, err)
		}
	}

	// Attempt UPnP mapping in background; on success, send external address.
	go func() {
		mappingCtx, cancel := context.WithTimeout(ctx, upnpTimeout)
		defer cancel()

		logVerbose(cfg.OnLog, "TCP: attempting UPnP mapping...")
		m, err := discoverAndMap(mappingCtx, uint16(localPort))
		if err != nil {
			logVerbose(cfg.OnLog, "TCP: UPnP failed: %v", err)
			return
		}
		mappingMu.Lock()
		if cleaned {
			// cleanup() already ran; remove mapping immediately.
			m.RemoveMapping()
			mappingMu.Unlock()
			return
		}
		mapping = m
		mappingMu.Unlock()

		externalAddr := fmt.Sprintf("%s:%d", m.ExternalIP, m.ExternalPort)
		logVerbose(cfg.OnLog, "TCP: UPnP mapped %s", externalAddr)
		if cfg.OnStatus != nil {
			cfg.OnStatus(MethodStatus{Method: "TCP", State: "trying", Detail: "UPnP mapped " + externalAddr})
		}
		if err := cfg.SignalClient.Send(ctx, signal.TypeDirect, signal.DirectEndpoint{TCP: externalAddr}); err != nil {
			logVerbose(cfg.OnLog, "TCP: failed to send UPnP address: %v", err)
		}
	}()

	// Channel for raw TCP connections (before handshake).
	rawConns := make(chan net.Conn, 8)

	// Accept inbound connections.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case rawConns <- c:
			case <-ctx.Done():
				c.Close()
				return
			}
		}
	}()

	// Dial outbound to peer addresses received (capped to avoid abuse).
	go func() {
		dialer := net.Dialer{Timeout: directTimeout}
		seen := make(map[string]struct{})
		for {
			select {
			case env := <-directCh:
				var ep signal.DirectEndpoint
				if err := env.ParsePayload(&ep); err != nil || ep.TCP == "" {
					continue
				}
				if _, dup := seen[ep.TCP]; dup {
					continue
				}
				if len(seen) >= maxDirectAddrs {
					logVerbose(cfg.OnLog, "TCP: ignoring %s (cap reached)", ep.TCP)
					continue
				}
				if !cfg.DevMode && isSensitiveAddr(ep.TCP) {
					logVerbose(cfg.OnLog, "TCP: ignoring %s (loopback/link-local)", ep.TCP)
					continue
				}
				seen[ep.TCP] = struct{}{}
				logVerbose(cfg.OnLog, "TCP: dialing peer at %s", ep.TCP)
				go func(addr string) {
					c, err := dialer.DialContext(ctx, "tcp", addr)
					if err != nil {
						logVerbose(cfg.OnLog, "TCP: dial %s failed: %v", addr, err)
						return
					}
					select {
					case rawConns <- c:
					case <-ctx.Done():
						c.Close()
					}
				}(ep.TCP)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Handshake to ensure both peers converge on the same connection.
	// The sender writes a magic byte and reads an ack; the receiver reads
	// the magic byte and writes an ack. This guarantees both sides use the
	// same physical TCP connection even when both dial simultaneously.
	var winner net.Conn

	if cfg.IsSender {
		// Sender: try connections sequentially — write magic, read ack.
		// Sequential ensures magic is only written to one connection at a time,
		// so the receiver can unambiguously identify the chosen connection.
		for winner == nil {
			select {
			case c := <-rawConns:
				c.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := c.Write([]byte{tcpMagic}); err != nil {
					c.Close()
					continue
				}
				buf := make([]byte, 1)
				if _, err := io.ReadFull(c, buf); err != nil || buf[0] != tcpMagic {
					c.Close()
					continue
				}
				c.SetDeadline(time.Time{})
				winner = c
			case <-ctx.Done():
				reportFailed(cfg.OnStatus, "TCP", ctx.Err())
				cleanup()
				drainRawConns(rawConns)
				return nil, ctx.Err()
			}
		}
	} else {
		// Receiver: try all connections concurrently — read magic, write ack.
		// First connection to receive the sender's magic byte wins.
		winCh := make(chan net.Conn, 1)
		go func() {
			for {
				select {
				case c := <-rawConns:
					go func(c net.Conn) {
						c.SetDeadline(time.Now().Add(5 * time.Second))
						buf := make([]byte, 1)
						if _, err := io.ReadFull(c, buf); err != nil || buf[0] != tcpMagic {
							c.Close()
							return
						}
						if _, err := c.Write([]byte{tcpMagic}); err != nil {
							c.Close()
							return
						}
						c.SetDeadline(time.Time{})
						select {
						case winCh <- c:
						default:
							c.Close()
						}
					}(c)
				case <-ctx.Done():
					return
				}
			}
		}()

		select {
		case c := <-winCh:
			winner = c
		case <-ctx.Done():
			reportFailed(cfg.OnStatus, "TCP", ctx.Err())
			cleanup()
			drainRawConns(rawConns)
			return nil, ctx.Err()
		}
	}

	if cfg.OnStatus != nil {
		cfg.OnStatus(MethodStatus{Method: "TCP", State: "connected"})
	}

	// Close the listener and unsubscribe; keep UPnP mapping alive.
	ln.Close()
	cfg.SignalClient.Unsubscribe(signal.TypeDirect, directCh)

	// Drain any remaining buffered connections in background.
	go func() {
		for {
			select {
			case c := <-rawConns:
				c.Close()
			case <-time.After(time.Second):
				return
			}
		}
	}()

	mappingCleanup := func() {
		mappingMu.Lock()
		if mapping != nil {
			mapping.RemoveMapping()
		}
		mappingMu.Unlock()
	}

	return &netConnAdapter{Conn: winner, onClose: mappingCleanup}, nil
}

// netConnAdapter wraps a net.Conn to implement P2PConn.
type netConnAdapter struct {
	net.Conn
	onClose func()
}

func (n *netConnAdapter) Close() error {
	err := n.Conn.Close()
	if n.onClose != nil {
		n.onClose()
		n.onClose = nil
	}
	return err
}

func (n *netConnAdapter) SetDeadline(t time.Time) error {
	return n.Conn.SetDeadline(t)
}
