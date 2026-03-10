// SPDX-License-Identifier: MIT

package conn

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"time"
)

// secondaryMagic distinguishes secondary connection handshakes from stale
// primary connection attempts.
const secondaryMagic = byte(0x54)

// SecondaryConfig holds configuration for establishing secondary parallel
// TCP connections after the primary connection has been established.
type SecondaryConfig struct {
	Count         int            // N-1 additional connections needed
	WeDialed      bool           // our role: true = we dial again, false = we accept
	Listener      net.Listener   // non-nil if we're accepting (acceptor side)
	PeerAddr      string         // non-empty if we're dialing (dialer side)
	Token         [16]byte       // HKDF-derived session token for authentication
	Timeout       time.Duration  // deadline for all secondary connections (5s default)
	AcceptStopped <-chan struct{} // wait for primary accept goroutine to exit before accepting
	OnLog         func(string)   // verbose logging (nil = disabled)
}

// EstablishSecondary opens count additional TCP connections using the same
// role (dialer/acceptor) as the primary. Each secondary is authenticated
// with a token + stream index handshake. Returns however many connections
// succeed (graceful degradation). The returned slice may be shorter than
// count if some connections fail.
func EstablishSecondary(ctx context.Context, cfg SecondaryConfig) ([]P2PConn, error) {
	if cfg.Count <= 0 {
		return nil, nil
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	deadline := time.Now().Add(cfg.Timeout)
	connCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	type indexedConn struct {
		index int
		conn  P2PConn
	}

	results := make(chan indexedConn, cfg.Count)
	errors := make(chan error, cfg.Count)

	if cfg.WeDialed {
		// Dialer: redial the same peer address for each secondary connection.
		for i := 0; i < cfg.Count; i++ {
			go func(streamIndex int) {
				c, err := dialSecondary(connCtx, cfg.PeerAddr, cfg.Token, byte(streamIndex+1), deadline)
				if err != nil {
					logVerbose(cfg.OnLog, "secondary dial %d failed: %v", streamIndex+1, err)
					errors <- err
					return
				}
				results <- indexedConn{index: streamIndex, conn: c}
			}(i)
		}
	} else {
		// Wait for the primary accept goroutine to exit before we start
		// accepting, so it can't steal our secondary connections.
		if cfg.AcceptStopped != nil {
			select {
			case <-cfg.AcceptStopped:
			case <-connCtx.Done():
				return nil, connCtx.Err()
			}
		}
		// Set a deadline on the listener for our secondary accepts.
		if dl, ok := cfg.Listener.(interface{ SetDeadline(time.Time) error }); ok {
			dl.SetDeadline(deadline)
		}
		// Acceptor: accept connections on the existing listener.
		// Each goroutine loops to retry after rejecting invalid connections
		// (e.g., stale primary dial attempts) so they don't consume an
		// accept slot permanently.
		for i := 0; i < cfg.Count; i++ {
			go func() {
				for {
					c, streamIndex, err := acceptSecondary(connCtx, cfg.Listener, cfg.Token, deadline)
					if err != nil {
						// Check if we timed out or context was cancelled.
						if connCtx.Err() != nil || time.Now().After(deadline) {
							logVerbose(cfg.OnLog, "secondary accept timed out: %v", err)
							errors <- err
							return
						}
						// Invalid handshake (stale connection) — retry.
						logVerbose(cfg.OnLog, "secondary accept rejected (retrying): %v", err)
						continue
					}
					// Stream index is 1-based on the wire (dialer sends streamIndex+1),
					// so subtract 1 to get the 0-based slot index.
					idx := int(streamIndex) - 1
					if idx < 0 || idx >= cfg.Count {
						logVerbose(cfg.OnLog, "secondary accept: stream index %d out of range [1,%d]", streamIndex, cfg.Count)
						c.Close()
						continue
					}
					results <- indexedConn{index: idx, conn: c}
					return
				}
			}()
		}
	}

	// Collect results, allowing partial success.
	conns := make([]P2PConn, cfg.Count)
	succeeded := 0
	for i := 0; i < cfg.Count; i++ {
		select {
		case r := <-results:
			if r.index >= 0 && r.index < cfg.Count {
				if conns[r.index] != nil {
					// Duplicate index — close the newer connection.
					logVerbose(cfg.OnLog, "secondary connection %d: duplicate index, closing", r.index+1)
					r.conn.Close()
				} else {
					conns[r.index] = r.conn
					succeeded++
					logVerbose(cfg.OnLog, "secondary connection %d established", r.index+1)
				}
			} else {
				r.conn.Close()
			}
		case <-errors:
			// Continue collecting — partial success is OK.
		case <-connCtx.Done():
			// Timeout reached — use whatever we have.
			i = cfg.Count // break out of loop
		}
	}

	// Drain any remaining results that arrived after the collector loop
	// exited (e.g. due to timeout). Without this, connections that
	// completed concurrently with the deadline would leak.
	for {
		select {
		case r := <-results:
			if r.index >= 0 && r.index < cfg.Count && conns[r.index] == nil {
				conns[r.index] = r.conn
				succeeded++
			} else {
				r.conn.Close()
			}
		default:
			goto drained
		}
	}
drained:

	if succeeded == 0 {
		return nil, fmt.Errorf("no secondary connections established")
	}

	// Filter to only successfully connected streams (maintain index order).
	live := make([]P2PConn, 0, succeeded)
	for _, c := range conns {
		if c != nil {
			live = append(live, c)
		}
	}

	logVerbose(cfg.OnLog, "established %d/%d secondary TCP connections", len(live), cfg.Count)
	return live, nil
}

// dialSecondary dials the peer and performs the secondary handshake.
// Handshake: write [0x54][16-byte token][1-byte stream index], read [0x54] ack.
func dialSecondary(ctx context.Context, addr string, token [16]byte, streamIndex byte, deadline time.Time) (P2PConn, error) {
	dialer := net.Dialer{Deadline: deadline}
	c, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dialing secondary: %w", err)
	}

	c.SetDeadline(deadline)

	// Write handshake: magic + token + stream index.
	var handshake [18]byte
	handshake[0] = secondaryMagic
	copy(handshake[1:17], token[:])
	handshake[17] = streamIndex
	if _, err := c.Write(handshake[:]); err != nil {
		c.Close()
		return nil, fmt.Errorf("writing secondary handshake: %w", err)
	}

	// Read ack.
	var ack [1]byte
	if _, err := io.ReadFull(c, ack[:]); err != nil {
		c.Close()
		return nil, fmt.Errorf("reading secondary ack: %w", err)
	}
	if ack[0] != secondaryMagic {
		c.Close()
		return nil, fmt.Errorf("invalid secondary ack: 0x%02x", ack[0])
	}

	c.SetDeadline(time.Time{}) // clear deadline
	return &netConnAdapter{Conn: c}, nil
}

// acceptSecondary accepts a connection and verifies the secondary handshake.
// Returns the connection and the stream index from the handshake.
func acceptSecondary(_ context.Context, ln net.Listener, token [16]byte, deadline time.Time) (P2PConn, byte, error) {
	c, err := ln.Accept()
	if err != nil {
		return nil, 0, fmt.Errorf("accepting secondary: %w", err)
	}

	c.SetDeadline(deadline)

	// Read handshake: magic + token + stream index.
	var handshake [18]byte
	if _, err := io.ReadFull(c, handshake[:]); err != nil {
		c.Close()
		return nil, 0, fmt.Errorf("reading secondary handshake: %w", err)
	}

	if handshake[0] != secondaryMagic {
		c.Close()
		return nil, 0, fmt.Errorf("invalid secondary magic: 0x%02x", handshake[0])
	}

	// Verify token.
	var peerToken [16]byte
	copy(peerToken[:], handshake[1:17])
	if subtle.ConstantTimeCompare(peerToken[:], token[:]) != 1 {
		c.Close()
		return nil, 0, fmt.Errorf("secondary token mismatch")
	}

	streamIndex := handshake[17]

	// Write ack.
	if _, err := c.Write([]byte{secondaryMagic}); err != nil {
		c.Close()
		return nil, 0, fmt.Errorf("writing secondary ack: %w", err)
	}

	c.SetDeadline(time.Time{}) // clear deadline
	return &netConnAdapter{Conn: c}, streamIndex, nil
}
