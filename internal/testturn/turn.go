// SPDX-License-Identifier: MIT

// Package testturn implements a minimal, CI-only TURN relay server used to
// prove real relay-only WebRTC transfers end-to-end (see docs/testing.md's
// TURN relay section). It wraps github.com/pion/turn/v5 directly instead of
// running a real coturn instance, so CI needs no extra service to install
// or configure, and it exposes exact allocation accounting
// (created/deleted/live, per session, never per-secret) via an atomically
// written stats.json that tests poll.
//
// This package has one deliberate exception to the repo's flat internal/
// package layout (see AGENTS.md, CLAUDE.md): its binary entrypoint lives at
// ./testturnd, nested under this package, instead of under cmd/. It is CI
// test tooling, not a shipped command -- it is built directly by CI
// (go build ./internal/testturn/testturnd) and never by the Makefile or
// .goreleaser.yaml.
package testturn

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// Config configures a Server. All fields except AllocationLifetime and
// LogLevel are required.
type Config struct {
	// ListenAddr is the UDP address (IP literal, not a hostname) the TURN
	// server listens on for both STUN and TURN control traffic, e.g.
	// "10.99.0.1:3478".
	ListenAddr string

	// RelayIP is the IPv4 address advertised to clients in
	// XOR-RELAYED-ADDRESS and bound for outgoing relay sockets. It must be
	// reachable from both peers (inside the sp2p network namespace, this is
	// dummy0's address).
	RelayIP net.IP

	// MinPort and MaxPort bound the inclusive UDP port range used for relay
	// allocations.
	MinPort, MaxPort uint16

	// Realm is the TURN realm sent in the server's 401 challenge.
	Realm string

	// Secret is the shared secret for TURN-REST ephemeral credentials. It
	// must match the sp2p signaling server's -turn-secret /
	// SP2P_TURN_SECRET so both sides derive the same password from a
	// session's TURN username (see internal/server/turn.go).
	Secret string

	// UserQuota caps live allocations per TURN userID (the sp2p session ID
	// -- both peers of a session share one username, so this is a
	// per-session cap shared across both peers). 0 means unlimited.
	UserQuota int

	// StatsPath is where stats.json is atomically written. Empty disables
	// stats output entirely (accounting is still tracked in memory and
	// available via Server.Snapshot).
	StatsPath string

	// AllocationLifetime overrides pion's default allocation lifetime
	// (10 minutes). Only useful for tests that want faster expiry.
	AllocationLifetime time.Duration

	// LogLevel controls pion/turn's own logging (never this package's
	// stats, which are always written regardless). Defaults to
	// logging.LogLevelDisabled: several pion log call sites include the
	// full TURN username -- which embeds the sp2p session ID -- at Debug
	// level and above, not just its long-term-credential auth handler (see
	// lt_cred.go) but also, e.g., server.go's per-datagram error log when a
	// request fails to parse or authenticate. This package's own auth
	// handler wrapper (see New) always uses a disabled logger regardless of
	// this field, so it never leaks; any LogLevel above Disabled on the
	// server as a whole is for local debugging only, never CI.
	LogLevel logging.LogLevel
}

func (c *Config) validate() error {
	if _, err := netip.ParseAddrPort(c.ListenAddr); err != nil {
		return fmt.Errorf("testturn: invalid ListenAddr %q (must be an IP:port literal, not a hostname): %w", c.ListenAddr, err)
	}
	if c.RelayIP == nil || c.RelayIP.To4() == nil {
		return fmt.Errorf("testturn: RelayIP must be a non-nil IPv4 address")
	}
	if c.MinPort == 0 {
		return fmt.Errorf("testturn: MinPort must be non-zero")
	}
	if c.MinPort > c.MaxPort {
		return fmt.Errorf("testturn: MinPort (%d) must be <= MaxPort (%d)", c.MinPort, c.MaxPort)
	}
	if c.Secret == "" {
		return fmt.Errorf("testturn: Secret must not be empty")
	}
	if c.Realm == "" {
		return fmt.Errorf("testturn: Realm must not be empty")
	}
	if c.UserQuota < 0 {
		return fmt.Errorf("testturn: UserQuota must be >= 0")
	}
	return nil
}

// Server is a running CI-only TURN relay server with exact allocation
// accounting.
type Server struct {
	cfg     Config
	conn    net.PacketConn
	turn    *turn.Server
	tracker *tracker
	writer  *statsWriter

	closeOnce sync.Once
	closeErr  error
}

// New starts a TURN server per cfg. The returned Server is ready to accept
// TURN traffic; if cfg.StatsPath is set, stats.json exists (with ready:true)
// before New returns.
func New(cfg Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	conn, err := net.ListenPacket("udp4", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("testturn: listen %s: %w", cfg.ListenAddr, err)
	}

	t := newTracker(cfg.UserQuota)
	s := &Server{cfg: cfg, conn: conn, tracker: t}

	writer := newStatsWriter(cfg.StatsPath, func() Snapshot {
		pionLive := 0
		if s.turn != nil {
			pionLive = s.turn.AllocationCount()
		}
		return t.snapshot(pionLive)
	})
	t.writer = writer
	s.writer = writer

	relayGen := &countingRelayGenerator{
		tracker: t,
		inner: &turn.RelayAddressGeneratorPortRange{
			RelayAddress: cfg.RelayIP,
			Address:      cfg.RelayIP.String(),
			MinPort:      cfg.MinPort,
			MaxPort:      cfg.MaxPort,
		},
	}

	// disabledLogger is always used for the auth handler regardless of
	// cfg.LogLevel: LongTermTURNRESTAuthHandler logs the full TURN username
	// -- which embeds the sp2p session ID -- and that must never happen
	// even when a caller raises the server's general log level for local
	// debugging (see AGENTS.md: never log transfer codes or TURN secrets).
	// This is not the only place a raised log level can leak a username --
	// see the LogLevel field's doc comment -- but it is the one this
	// package fully controls.
	disabledLogger := (&logging.DefaultLoggerFactory{DefaultLogLevel: logging.LogLevelDisabled}).NewLogger("testturn-auth")
	restAuthHandler := turn.LongTermTURNRESTAuthHandler(cfg.Secret, disabledLogger)

	// Wraps restAuthHandler purely to count its ok=false outcomes (an
	// expired or malformed TURN username -- e.g. a testturnd/sp2p-server
	// clock skew, or a -turn-secret typo producing a username pion can't
	// parse). This wrapper logs nothing itself, so it adds no leak risk.
	// It is necessary because pion fires no event hook at all on this
	// path: internal/server/util.go's authenticateRequest returns early
	// (straight to a "no such user" STUN error) as soon as AuthHandler
	// returns ok=false, before it would ever call genAuthEvent/OnAuth --
	// OnAuth's verdict only covers the *other* auth failure mode (a
	// present-and-parseable username whose STUN MESSAGE-INTEGRITY doesn't
	// match, i.e. a wrong secret -- see the OnAuth wiring below). Without
	// this wrapper, an expired/malformed-username failure would silently
	// never increment AuthFailures at all.
	authHandler := func(ra *turn.RequestAttributes) (string, []byte, bool) {
		userID, key, ok := restAuthHandler(ra)
		if !ok {
			t.authFailed()
		}
		return userID, key, ok
	}

	// Invariant this package's quota/accounting logic depends on (see
	// tracker.allow in stats.go): pion runs exactly one read-loop goroutine
	// per turn.PacketConnConfig entry (server.go's NewServer spawns one
	// readLoop goroutine per entry in PacketConnConfigs, and none for
	// ListenerConfigs since there are none here), and every request on that
	// PacketConn -- QuotaHandler, CreateAllocation, and the resulting
	// OnAllocationCreated -- is handled synchronously within that one
	// goroutine's HandleRequest call (internal/server/turn.go). So exactly
	// one PacketConnConfig entry and zero ListenerConfigs (as below) makes
	// tracker.allow's check-then-increment race-free without a reservation
	// step, even under concurrent client Allocate requests. Adding a
	// TCP/TLS ListenerConfig would break this (each accepted connection
	// gets its own goroutine) and would need a reservation-with-timeout
	// scheme instead.
	turnServer, err := turn.NewServer(turn.ServerConfig{
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            conn,
			RelayAddressGenerator: relayGen,
		}},
		Realm:       cfg.Realm,
		AuthHandler: authHandler,
		QuotaHandler: func(userID, _ string, _ net.Addr) bool {
			return t.allow(userID)
		},
		EventHandler: turn.EventHandler{
			OnAllocationCreated: func(_, _ net.Addr, _, userID, _ string, _ net.Addr, _ int) {
				t.recordCreated(userID)
			},
			OnAllocationDeleted: func(_, _ net.Addr, _, userID, _ string) {
				t.recordDeleted(userID)
			},
			// OnAuth's verdict is the STUN MESSAGE-INTEGRITY check against the
			// key AuthHandler returned -- i.e. a real credential mismatch
			// (wrong secret), the OTHER auth-failure mode alongside the
			// authHandler wrapper's ok=false case above. Together the two
			// cover both ways a TURN authentication attempt can fail.
			OnAuth: func(_, _ net.Addr, _, _, _, _ string, verdict bool) {
				if !verdict {
					t.authFailed()
				}
			},
		},
		LoggerFactory:      &logging.DefaultLoggerFactory{DefaultLogLevel: cfg.LogLevel},
		AllocationLifetime: cfg.AllocationLifetime,
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("testturn: start pion TURN server: %w", err)
	}
	s.turn = turnServer

	// Write the first snapshot synchronously so a caller that polls
	// stats.json immediately after New returns never sees a missing file,
	// then hand off to the async writer for every subsequent update.
	writer.flush()
	writer.start()

	return s, nil
}

// Addr returns the server's UDP listen address.
func (s *Server) Addr() net.Addr {
	return s.conn.LocalAddr()
}

// Snapshot returns the current allocation accounting, cross-checked
// against pion's own live allocation count.
func (s *Server) Snapshot() Snapshot {
	return s.tracker.snapshot(s.turn.AllocationCount())
}

// Close stops the TURN server and performs a final stats.json write with
// closed:true. It is safe to call more than once. Closing the listener
// unblocks pion's read-loop goroutine, which then closes each
// allocation's manager; that in turn makes each allocation's own relay-
// socket read error out and call DeleteAllocation, firing
// OnAllocationDeleted -- but that happens asynchronously, on each
// allocation's own goroutine, not synchronously within this call. So the
// final snapshot written here can still show Live > 0 for allocations that
// are in the process of tearing down, even though they will in fact reach
// Deleted shortly after (milliseconds in practice). Callers that need "no
// leaked allocations" must observe Live reach 0 (e.g. by polling
// Snapshot/stats.json) before calling Close, not rely on Close's own
// synchronous return to report a final, settled state.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.turn.Close()
		s.tracker.markClosed()
		s.writer.flush()
		s.writer.close()
	})
	return s.closeErr
}

// countingRelayGenerator wraps a turn.RelayAddressGenerator so relayed
// bytes can be counted per user without touching pion internals. It
// delegates every method to inner and only instruments AllocatePacketConn
// (the UDP relay path this package uses -- see Server.New, which registers
// no ListenerConfigs, so AllocateListener/AllocateConn are unused by this
// server but still delegated for interface completeness and in case a
// future caller adds TCP/TLS support).
type countingRelayGenerator struct {
	tracker *tracker
	inner   turn.RelayAddressGenerator
}

var _ turn.RelayAddressGenerator = (*countingRelayGenerator)(nil)

func (g *countingRelayGenerator) Validate() error {
	return g.inner.Validate()
}

func (g *countingRelayGenerator) AllocatePacketConn(conf turn.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
	pc, addr, err := g.inner.AllocatePacketConn(conf)
	if err != nil {
		g.tracker.relayAllocFailed()
		return nil, nil, err
	}
	return &countingPacketConn{PacketConn: pc, bytes: g.tracker.relayBytesFor(conf.UserID)}, addr, nil
}

func (g *countingRelayGenerator) AllocateListener(conf turn.AllocateListenerConfig) (net.Listener, net.Addr, error) {
	return g.inner.AllocateListener(conf)
}

func (g *countingRelayGenerator) AllocateConn(conf turn.AllocateConnConfig) (net.Conn, error) {
	return g.inner.AllocateConn(conf)
}

// countingPacketConn counts bytes read from and written to a relay socket.
// ReadFrom runs on that allocation's own dedicated relay-read goroutine
// (data arriving from the remote peer); WriteTo runs on pion's shared
// control-plane read-loop goroutine (data the client asked to send to the
// peer) -- see the invariant comment in Server.New. The two accessors never
// touch the same field concurrently, but a concurrent stats snapshot read
// still requires atomics for safe visibility, hence relayBytes.
type countingPacketConn struct {
	net.PacketConn
	bytes *relayBytes
}

func (c *countingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 {
		c.bytes.fromPeers.Add(uint64(n))
	}
	return n, addr, err
}

func (c *countingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if n > 0 {
		c.bytes.toPeers.Add(uint64(n))
	}
	return n, err
}
