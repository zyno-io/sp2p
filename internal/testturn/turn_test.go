// SPDX-License-Identifier: MIT

package testturn

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun/v4"
	"github.com/pion/turn/v5"
)

const (
	testSecret = "test-secret-do-not-use-in-production" //nolint:gosec // test fixture only
	testRealm  = "testturn.test"
)

func newTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:0"
	}
	if cfg.RelayIP == nil {
		cfg.RelayIP = net.ParseIP("127.0.0.1")
	}
	if cfg.MinPort == 0 {
		cfg.MinPort = 40000
	}
	if cfg.MaxPort == 0 {
		cfg.MaxPort = 40999
	}
	if cfg.Realm == "" {
		cfg.Realm = testRealm
	}
	if cfg.Secret == "" {
		cfg.Secret = testSecret
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

// newTestClient returns a listening, credentialed TURN client for userID
// against srv, using secret to derive TURN-REST credentials (defaults to
// testSecret -- pass a different value to test an auth mismatch).
func newTestClient(t *testing.T, srv *Server, userID string, secret string) *turn.Client {
	t.Helper()
	if secret == "" {
		secret = testSecret
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	username, password, err := turn.GenerateLongTermTURNRESTCredentials(secret, userID, time.Minute)
	if err != nil {
		conn.Close()
		t.Fatalf("generate credentials: %v", err)
	}
	client, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr: srv.Addr().String(),
		Conn:           conn,
		Username:       username,
		Password:       password,
	})
	if err != nil {
		conn.Close()
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Listen(); err != nil {
		conn.Close()
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: not met within %s", what, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServer_AllocateAndRelease(t *testing.T) {
	srv := newTestServer(t, Config{})
	client := newTestClient(t, srv, "session-1", "")

	relayConn, err := client.Allocate()
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	snap := srv.Snapshot()
	if snap.Created != 1 || snap.Live != 1 || snap.PeakLive != 1 || snap.PionLive != 1 {
		t.Fatalf("after allocate: got %+v", snap)
	}
	u := snap.Users[userKey("session-1")]
	if u.Created != 1 || u.Live != 1 {
		t.Fatalf("after allocate, user stats: got %+v", u)
	}

	if err := relayConn.Close(); err != nil {
		t.Fatalf("relayConn.Close: %v", err)
	}

	waitFor(t, 5*time.Second, "live allocation released", func() bool {
		s := srv.Snapshot()
		return s.Live == 0 && s.Deleted == 1 && s.PionLive == 0
	})
	final := srv.Snapshot()
	if final.Created != 1 || final.Deleted != 1 {
		t.Fatalf("final: got %+v", final)
	}
}

func TestServer_SharedUsername_TwoAllocationsOneUser(t *testing.T) {
	srv := newTestServer(t, Config{})

	// Mirrors real sp2p sessions: both peers share one TURN username.
	username, password, err := turn.GenerateLongTermTURNRESTCredentials(testSecret, "shared-session", time.Minute)
	if err != nil {
		t.Fatalf("generate credentials: %v", err)
	}

	newSharedClient := func() *turn.Client {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("client listen: %v", err)
		}
		client, err := turn.NewClient(&turn.ClientConfig{
			TURNServerAddr: srv.Addr().String(),
			Conn:           conn,
			Username:       username,
			Password:       password,
		})
		if err != nil {
			conn.Close()
			t.Fatalf("NewClient: %v", err)
		}
		if err := client.Listen(); err != nil {
			conn.Close()
			t.Fatalf("Listen: %v", err)
		}
		t.Cleanup(client.Close)
		return client
	}

	clientA := newSharedClient()
	clientB := newSharedClient()

	if _, err := clientA.Allocate(); err != nil {
		t.Fatalf("clientA.Allocate: %v", err)
	}
	if _, err := clientB.Allocate(); err != nil {
		t.Fatalf("clientB.Allocate: %v", err)
	}

	snap := srv.Snapshot()
	if len(snap.Users) != 1 {
		t.Fatalf("expected exactly 1 user key (one shared session), got %d: %+v", len(snap.Users), snap.Users)
	}
	u := snap.Users[userKey("shared-session")]
	if u.Created != 2 || u.Live != 2 {
		t.Fatalf("shared session: got %+v", u)
	}
}

func TestServer_Quota(t *testing.T) {
	srv := newTestServer(t, Config{UserQuota: 2})

	client1 := newTestClient(t, srv, "quota-user", "")
	if _, err := client1.Allocate(); err != nil {
		t.Fatalf("allocation 1: %v", err)
	}
	client2 := newTestClient(t, srv, "quota-user", "")
	if _, err := client2.Allocate(); err != nil {
		t.Fatalf("allocation 2: %v", err)
	}

	client3 := newTestClient(t, srv, "quota-user", "")
	_, err := client3.Allocate()
	if err == nil {
		t.Fatal("allocation 3 should have been rejected by quota 2")
	}
	assertQuotaError(t, err)

	snap := srv.Snapshot()
	if snap.QuotaRejected != 1 || snap.Users[userKey("quota-user")].QuotaRejected != 1 {
		t.Fatalf("expected exactly 1 quota rejection, got %+v", snap)
	}
	if snap.Created != 2 {
		t.Fatalf("a rejected allocation must not count as created: got Created=%d", snap.Created)
	}

	// A different user is unaffected.
	otherClient := newTestClient(t, srv, "other-user", "")
	if _, err := otherClient.Allocate(); err != nil {
		t.Fatalf("a different user should not be blocked by quota-user's quota: %v", err)
	}
}

func TestServer_QuotaConcurrency(t *testing.T) {
	const quota = 4
	const clients = 12
	srv := newTestServer(t, Config{UserQuota: quota, MinPort: 41000, MaxPort: 41999})

	turnClients := make([]*turn.Client, clients)
	for i := range turnClients {
		turnClients[i] = newTestClient(t, srv, "concurrent-user", "")
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	var succeeded, failed int
	var mu sync.Mutex
	for _, c := range turnClients {
		wg.Add(1)
		go func(c *turn.Client) {
			defer wg.Done()
			<-start
			_, err := c.Allocate()
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				succeeded++
			} else {
				assertQuotaError(t, err)
				failed++
			}
		}(c)
	}
	close(start)
	wg.Wait()

	if succeeded != quota {
		t.Fatalf("expected exactly %d successful allocations under concurrent contention, got %d (failed=%d)", quota, succeeded, failed)
	}
	if failed != clients-quota {
		t.Fatalf("expected exactly %d rejected allocations, got %d", clients-quota, failed)
	}

	snap := srv.Snapshot()
	if snap.Created != uint64(quota) {
		t.Fatalf("Created: got %d, want %d", snap.Created, quota)
	}
	if snap.QuotaRejected != uint64(clients-quota) {
		t.Fatalf("QuotaRejected: got %d, want %d", snap.QuotaRejected, clients-quota)
	}
	if snap.Live != int64(quota) {
		t.Fatalf("Live: got %d, want %d", snap.Live, quota)
	}
}

func assertQuotaError(t *testing.T, err error) {
	t.Helper()
	var turnErr *stun.TurnError
	if !errors.As(err, &turnErr) {
		t.Fatalf("expected a *stun.TurnError, got %T: %v", err, err)
	}
	if turnErr.ErrorCodeAttr.Code != stun.CodeAllocQuotaReached {
		t.Fatalf("expected STUN error code %d (Allocation Quota Reached), got %d", stun.CodeAllocQuotaReached, turnErr.ErrorCodeAttr.Code)
	}
}

func TestServer_RelayAllocFailure_PortExhaustion(t *testing.T) {
	// Occupy a port before the server exists, then pin the server's entire
	// relay range to exactly that one (already-taken) port so every
	// allocation attempt fails, deterministically, at bind time.
	blocker, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("blocker listen: %v", err)
	}
	port := uint16(blocker.LocalAddr().(*net.UDPAddr).Port) //nolint:forcetypeassert

	srv := newTestServer(t, Config{MinPort: port, MaxPort: port})
	client := newTestClient(t, srv, "exhausted-user", "")

	if _, err := client.Allocate(); err == nil {
		t.Fatal("expected Allocate to fail while the only relay port is occupied")
	}

	snap := srv.Snapshot()
	if snap.RelayAllocFailures != 1 {
		t.Fatalf("expected exactly 1 relay allocation failure, got %d", snap.RelayAllocFailures)
	}
	if snap.Created != 0 || snap.Live != 0 {
		t.Fatalf("a failed allocation must not count as created/live: got %+v", snap)
	}

	blocker.Close()

	client2 := newTestClient(t, srv, "exhausted-user", "")
	if _, err := client2.Allocate(); err != nil {
		t.Fatalf("expected Allocate to succeed once the port is free: %v", err)
	}
	snap = srv.Snapshot()
	if snap.Created != 1 {
		t.Fatalf("expected 1 successful allocation after freeing the port, got Created=%d", snap.Created)
	}
}

func TestServer_RelayedBytes_BothDirections(t *testing.T) {
	srv := newTestServer(t, Config{})

	username, password, err := turn.GenerateLongTermTURNRESTCredentials(testSecret, "peer-session", time.Minute)
	if err != nil {
		t.Fatalf("generate credentials: %v", err)
	}

	newPeer := func() (*turn.Client, net.PacketConn) {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("client listen: %v", err)
		}
		client, err := turn.NewClient(&turn.ClientConfig{
			TURNServerAddr: srv.Addr().String(),
			Conn:           conn,
			Username:       username,
			Password:       password,
		})
		if err != nil {
			conn.Close()
			t.Fatalf("NewClient: %v", err)
		}
		if err := client.Listen(); err != nil {
			conn.Close()
			t.Fatalf("Listen: %v", err)
		}
		t.Cleanup(client.Close)
		relayConn, err := client.Allocate()
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		return client, relayConn
	}

	clientA, relayA := newPeer()
	clientB, relayB := newPeer()

	if err := clientA.CreatePermission(relayB.LocalAddr()); err != nil {
		t.Fatalf("A CreatePermission(B): %v", err)
	}
	if err := clientB.CreatePermission(relayA.LocalAddr()); err != nil {
		t.Fatalf("B CreatePermission(A): %v", err)
	}

	payloadAtoB := []byte("hello from A")
	payloadBtoA := []byte("hello from B, a bit longer than A's message")

	recvB := make([]byte, 1500)
	recvA := make([]byte, 1500)

	if _, err := relayA.WriteTo(payloadAtoB, relayB.LocalAddr()); err != nil {
		t.Fatalf("A WriteTo B: %v", err)
	}
	if err := relayB.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, _, err := relayB.ReadFrom(recvB)
	if err != nil {
		t.Fatalf("B ReadFrom: %v", err)
	}
	if string(recvB[:n]) != string(payloadAtoB) {
		t.Fatalf("B received %q, want %q", recvB[:n], payloadAtoB)
	}

	if _, err := relayB.WriteTo(payloadBtoA, relayA.LocalAddr()); err != nil {
		t.Fatalf("B WriteTo A: %v", err)
	}
	if err := relayA.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, _, err = relayA.ReadFrom(recvA)
	if err != nil {
		t.Fatalf("A ReadFrom: %v", err)
	}
	if string(recvA[:n]) != string(payloadBtoA) {
		t.Fatalf("A received %q, want %q", recvA[:n], payloadBtoA)
	}

	// A wrote to B (toPeers, from A's relay socket) and B's relay socket
	// received it (fromPeers) -- and symmetrically for B->A -- all under the
	// one shared session user, so both aggregate fields must reflect both
	// messages. The server counts after its write returns, so the peer can
	// read a message before it is counted.
	wantTotal := uint64(len(payloadAtoB) + len(payloadBtoA))
	waitFor(t, 5*time.Second, "relayed bytes counted", func() bool {
		u := srv.Snapshot().Users[userKey("peer-session")]
		return u.RelayedBytesToPeers >= wantTotal && u.RelayedBytesFromPeers >= wantTotal
	})
	snap := srv.Snapshot()
	u := snap.Users[userKey("peer-session")]
	if u.RelayedBytesToPeers < wantTotal {
		t.Fatalf("RelayedBytesToPeers = %d, want >= %d", u.RelayedBytesToPeers, wantTotal)
	}
	if u.RelayedBytesFromPeers < wantTotal {
		t.Fatalf("RelayedBytesFromPeers = %d, want >= %d", u.RelayedBytesFromPeers, wantTotal)
	}
	if snap.RelayedBytesToPeers < wantTotal || snap.RelayedBytesFromPeers < wantTotal {
		t.Fatalf("snapshot-wide totals too small: %+v", snap)
	}
}

func TestServer_AuthFailure_WrongSecret(t *testing.T) {
	srv := newTestServer(t, Config{})
	// A client that derives its password from the WRONG shared secret --
	// simulating a sp2p-server/testturnd -turn-secret mismatch -- passes
	// LongTermTURNRESTAuthHandler's own timestamp check (ok=true) but fails
	// the server's MESSAGE-INTEGRITY verification against the key computed
	// from the SERVER's real secret. See the OnAuth comment in turn.go.
	client := newTestClient(t, srv, "wrong-secret-user", "not-the-real-secret")

	if _, err := client.Allocate(); err == nil {
		t.Fatal("expected Allocate to fail with a mismatched secret")
	}

	snap := srv.Snapshot()
	if snap.AuthFailures < 1 {
		t.Fatalf("expected at least 1 auth failure, got %d", snap.AuthFailures)
	}
	if snap.Created != 0 {
		t.Fatalf("a failed auth must never result in an allocation: Created=%d", snap.Created)
	}
}

// TestServer_AuthFailure_ExpiredCredential exercises the OTHER auth-failure
// path alongside TestServer_AuthFailure_WrongSecret's MESSAGE-INTEGRITY
// mismatch: LongTermTURNRESTAuthHandler itself returns ok=false for an
// already-expired (or malformed) username, and pion's
// internal/server/util.go authenticateRequest returns straight to a
// "no such user" STUN error without ever calling OnAuth for that path. This
// needs its own AuthHandler-wrapping counter (see the authHandler closure
// in turn.go's New) -- without it, this failure class would never
// increment AuthFailures at all.
func TestServer_AuthFailure_ExpiredCredential(t *testing.T) {
	srv := newTestServer(t, Config{})
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer conn.Close()

	username, password, err := turn.GenerateLongTermTURNRESTCredentials(testSecret, "expired-user", -time.Minute)
	if err != nil {
		t.Fatalf("generate credentials: %v", err)
	}
	client, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr: srv.Addr().String(),
		Conn:           conn,
		Username:       username,
		Password:       password,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer client.Close()

	if _, err := client.Allocate(); err == nil {
		t.Fatal("expected Allocate to fail with an expired credential")
	}

	snap := srv.Snapshot()
	if snap.AuthFailures < 1 {
		t.Fatalf("expected at least 1 auth failure for an expired credential, got %d", snap.AuthFailures)
	}
	if snap.Created != 0 {
		t.Fatalf("a failed auth must never result in an allocation: Created=%d", snap.Created)
	}
}

func TestServer_Close_MarksClosed(t *testing.T) {
	srv := newTestServer(t, Config{})
	client := newTestClient(t, srv, "closing-user", "")
	if _, err := client.Allocate(); err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Idempotent: a second Close must not panic or error.
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	snap := srv.tracker.snapshot(0)
	if !snap.Closed {
		t.Fatal("expected Closed=true after Close")
	}
}

func TestConfig_Validate(t *testing.T) {
	base := func() Config {
		return Config{
			ListenAddr: "127.0.0.1:0",
			RelayIP:    net.ParseIP("127.0.0.1"),
			MinPort:    1000,
			MaxPort:    2000,
			Realm:      "r",
			Secret:     "s",
		}
	}

	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"valid", func(c *Config) {}, false},
		{"hostname listen addr", func(c *Config) { c.ListenAddr = "localhost:3478" }, true},
		{"no port", func(c *Config) { c.ListenAddr = "127.0.0.1" }, true},
		{"nil relay ip", func(c *Config) { c.RelayIP = nil }, true},
		{"ipv6 relay ip", func(c *Config) { c.RelayIP = net.ParseIP("::1") }, true},
		{"zero min port", func(c *Config) { c.MinPort = 0 }, true},
		{"min greater than max", func(c *Config) { c.MinPort = 3000; c.MaxPort = 2000 }, true},
		{"min equals max is fine", func(c *Config) { c.MinPort = 1500; c.MaxPort = 1500 }, false},
		{"empty secret", func(c *Config) { c.Secret = "" }, true},
		{"empty realm", func(c *Config) { c.Realm = "" }, true},
		{"negative quota", func(c *Config) { c.UserQuota = -1 }, true},
		{"zero quota is fine", func(c *Config) { c.UserQuota = 0 }, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(&cfg)
			err := cfg.validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestNew_RejectsInvalidConfig(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("expected New to reject an empty Config")
	}
}

func TestNew_StatsFileExistsAndReadyBeforeReturn(t *testing.T) {
	dir := t.TempDir()
	statsPath := filepath.Join(dir, "stats.json")
	srv := newTestServer(t, Config{StatsPath: statsPath})
	defer srv.Close()

	data, err := os.ReadFile(statsPath)
	if err != nil {
		t.Fatalf("stats.json should exist immediately after New returns: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("stats.json is empty")
	}
}
