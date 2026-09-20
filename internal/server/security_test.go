// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/zyno-io/sp2p/internal/signal"
)

func TestIdleSignalingSocketAdmissionAndExpiry(t *testing.T) {
	sm := NewSessionManager(1, 1)
	defer sm.Stop()
	h := NewSignalHandler(sm, "test", "", nil, nil, nil, nil, nil, false, nil)
	ts := httptest.NewServer(h)
	defer ts.Close()
	url := "ws" + strings.TrimPrefix(ts.URL, "http")
	var conns []*websocket.Conn
	for i := 0; i < 6; i++ {
		conns = append(conns, wsConnect(t, url))
	}
	defer func() {
		for _, c := range conns {
			c.CloseNow()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 13*time.Second)
	defer cancel()
	c, response, err := websocket.Dial(ctx, url, nil)
	if c != nil {
		c.CloseNow()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("idle socket cap: %v %v", response, err)
	}
	if _, _, err := conns[0].Read(ctx); err == nil {
		t.Fatal("idle pre-Hello socket remained open")
	}
	if ctx.Err() != nil {
		t.Fatal("first-message deadline not enforced")
	}
}

func TestProxyResolverUsesTrustedSideOfChain(t *testing.T) {
	trusted := netip.MustParsePrefix("10.0.0.0/8")
	r := httptest.NewRequest("GET", "http://localhost", nil)
	r.RemoteAddr = "198.51.100.1:1234"
	r.Header.Set("X-Forwarded-For", "192.0.2.4")
	if got := extractIP(r, true, trusted); got != "198.51.100.1" {
		t.Fatalf("trusted direct spoof: %s", got)
	}
	r.RemoteAddr = "10.1.1.1:1234"
	r.Header.Set("X-Forwarded-For", "192.0.2.4, 198.51.100.2, 10.2.2.2")
	if got := extractIP(r, true, trusted); got != "198.51.100.2" {
		t.Fatalf("wrong trust boundary: %s", got)
	}
}

func TestRejectedVersionDoesNotConsumeReceiverSlot(t *testing.T) {
	sm := NewSessionManager(1, 1)
	defer sm.Stop()
	s, err := sm.Create(nil, "192.0.2.1", signal.Hello{Version: signal.ProtocolVersion})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sm.Join(s.ID, nil, signal.ProtocolVersion-1); err != ErrPeerVersion {
		t.Fatalf("expected version error: %v", err)
	}
	if !s.JoinedAt().IsZero() {
		t.Fatal("rejected receiver modified session")
	}
}
