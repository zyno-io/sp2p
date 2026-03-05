// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/zyno-io/sp2p/internal/signal"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// wsConnect dials the test server's /ws endpoint and returns the conn + cleanup.
func wsConnect(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return conn
}

func wsSend(t *testing.T, conn *websocket.Conn, msgType string, payload any) {
	t.Helper()
	env, err := signal.NewEnvelope(msgType, payload)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(env)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("ws write: %v", err)
	}
}

func wsRead(t *testing.T, conn *websocket.Conn) signal.Envelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("ws read: %v", err)
	}
	var env signal.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return env
}

// wsReadMaybe reads a message or returns nil on timeout.
func wsReadMaybe(conn *websocket.Conn, timeout time.Duration) *signal.Envelope {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		return nil
	}
	var env signal.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil
	}
	return &env
}

// wsReadSlow reads a message with a 10-second timeout, needed for tests where
// the server enforces turnMinWait (5s) before responding.
func wsReadSlow(t *testing.T, conn *websocket.Conn) signal.Envelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("ws read (slow): %v", err)
	}
	var env signal.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return env
}

func startTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	return startTestServerWithConfig(t, Config{Addr: ":0", BaseURL: "http://localhost"})
}

func startTestServerWithConfig(t *testing.T, cfg Config) (*httptest.Server, string) {
	t.Helper()
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		srv.sessions.Stop()
		ts.Close()
	})
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	return ts, wsURL
}

// ── SignalHandler tests ─────────────────────────────────────────────────────

func TestSignal_SenderRegistersAndGetsWelcome(t *testing.T) {
	_, wsURL := startTestServer(t)
	conn := wsConnect(t, wsURL)

	wsSend(t, conn, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion})
	env := wsRead(t, conn)

	if env.Type != signal.TypeWelcome {
		t.Fatalf("expected welcome, got %s", env.Type)
	}
	var w signal.Welcome
	env.ParsePayload(&w)
	if len(w.SessionID) != sessionIDLength {
		t.Fatalf("session ID length: got %d, want %d", len(w.SessionID), sessionIDLength)
	}
}

func TestSignal_WelcomeIncludesBaseURL(t *testing.T) {
	_, wsURL := startTestServerWithConfig(t, Config{
		Addr:    ":0",
		BaseURL: "https://sp2p.example.com",
	})

	// Sender should get BaseURL in welcome.
	sender := wsConnect(t, wsURL)
	wsSend(t, sender, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion})
	env := wsRead(t, sender)
	var sw signal.Welcome
	env.ParsePayload(&sw)
	if sw.BaseURL != "https://sp2p.example.com" {
		t.Fatalf("sender welcome BaseURL = %q, want %q", sw.BaseURL, "https://sp2p.example.com")
	}

	// Receiver should also get BaseURL in welcome.
	receiver := wsConnect(t, wsURL)
	wsSend(t, receiver, signal.TypeJoin, signal.Join{Version: signal.ProtocolVersion, SessionID: sw.SessionID})
	recvEnv := wsRead(t, receiver)
	var rw signal.Welcome
	recvEnv.ParsePayload(&rw)
	if rw.BaseURL != "https://sp2p.example.com" {
		t.Fatalf("receiver welcome BaseURL = %q, want %q", rw.BaseURL, "https://sp2p.example.com")
	}
}

func TestSignal_ReceiverJoinsSession(t *testing.T) {
	_, wsURL := startTestServer(t)

	// Sender registers.
	sender := wsConnect(t, wsURL)
	wsSend(t, sender, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion})
	env := wsRead(t, sender)
	var w signal.Welcome
	env.ParsePayload(&w)

	// Receiver joins.
	receiver := wsConnect(t, wsURL)
	wsSend(t, receiver, signal.TypeJoin, signal.Join{Version: signal.ProtocolVersion, SessionID: w.SessionID})

	// Sender should get peer-joined.
	pj := wsRead(t, sender)
	if pj.Type != signal.TypePeerJoined {
		t.Fatalf("expected peer-joined, got %s", pj.Type)
	}
}

func TestSignal_ReceiverJoinsNonexistentSession(t *testing.T) {
	_, wsURL := startTestServer(t)

	receiver := wsConnect(t, wsURL)
	wsSend(t, receiver, signal.TypeJoin, signal.Join{Version: signal.ProtocolVersion, SessionID: "nonexist"})

	env := wsRead(t, receiver)
	if env.Type != signal.TypeError {
		t.Fatalf("expected error, got %s", env.Type)
	}
	var e signal.Error
	env.ParsePayload(&e)
	if e.Code != signal.ErrCodeSessionNotFound {
		t.Fatalf("expected session_not_found, got %s", e.Code)
	}
}

func TestSignal_VersionMismatch(t *testing.T) {
	_, wsURL := startTestServer(t)
	conn := wsConnect(t, wsURL)

	wsSend(t, conn, signal.TypeHello, signal.Hello{Version: 9999})
	env := wsRead(t, conn)

	if env.Type != signal.TypeError {
		t.Fatalf("expected error, got %s", env.Type)
	}
	var e signal.Error
	env.ParsePayload(&e)
	if e.Code != signal.ErrCodeVersionMismatch {
		t.Fatalf("expected version_mismatch, got %s", e.Code)
	}
}

func TestSignal_InvalidFirstMessage(t *testing.T) {
	_, wsURL := startTestServer(t)
	conn := wsConnect(t, wsURL)

	// Send an offer as the first message (should be hello or join).
	wsSend(t, conn, signal.TypeOffer, signal.SDP{SDP: "x", Type: "offer"})
	env := wsRead(t, conn)

	if env.Type != signal.TypeError {
		t.Fatalf("expected error, got %s", env.Type)
	}
	var e signal.Error
	env.ParsePayload(&e)
	if e.Code != signal.ErrCodeInvalidMessage {
		t.Fatalf("expected invalid_message, got %s", e.Code)
	}
}

func TestSignal_RelayAllowedTypes(t *testing.T) {
	_, wsURL := startTestServer(t)

	// Set up sender + receiver.
	sender := wsConnect(t, wsURL)
	wsSend(t, sender, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion})
	env := wsRead(t, sender)
	var w signal.Welcome
	env.ParsePayload(&w)

	receiver := wsConnect(t, wsURL)
	wsSend(t, receiver, signal.TypeJoin, signal.Join{Version: signal.ProtocolVersion, SessionID: w.SessionID})
	wsRead(t, receiver) // consume receiver welcome
	wsRead(t, sender)   // consume peer-joined

	// Sender sends an offer — should be relayed to receiver.
	wsSend(t, sender, signal.TypeOffer, signal.SDP{SDP: "test-sdp", Type: "offer"})
	relayed := wsRead(t, receiver)
	if relayed.Type != signal.TypeOffer {
		t.Fatalf("expected offer, got %s", relayed.Type)
	}
	var sdp signal.SDP
	relayed.ParsePayload(&sdp)
	if sdp.SDP != "test-sdp" {
		t.Fatalf("SDP mismatch: %s", sdp.SDP)
	}

	// Receiver sends an answer — should be relayed to sender.
	wsSend(t, receiver, signal.TypeAnswer, signal.SDP{SDP: "test-answer", Type: "answer"})
	relayed = wsRead(t, sender)
	if relayed.Type != signal.TypeAnswer {
		t.Fatalf("expected answer, got %s", relayed.Type)
	}

	// Receiver sends a candidate — should be relayed to sender.
	wsSend(t, receiver, signal.TypeCandidate, signal.Candidate{Candidate: "cand1"})
	relayed = wsRead(t, sender)
	if relayed.Type != signal.TypeCandidate {
		t.Fatalf("expected candidate, got %s", relayed.Type)
	}
}

func TestSignal_DisallowedTypesNotRelayed(t *testing.T) {
	_, wsURL := startTestServer(t)

	sender := wsConnect(t, wsURL)
	wsSend(t, sender, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion})
	env := wsRead(t, sender)
	var w signal.Welcome
	env.ParsePayload(&w)

	receiver := wsConnect(t, wsURL)
	wsSend(t, receiver, signal.TypeJoin, signal.Join{Version: signal.ProtocolVersion, SessionID: w.SessionID})
	wsRead(t, receiver) // consume receiver welcome
	wsRead(t, sender)   // consume peer-joined

	// Sender sends a "hello" (not in relay allow-list) — should NOT be relayed.
	wsSend(t, sender, signal.TypeHello, signal.Hello{Version: 1})

	// Then sends an offer (allowed) to verify the relay is still working.
	wsSend(t, sender, signal.TypeOffer, signal.SDP{SDP: "after-hello", Type: "offer"})

	// Receiver should get the offer, not the hello.
	got := wsRead(t, receiver)
	if got.Type != signal.TypeOffer {
		t.Fatalf("expected offer (hello should be dropped), got %s", got.Type)
	}
}

func TestSignal_SessionFullRejectsSecondReceiver(t *testing.T) {
	_, wsURL := startTestServer(t)

	// Sender registers.
	sender := wsConnect(t, wsURL)
	wsSend(t, sender, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion})
	env := wsRead(t, sender)
	var w signal.Welcome
	env.ParsePayload(&w)

	// First receiver joins.
	r1 := wsConnect(t, wsURL)
	wsSend(t, r1, signal.TypeJoin, signal.Join{Version: signal.ProtocolVersion, SessionID: w.SessionID})
	wsRead(t, sender) // peer-joined

	// Second receiver tries to join — should fail.
	r2 := wsConnect(t, wsURL)
	wsSend(t, r2, signal.TypeJoin, signal.Join{Version: signal.ProtocolVersion, SessionID: w.SessionID})
	errEnv := wsRead(t, r2)
	if errEnv.Type != signal.TypeError {
		t.Fatalf("expected error for second receiver, got %s", errEnv.Type)
	}
}

func TestSignal_JoinVersionMismatch(t *testing.T) {
	_, wsURL := startTestServer(t)

	sender := wsConnect(t, wsURL)
	wsSend(t, sender, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion})
	env := wsRead(t, sender)
	var w signal.Welcome
	env.ParsePayload(&w)

	receiver := wsConnect(t, wsURL)
	wsSend(t, receiver, signal.TypeJoin, signal.Join{Version: 9999, SessionID: w.SessionID})
	errEnv := wsRead(t, receiver)
	if errEnv.Type != signal.TypeError {
		t.Fatalf("expected error, got %s", errEnv.Type)
	}
	var e signal.Error
	errEnv.ParsePayload(&e)
	if e.Code != signal.ErrCodeVersionMismatch {
		t.Fatalf("expected version_mismatch, got %s", e.Code)
	}
}

func TestSignal_BidirectionalRelay(t *testing.T) {
	_, wsURL := startTestServer(t)

	sender := wsConnect(t, wsURL)
	wsSend(t, sender, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion})
	env := wsRead(t, sender)
	var w signal.Welcome
	env.ParsePayload(&w)

	receiver := wsConnect(t, wsURL)
	wsSend(t, receiver, signal.TypeJoin, signal.Join{Version: signal.ProtocolVersion, SessionID: w.SessionID})
	wsRead(t, receiver) // consume receiver welcome
	wsRead(t, sender)   // peer-joined

	// Sender → Receiver crypto.
	wsSend(t, sender, signal.TypeCrypto, signal.CryptoExchange{PublicKey: []byte("sender-pub")})
	got := wsRead(t, receiver)
	if got.Type != signal.TypeCrypto {
		t.Fatalf("expected crypto, got %s", got.Type)
	}

	// Receiver → Sender crypto.
	wsSend(t, receiver, signal.TypeCrypto, signal.CryptoExchange{PublicKey: []byte("receiver-pub")})
	got = wsRead(t, sender)
	if got.Type != signal.TypeCrypto {
		t.Fatalf("expected crypto, got %s", got.Type)
	}
}

// ── SessionManager tests ────────────────────────────────────────────────────

func TestSessionManager_CreateAndGet(t *testing.T) {
	sm := NewSessionManager()
	defer sm.Stop()

	s, err := sm.Create(nil, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.ID) != sessionIDLength {
		t.Fatalf("expected ID length %d, got %d", sessionIDLength, len(s.ID))
	}

	got := sm.Get(s.ID)
	if got != s {
		t.Fatal("Get returned different session")
	}
}

func TestSessionManager_JoinNonexistent(t *testing.T) {
	sm := NewSessionManager()
	defer sm.Stop()

	if _, err := sm.Join("nope", nil); err == nil {
		t.Fatal("join nonexistent should return error")
	}
}

func TestSessionManager_JoinFull(t *testing.T) {
	// Use real WebSocket connections to test the "already full" check,
	// since Join checks s.Receiver != nil.
	_, wsURL := startTestServer(t)

	sender := wsConnect(t, wsURL)
	wsSend(t, sender, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion})
	env := wsRead(t, sender)
	var w signal.Welcome
	env.ParsePayload(&w)

	// First receiver joins.
	r1 := wsConnect(t, wsURL)
	wsSend(t, r1, signal.TypeJoin, signal.Join{Version: signal.ProtocolVersion, SessionID: w.SessionID})
	wsRead(t, sender) // consume peer-joined

	// Second receiver should fail.
	r2 := wsConnect(t, wsURL)
	wsSend(t, r2, signal.TypeJoin, signal.Join{Version: signal.ProtocolVersion, SessionID: w.SessionID})
	errEnv := wsRead(t, r2)
	if errEnv.Type != signal.TypeError {
		t.Fatalf("expected error, got %s", errEnv.Type)
	}
}

func TestSessionManager_Remove(t *testing.T) {
	sm := NewSessionManager()
	defer sm.Stop()

	s, err := sm.Create(nil, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	sm.Remove(s.ID)

	if sm.Get(s.ID) != nil {
		t.Fatal("session should be removed")
	}
}

func TestSessionManager_Touch(t *testing.T) {
	sm := NewSessionManager()
	defer sm.Stop()

	s, err := sm.Create(nil, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	before := s.LastSeen
	time.Sleep(10 * time.Millisecond)
	sm.Touch(s.ID)

	got := sm.Get(s.ID)
	if !got.LastSeen.After(before) {
		t.Fatal("Touch should update LastSeen")
	}
}

func TestSessionManager_IDAlphabet(t *testing.T) {
	// Verify all generated IDs use only the expected alphabet.
	sm := NewSessionManager()
	defer sm.Stop()

	for i := 0; i < 100; i++ {
		s, err := sm.Create(nil, fmt.Sprintf("10.0.%d.%d", i/256, i%256))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range s.ID {
			if !strings.ContainsRune(alphabet, c) {
				t.Fatalf("ID contains invalid char %c", c)
			}
		}
	}
}

func TestSessionManager_UniqueIDs(t *testing.T) {
	sm := NewSessionManager()
	defer sm.Stop()

	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		s, err := sm.Create(nil, fmt.Sprintf("10.0.%d.%d", i/256, i%256))
		if err != nil {
			t.Fatal(err)
		}
		if seen[s.ID] {
			t.Fatalf("duplicate ID: %s", s.ID)
		}
		seen[s.ID] = true
	}
}

func TestSessionManager_PerIPLimit(t *testing.T) {
	sm := NewSessionManager()
	defer sm.Stop()

	// Create sessions up to the per-IP limit.
	for i := 0; i < maxSessionsPerIP; i++ {
		_, err := sm.Create(nil, "10.0.0.1")
		if err != nil {
			t.Fatalf("session %d should be allowed: %v", i, err)
		}
	}

	// Next session from the same IP should be rejected.
	_, err := sm.Create(nil, "10.0.0.1")
	if !errors.Is(err, ErrTooManySessionsForIP) {
		t.Fatalf("expected ErrTooManySessionsForIP, got %v", err)
	}

	// Different IP should still work.
	_, err = sm.Create(nil, "10.0.0.2")
	if err != nil {
		t.Fatalf("different IP should be allowed: %v", err)
	}
}

func TestSessionManager_PerIPLimitReleasedOnRemove(t *testing.T) {
	sm := NewSessionManager()
	defer sm.Stop()

	var sessions []*Session
	for i := 0; i < maxSessionsPerIP; i++ {
		s, err := sm.Create(nil, "10.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, s)
	}

	// At limit — should fail.
	_, err := sm.Create(nil, "10.0.0.1")
	if !errors.Is(err, ErrTooManySessionsForIP) {
		t.Fatalf("expected ErrTooManySessionsForIP, got %v", err)
	}

	// Remove one session — should succeed again.
	sm.Remove(sessions[0].ID)
	_, err = sm.Create(nil, "10.0.0.1")
	if err != nil {
		t.Fatalf("after removal should be allowed: %v", err)
	}
}

func TestSessionManager_GlobalLimit(t *testing.T) {
	sm := NewSessionManager()
	defer sm.Stop()

	// Fill up to global limit.
	for i := 0; i < maxTotalSessions; i++ {
		_, err := sm.Create(nil, fmt.Sprintf("10.%d.%d.%d", i/(256*256), (i/256)%256, i%256))
		if err != nil {
			t.Fatalf("session %d should be allowed: %v", i, err)
		}
	}

	// Next session should be rejected regardless of IP.
	_, err := sm.Create(nil, "192.168.1.1")
	if !errors.Is(err, ErrTooManySessions) {
		t.Fatalf("expected ErrTooManySessions, got %v", err)
	}
}

// ── RateLimiter tests ───────────────────────────────────────────────────────

func TestRateLimiter_AllowWithinRate(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	for i := 0; i < 5; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiter_DenyOverRate(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		rl.Allow("1.2.3.4")
	}
	if rl.Allow("1.2.3.4") {
		t.Fatal("4th request should be denied")
	}
}

func TestRateLimiter_SeparateIPs(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	rl.Allow("1.1.1.1")
	rl.Allow("1.1.1.1")
	if rl.Allow("1.1.1.1") {
		t.Fatal("IP 1 should be denied")
	}
	if !rl.Allow("2.2.2.2") {
		t.Fatal("IP 2 should be allowed")
	}
}

func TestRateLimiter_WindowReset(t *testing.T) {
	rl := NewRateLimiter(1, 50*time.Millisecond)
	rl.Allow("1.1.1.1")
	if rl.Allow("1.1.1.1") {
		t.Fatal("should be denied within window")
	}
	time.Sleep(60 * time.Millisecond)
	if !rl.Allow("1.1.1.1") {
		t.Fatal("should be allowed after window expires")
	}
}

func TestRateLimiter_Middleware429(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request passes.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ws", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rec.Code)
	}

	// Second request is rate-limited.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/ws", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: expected 429, got %d", rec.Code)
	}
}

func TestExtractIP_RemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	if got := extractIP(r, false); got != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1, got %s", got)
	}
}

func TestExtractIP_XForwardedFor(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	// Last IP is the one appended by the trusted reverse proxy.
	r.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18, 150.172.238.178")
	if got := extractIP(r, true); got != "150.172.238.178" {
		t.Fatalf("expected 150.172.238.178, got %s", got)
	}
}

func TestExtractIP_XForwardedForSingle(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "8.8.8.8")
	if got := extractIP(r, true); got != "8.8.8.8" {
		t.Fatalf("expected 8.8.8.8, got %s", got)
	}
}

func TestExtractIP_XForwardedForIgnoredWithoutTrustProxy(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.50")
	if got := extractIP(r, false); got != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1 (XFF ignored), got %s", got)
	}
}

// ── BootstrapHandler tests ──────────────────────────────────────────────────

func mustBootstrapHandler(t *testing.T, baseURL, wsURL string) *BootstrapHandler {
	t.Helper()
	h, err := NewBootstrapHandler(baseURL, wsURL, nil)
	if err != nil {
		t.Fatalf("NewBootstrapHandler: %v", err)
	}
	return h
}

func TestBootstrap_SendScriptContent(t *testing.T) {
	h := mustBootstrapHandler(t, "https://sp2p.io", "wss://sp2p.io/ws")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	h.ServeSendScript(rec, req)

	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	if !strings.Contains(body, "#!/bin/sh") {
		t.Fatal("missing shebang")
	}
	if !strings.Contains(body, "send") {
		t.Fatal("missing send command")
	}
	if !strings.Contains(body, "sp2p.io") {
		t.Fatal("missing base URL")
	}
}

func TestBootstrap_RecvScriptContent(t *testing.T) {
	h := mustBootstrapHandler(t, "https://sp2p.io", "wss://sp2p.io/ws")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/r", nil)
	h.ServeRecvScript(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "receive") {
		t.Fatal("missing receive command")
	}
}

func TestBootstrap_BinaryInvalidPath(t *testing.T) {
	h := mustBootstrapHandler(t, "", "")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/dl/a/b/c", nil)
	h.ServeBinary(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestBootstrap_BinaryUnsupportedPlatform(t *testing.T) {
	h := mustBootstrapHandler(t, "", "")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/dl/freebsd/arm64", nil)
	h.ServeBinary(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestBootstrap_BinaryRedirectsToGitHub(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantURL  string
	}{
		{"linux/amd64", "/dl/linux/amd64", "https://github.com/zyno-io/sp2p/releases/latest/download/sp2p_linux_amd64.tar.gz"},
		{"darwin/arm64", "/dl/darwin/arm64", "https://github.com/zyno-io/sp2p/releases/latest/download/sp2p_darwin_arm64.tar.gz"},
		{"windows/amd64", "/dl/windows/amd64", "https://github.com/zyno-io/sp2p/releases/latest/download/sp2p_windows_amd64.zip"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := mustBootstrapHandler(t, "https://sp2p.io", "wss://sp2p.io/ws")
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tt.path, nil)
			h.ServeBinary(rec, req)
			if rec.Code != http.StatusFound {
				t.Fatalf("expected 302, got %d", rec.Code)
			}
			loc := rec.Header().Get("Location")
			if loc != tt.wantURL {
				t.Fatalf("redirect URL:\n  got  %s\n  want %s", loc, tt.wantURL)
			}
		})
	}
}

func TestIsScriptClient(t *testing.T) {
	tests := []struct {
		name   string
		ua     string
		accept string
		want   bool
	}{
		{"curl", "curl/7.81", "", true},
		{"wget", "Wget/1.21", "", true},
		{"httpie", "HTTPie/3.2", "", true},
		{"libcurl", "libcurl/7.81", "", true},
		{"browser", "Mozilla/5.0", "text/html,application/xhtml+xml", false},
		{"curl-with-accept", "curl/7.81", "text/html", false}, // Accept overrides UA
		{"unknown-no-html", "SomeAgent", "application/json", true},
		{"no-headers", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tt.ua != "" {
				r.Header.Set("User-Agent", tt.ua)
			}
			if tt.accept != "" {
				r.Header.Set("Accept", tt.accept)
			}
			if got := isScriptClient(r); got != tt.want {
				t.Fatalf("isScriptClient(%s, accept=%s) = %v, want %v", tt.ua, tt.accept, got, tt.want)
			}
		})
	}
}

func TestBootstrap_InvalidURLReturnsError(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		wsURL   string
	}{
		{"shell injection in base", "https://example.com; rm -rf /", "wss://ok.com/ws"},
		{"shell injection in ws", "https://ok.com", "wss://example.com$(cmd)/ws"},
		{"backtick in base", "https://`whoami`.com", "wss://ok.com/ws"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBootstrapHandler(tt.baseURL, tt.wsURL, nil)
			if err == nil {
				t.Fatal("expected error for unsafe URL")
			}
		})
	}
}

func TestBootstrap_ValidURLSucceeds(t *testing.T) {
	h, err := NewBootstrapHandler("https://sp2p.io", "wss://sp2p.io/ws", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestBootstrap_FilenameRedirect(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantCode int
		wantURL  string
	}{
		{"deb", "/dl/sp2p_amd64.deb", http.StatusFound, githubReleaseBaseURL + "/sp2p_amd64.deb"},
		{"rpm", "/dl/sp2p_x86_64.rpm", http.StatusFound, githubReleaseBaseURL + "/sp2p_x86_64.rpm"},
		{"apk", "/dl/sp2p_x86_64.apk", http.StatusFound, githubReleaseBaseURL + "/sp2p_x86_64.apk"},
		{"tar.gz", "/dl/sp2p_linux_amd64.tar.gz", http.StatusFound, githubReleaseBaseURL + "/sp2p_linux_amd64.tar.gz"},
		{"zip", "/dl/sp2p_windows_amd64.zip", http.StatusFound, githubReleaseBaseURL + "/sp2p_windows_amd64.zip"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := mustBootstrapHandler(t, "https://sp2p.io", "wss://sp2p.io/ws")
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tt.path, nil)
			h.ServeBinary(rec, req)
			if rec.Code != tt.wantCode {
				t.Fatalf("expected %d, got %d", tt.wantCode, rec.Code)
			}
			if loc := rec.Header().Get("Location"); loc != tt.wantURL {
				t.Fatalf("redirect:\n  got  %s\n  want %s", loc, tt.wantURL)
			}
		})
	}
}

func TestBootstrap_FilenameValidation(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantCode int
	}{
		{"no sp2p prefix", "/dl/malware.deb", http.StatusBadRequest},
		{"path traversal", "/dl/sp2p_../../etc/passwd.tar.gz", http.StatusBadRequest},
		{"backslash", "/dl/sp2p_foo\\.tar.gz", http.StatusBadRequest},
		{"bad extension", "/dl/sp2p_linux.exe", http.StatusBadRequest},
		{"empty filename", "/dl/", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := mustBootstrapHandler(t, "https://sp2p.io", "wss://sp2p.io/ws")
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", tt.path, nil)
			h.ServeBinary(rec, req)
			if rec.Code != tt.wantCode {
				t.Fatalf("expected %d, got %d", tt.wantCode, rec.Code)
			}
		})
	}
}

func TestBootstrap_BinaryRedirectWithResolver(t *testing.T) {
	// Set up a mock GitHub API that simulates a scoped release scenario.
	releases := []githubRelease{
		{
			TagName: "v0.1.1-cli-windows",
			Assets: []githubAsset{
				{Name: "sp2p_windows_amd64.zip", BrowserDownloadURL: "https://github.com/zyno-io/sp2p/releases/download/v0.1.1-cli-windows/sp2p_windows_amd64.zip"},
			},
		},
		{
			TagName: "v0.1.0",
			Assets: []githubAsset{
				{Name: "sp2p_linux_amd64.tar.gz", BrowserDownloadURL: "https://github.com/zyno-io/sp2p/releases/download/v0.1.0/sp2p_linux_amd64.tar.gz"},
				{Name: "sp2p_windows_amd64.zip", BrowserDownloadURL: "https://github.com/zyno-io/sp2p/releases/download/v0.1.0/sp2p_windows_amd64.zip"},
			},
		},
	}
	api := newTestGitHubAPI(t, releases)
	defer api.Close()

	resolver := newResolverWithURL(api.URL)
	h, err := NewBootstrapHandler("https://sp2p.io", "wss://sp2p.io/ws", resolver)
	if err != nil {
		t.Fatal(err)
	}

	// Linux should resolve to v0.1.0 (not "latest").
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/dl/linux/amd64", nil)
	h.ServeBinary(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	want := "https://github.com/zyno-io/sp2p/releases/download/v0.1.0/sp2p_linux_amd64.tar.gz"
	if loc != want {
		t.Fatalf("linux redirect:\n  got  %s\n  want %s", loc, want)
	}

	// Windows should resolve to the scoped release.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/dl/windows/amd64", nil)
	h.ServeBinary(rec, req)
	loc = rec.Header().Get("Location")
	want = "https://github.com/zyno-io/sp2p/releases/download/v0.1.1-cli-windows/sp2p_windows_amd64.zip"
	if loc != want {
		t.Fatalf("windows redirect:\n  got  %s\n  want %s", loc, want)
	}
}

func TestSignalHandler_TrustProxyForSessionIP(t *testing.T) {
	// Verify that NewSignalHandler accepts the trustProxy parameter.
	sessions := NewSessionManager()
	defer sessions.Stop()
	stats := NewStatsTracker("")
	defer stats.Stop()

	// Should not panic — just verify construction with trustProxy=true.
	h := NewSignalHandler(sessions, "1.0.0", "https://sp2p.io", nil, nil, nil, []string{"*"}, true, stats)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	if !h.trustProxy {
		t.Error("trustProxy should be true")
	}
}

// ── WebHandler tests ────────────────────────────────────────────────────────

func TestWebHandler_PlaceholderWhenNoFS(t *testing.T) {
	h := NewWebHandler(nil, "", "")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	h.ServeSendPage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "make build-web") {
		t.Fatal("expected placeholder mentioning make build-web")
	}
}

func TestWebHandler_ReceivePlaceholder(t *testing.T) {
	h := NewWebHandler(nil, "", "")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/r", nil)
	h.ServeReceivePage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "SP2P Receive") {
		t.Fatal("expected receive placeholder")
	}
}

func TestWebHandler_AssetNotFoundWhenNoFS(t *testing.T) {
	h := NewWebHandler(nil, "", "")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/app.js", nil)
	h.ServeAsset(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	setSecurityHeaders(rec)

	headers := map[string]string{
		"Content-Security-Policy": "default-src 'self'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
	}
	for key, want := range headers {
		got := rec.Header().Get(key)
		if !strings.Contains(got, want) {
			t.Fatalf("%s: expected to contain %q, got %q", key, want, got)
		}
	}
}

// ── Server routing tests ────────────────────────────────────────────────────

func TestRoute_HealthCheck(t *testing.T) {
	ts, _ := startTestServer(t)

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health: expected 200, got %d", resp.StatusCode)
	}
}

func TestRoute_RootCurlGetsScript(t *testing.T) {
	ts, _ := startTestServer(t)

	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.Header.Set("User-Agent", "curl/7.81")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("expected text/plain, got %s", ct)
	}
}

func TestRoute_RootBrowserGetsHTML(t *testing.T) {
	ts, _ := startTestServer(t)

	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected text/html, got %s", ct)
	}
}

func TestRoute_ReceiveCurlGetsScript(t *testing.T) {
	ts, _ := startTestServer(t)

	req, _ := http.NewRequest("GET", ts.URL+"/r", nil)
	req.Header.Set("User-Agent", "curl/7.81")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("expected text/plain, got %s", ct)
	}
}

func TestRoute_PSRootGetsScript(t *testing.T) {
	ts, _ := startTestServer(t)

	resp, err := http.Get(ts.URL + "/ps")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("expected text/plain, got %s", ct)
	}
	data, _ := io.ReadAll(resp.Body)
	s := string(data)
	if !strings.Contains(s, "$ErrorActionPreference") {
		t.Fatal("missing $ErrorActionPreference")
	}
	if !strings.Contains(s, "Invoke-WebRequest") {
		t.Fatal("missing Invoke-WebRequest")
	}
	if !strings.Contains(s, "send") {
		t.Fatal("missing send command")
	}
}

func TestRoute_PSReceiveGetsScript(t *testing.T) {
	ts, _ := startTestServer(t)

	resp, err := http.Get(ts.URL + "/ps/r")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("expected text/plain, got %s", ct)
	}
	data, _ := io.ReadAll(resp.Body)
	s := string(data)
	if !strings.Contains(s, "$ErrorActionPreference") {
		t.Fatal("missing $ErrorActionPreference")
	}
	if !strings.Contains(s, "Invoke-WebRequest") {
		t.Fatal("missing Invoke-WebRequest")
	}
	if !strings.Contains(s, "receive") {
		t.Fatal("missing receive command")
	}
}

func TestRoute_404ForUnknownPaths(t *testing.T) {
	ts, _ := startTestServer(t)

	resp, err := http.Get(ts.URL + "/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ── ICE Server / TURN tests ─────────────────────────────────────────────────

func TestSignal_WelcomeIncludesSTUNAndTURNAvailable(t *testing.T) {
	_, wsURL := startTestServerWithConfig(t, Config{
		Addr:    ":0",
		BaseURL: "http://localhost",
		STUNServers: []signal.ICEServer{
			{URLs: []string{"stun:stun.example.com:3478"}},
		},
		StaticTURN: []signal.ICEServer{
			{URLs: []string{"turn:turn.example.com:3478"}, Username: "user", Credential: "pass"},
		},
	})

	conn := wsConnect(t, wsURL)
	wsSend(t, conn, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion})
	env := wsRead(t, conn)

	if env.Type != signal.TypeWelcome {
		t.Fatalf("expected welcome, got %s", env.Type)
	}
	var w signal.Welcome
	env.ParsePayload(&w)
	// Welcome should contain only STUN servers, not TURN.
	if len(w.ICEServers) != 1 {
		t.Fatalf("expected 1 ICE server (STUN only), got %d", len(w.ICEServers))
	}
	if w.ICEServers[0].URLs[0] != "stun:stun.example.com:3478" {
		t.Fatalf("unexpected STUN URL: %s", w.ICEServers[0].URLs[0])
	}
	if !w.TURNAvailable {
		t.Fatal("expected TURNAvailable to be true")
	}
}

func TestSignal_WelcomeOmitsICEServersWhenEmpty(t *testing.T) {
	_, wsURL := startTestServer(t) // no ICE servers configured

	conn := wsConnect(t, wsURL)
	wsSend(t, conn, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion})
	env := wsRead(t, conn)

	var w signal.Welcome
	env.ParsePayload(&w)
	if len(w.ICEServers) != 0 {
		t.Fatalf("expected 0 ICE servers, got %d", len(w.ICEServers))
	}
}

func TestSignal_ReceiverGetsTURNAvailableInWelcome(t *testing.T) {
	_, wsURL := startTestServerWithConfig(t, Config{
		Addr:    ":0",
		BaseURL: "http://localhost",
		StaticTURN: []signal.ICEServer{
			{URLs: []string{"turn:relay.example.com:443"}, Username: "u", Credential: "c"},
		},
	})

	// Sender registers.
	sender := wsConnect(t, wsURL)
	wsSend(t, sender, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion})
	wsRead(t, sender) // consume welcome

	var senderWelcome signal.Welcome
	// Re-register to get session ID cleanly.
	sender.CloseNow()
	sender = wsConnect(t, wsURL)
	wsSend(t, sender, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion})
	env := wsRead(t, sender)
	env.ParsePayload(&senderWelcome)

	// Receiver joins.
	receiver := wsConnect(t, wsURL)
	wsSend(t, receiver, signal.TypeJoin, signal.Join{
		Version:   signal.ProtocolVersion,
		SessionID: senderWelcome.SessionID,
	})

	// Receiver should get a welcome with TURNAvailable but no TURN ICE servers.
	recvEnv := wsRead(t, receiver)
	if recvEnv.Type != signal.TypeWelcome {
		t.Fatalf("expected welcome for receiver, got %s", recvEnv.Type)
	}
	var recvWelcome signal.Welcome
	recvEnv.ParsePayload(&recvWelcome)
	if !recvWelcome.TURNAvailable {
		t.Fatal("expected TURNAvailable to be true for receiver")
	}
	// Welcome should NOT contain TURN servers (they are delivered on relay-retry).
	for _, s := range recvWelcome.ICEServers {
		for _, u := range s.URLs {
			if strings.HasPrefix(u, "turn:") || strings.HasPrefix(u, "turns:") {
				t.Fatalf("Welcome should not contain TURN URLs, got %s", u)
			}
		}
	}
}

func TestSignal_ReceiverAlwaysGetsWelcome(t *testing.T) {
	_, wsURL := startTestServer(t) // no ICE servers configured

	sender := wsConnect(t, wsURL)
	wsSend(t, sender, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion})
	env := wsRead(t, sender)
	var w signal.Welcome
	env.ParsePayload(&w)

	receiver := wsConnect(t, wsURL)
	wsSend(t, receiver, signal.TypeJoin, signal.Join{
		Version:   signal.ProtocolVersion,
		SessionID: w.SessionID,
	})

	// Receiver always gets welcome (even with empty ICE servers).
	recvWelcome := wsRead(t, receiver)
	if recvWelcome.Type != signal.TypeWelcome {
		t.Fatalf("expected welcome, got %s", recvWelcome.Type)
	}
	var recvW signal.Welcome
	recvWelcome.ParsePayload(&recvW)
	if len(recvW.ICEServers) != 0 {
		t.Fatalf("expected empty ICE servers, got %d", len(recvW.ICEServers))
	}

	// Sender gets peer-joined (confirming join worked).
	pj := wsRead(t, sender)
	if pj.Type != signal.TypePeerJoined {
		t.Fatalf("expected peer-joined, got %s", pj.Type)
	}

	// Sender sends crypto — receiver should get it.
	wsSend(t, sender, signal.TypeCrypto, signal.CryptoExchange{PublicKey: []byte("test")})
	got := wsRead(t, receiver)
	if got.Type != signal.TypeCrypto {
		t.Fatalf("expected crypto, got %s", got.Type)
	}
}

// ── Relay-retry / TURN credential tests ─────────────────────────────────────

// setupPeers creates a sender+receiver pair and drains their setup messages
// (welcome, peer-joined). Returns the two connections.
func setupPeers(t *testing.T, wsURL string) (sender, receiver *websocket.Conn) {
	t.Helper()
	sender = wsConnect(t, wsURL)
	wsSend(t, sender, signal.TypeHello, signal.Hello{Version: signal.ProtocolVersion})
	env := wsRead(t, sender)
	var w signal.Welcome
	env.ParsePayload(&w)

	receiver = wsConnect(t, wsURL)
	wsSend(t, receiver, signal.TypeJoin, signal.Join{Version: signal.ProtocolVersion, SessionID: w.SessionID})
	wsRead(t, receiver) // consume receiver welcome
	wsRead(t, sender)   // consume peer-joined
	return sender, receiver
}

func TestSignal_RelayRetryDeliversStaticTURN(t *testing.T) {
	wantURLs := []string{"turn:relay.example.com:3478"}
	wantUser := "staticuser"
	wantPass := "staticpass"

	_, wsURL := startTestServerWithConfig(t, Config{
		Addr:    ":0",
		BaseURL: "http://localhost",
		StaticTURN: []signal.ICEServer{
			{URLs: wantURLs, Username: wantUser, Credential: wantPass},
		},
	})

	sender, receiver := setupPeers(t, wsURL)

	// Sender sends relay-retry.
	wsSend(t, sender, signal.TypeRelayRetry, struct{}{})

	// Sender receives turn-credentials.
	creds := wsReadSlow(t, sender)
	if creds.Type != signal.TypeTURNCredentials {
		t.Fatalf("expected turn-credentials, got %s", creds.Type)
	}
	var tc signal.TURNCredentials
	creds.ParsePayload(&tc)
	if len(tc.ICEServers) != 1 {
		t.Fatalf("expected 1 ICE server, got %d", len(tc.ICEServers))
	}
	if tc.ICEServers[0].URLs[0] != wantURLs[0] {
		t.Fatalf("URL mismatch: got %s", tc.ICEServers[0].URLs[0])
	}
	if tc.ICEServers[0].Username != wantUser {
		t.Fatalf("username mismatch: got %s", tc.ICEServers[0].Username)
	}
	if tc.ICEServers[0].Credential != wantPass {
		t.Fatalf("credential mismatch: got %s", tc.ICEServers[0].Credential)
	}

	// Receiver receives the relayed relay-retry.
	relayed := wsReadSlow(t, receiver)
	if relayed.Type != signal.TypeRelayRetry {
		t.Fatalf("expected relay-retry, got %s", relayed.Type)
	}
}

func TestSignal_RelayRetryDeliversEphemeralTURN(t *testing.T) {
	secret := "ephemeral-secret"
	wantURLs := []string{"turn:relay.example.com:3478"}

	_, wsURL := startTestServerWithConfig(t, Config{
		Addr:    ":0",
		BaseURL: "http://localhost",
		TURNGen: &TURNCredentialGenerator{
			URLs:   wantURLs,
			Secret: secret,
			TTL:    24 * time.Hour,
		},
	})

	sender, receiver := setupPeers(t, wsURL)

	wsSend(t, sender, signal.TypeRelayRetry, struct{}{})

	creds := wsReadSlow(t, sender)
	if creds.Type != signal.TypeTURNCredentials {
		t.Fatalf("expected turn-credentials, got %s", creds.Type)
	}
	var tc signal.TURNCredentials
	creds.ParsePayload(&tc)
	if len(tc.ICEServers) != 1 {
		t.Fatalf("expected 1 ICE server, got %d", len(tc.ICEServers))
	}
	srv := tc.ICEServers[0]
	if srv.URLs[0] != wantURLs[0] {
		t.Fatalf("URL mismatch: got %s", srv.URLs[0])
	}

	// Username should be a numeric unix timestamp.
	_, err := strconv.ParseInt(srv.Username, 10, 64)
	if err != nil {
		t.Fatalf("username is not a numeric timestamp: %q", srv.Username)
	}

	// Credential should be valid base64.
	_, err = base64.StdEncoding.DecodeString(srv.Credential)
	if err != nil {
		t.Fatalf("credential is not valid base64: %q", srv.Credential)
	}

	// Receiver gets the relayed relay-retry.
	relayed := wsReadSlow(t, receiver)
	if relayed.Type != signal.TypeRelayRetry {
		t.Fatalf("expected relay-retry, got %s", relayed.Type)
	}
}

func TestSignal_RelayRetryMinimumWait(t *testing.T) {
	_, wsURL := startTestServerWithConfig(t, Config{
		Addr:    ":0",
		BaseURL: "http://localhost",
		StaticTURN: []signal.ICEServer{
			{URLs: []string{"turn:relay.example.com:3478"}, Username: "u", Credential: "c"},
		},
	})

	sender, _ := setupPeers(t, wsURL)

	// Send relay-retry immediately after receiver joins.
	start := time.Now()
	wsSend(t, sender, signal.TypeRelayRetry, struct{}{})

	creds := wsReadSlow(t, sender)
	elapsed := time.Since(start)

	if creds.Type != signal.TypeTURNCredentials {
		t.Fatalf("expected turn-credentials, got %s", creds.Type)
	}

	// Should have waited at least turnMinWait (5s), minus small tolerance.
	if elapsed < turnMinWait-100*time.Millisecond {
		t.Fatalf("response too fast: %v (expected >= %v)", elapsed, turnMinWait)
	}
}

func TestSignal_RelayRetryWithoutTURNNoCredentials(t *testing.T) {
	_, wsURL := startTestServer(t) // no TURN configured

	sender, receiver := setupPeers(t, wsURL)

	wsSend(t, sender, signal.TypeRelayRetry, struct{}{})

	// Receiver should get the relayed relay-retry.
	relayed := wsRead(t, receiver)
	if relayed.Type != signal.TypeRelayRetry {
		t.Fatalf("expected relay-retry, got %s", relayed.Type)
	}

	// Sender should NOT receive turn-credentials.
	env := wsReadMaybe(sender, 500*time.Millisecond)
	if env != nil {
		t.Fatalf("expected no message, got %s", env.Type)
	}
}

func TestSignal_BothPeersGetTURNCredentials(t *testing.T) {
	_, wsURL := startTestServerWithConfig(t, Config{
		Addr:    ":0",
		BaseURL: "http://localhost",
		StaticTURN: []signal.ICEServer{
			{URLs: []string{"turn:relay.example.com:3478"}, Username: "u", Credential: "c"},
		},
	})

	sender, receiver := setupPeers(t, wsURL)

	// Both peers send relay-retry.
	wsSend(t, sender, signal.TypeRelayRetry, struct{}{})
	wsSend(t, receiver, signal.TypeRelayRetry, struct{}{})

	// Each peer should receive exactly one turn-credentials and one relay-retry
	// (the relayed message from the other peer), in either order.
	checkPeer := func(name string, conn *websocket.Conn) {
		t.Helper()
		msg1 := wsReadSlow(t, conn)
		msg2 := wsReadSlow(t, conn)
		types := map[string]bool{msg1.Type: true, msg2.Type: true}
		if !types[signal.TypeTURNCredentials] {
			t.Fatalf("%s: missing turn-credentials in {%s, %s}", name, msg1.Type, msg2.Type)
		}
		if !types[signal.TypeRelayRetry] {
			t.Fatalf("%s: missing relay-retry in {%s, %s}", name, msg1.Type, msg2.Type)
		}
	}

	checkPeer("sender", sender)
	checkPeer("receiver", receiver)
}
