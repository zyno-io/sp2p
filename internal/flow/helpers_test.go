// SPDX-License-Identifier: MIT

package flow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/signal"
	"github.com/zyno-io/sp2p/internal/transfer"
)

type relayPromptTestHandler struct {
	promptStarted  chan struct{}
	promptCanceled chan struct{}
	errors         chan string
}

func (h *relayPromptTestHandler) OnPhaseChanged(Phase)                 {}
func (h *relayPromptTestHandler) OnTransferCode(string, string)        {}
func (h *relayPromptTestHandler) OnConnectionStatus(conn.MethodStatus) {}
func (h *relayPromptTestHandler) OnConnectionMethodsReset()            {}
func (h *relayPromptTestHandler) OnMetadata(*transfer.Metadata)        {}
func (h *relayPromptTestHandler) OnProgress(uint64)                    {}
func (h *relayPromptTestHandler) OnVerifyCode(string)                  {}
func (h *relayPromptTestHandler) OnComplete(uint64, time.Duration)     {}
func (h *relayPromptTestHandler) OnUpdateAvailable(string, string)     {}
func (h *relayPromptTestHandler) OnParallelStreams(int)                {}
func (h *relayPromptTestHandler) OnVerbose(string)                     {}
func (h *relayPromptTestHandler) PromptRelay() bool                    { return false }
func (h *relayPromptTestHandler) OnError(message string)               { h.errors <- message }
func (h *relayPromptTestHandler) PromptRelayAnswer(ctx context.Context) conn.RelayAnswer {
	close(h.promptStarted)
	<-ctx.Done()
	close(h.promptCanceled)
	return conn.RelayUnavailable
}

func TestRetryWithRelayCancelsMachinePromptWhenSignalingConnectionCloses(t *testing.T) {
	handler := &relayPromptTestHandler{
		promptStarted:  make(chan struct{}),
		promptCanceled: make(chan struct{}),
		errors:         make(chan string, 1),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverConn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept WebSocket: %v", err)
			return
		}
		defer serverConn.Close(websocket.StatusNormalClosure, "disconnect")

		_, data, err := serverConn.Read(r.Context())
		if err != nil {
			t.Errorf("read relay retry: %v", err)
			return
		}
		var request signal.Envelope
		if err := json.Unmarshal(data, &request); err != nil {
			t.Errorf("decode relay retry: %v", err)
			return
		}
		if request.Type != signal.TypeRelayRetry {
			t.Errorf("request type = %q, want %q", request.Type, signal.TypeRelayRetry)
			return
		}

		envelope, err := signal.NewEnvelope(signal.TypeTURNCredentials, signal.TURNCredentials{
			ICEServers: []signal.ICEServer{{URLs: []string{"turn:relay.example.com:3478"}}},
		})
		if err != nil {
			t.Errorf("create TURN credentials: %v", err)
			return
		}
		payload, err := json.Marshal(envelope)
		if err != nil {
			t.Errorf("encode TURN credentials: %v", err)
			return
		}
		if err := serverConn.Write(r.Context(), websocket.MessageText, payload); err != nil {
			t.Errorf("send TURN credentials: %v", err)
			return
		}
		select {
		case <-handler.promptStarted:
		case <-time.After(2 * time.Second):
			t.Error("relay prompt did not start")
		}
	}))
	defer server.Close()

	serverURL := strings.Replace(server.URL, "http://", "ws://", 1)
	client, err := signal.Connect(context.Background(), serverURL)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	watch := conn.WatchRelay(client)
	defer watch.Close()

	_, err = retryWithRelay(context.Background(), client, watch, false, handler, conn.ConnectConfig{}, "receiver")
	if !errors.Is(err, conn.ErrSignalingLost) {
		t.Fatalf("retryWithRelay error = %v, want conn.ErrSignalingLost", err)
	}
	select {
	case <-handler.promptCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("relay prompt was not canceled after signaling connection loss")
	}
	select {
	case message := <-handler.errors:
		if message != "Signaling server disconnected" {
			t.Fatalf("error message = %q", message)
		}
	default:
		t.Fatal("expected signaling-disconnect error")
	}
}

// relayRoleTestHandler is a minimal flow.Handler that captures OnError
// messages and always locally allows the relay (it does not implement
// RelayPromptHandler, so retryWithRelay falls back to PromptRelay()).
type relayRoleTestHandler struct {
	errs chan string
}

func (h *relayRoleTestHandler) OnPhaseChanged(Phase)                 {}
func (h *relayRoleTestHandler) OnTransferCode(string, string)        {}
func (h *relayRoleTestHandler) OnConnectionStatus(conn.MethodStatus) {}
func (h *relayRoleTestHandler) OnConnectionMethodsReset()            {}
func (h *relayRoleTestHandler) OnMetadata(*transfer.Metadata)        {}
func (h *relayRoleTestHandler) OnProgress(uint64)                    {}
func (h *relayRoleTestHandler) OnVerifyCode(string)                  {}
func (h *relayRoleTestHandler) OnComplete(uint64, time.Duration)     {}
func (h *relayRoleTestHandler) OnUpdateAvailable(string, string)     {}
func (h *relayRoleTestHandler) OnParallelStreams(int)                {}
func (h *relayRoleTestHandler) OnVerbose(string)                     {}
func (h *relayRoleTestHandler) PromptRelay() bool                    { return true }
func (h *relayRoleTestHandler) OnError(message string)               { h.errs <- message }

// TestRetryWithRelay_ErrorTextNamesPeerRole checks that a peer decline is
// reported using the role passed by the caller (flow/send.go passes
// "receiver", flow/receive.go passes "sender").
func TestRetryWithRelay_ErrorTextNamesPeerRole(t *testing.T) {
	for _, tc := range []struct{ role, want string }{
		{"receiver", "the receiver declined the relay"},
		{"sender", "the sender declined the relay"},
	} {
		t.Run(tc.role, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				serverConn, err := websocket.Accept(w, r, nil)
				if err != nil {
					t.Errorf("accept WebSocket: %v", err)
					return
				}
				defer serverConn.Close(websocket.StatusNormalClosure, "done")
				ctx := r.Context()

				// Client's relay-retry{pending}.
				if _, _, err := serverConn.Read(ctx); err != nil {
					t.Errorf("read relay retry: %v", err)
					return
				}
				sendTestEnvelope(t, ctx, serverConn, signal.TypeTURNCredentials, signal.TURNCredentials{
					ICEServers: []signal.ICEServer{{URLs: []string{"turn:relay.example.com:3478"}}},
				})

				// Give the client a moment to locally allow and send
				// relay-retry{granted} (ignored here), then the peer declines.
				time.Sleep(50 * time.Millisecond)
				sendTestEnvelope(t, ctx, serverConn, signal.TypeRelayDenied, signal.RelayDenied{Reason: signal.RelayDeniedDeclined})
				time.Sleep(200 * time.Millisecond)
			}))
			defer server.Close()

			serverURL := strings.Replace(server.URL, "http://", "ws://", 1)
			client, err := signal.Connect(context.Background(), serverURL)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			watch := conn.WatchRelay(client)
			defer watch.Close()

			h := &relayRoleTestHandler{errs: make(chan string, 4)}
			_, err = retryWithRelay(context.Background(), client, watch, false, h, conn.ConnectConfig{}, tc.role)
			var declined *conn.PeerDeclinedRelayError
			if !errors.As(err, &declined) {
				t.Fatalf("error = %v, want *conn.PeerDeclinedRelayError", err)
			}
			select {
			case msg := <-h.errs:
				if !strings.Contains(msg, tc.want) {
					t.Fatalf("OnError message = %q, want to contain %q", msg, tc.want)
				}
			case <-time.After(time.Second):
				t.Fatal("OnError was never called")
			}
		})
	}
}

// TestReportRelayWatchErr covers the full mapping table directly (rather
// than only through retryWithRelay's network-facing wrapper above),
// including the credential-timeout case restored by this fix and the case
// (declined/lost during attempt 1, before relay retry is ever reached)
// that reportRelayWatchErr exists specifically to serve.
func TestReportRelayWatchErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"peer declined", &conn.PeerDeclinedRelayError{Reason: signal.RelayDeniedDeclined}, "Direct connection failed and the receiver declined the relay."},
		{"peer unavailable", &conn.PeerDeclinedRelayError{Reason: signal.RelayDeniedUnavailable}, "Direct connection failed and the receiver could not be asked to allow the relay. They can rerun sp2p with -allow-relay."},
		{"peer left", conn.ErrPeerLeft, "Peer disconnected"},
		{"decision timeout", conn.ErrPeerRelayTimeout, "Timed out waiting for the receiver to allow the relay."},
		{"signaling lost", conn.ErrSignalingLost, "Signaling server disconnected"},
		{"credential timeout", conn.ErrTURNCredentialsTimeout, "Server did not provide TURN credentials"},
		{"relay not allowed", conn.ErrRelayNotAllowed, "Could not establish direct connection. Use -allow-relay to route encrypted data through a TURN relay."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &relayRoleTestHandler{errs: make(chan string, 1)}
			got := reportRelayWatchErr(h, tc.err, "receiver")
			if got != tc.err {
				t.Fatalf("reportRelayWatchErr returned %v, want the original error unchanged", got)
			}
			select {
			case msg := <-h.errs:
				if msg != tc.want {
					t.Fatalf("OnError message = %q, want %q", msg, tc.want)
				}
			default:
				t.Fatal("OnError was never called")
			}
		})
	}
}

// TestReportRelayWatchErr_ContextCancellationPassesThroughSilently checks
// that a context cancellation is never reported via OnError — that's the
// caller's (or the user's Ctrl+C's) business, not a relay-consent outcome
// — and that a nil error passes through as nil.
func TestReportRelayWatchErr_ContextCancellationPassesThroughSilently(t *testing.T) {
	h := &relayRoleTestHandler{errs: make(chan string, 1)}
	if got := reportRelayWatchErr(h, context.Canceled, "receiver"); got != context.Canceled {
		t.Fatalf("reportRelayWatchErr(context.Canceled) = %v, want unchanged", got)
	}
	if got := reportRelayWatchErr(h, context.DeadlineExceeded, "receiver"); got != context.DeadlineExceeded {
		t.Fatalf("reportRelayWatchErr(context.DeadlineExceeded) = %v, want unchanged", got)
	}
	if got := reportRelayWatchErr(h, nil, "receiver"); got != nil {
		t.Fatalf("reportRelayWatchErr(nil) = %v, want nil", got)
	}
	select {
	case msg := <-h.errs:
		t.Fatalf("OnError was called unexpectedly with %q", msg)
	default:
	}
}

func sendTestEnvelope(t *testing.T, ctx context.Context, c *websocket.Conn, msgType string, payload any) {
	t.Helper()
	env, err := signal.NewEnvelope(msgType, payload)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := c.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// ── iceServersToConn ─────────────────────────────────────────────────────────

func TestIceServersToConn_STUNOnly(t *testing.T) {
	servers := []signal.ICEServer{
		{URLs: []string{"stun:stun.example.com:3478"}},
	}
	stun, turn := iceServersToConn(servers)
	if len(stun) != 1 || stun[0] != "stun:stun.example.com:3478" {
		t.Fatalf("stun = %v, want [stun:stun.example.com:3478]", stun)
	}
	if len(turn) != 0 {
		t.Fatalf("turn = %v, want empty", turn)
	}
}

func TestIceServersToConn_TURNOnly(t *testing.T) {
	servers := []signal.ICEServer{
		{URLs: []string{"turn:relay.example.com:3478"}, Username: "user", Credential: "pass"},
	}
	stun, turn := iceServersToConn(servers)
	// No STUN provided, should fall back to defaults.
	if len(stun) == 0 {
		t.Fatal("expected default STUN servers")
	}
	defaults := conn.DefaultSTUNServers()
	if len(stun) != len(defaults) {
		t.Fatalf("stun = %v, want defaults %v", stun, defaults)
	}
	if len(turn) != 1 {
		t.Fatalf("turn count = %d, want 1", len(turn))
	}
	if turn[0].Username != "user" || turn[0].Credential != "pass" {
		t.Fatalf("turn creds = %s/%s, want user/pass", turn[0].Username, turn[0].Credential)
	}
}

func TestIceServersToConn_Mixed(t *testing.T) {
	servers := []signal.ICEServer{
		{URLs: []string{"stun:stun1.example.com"}},
		{URLs: []string{"turns:relay.example.com:5349"}, Username: "u", Credential: "c"},
		{URLs: []string{"stun:stun2.example.com"}},
	}
	stun, turn := iceServersToConn(servers)
	if len(stun) != 2 {
		t.Fatalf("stun count = %d, want 2", len(stun))
	}
	if len(turn) != 1 {
		t.Fatalf("turn count = %d, want 1", len(turn))
	}
}

func TestIceServersToConn_Empty(t *testing.T) {
	stun, turn := iceServersToConn(nil)
	defaults := conn.DefaultSTUNServers()
	if len(stun) != len(defaults) {
		t.Fatalf("stun = %v, want defaults", stun)
	}
	if len(turn) != 0 {
		t.Fatalf("turn = %v, want empty", turn)
	}
}

// ── safeRename ───────────────────────────────────────────────────────────────

func TestSafeRename_Basic(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "tmp-file")
	os.WriteFile(tmp, []byte("hello"), 0o644)

	dest, err := safeRename(tmp, "file.txt", dir)
	if err != nil {
		t.Fatalf("safeRename: %v", err)
	}
	if filepath.Base(dest) != "file.txt" {
		t.Fatalf("dest = %q, want file.txt", filepath.Base(dest))
	}
	data, _ := os.ReadFile(dest)
	if string(data) != "hello" {
		t.Fatalf("content = %q, want hello", data)
	}
	// Temp file should be removed.
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("tmp file should be removed")
	}
}

func TestSafeRename_CollisionAddsNumber(t *testing.T) {
	dir := t.TempDir()

	// Create existing file.
	os.WriteFile(filepath.Join(dir, "file.txt"), []byte("existing"), 0o644)

	tmp := filepath.Join(dir, "tmp-file")
	os.WriteFile(tmp, []byte("new"), 0o644)

	dest, err := safeRename(tmp, "file.txt", dir)
	if err != nil {
		t.Fatalf("safeRename: %v", err)
	}
	if filepath.Base(dest) != "file (1).txt" {
		t.Fatalf("dest = %q, want file (1).txt", filepath.Base(dest))
	}
}

func TestSafeRename_MultipleCollisions(t *testing.T) {
	dir := t.TempDir()

	// Create file.txt and file (1).txt.
	os.WriteFile(filepath.Join(dir, "file.txt"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(dir, "file (1).txt"), []byte("b"), 0o644)

	tmp := filepath.Join(dir, "tmp-file")
	os.WriteFile(tmp, []byte("c"), 0o644)

	dest, err := safeRename(tmp, "file.txt", dir)
	if err != nil {
		t.Fatalf("safeRename: %v", err)
	}
	if filepath.Base(dest) != "file (2).txt" {
		t.Fatalf("dest = %q, want file (2).txt", filepath.Base(dest))
	}
}

func TestSafeRename_NoExtension(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "README"), []byte("a"), 0o644)

	tmp := filepath.Join(dir, "tmp-file")
	os.WriteFile(tmp, []byte("b"), 0o644)

	dest, err := safeRename(tmp, "README", dir)
	if err != nil {
		t.Fatalf("safeRename: %v", err)
	}
	if filepath.Base(dest) != "README (1)" {
		t.Fatalf("dest = %q, want README (1)", filepath.Base(dest))
	}
}

// ── PrepareInput ─────────────────────────────────────────────────────────────

func TestPrepareInput_SingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	os.WriteFile(path, []byte("hello world"), 0o644)

	meta, r, cleanup, err := PrepareInput([]string{path}, "")
	if err != nil {
		t.Fatalf("PrepareInput: %v", err)
	}
	defer cleanup()

	if meta.Name != "hello.txt" {
		t.Errorf("name = %q, want hello.txt", meta.Name)
	}
	if meta.Size != 11 {
		t.Errorf("size = %d, want 11", meta.Size)
	}
	if meta.IsFolder {
		t.Error("isFolder should be false")
	}
	if meta.StreamMode {
		t.Error("streamMode should be false")
	}

	data, _ := io.ReadAll(r)
	if string(data) != "hello world" {
		t.Errorf("content = %q", data)
	}
}

func TestPrepareInput_Stdin(t *testing.T) {
	meta, _, cleanup, err := PrepareInput([]string{"-"}, "")
	if err != nil {
		t.Fatalf("PrepareInput: %v", err)
	}
	defer cleanup()

	if meta.Name != "stdin" {
		t.Errorf("name = %q, want stdin", meta.Name)
	}
	if !meta.StreamMode {
		t.Error("streamMode should be true")
	}
}

func TestPrepareInput_StdinWithName(t *testing.T) {
	meta, _, cleanup, err := PrepareInput([]string{"-"}, "data.csv")
	if err != nil {
		t.Fatalf("PrepareInput: %v", err)
	}
	defer cleanup()

	if meta.Name != "data.csv" {
		t.Errorf("name = %q, want data.csv", meta.Name)
	}
}

func TestPrepareInput_Folder(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0o644)
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("bbb"), 0o644)

	meta, r, cleanup, err := PrepareInput([]string{dir}, "")
	if err != nil {
		t.Fatalf("PrepareInput: %v", err)
	}
	defer cleanup()

	if !meta.IsFolder {
		t.Error("isFolder should be true")
	}
	if meta.FileCount < 2 {
		t.Errorf("fileCount = %d, want >= 2", meta.FileCount)
	}
	if meta.Size == 0 {
		t.Error("size should be > 0")
	}
	// Should be readable.
	data, _ := io.ReadAll(r)
	if len(data) == 0 {
		t.Error("expected tar data")
	}
}

func TestPrepareInput_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "one.txt")
	f2 := filepath.Join(dir, "two.txt")
	os.WriteFile(f1, []byte("111"), 0o644)
	os.WriteFile(f2, []byte("222"), 0o644)

	meta, r, cleanup, err := PrepareInput([]string{f1, f2}, "")
	if err != nil {
		t.Fatalf("PrepareInput: %v", err)
	}
	defer cleanup()

	if !meta.IsFolder {
		t.Error("isFolder should be true for multi-file")
	}
	if !strings.HasSuffix(meta.Name, "-files") {
		t.Errorf("name = %q, want N-files suffix", meta.Name)
	}
	data, _ := io.ReadAll(r)
	if len(data) == 0 {
		t.Error("expected tar data")
	}
}

func TestPrepareInput_NonexistentFile(t *testing.T) {
	_, _, _, err := PrepareInput([]string{"/nonexistent/file.txt"}, "")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestPrepareInput_MIMEType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image.png")
	os.WriteFile(path, []byte("fake png"), 0o644)

	meta, _, cleanup, err := PrepareInput([]string{path}, "")
	if err != nil {
		t.Fatalf("PrepareInput: %v", err)
	}
	defer cleanup()

	if meta.Type != "image/png" {
		t.Errorf("type = %q, want image/png", meta.Type)
	}
}
