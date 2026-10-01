// SPDX-License-Identifier: MIT

package conn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/zyno-io/sp2p/internal/signal"
)

// relayHub is a small fake signaling peer: it accepts one WebSocket
// connection from a signal.Client under test, records every envelope the
// client sends (in arrival order), lets the test inject envelopes as if
// from the peer, and auto-replies TURN credentials to every relay-retry —
// the same pattern flow/helpers_test.go uses for its own fake server.
type relayHub struct {
	t      *testing.T
	client *signal.Client
	server *httptest.Server

	connMu sync.Mutex
	conn   *websocket.Conn
	connCh chan struct{}

	sent chan signal.Envelope

	turnServers []signal.ICEServer
	noAutoReply bool
}

func newRelayHub(t *testing.T) *relayHub {
	t.Helper()
	h := &relayHub{
		t:           t,
		sent:        make(chan signal.Envelope, 64),
		connCh:      make(chan struct{}),
		turnServers: []signal.ICEServer{{URLs: []string{"turn:relay.example.com:3478"}}},
	}
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		h.connMu.Lock()
		h.conn = c
		h.connMu.Unlock()
		close(h.connCh)
		ctx := r.Context()
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			var env signal.Envelope
			if err := json.Unmarshal(data, &env); err != nil {
				continue
			}
			h.sent <- env
			if env.Type == signal.TypeRelayRetry && !h.noAutoReply {
				h.sendRaw(signal.TypeTURNCredentials, signal.TURNCredentials{ICEServers: h.turnServers})
			}
		}
	}))

	wsURL := strings.Replace(h.server.URL, "http://", "ws://", 1)
	client, err := signal.Connect(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	h.client = client

	select {
	case <-h.connCh:
	case <-time.After(2 * time.Second):
		t.Fatal("server never accepted connection")
	}
	t.Cleanup(func() {
		h.client.Close()
		h.server.Close()
	})
	return h
}

// send delivers an envelope from the "peer" to the client under test.
func (h *relayHub) send(msgType string, payload any) {
	h.t.Helper()
	h.sendRaw(msgType, payload)
}

func (h *relayHub) sendRaw(msgType string, payload any) {
	env, err := signal.NewEnvelope(msgType, payload)
	if err != nil {
		h.t.Fatalf("NewEnvelope: %v", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		h.t.Fatalf("marshal: %v", err)
	}
	h.connMu.Lock()
	c := h.conn
	h.connMu.Unlock()
	if c == nil {
		h.t.Fatal("send before connection accepted")
	}
	if err := c.Write(context.Background(), websocket.MessageText, data); err != nil {
		h.t.Fatalf("write: %v", err)
	}
}

// closeConn simulates signaling loss.
func (h *relayHub) closeConn() {
	h.connMu.Lock()
	c := h.conn
	h.connMu.Unlock()
	if c != nil {
		c.Close(websocket.StatusNormalClosure, "test close")
	}
}

// waitSent waits for the next envelope of msgType the client sends,
// skipping others (there normally are none besides the credential replies,
// which this hub answers itself rather than the client sending them).
func (h *relayHub) waitSent(t *testing.T, msgType string, timeout time.Duration) signal.Envelope {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case env := <-h.sent:
			if env.Type == msgType {
				return env
			}
		case <-deadline:
			t.Fatalf("timed out waiting for client to send %s", msgType)
		}
	}
}

// expectNoSend fails the test if the client sends anything within d.
func (h *relayHub) expectNoSend(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case env := <-h.sent:
		t.Fatalf("unexpected send: %s", env.Type)
	case <-time.After(d):
	}
}

func blockingEstablish(ctx context.Context, cfg ConnectConfig) (*EstablishResult, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func successEstablish(ctx context.Context, cfg ConnectConfig) (*EstablishResult, error) {
	return &EstablishResult{Method: "WebRTC"}, nil
}

func blockUntilCalled(called chan<- struct{}) func(ctx context.Context, cfg ConnectConfig) (*EstablishResult, error) {
	return func(ctx context.Context, cfg ConnectConfig) (*EstablishResult, error) {
		close(called)
		<-ctx.Done()
		return nil, ctx.Err()
	}
}

func allowPrompt(context.Context) RelayAnswer { return RelayAllow }

// ── Case 1: pending-then-granted vs. RelayOK sends only granted ────────────

func TestRetryWithRelay_PendingThenGranted(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	resultCh := make(chan error, 1)
	go func() {
		_, err := RetryWithRelay(context.Background(), h.client, w, ConnectConfig{}, RelayOptions{
			Prompt:    allowPrompt,
			establish: successEstablish,
		})
		resultCh <- err
	}()

	first := h.waitSent(t, signal.TypeRelayRetry, 2*time.Second)
	var rr signal.RelayRetry
	first.ParsePayload(&rr)
	if rr.Consent != signal.RelayConsentPending {
		t.Fatalf("first relay-retry consent = %q, want pending", rr.Consent)
	}
	second := h.waitSent(t, signal.TypeRelayRetry, 2*time.Second)
	second.ParsePayload(&rr)
	if rr.Consent != signal.RelayConsentGranted {
		t.Fatalf("second relay-retry consent = %q, want granted", rr.Consent)
	}

	h.send(signal.TypeRelayRetry, signal.RelayRetry{Consent: signal.RelayConsentGranted})
	select {
	case err := <-resultCh:
		if err != nil {
			t.Fatalf("RetryWithRelay error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RetryWithRelay did not return")
	}
}

func TestRetryWithRelay_RelayOKSendsOnlyGranted(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	resultCh := make(chan error, 1)
	go func() {
		_, err := RetryWithRelay(context.Background(), h.client, w, ConnectConfig{}, RelayOptions{
			RelayOK:   true,
			establish: successEstablish,
		})
		resultCh <- err
	}()

	only := h.waitSent(t, signal.TypeRelayRetry, 2*time.Second)
	var rr signal.RelayRetry
	only.ParsePayload(&rr)
	if rr.Consent != signal.RelayConsentGranted {
		t.Fatalf("consent = %q, want granted", rr.Consent)
	}
	h.expectNoSend(t, 150*time.Millisecond)

	h.send(signal.TypeRelayRetry, signal.RelayRetry{Consent: signal.RelayConsentGranted})
	select {
	case err := <-resultCh:
		if err != nil {
			t.Fatalf("RetryWithRelay error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RetryWithRelay did not return")
	}
}

// ── Case 2: attempt 2 is not called before the peer's granted ──────────────

func TestRetryWithRelay_Attempt2WaitsForPeerGrant(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	called := make(chan struct{})
	resultCh := make(chan error, 1)
	go func() {
		_, err := RetryWithRelay(context.Background(), h.client, w, ConnectConfig{}, RelayOptions{
			RelayOK:   true,
			establish: blockUntilCalled(called),
		})
		resultCh <- err
	}()
	h.waitSent(t, signal.TypeRelayRetry, 2*time.Second)

	select {
	case <-called:
		t.Fatal("attempt 2 (establish) started before the peer granted")
	case <-time.After(200 * time.Millisecond):
	}

	h.send(signal.TypeRelayRetry, signal.RelayRetry{Consent: signal.RelayConsentGranted})
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("attempt 2 never started after the peer granted")
	}
	h.closeConn()
	<-resultCh
}

// ── Case 3: peer declines while we wait ─────────────────────────────────────

func TestRetryWithRelay_PeerDeclinesWhileWaiting(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	establishCalled := make(chan struct{})
	promptStarted := make(chan struct{})
	resultCh := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := RetryWithRelay(context.Background(), h.client, w, ConnectConfig{}, RelayOptions{
			Prompt: func(ctx context.Context) RelayAnswer {
				close(promptStarted)
				<-ctx.Done()
				return RelayUnavailable
			},
			establish: blockUntilCalled(establishCalled),
		})
		resultCh <- err
	}()

	h.waitSent(t, signal.TypeRelayRetry, 2*time.Second)
	select {
	case <-promptStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("prompt never started")
	}

	h.send(signal.TypeRelayDenied, signal.RelayDenied{Reason: signal.RelayDeniedDeclined})
	select {
	case err := <-resultCh:
		if !errors.Is(err, ErrPeerDeclinedRelay) {
			t.Fatalf("error = %v, want ErrPeerDeclinedRelay", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("took %v, want under 1s", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("RetryWithRelay did not return within 1s of the peer's decline")
	}
	select {
	case <-establishCalled:
		t.Fatal("attempt 2 ran despite the peer's decline")
	default:
	}
}

// ── Case 4: decline already known ───────────────────────────────────────────

func TestRetryWithRelay_DeclineAlreadyKnown(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	h.send(signal.TypeRelayDenied, signal.RelayDenied{Reason: signal.RelayDeniedDeclined})
	waitForCondition(t, func() bool { declined, _ := w.Declined(); return declined })

	promptCalled := false
	establishCalled := false
	_, err := RetryWithRelay(context.Background(), h.client, w, ConnectConfig{}, RelayOptions{
		Prompt: func(context.Context) RelayAnswer { promptCalled = true; return RelayAllow },
		establish: func(context.Context, ConnectConfig) (*EstablishResult, error) {
			establishCalled = true
			return nil, nil
		},
	})
	if !errors.Is(err, ErrPeerDeclinedRelay) {
		t.Fatalf("error = %v, want ErrPeerDeclinedRelay", err)
	}
	if promptCalled {
		t.Fatal("prompt was called despite an already-known decline")
	}
	if establishCalled {
		t.Fatal("attempt 2 ran despite an already-known decline")
	}
	h.expectNoSend(t, 150*time.Millisecond)
}

// ── Case 5: decline cancels an open prompt without sending our own denial ──

func TestRetryWithRelay_DeclineCancelsPromptWithoutOwnDenial(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	promptStarted := make(chan struct{})
	resultCh := make(chan error, 1)
	go func() {
		_, err := RetryWithRelay(context.Background(), h.client, w, ConnectConfig{}, RelayOptions{
			Prompt: func(ctx context.Context) RelayAnswer {
				close(promptStarted)
				<-ctx.Done()
				return RelayDeny // even an explicit "no" from the interrupted prompt...
			},
		})
		resultCh <- err
	}()

	h.waitSent(t, signal.TypeRelayRetry, 2*time.Second)
	<-promptStarted
	h.send(signal.TypeRelayDenied, signal.RelayDenied{Reason: signal.RelayDeniedDeclined})

	err := <-resultCh
	if !errors.Is(err, ErrPeerDeclinedRelay) {
		t.Fatalf("error = %v, want ErrPeerDeclinedRelay", err)
	}
	// ...must not produce our own relay-denied on the wire.
	h.expectNoSend(t, 150*time.Millisecond)
}

// ── Case 6: old peer {} then relay-denied during attempt 2 ─────────────────

func TestRetryWithRelay_DeclineDuringAttempt2(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	established := make(chan struct{})
	resultCh := make(chan error, 1)
	go func() {
		_, err := RetryWithRelay(context.Background(), h.client, w, ConnectConfig{}, RelayOptions{
			RelayOK:   true,
			establish: blockUntilCalled(established),
		})
		resultCh <- err
	}()
	h.waitSent(t, signal.TypeRelayRetry, 2*time.Second)

	// Old client: empty relay-retry payload means granted.
	h.send(signal.TypeRelayRetry, struct{}{})
	select {
	case <-established:
	case <-time.After(2 * time.Second):
		t.Fatal("attempt 2 never started")
	}

	h.send(signal.TypeRelayDenied, signal.RelayDenied{Reason: signal.RelayDeniedDeclined})
	select {
	case err := <-resultCh:
		if !errors.Is(err, ErrPeerDeclinedRelay) {
			t.Fatalf("error = %v, want ErrPeerDeclinedRelay", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("attempt 2's context was not cancelled by the late decline")
	}
}

// ── Case 7: peer-left during attempt 2 ──────────────────────────────────────

func TestRetryWithRelay_PeerLeftDuringAttempt2(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	established := make(chan struct{})
	resultCh := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := RetryWithRelay(context.Background(), h.client, w, ConnectConfig{}, RelayOptions{
			RelayOK:   true,
			establish: blockUntilCalled(established),
		})
		resultCh <- err
	}()
	h.waitSent(t, signal.TypeRelayRetry, 2*time.Second)
	h.send(signal.TypeRelayRetry, signal.RelayRetry{Consent: signal.RelayConsentGranted})
	<-established

	h.send(signal.TypePeerLeft, struct{}{})
	select {
	case err := <-resultCh:
		if !errors.Is(err, ErrPeerLeft) {
			t.Fatalf("error = %v, want ErrPeerLeft", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("took %v, want well under the old 30s timeout", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("attempt 2's context was not cancelled by peer-left")
	}
}

// ── Cases 8 & 9: decline always wins regardless of arrival order ──────────

func freshWatchState() *RelayWatch {
	return &RelayWatch{
		declinedCh: make(chan struct{}),
		leftCh:     make(chan struct{}),
		lostCh:     make(chan struct{}),
		retryCh:    make(chan struct{}),
		grantedCh:  make(chan struct{}),
		abortCh:    make(chan struct{}),
		closeCh:    make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
}

func TestRelayWatch_DeclineBeatsPeerLeftRegardlessOfOrder(t *testing.T) {
	for i := 0; i < 200; i++ {
		w := freshWatchState()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); w.setDeclined(signal.RelayDeniedDeclined) }()
		go func() { defer wg.Done(); w.setLeft() }()
		wg.Wait()
		if err := w.Err(); !errors.Is(err, ErrPeerDeclinedRelay) {
			t.Fatalf("iteration %d: Err() = %v, want ErrPeerDeclinedRelay", i, err)
		}
	}
}

func TestRelayWatch_DeclineBeatsSignalingLoss(t *testing.T) {
	for i := 0; i < 200; i++ {
		w := freshWatchState()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); w.setDeclined(signal.RelayDeniedDeclined) }()
		go func() { defer wg.Done(); w.setLost() }()
		wg.Wait()
		if err := w.Err(); !errors.Is(err, ErrPeerDeclinedRelay) {
			t.Fatalf("iteration %d: Err() = %v, want ErrPeerDeclinedRelay", i, err)
		}
	}
}

// TestRelayWatch_DrainConsumesBufferedDeclineBeforeMarkingLost directly
// exercises run()'s own drain() call (internal/conn/relay.go's
// `case <-w.client.Done(): w.drain(); w.setLost()`), which is what
// guarantees a decline already buffered in w.ch ahead of a disconnect is
// processed before the connection is marked lost — a real network replay
// of "send relay-denied then close" cannot reliably force run()'s select
// to actually race w.ch against client.Done() (message delivery on the
// same readLoop goroutine happens-before the close is even detected, so
// w.ch is consumed on its own well before client.Done() ever becomes
// ready in practice); this instead drives the exact same code run() calls
// against a directly-populated w.ch, which fails immediately and
// deterministically if drain()'s call or body were ever removed.
func TestRelayWatch_DrainConsumesBufferedDeclineBeforeMarkingLost(t *testing.T) {
	w := freshWatchState()
	w.ch = make(chan *signal.Envelope, 4)
	env, err := signal.NewEnvelope(signal.TypeRelayDenied, signal.RelayDenied{Reason: signal.RelayDeniedDeclined})
	if err != nil {
		t.Fatal(err)
	}
	w.ch <- env

	w.drain()
	w.setLost()

	if got := w.Err(); !errors.Is(got, ErrPeerDeclinedRelay) {
		t.Fatalf("Err() = %v, want ErrPeerDeclinedRelay (drain() must consume the buffered decline before setLost())", got)
	}
}

// ── Case 10: local Deny/Unavailable send the right reason ──────────────────

func TestRetryWithRelay_LocalDenySendsDeclinedReason(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	_, err := RetryWithRelay(context.Background(), h.client, w, ConnectConfig{}, RelayOptions{
		Prompt: func(context.Context) RelayAnswer { return RelayDeny },
	})
	if !errors.Is(err, ErrRelayNotAllowed) {
		t.Fatalf("error = %v, want ErrRelayNotAllowed", err)
	}
	env := h.waitSent(t, signal.TypeRelayDenied, 2*time.Second)
	var rd signal.RelayDenied
	env.ParsePayload(&rd)
	if rd.Reason != signal.RelayDeniedDeclined {
		t.Fatalf("reason = %q, want declined", rd.Reason)
	}
}

func TestRetryWithRelay_LocalUnavailableSendsUnavailableReason(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	_, err := RetryWithRelay(context.Background(), h.client, w, ConnectConfig{}, RelayOptions{
		Prompt: func(context.Context) RelayAnswer { return RelayUnavailable },
	})
	if !errors.Is(err, ErrRelayNotAllowed) {
		t.Fatalf("error = %v, want ErrRelayNotAllowed", err)
	}
	env := h.waitSent(t, signal.TypeRelayDenied, 2*time.Second)
	var rd signal.RelayDenied
	env.ParsePayload(&rd)
	if rd.Reason != signal.RelayDeniedUnavailable {
		t.Fatalf("reason = %q, want unavailable", rd.Reason)
	}
}

// ── Case 11: unknown consent value is treated as pending ───────────────────

func TestRelayWatch_UnknownConsentIsPending(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	h.send(signal.TypeRelayRetry, signal.RelayRetry{Consent: "bogus-value"})
	waitForCondition(t, w.PeerRequestedRelay)
	time.Sleep(150 * time.Millisecond)
	if w.Granted() {
		t.Fatal("unknown consent value was treated as granted")
	}
}

// TestRelayWatch_PeerRequestedRelay checks PeerRequestedRelay against
// Granted: a pending relay-retry (the peer giving up on its own direct
// attempt, before it has decided whether to allow the relay) must set
// PeerRequestedRelay but not Granted — the distinction
// internal/flow/send.go, receive.go, and internal/peer/peer.go depend on to
// report a clear error instead of a bare context-canceled attemptCtx
// cancellation when this side won't itself be retrying via relay.
func TestRelayWatch_PeerRequestedRelay(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	if w.PeerRequestedRelay() {
		t.Fatal("PeerRequestedRelay before any relay-retry arrived")
	}
	h.send(signal.TypeRelayRetry, signal.RelayRetry{Consent: signal.RelayConsentPending})
	waitForCondition(t, w.PeerRequestedRelay)
	time.Sleep(150 * time.Millisecond)
	if w.Granted() {
		t.Fatal("a pending relay-retry must not be treated as granted")
	}
}

// ── AttemptContext: cancels on peer signals, NOT on bare signaling loss ───

func TestRelayWatch_AttemptContextCancelsOnRelayRetry(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	attemptCtx := w.AttemptContext(context.Background())
	select {
	case <-attemptCtx.Done():
		t.Fatal("AttemptContext canceled before any signal arrived")
	case <-time.After(100 * time.Millisecond):
	}

	h.send(signal.TypeRelayRetry, signal.RelayRetry{Consent: signal.RelayConsentPending})
	select {
	case <-attemptCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("AttemptContext was not canceled by relay-retry")
	}
}

func TestRelayWatch_AttemptContextCancelsOnRelayDenied(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	attemptCtx := w.AttemptContext(context.Background())
	h.send(signal.TypeRelayDenied, signal.RelayDenied{Reason: signal.RelayDeniedDeclined})
	select {
	case <-attemptCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("AttemptContext was not canceled by relay-denied")
	}
}

func TestRelayWatch_AttemptContextCancelsOnPeerLeft(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	attemptCtx := w.AttemptContext(context.Background())
	h.send(signal.TypePeerLeft, struct{}{})
	select {
	case <-attemptCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("AttemptContext was not canceled by peer-left")
	}
}

// TestRelayWatch_AttemptContextIgnoresBareSignalingLoss is the regression
// guard for attempt 1 not being cut short by signaling merely dropping:
// attempt 1 (WebRTC via STUN, or symmetric TCP with LAN/UPnP addresses) can
// need no further signaling once candidates/direct endpoints are already
// exchanged — this package's own callers close signaling right after key
// confirmation specifically because it becomes disposable that early — so
// AttemptContext must not cancel attempt 1 just because signaling itself
// drops. Only an explicit peer relay-retry/relay-denied/peer-left should.
func TestRelayWatch_AttemptContextIgnoresBareSignalingLoss(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	attemptCtx := w.AttemptContext(context.Background())
	h.closeConn()

	// The watch itself must still learn about the loss — Err() reports it
	// once the caller checks after attempt 1 concludes on its own — ...
	waitForCondition(t, func() bool { return w.Err() != nil })
	if !errors.Is(w.Err(), ErrSignalingLost) {
		t.Fatalf("Err() = %v, want ErrSignalingLost", w.Err())
	}
	// ... but AttemptContext itself must NOT have been canceled by it.
	select {
	case <-attemptCtx.Done():
		t.Fatal("AttemptContext was canceled by bare signaling loss")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestRelayWatch_AttemptContextCancelsOnParentDone(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	parent, cancel := context.WithCancel(context.Background())
	attemptCtx := w.AttemptContext(parent)
	cancel()
	select {
	case <-attemptCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("AttemptContext was not canceled when parent was")
	}
}

// TestRelayWatch_AttemptContextExitsOnClose is the regression guard for the
// watcher goroutine outliving the watch itself: with a parent that is never
// done on its own (context.Background(), as a caller with a long-lived flow
// ctx or a background process effectively has) and none of
// retry/declined/left ever arriving, Close must still unblock the
// goroutine — otherwise it (and the RelayWatch/signal client it holds)
// leaks for as long as parent lives, which can be the rest of the process.
func TestRelayWatch_AttemptContextExitsOnClose(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)

	attemptCtx := w.AttemptContext(context.Background())
	select {
	case <-attemptCtx.Done():
		t.Fatal("AttemptContext canceled before Close")
	case <-time.After(100 * time.Millisecond):
	}

	w.Close()
	select {
	case <-attemptCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("AttemptContext's watcher goroutine did not exit after Close — it leaks past the watch's own lifetime")
	}
}

// TestRelayWatch_AbortContextExitsOnClose is abortContext's counterpart to
// TestRelayWatch_AttemptContextExitsOnClose: RetryWithRelay's promptCtx and
// attempt2Ctx are both built via abortContext, and a caller that closes the
// watch right after RetryWithRelay returns — rather than only via a much
// later deferred Close once the whole transfer finishes — must not leak
// this goroutine either. Before abortContext also selected on closeCh, bare
// signaling loss (client.Done()) no longer reached abortCh once Close had
// already stopped run() from observing it, so Close was the only remaining
// way to unblock it — and didn't.
func TestRelayWatch_AbortContextExitsOnClose(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)

	abortCtx := w.abortContext(context.Background())
	select {
	case <-abortCtx.Done():
		t.Fatal("abortContext canceled before Close")
	case <-time.After(100 * time.Millisecond):
	}

	w.Close()
	select {
	case <-abortCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("abortContext's watcher goroutine did not exit after Close — it leaks past the watch's own lifetime")
	}
}

// ── Case 12: decision timeout ───────────────────────────────────────────────

func TestRetryWithRelay_DecisionTimeout(t *testing.T) {
	h := newRelayHub(t)
	w := WatchRelay(h.client)
	defer w.Close()

	_, err := RetryWithRelay(context.Background(), h.client, w, ConnectConfig{}, RelayOptions{
		RelayOK:      true,
		DecisionWait: 100 * time.Millisecond,
	})
	if !errors.Is(err, ErrPeerRelayTimeout) {
		t.Fatalf("error = %v, want ErrPeerRelayTimeout", err)
	}
}

// ── Case 13: duplicate credential messages are harmless ────────────────────

func TestRetryWithRelay_DuplicateCredentialsHarmless(t *testing.T) {
	h := newRelayHub(t)
	h.noAutoReply = true
	w := WatchRelay(h.client)
	defer w.Close()

	resultCh := make(chan error, 1)
	go func() {
		_, err := RetryWithRelay(context.Background(), h.client, w, ConnectConfig{}, RelayOptions{
			RelayOK:   true,
			establish: successEstablish,
		})
		resultCh <- err
	}()

	h.waitSent(t, signal.TypeRelayRetry, 2*time.Second)
	creds := signal.TURNCredentials{ICEServers: h.turnServers}
	h.send(signal.TypeTURNCredentials, creds)
	h.send(signal.TypeTURNCredentials, creds) // duplicate: must not confuse or hang RetryWithRelay
	h.send(signal.TypeRelayRetry, signal.RelayRetry{Consent: signal.RelayConsentGranted})

	select {
	case err := <-resultCh:
		if err != nil {
			t.Fatalf("RetryWithRelay error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RetryWithRelay hung on duplicate credentials")
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────

func waitForCondition(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition never became true")
}
