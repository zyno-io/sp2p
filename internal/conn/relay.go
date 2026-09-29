// SPDX-License-Identifier: MIT

package conn

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zyno-io/sp2p/internal/signal"
)

// RelayAnswer is a local relay-consent decision.
type RelayAnswer int

const (
	// RelayDeny means the local user was asked and said no.
	RelayDeny RelayAnswer = iota
	// RelayAllow means the local user (or -allow-relay) consented.
	RelayAllow
	// RelayUnavailable means the local side could not ask: no TTY/CONIN, a
	// machine-mode response-file error, or a nil prompt callback.
	RelayUnavailable
)

// Sentinel errors returned by RetryWithRelay. Use errors.Is to test for
// them; *PeerDeclinedRelayError additionally carries the peer's reason and
// matches ErrPeerDeclinedRelay via errors.Is.
var (
	// ErrRelayNotAllowed is returned when the local side declined (or could
	// not be asked to allow) the relay. The text is preserved from the
	// pre-consent-split implementation.
	ErrRelayNotAllowed = errors.New("direct connection failed and relay not allowed")
	// ErrPeerDeclinedRelay is the sentinel matched by *PeerDeclinedRelayError.
	ErrPeerDeclinedRelay = errors.New("peer declined relay")
	// ErrPeerRelayTimeout means the peer did not reach a relay decision
	// within RelayOptions.DecisionWait.
	ErrPeerRelayTimeout = errors.New("peer did not decide on relay in time")
	// ErrPeerLeft means the peer disconnected while relay consent/retry was
	// in progress.
	ErrPeerLeft = errors.New("peer disconnected")
	// ErrSignalingLost means the signaling connection was lost while relay
	// consent/retry was in progress.
	ErrSignalingLost = errors.New("signaling connection lost")
)

// PeerDeclinedRelayError reports that the peer sent relay-denied (or is an
// old client whose empty relay-denied payload is always treated as
// "declined"). It matches ErrPeerDeclinedRelay via errors.Is.
type PeerDeclinedRelayError struct {
	// Reason is the peer's RelayDenied.Reason: RelayDeniedDeclined,
	// RelayDeniedUnavailable, or "" for an old (≤0.6.2) peer.
	Reason string
}

func (e *PeerDeclinedRelayError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("peer declined relay: %s", e.Reason)
	}
	return "peer declined relay"
}

// Is reports whether target is ErrPeerDeclinedRelay, so callers can use
// errors.Is(err, ErrPeerDeclinedRelay) without caring about the reason.
func (e *PeerDeclinedRelayError) Is(target error) bool {
	return target == ErrPeerDeclinedRelay
}

// RelayWatch tracks the peer's relay-retry/relay-denied/peer-left messages
// (and signaling loss) for one connection attempt, in arrival order, so
// callers can cancel an in-flight attempt and report the right error the
// instant the peer's state is known — instead of racing a fixed timeout.
//
// Priority when more than one condition is true is always: peer declined,
// then peer left, then signaling lost. This is a property of Err()/Declined,
// not of arrival order: a decline that arrives before or after a peer-left
// or signaling-loss event is always reported as a decline.
type RelayWatch struct {
	client *signal.Client
	ch     chan *signal.Envelope

	mu       sync.Mutex
	declined bool
	reason   string
	left     bool
	lost     bool
	granted  bool
	sawRetry bool

	declinedCh chan struct{}
	leftCh     chan struct{}
	lostCh     chan struct{}
	retryCh    chan struct{}
	grantedCh  chan struct{}
	abortCh    chan struct{} // closed on first declined/left/lost
	abortOnce  sync.Once

	closeOnce sync.Once
	closeCh   chan struct{}
	doneCh    chan struct{}
}

// WatchRelay subscribes to relay-retry, relay-denied and peer-left on c and
// starts tracking their arrival. Callers must call Close when the watch is
// no longer needed (typically via defer, right after WatchRelay).
func WatchRelay(c *signal.Client) *RelayWatch {
	w := &RelayWatch{
		client:     c,
		ch:         c.SubscribeTypes(signal.TypeRelayRetry, signal.TypeRelayDenied, signal.TypePeerLeft),
		declinedCh: make(chan struct{}),
		leftCh:     make(chan struct{}),
		lostCh:     make(chan struct{}),
		retryCh:    make(chan struct{}),
		grantedCh:  make(chan struct{}),
		abortCh:    make(chan struct{}),
		closeCh:    make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
	go w.run()
	return w
}

// Close stops the watch and unsubscribes from the signaling client. Safe to
// call more than once.
func (w *RelayWatch) Close() {
	w.closeOnce.Do(func() {
		close(w.closeCh)
		<-w.doneCh
		w.client.UnsubscribeTypes(w.ch, signal.TypeRelayRetry, signal.TypeRelayDenied, signal.TypePeerLeft)
	})
}

func (w *RelayWatch) run() {
	defer close(w.doneCh)
	for {
		select {
		case env := <-w.ch:
			w.handle(env)
		case <-w.client.Done():
			// Drain any messages already buffered ahead of the disconnect
			// (e.g. a decline delivered just before the connection closed)
			// before recording signaling loss, so a decline that beat the
			// disconnect on the wire is never reported as a lost connection.
			w.drain()
			w.setLost()
			return
		case <-w.closeCh:
			return
		}
	}
}

func (w *RelayWatch) drain() {
	for {
		select {
		case env := <-w.ch:
			w.handle(env)
		default:
			return
		}
	}
}

func (w *RelayWatch) handle(env *signal.Envelope) {
	if env == nil {
		return
	}
	switch env.Type {
	case signal.TypeRelayDenied:
		var rd signal.RelayDenied
		_ = env.ParsePayload(&rd) // empty/unparseable payload still means declined
		w.setDeclined(rd.Reason)
	case signal.TypeRelayRetry:
		var rr signal.RelayRetry
		err := env.ParsePayload(&rr)
		w.setRetry()
		// Consent "" or "granted" means go (old client or explicit grant).
		// An unparseable payload, or any other value, is pending: this
		// watch never starts a relay on a signal it doesn't recognize.
		if err == nil && (rr.Consent == "" || rr.Consent == signal.RelayConsentGranted) {
			w.setGranted()
		}
	case signal.TypePeerLeft:
		w.setLeft()
	}
}

func (w *RelayWatch) setDeclined(reason string) {
	w.mu.Lock()
	first := !w.declined
	if first {
		w.declined = true
		w.reason = reason
	}
	w.mu.Unlock()
	if first {
		close(w.declinedCh)
		w.signalAbort()
	}
}

func (w *RelayWatch) setLeft() {
	w.mu.Lock()
	first := !w.left
	if first {
		w.left = true
	}
	w.mu.Unlock()
	if first {
		close(w.leftCh)
		w.signalAbort()
	}
}

func (w *RelayWatch) setLost() {
	w.mu.Lock()
	first := !w.lost
	if first {
		w.lost = true
	}
	w.mu.Unlock()
	if first {
		close(w.lostCh)
		w.signalAbort()
	}
}

func (w *RelayWatch) setRetry() {
	w.mu.Lock()
	first := !w.sawRetry
	if first {
		w.sawRetry = true
	}
	w.mu.Unlock()
	if first {
		close(w.retryCh)
	}
}

func (w *RelayWatch) setGranted() {
	w.mu.Lock()
	first := !w.granted
	if first {
		w.granted = true
	}
	w.mu.Unlock()
	if first {
		close(w.grantedCh)
	}
}

func (w *RelayWatch) signalAbort() {
	w.abortOnce.Do(func() { close(w.abortCh) })
}

// PeerLeft reports whether the peer has disconnected.
func (w *RelayWatch) PeerLeft() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.left
}

// Declined reports whether the peer has declined the relay, and its reason
// (empty for an old client or a message with no reason field).
func (w *RelayWatch) Declined() (bool, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.declined, w.reason
}

// Granted reports whether the peer has consented to the relay (or is an old
// client, whose empty relay-retry payload is always treated as granted).
func (w *RelayWatch) Granted() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.granted
}

// Err returns the watch's current error, applying the fixed priority order
// (declined, then left, then lost). It returns nil if none apply yet.
func (w *RelayWatch) Err() error {
	w.mu.Lock()
	declined, reason, left, lost := w.declined, w.reason, w.left, w.lost
	w.mu.Unlock()
	switch {
	case declined:
		return &PeerDeclinedRelayError{Reason: reason}
	case left:
		return ErrPeerLeft
	case lost:
		return ErrSignalingLost
	default:
		return nil
	}
}

// AttemptContext returns a context for connection attempt 1: it is canceled
// when parent is done, or the instant the peer's first relay-retry or
// relay-denied message, a peer-left, or signaling loss arrives — so both
// sides reach the relay retry/prompt step at roughly the same time instead
// of each waiting out its own attempt-1 timeout.
//
// The returned context's watcher goroutine exits when parent is done (it
// does not otherwise leak beyond the lifetime of parent).
func (w *RelayWatch) AttemptContext(parent context.Context) context.Context {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		select {
		case <-w.retryCh:
		case <-w.abortCh:
		case <-parent.Done():
		}
		cancel()
	}()
	return ctx
}

// abortContext returns a context canceled when parent is done or the peer
// declines, leaves, or signaling is lost (but NOT merely on a peer
// relay-retry, unlike AttemptContext) — used once attempt 1 has already
// given way to relay retry, so a peer's earlier relay-retry doesn't
// immediately cancel the very context built in response to it.
func (w *RelayWatch) abortContext(parent context.Context) context.Context {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		select {
		case <-w.abortCh:
		case <-parent.Done():
		}
		cancel()
	}()
	return ctx
}

// RelayOptions configures RetryWithRelay.
type RelayOptions struct {
	// RelayOK skips the local prompt and sends relay-retry{granted}
	// immediately (the -allow-relay / RelayOK config path).
	RelayOK bool
	// Prompt asks the local user for consent and must return promptly when
	// ctx is canceled. A nil Prompt is treated as RelayUnavailable.
	Prompt func(ctx context.Context) RelayAnswer
	// OnLog reports a verbose diagnostic message. May be nil.
	OnLog func(string)
	// OnReset is called just before attempt 2, to let the caller clear any
	// connection-method display state. May be nil.
	OnReset func()
	// CredentialWait bounds the wait for the server's TURN credentials.
	// Defaults to 30s.
	CredentialWait time.Duration
	// DecisionWait bounds the wait for the peer's relay decision once both
	// sides have credentials. Defaults to 2 minutes (a human is answering).
	DecisionWait time.Duration

	// establish is a test seam; nil defaults to Establish.
	establish func(ctx context.Context, cfg ConnectConfig) (*EstablishResult, error)
}

// RetryWithRelay implements relay-consent steps 2-6 of the state machine: it
// checks for an already-known peer decline, signals our own consent stage,
// waits for TURN credentials, prompts locally if needed, waits for the
// peer's decision, and finally retries the connection over the relay. w must
// have been created (via WatchRelay) before connection attempt 1 started.
func RetryWithRelay(ctx context.Context, c *signal.Client, w *RelayWatch, cfg ConnectConfig, o RelayOptions) (*EstablishResult, error) {
	if o.CredentialWait <= 0 {
		o.CredentialWait = 30 * time.Second
	}
	if o.DecisionWait <= 0 {
		o.DecisionWait = 2 * time.Minute
	}
	establish := o.establish
	if establish == nil {
		establish = Establish
	}
	logf := func(format string, args ...any) { logVerbose(o.OnLog, format, args...) }

	// Step 2: if the peer has already declined, fail now — don't send
	// relay-retry, don't prompt, don't fetch credentials.
	if err := w.Err(); err != nil {
		return nil, err
	}

	// Step 3: signal our consent stage and wait for TURN credentials.
	consent := signal.RelayConsentPending
	if o.RelayOK {
		consent = signal.RelayConsentGranted
	}
	turnCh := c.Subscribe(signal.TypeTURNCredentials)
	defer c.Unsubscribe(signal.TypeTURNCredentials, turnCh)
	logf("requesting TURN relay credentials from server (consent=%s)", consent)
	if err := c.Send(ctx, signal.TypeRelayRetry, signal.RelayRetry{Consent: consent}); err != nil {
		return nil, fmt.Errorf("sending relay retry signal: %w", err)
	}

	select {
	case env := <-turnCh:
		if env == nil {
			return nil, ErrSignalingLost
		}
		var tc signal.TURNCredentials
		if err := env.ParsePayload(&tc); err != nil {
			return nil, fmt.Errorf("invalid TURN credentials: %w", err)
		}
		if len(tc.ICEServers) == 0 {
			return nil, fmt.Errorf("server returned empty TURN credentials")
		}
		for _, s := range tc.ICEServers {
			cfg.TURNServers = append(cfg.TURNServers, TURNServer{URLs: s.URLs, Username: s.Username, Credential: s.Credential})
		}
		logf("received %d TURN servers from signaling server", len(tc.ICEServers))
	case <-w.abortCh:
		return nil, w.Err()
	case <-time.After(o.CredentialWait):
		return nil, fmt.Errorf("timeout waiting for TURN credentials")
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Step 4: prompt locally unless RelayOK already granted above.
	if !o.RelayOK {
		var answer RelayAnswer
		var canceled bool
		if o.Prompt == nil {
			answer = RelayUnavailable
		} else {
			promptCtx := w.abortContext(ctx)
			answer = o.Prompt(promptCtx)
			canceled = promptCtx.Err() != nil
		}
		if canceled {
			// The prompt was interrupted, not genuinely answered. If that's
			// because the peer (or signaling) already ended things, report
			// that instead of treating the interrupted answer as our own.
			if err := w.Err(); err != nil {
				return nil, err
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		switch answer {
		case RelayAllow:
			// Our own consent, but the peer may have declined while we
			// were prompting: check once more before committing to it.
			if err := w.Err(); err != nil {
				return nil, err
			}
			logf("relay allowed: sending granted consent")
			if err := c.Send(ctx, signal.TypeRelayRetry, signal.RelayRetry{Consent: signal.RelayConsentGranted}); err != nil {
				return nil, fmt.Errorf("sending relay retry signal: %w", err)
			}
		default: // RelayDeny or RelayUnavailable
			reason := signal.RelayDeniedDeclined
			if answer == RelayUnavailable {
				reason = signal.RelayDeniedUnavailable
			}
			logf("relay not allowed locally (reason=%s)", reason)
			c.Send(ctx, signal.TypeRelayDenied, signal.RelayDenied{Reason: reason})
			return nil, ErrRelayNotAllowed
		}
	}

	// Step 5: wait for the peer's decision. Bounded at DecisionWait because
	// a human may be answering on the other side.
	select {
	case <-w.grantedCh:
		logf("peer granted relay retry")
	case <-w.abortCh:
		return nil, w.Err()
	case <-time.After(o.DecisionWait):
		return nil, ErrPeerRelayTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Step 6: brief abortable pause, reset the connection display, retry.
	select {
	case <-time.After(500 * time.Millisecond):
	case <-w.abortCh:
		return nil, w.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if o.OnReset != nil {
		o.OnReset()
	}
	attempt2Ctx := w.abortContext(ctx)
	result, err := establish(attempt2Ctx, cfg)
	if err != nil {
		if wErr := w.Err(); wErr != nil {
			return nil, wErr
		}
		return nil, err
	}
	return result, nil
}
