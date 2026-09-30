// SPDX-License-Identifier: MIT

package peer

import (
	"context"
	"errors"
	"testing"

	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/signal"
)

// TestMapRelayErr checks peer's relay error mapping, which stands in for
// flow.Handler.OnError here (this package has no separate user-facing
// message channel: err.Error() itself is what a human sees). Each case must
// also keep errors.Is/As traversal to the underlying conn sentinel intact,
// since internal/cli/machine.go's peer_relay_denied code depends on it for
// tunnel/rsync too.
func TestMapRelayErr(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		wantIs  error
		wantMsg string
	}{
		{
			name:    "peer declined",
			err:     &conn.PeerDeclinedRelayError{Reason: signal.RelayDeniedDeclined},
			wantIs:  conn.ErrPeerDeclinedRelay,
			wantMsg: "direct connection failed and the peer declined the relay",
		},
		{
			name:    "peer unavailable",
			err:     &conn.PeerDeclinedRelayError{Reason: signal.RelayDeniedUnavailable},
			wantIs:  conn.ErrPeerDeclinedRelay,
			wantMsg: "direct connection failed and the peer could not be asked to allow the relay; they can rerun sp2p with -allow-relay",
		},
		{
			name:    "peer left",
			err:     conn.ErrPeerLeft,
			wantIs:  conn.ErrPeerLeft,
			wantMsg: "peer disconnected",
		},
		{
			name:    "decision timeout",
			err:     conn.ErrPeerRelayTimeout,
			wantIs:  conn.ErrPeerRelayTimeout,
			wantMsg: "timed out waiting for the peer to allow the relay",
		},
		{
			name:    "signaling lost",
			err:     conn.ErrSignalingLost,
			wantIs:  conn.ErrSignalingLost,
			wantMsg: "signaling connection lost",
		},
		{
			name:    "credential timeout",
			err:     conn.ErrTURNCredentialsTimeout,
			wantIs:  conn.ErrTURNCredentialsTimeout,
			wantMsg: "server did not provide TURN credentials",
		},
		{
			name:    "own relay not allowed",
			err:     conn.ErrRelayNotAllowed,
			wantIs:  conn.ErrRelayNotAllowed,
			wantMsg: "direct connection failed and relay was not allowed",
		},
		{
			name:    "peer requested relay, this side is TCP-only",
			err:     &conn.PeerRelayUnusableError{TCPOnly: true},
			wantIs:  conn.ErrPeerRelayUnusable,
			wantMsg: "direct connection failed; the peer asked to retry via relay, but this side is restricted to TCP (-transport tcp) and cannot use one",
		},
		{
			name:    "peer requested relay, no TURN available",
			err:     &conn.PeerRelayUnusableError{TCPOnly: false},
			wantIs:  conn.ErrPeerRelayUnusable,
			wantMsg: "direct connection failed; the peer asked to retry via relay, but no relay is available on this side",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapRelayErr(tc.err)
			if got.Error() != tc.wantMsg {
				t.Fatalf("Error() = %q, want %q", got.Error(), tc.wantMsg)
			}
			if !errors.Is(got, tc.wantIs) {
				t.Fatalf("errors.Is(%v, %v) = false, want true (errors.Is/As traversal must survive mapping)", got, tc.wantIs)
			}
		})
	}
}

// TestMapRelayErr_ContextCancellationPassesThrough checks that mapRelayErr
// doesn't wrap (or otherwise reword) a plain context cancellation — that's
// the caller's business, not a relay-consent outcome.
func TestMapRelayErr_ContextCancellationPassesThrough(t *testing.T) {
	if got := mapRelayErr(context.Canceled); got != context.Canceled {
		t.Fatalf("mapRelayErr(context.Canceled) = %v, want unchanged", got)
	}
	if got := mapRelayErr(context.DeadlineExceeded); got != context.DeadlineExceeded {
		t.Fatalf("mapRelayErr(context.DeadlineExceeded) = %v, want unchanged", got)
	}
}

// TestMapRelayErr_UnrelatedErrorPassesThrough checks that an error outside
// the relay-consent sentinel set (e.g. a genuine attempt-2 connection
// failure) is returned unchanged.
func TestMapRelayErr_UnrelatedErrorPassesThrough(t *testing.T) {
	original := errors.New("webrtc connection timed out")
	if got := mapRelayErr(original); got != original {
		t.Fatalf("mapRelayErr(unrelated) = %v, want unchanged", got)
	}
}
