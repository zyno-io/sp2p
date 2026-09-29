// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/zyno-io/sp2p/internal/conn"
)

// TestReadRelayAnswer_CancelReturnsPromptlyWithoutClosing checks that
// readRelayAnswer returns the instant ctx is canceled, even though nothing
// is ever written to the read side and the underlying reader is never
// closed to interrupt it (see readRelayAnswer's doc comment: closing the fd
// out from under a blocked read is not reliable on every platform, so this
// must not depend on it).
func TestReadRelayAnswer_CancelReturnsPromptlyWithoutClosing(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// Never write to w and never close it here: a correct readRelayAnswer
	// must return on ctx cancellation alone, without relying on the reader
	// unblocking. Close it now so the leaked background goroutine (see the
	// doc comment: it outlives a canceled call until the read itself
	// returns) unblocks with EOF once this test is done, instead of
	// leaking for the rest of the test binary's run.
	t.Cleanup(func() { w.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	start := time.Now()
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	answer := readRelayAnswer(ctx, r)
	if answer != conn.RelayUnavailable {
		t.Fatalf("answer = %v, want RelayUnavailable", answer)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("readRelayAnswer took %v to return after cancellation, want well under 1s", elapsed)
	}
}

// TestReadRelayAnswer_LateAnswerIsDiscarded checks that a real answer which
// arrives after the caller already gave up on cancellation is never
// observable: readRelayAnswer must have already returned, and writing to
// the pipe afterward must not panic or block anything (resultCh is
// buffered, so the leaked goroutine's send always succeeds).
func TestReadRelayAnswer_LateAnswerIsDiscarded(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled: readRelayAnswer must not block at all
	answer := readRelayAnswer(ctx, r)
	if answer != conn.RelayUnavailable {
		t.Fatalf("answer = %v, want RelayUnavailable", answer)
	}

	// The "late" answer: nothing reads it, and this must not hang or panic.
	done := make(chan struct{})
	go func() {
		w.Write([]byte("y\n"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("writing the late answer blocked")
	}
}

// TestReadRelayAnswer_ReadsAnswers checks the three real outcomes: allow,
// deny, and unavailable (EOF/closed input) — all returned promptly with an
// uncanceled context.
func TestReadRelayAnswer_ReadsAnswers(t *testing.T) {
	cases := []struct {
		name  string
		input string
		close bool
		want  conn.RelayAnswer
	}{
		{name: "yes", input: "y\n", want: conn.RelayAllow},
		{name: "YES", input: "YES\n", want: conn.RelayAllow},
		{name: "no", input: "n\n", want: conn.RelayDeny},
		{name: "garbage treated as deny", input: "sure\n", want: conn.RelayDeny},
		{name: "EOF", input: "", close: true, want: conn.RelayUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				if tc.input != "" {
					w.Write([]byte(tc.input))
				}
				if tc.close {
					w.Close()
				}
			}()
			if !tc.close {
				defer w.Close()
			}

			result := make(chan conn.RelayAnswer, 1)
			go func() { result <- readRelayAnswer(context.Background(), r) }()
			select {
			case answer := <-result:
				if answer != tc.want {
					t.Fatalf("answer = %v, want %v", answer, tc.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("readRelayAnswer did not return")
			}
		})
	}
}
