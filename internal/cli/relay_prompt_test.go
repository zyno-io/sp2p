// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"io"
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

// blockingReadCloser is a custom io.ReadCloser whose Read blocks until
// release is signaled (simulating a human who hasn't answered yet) and
// whose Close signals closed. It exists to detect whether
// readRelayAnswer's background goroutine actually exits — by successfully
// sending on resultCh and returning, which runs its deferred tty.Close() —
// once ctx is canceled and the blocked read is then allowed to complete.
//
// Writing a couple of bytes to a real os.Pipe (the previous approach) can't
// tell an unbuffered resultCh from a buffered one: the kernel pipe buffer
// (tens of KB) absorbs a two-byte write immediately regardless of whether
// anything ever drains resultCh, so that write completing proves nothing
// about the goroutine. Close only runs once the goroutine's send on
// resultCh has actually completed (it's deferred, so it runs last), so
// observing Close is direct evidence the goroutine returned instead of
// blocking forever trying to send to an unbuffered, unread channel.
type blockingReadCloser struct {
	release chan struct{}
	closed  chan struct{}
	data    []byte
	sent    bool
}

func newBlockingReadCloser(data string) *blockingReadCloser {
	return &blockingReadCloser{
		release: make(chan struct{}),
		closed:  make(chan struct{}),
		data:    []byte(data),
	}
}

func (b *blockingReadCloser) Read(p []byte) (int, error) {
	<-b.release
	if b.sent {
		return 0, io.EOF
	}
	b.sent = true
	return copy(p, b.data), nil
}

func (b *blockingReadCloser) Close() error {
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

// TestReadRelayAnswer_GoroutineExitsAfterCancelAndRelease is the regression
// guard for a leaked reader goroutine that can never exit: it checks that,
// after ctx is canceled (so readRelayAnswer itself returns immediately,
// without waiting on the read at all) and the blocked read is then
// released, the background goroutine still runs to completion — evidenced
// by its deferred tty.Close(). With an unbuffered resultCh, the goroutine's
// send blocks forever (nothing reads resultCh once readRelayAnswer has
// already returned), so Close never happens and this test times out —
// verified by temporarily making resultCh unbuffered.
func TestReadRelayAnswer_GoroutineExitsAfterCancelAndRelease(t *testing.T) {
	tty := newBlockingReadCloser("y\n")

	ctx, cancel := context.WithCancel(context.Background())
	start := time.Now()
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	answer := readRelayAnswer(ctx, tty)
	if answer != conn.RelayUnavailable {
		t.Fatalf("answer = %v, want RelayUnavailable", answer)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("readRelayAnswer took %v to return after cancellation, want well under 1s", elapsed)
	}

	// The background goroutine must still be blocked in Read (release not
	// yet signaled) — it must not have closed tty already.
	select {
	case <-tty.closed:
		t.Fatal("tty closed before the blocked read was released")
	default:
	}

	// Let the blocked read complete so the goroutine can produce its
	// answer and, via its deferred tty.Close(), signal that it returned.
	close(tty.release)
	select {
	case <-tty.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("reader goroutine did not exit after release — resultCh send may be blocking forever")
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
