// SPDX-License-Identifier: MIT

package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/flow"
)

// SendConfig holds configuration for the send command.
type SendConfig struct {
	ServerURL     string   // WebSocket URL for signaling server
	BaseURL       string   // Public base URL for display
	Paths         []string // File/folder paths, or ["-"] for stdin
	Name          string   // Override filename (useful for stdin)
	RelayOK       bool     // Allow TURN relay without prompting
	Verbose       bool     // Enable verbose diagnostic output
	ClientVersion string   // Client version for update check
	CompressLevel int      // zstd compression level (0=disabled, 1-9)
	Transport     string   // conn.TransportAuto, conn.TransportTCP, or conn.TransportWebRTC
	Parallel      int      // connections: 0=auto, 1=single, 2-6=request count (WebRTC auto uses up to 8)
	Output        OutputConfig
}

// Send performs the send flow.
func Send(ctx context.Context, cfg SendConfig) error {
	if cfg.Output.isMachine() {
		return sendMachine(ctx, cfg)
	}

	progress := NewProgress(os.Stderr, true, cfg.Verbose)
	progress.SetPhase(PhasePreparing)
	progress.StartTicker()
	defer progress.Stop()

	meta, reader, cleanup, err := flow.PrepareInput(cfg.Paths, cfg.Name)
	if err != nil {
		return err
	}
	defer cleanup()

	handler := &cliHandler{progress: progress}
	defer func() {
		if handler.keyListener != nil {
			handler.keyListener.Stop()
		}
	}()

	return flow.Send(ctx, flow.SendConfig{
		ServerURL:     cfg.ServerURL,
		BaseURL:       cfg.BaseURL,
		Meta:          meta,
		Reader:        reader,
		RelayOK:       cfg.RelayOK,
		ClientVersion: cfg.ClientVersion,
		CompressLevel: cfg.CompressLevel,
		Transport:     cfg.Transport,
		Parallel:      cfg.Parallel,
	}, handler)
}

func sendMachine(ctx context.Context, cfg SendConfig) error {
	reporter := newMachineReporter(ctx, cfg.Output, "send", cfg.Verbose)
	reporter.OnPhaseChanged(flow.Phase("preparing"))

	meta, reader, cleanup, err := flow.PrepareInput(cfg.Paths, cfg.Name)
	if err != nil {
		reporter.finish(err, "")
		return reportedMachineError(err)
	}
	defer cleanup()

	err = flow.Send(ctx, flow.SendConfig{
		ServerURL:     cfg.ServerURL,
		BaseURL:       cfg.BaseURL,
		Meta:          meta,
		Reader:        reader,
		RelayOK:       cfg.RelayOK,
		ClientVersion: cfg.ClientVersion,
		CompressLevel: cfg.CompressLevel,
		Transport:     cfg.Transport,
		Parallel:      cfg.Parallel,
	}, reporter)
	reporter.finish(err, "")
	if err != nil {
		return reportedMachineError(err)
	}
	return nil
}

// promptRelay asks the user whether to allow TURN relay. It opens /dev/tty
// directly so it works even when stdin is piped. Returns false if no TTY is
// available. Kept for the plain Handler.PromptRelay() bool contract; the
// interactive CLI itself uses the cancellable promptRelayTTY below.
func promptRelay() bool {
	return promptRelayTTY(context.Background()) == conn.RelayAllow
}

// promptRelayTTY asks the user whether to allow TURN relay, honoring ctx
// cancellation. It opens /dev/tty directly so it works even when stdin is
// piped. Returns Unavailable if no TTY is available, ctx is canceled before
// an answer arrives, or input hits EOF.
func promptRelayTTY(ctx context.Context) conn.RelayAnswer {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return conn.RelayUnavailable
	}

	// Check that the TTY is actually readable (not EOF) before printing
	// the prompt. In environments like Docker without -t, /dev/tty may
	// open successfully but read returns EOF immediately.
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  Could not establish a direct connection.\n")
	fmt.Fprintf(os.Stderr, "  A TURN relay is available — data stays E2E encrypted.\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  Allow relay? [y/N]: ")

	return readRelayAnswer(ctx, tty)
}

// readRelayAnswer reads one line from tty (expected to be a blocking
// character device such as /dev/tty) on a background goroutine and returns
// its y/n answer, or Unavailable promptly if ctx is canceled or the read
// hits EOF/error first.
//
// This deliberately does NOT rely on canceling ctx to close tty out from
// under the blocked read: that pattern (context.AfterFunc(ctx, tty.Close))
// does not reliably unblock a pending read on every platform. In
// particular, on macOS a /dev/tty character device can't be registered
// with the runtime's kqueue-based netpoller, so Go falls back to a plain
// blocking read syscall for it — closing the fd from another goroutine
// does not interrupt that blocked read (verified under `script`: still
// blocked 3+ seconds after the close).
//
// Instead, the read runs on its own goroutine that owns tty and closes it
// only once the read itself returns. If ctx fires first, this function
// returns immediately without waiting for (or ever using) that goroutine's
// eventual answer — resultCh is buffered so the goroutine's send never
// blocks, and nothing reads resultCh again after this function has
// returned, so a "late" answer (the user finally pressing enter well after
// the peer already decided) can never be acted on. The goroutine — and the
// open tty fd — may outlive this call until the user answers or the
// process exits; that's an accepted, bounded leak (at most one per
// canceled prompt), not an unbounded one.
func readRelayAnswer(ctx context.Context, tty io.ReadCloser) conn.RelayAnswer {
	resultCh := make(chan conn.RelayAnswer, 1)
	go func() {
		defer tty.Close()
		scanner := bufio.NewScanner(tty)
		if scanner.Scan() {
			answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if answer == "y" || answer == "yes" {
				resultCh <- conn.RelayAllow
				return
			}
			resultCh <- conn.RelayDeny
			return
		}
		resultCh <- conn.RelayUnavailable
	}()

	select {
	case answer := <-resultCh:
		if answer == conn.RelayUnavailable {
			// Scanner failed (EOF / no TTY input). Print a newline so the
			// cursor moves off the prompt line and Resume() doesn't erase it.
			fmt.Fprintf(os.Stderr, "\n")
		}
		return answer
	case <-ctx.Done():
		// The prompt line has no trailing newline yet (the user hasn't
		// answered); move the cursor off it before returning so a redraw
		// (e.g. progress.Resume()) doesn't corrupt it.
		fmt.Fprintf(os.Stderr, "\n")
		return conn.RelayUnavailable
	}
}
