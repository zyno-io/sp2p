// SPDX-License-Identifier: MIT

package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

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
}

// Send performs the send flow.
func Send(ctx context.Context, cfg SendConfig) error {
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
	}, handler)
}

// promptRelay asks the user whether to allow TURN relay.
// It opens /dev/tty directly so it works even when stdin is piped.
// Returns false if no TTY is available.
func promptRelay() bool {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return false
	}
	defer tty.Close()

	// Check that the TTY is actually readable (not EOF) before printing
	// the prompt. In environments like Docker without -t, /dev/tty may
	// open successfully but read returns EOF immediately.
	// Use a non-blocking peek via bufio.Scanner on the tty: we print the
	// prompt first, then scan. If scan fails (EOF), the prompt is still
	// preserved because we print a trailing newline.
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  Could not establish a direct connection.\n")
	fmt.Fprintf(os.Stderr, "  A TURN relay is available — data stays E2E encrypted.\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  Allow relay? [y/N]: ")

	scanner := bufio.NewScanner(tty)
	if scanner.Scan() {
		answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
		return answer == "y" || answer == "yes"
	}
	// Scanner failed (EOF / no TTY input). Print newline so the cursor
	// moves off the prompt line and Resume() doesn't erase it.
	fmt.Fprintf(os.Stderr, "\n")
	return false
}
