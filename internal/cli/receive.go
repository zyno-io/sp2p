// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/zyno-io/sp2p/internal/flow"
)

// ReceiveConfig holds configuration for the receive command.
type ReceiveConfig struct {
	ServerURL     string // WebSocket URL for signaling server
	Code          string // Full transfer code (SESSION_ID-SEED)
	OutputDir     string // Output directory (default: current dir)
	Stdout        bool   // Write to stdout instead of file
	RelayOK       bool   // Allow TURN relay without prompting
	Verbose       bool   // Enable verbose diagnostic output
	ClientVersion string // Client version for update check
}

// Receive performs the receive flow.
func Receive(ctx context.Context, cfg ReceiveConfig) error {
	progress := NewProgress(os.Stderr, false, cfg.Verbose)
	progress.StartTicker()
	defer progress.Stop()

	flowCfg := flow.ReceiveConfig{
		ServerURL:     cfg.ServerURL,
		Code:          cfg.Code,
		OutputDir:     cfg.OutputDir,
		RelayOK:       cfg.RelayOK,
		ClientVersion: cfg.ClientVersion,
	}
	if cfg.Stdout {
		flowCfg.Writer = os.Stdout
	}

	result, err := flow.Receive(ctx, flowCfg, &cliHandler{progress: progress})
	if err != nil {
		return err
	}

	// Print save location (CLI-specific output).
	if !cfg.Stdout && result.SavedPath != "" {
		if result.Metadata.IsFolder {
			fmt.Fprintf(os.Stderr, "  Extracted to: %s/\n", result.SavedPath)
		} else {
			fmt.Fprintf(os.Stderr, "  Saved to: %s\n", result.SavedPath)
		}
	}

	return nil
}
