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
	ServerURL       string // WebSocket URL for signaling server
	Code            string // Full transfer code (SESSION_ID-SEED)
	OutputDir       string // Output directory (default: current dir)
	Stdout          bool   // Write to stdout instead of file
	RelayOK         bool   // Allow TURN relay without prompting
	Verbose         bool   // Enable verbose diagnostic output
	ClientVersion   string // Client version for update check
	Transport       string // conn.TransportAuto, conn.TransportTCP, or conn.TransportWebRTC
	Parallel        int    // connections: 0=auto, 1=single, 2-6=request count (WebRTC max 4)
	Output          OutputConfig
	MaxReceiveBytes uint64
	MaxExtractBytes uint64
}

// Receive performs the receive flow.
func Receive(ctx context.Context, cfg ReceiveConfig) error {
	if cfg.Output.isMachine() {
		return receiveMachine(ctx, cfg)
	}

	progress := NewProgress(os.Stderr, false, cfg.Verbose)
	progress.StartTicker()
	defer progress.Stop()

	flowCfg := flow.ReceiveConfig{
		MaxReceiveBytes: cfg.MaxReceiveBytes, MaxExtractBytes: cfg.MaxExtractBytes,
		ServerURL:     cfg.ServerURL,
		Code:          cfg.Code,
		OutputDir:     cfg.OutputDir,
		RelayOK:       cfg.RelayOK,
		ClientVersion: cfg.ClientVersion,
		Transport:     cfg.Transport,
		Parallel:      cfg.Parallel,
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
			fmt.Fprintf(os.Stderr, "  Extracted to: %s/\n", terminalText(result.SavedPath))
		} else {
			fmt.Fprintf(os.Stderr, "  Saved to: %s\n", terminalText(result.SavedPath))
		}
	}

	return nil
}

func receiveMachine(ctx context.Context, cfg ReceiveConfig) error {
	reporter := newMachineReporter(ctx, cfg.Output, "receive", cfg.Verbose)
	flowCfg := flow.ReceiveConfig{
		MaxReceiveBytes: cfg.MaxReceiveBytes, MaxExtractBytes: cfg.MaxExtractBytes,
		ServerURL:     cfg.ServerURL,
		Code:          cfg.Code,
		OutputDir:     cfg.OutputDir,
		RelayOK:       cfg.RelayOK,
		ClientVersion: cfg.ClientVersion,
		Transport:     cfg.Transport,
		Parallel:      cfg.Parallel,
	}
	if cfg.Stdout {
		flowCfg.Writer = os.Stdout
	}

	result, err := flow.Receive(ctx, flowCfg, reporter)
	savedPath := ""
	if result != nil {
		savedPath = result.SavedPath
	}
	reporter.finish(err, savedPath)
	if err != nil {
		return reportedMachineError(err)
	}
	return nil
}
