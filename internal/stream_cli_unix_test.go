// SPDX-License-Identifier: MIT

//go:build !windows

package internal

import (
	"context"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestStreamCLIStdioCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess integration")
	}
	binary := buildBinary(t)
	wsURL := startSignalServer(t)
	for _, role := range []string{"serve", "connect"} {
		for _, signal := range []os.Signal{os.Interrupt, syscall.SIGTERM, os.Kill} {
			t.Run(role+"/"+signal.String(), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				// Both input writers stay open and idle until after exit. Passing
				// files directly recreates stdio inherited from a shell pipe.
				inputs := make([]*os.File, 2)
				for i := range inputs {
					input, feed, err := os.Pipe()
					if err != nil {
						t.Fatal(err)
					}
					defer input.Close()
					defer feed.Close()
					inputs[i] = input
				}
				provider := startStreamCLIWithIO(t, ctx, binary, inputs[0], io.Discard,
					"tunnel", "serve", "--server", wsURL, "--transport", "tcp", "--format", "json", "--event-output", "stderr", "--stdio")
				code := provider.event(t, ctx, "session").Code
				connector := startStreamCLIWithIO(t, ctx, binary, inputs[1], io.Discard,
					"tunnel", "connect", "--server", wsURL, "--transport", "tcp", "--format", "json", "--event-output", "stderr", "--stdio", code)
				// Progress is emitted after setup while both pumps wait on input.
				provider.event(t, ctx, "progress")
				connector.event(t, ctx, "progress")
				target, peer := provider, connector
				if role == "connect" {
					target, peer = connector, provider
				}
				if err := target.process.Signal(signal); err != nil {
					t.Fatal(err)
				}
				exitCtx, stop := context.WithTimeout(ctx, 5*time.Second)
				defer stop()
				if signal == os.Kill {
					select {
					case <-target.done:
					case <-exitCtx.Done():
						t.Fatal("killed command did not exit")
					}
				} else {
					target.failed(t, exitCtx)
				}
				// A killed peer sends no abort; transport closure must still
				// cancel an idle stdio bridge and produce its terminal result.
				peer.failed(t, exitCtx)
			})
		}
	}
}
