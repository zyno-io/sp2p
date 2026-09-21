// SPDX-License-Identifier: MIT

//go:build windows

package rsync

import (
	"context"
	"os/exec"
)

func configureProcessGroup(command *exec.Cmd) {}

func waitCommand(ctx context.Context, command *exec.Cmd) error {
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = command.Process.Kill()
		<-done
		return ctx.Err()
	}
}
