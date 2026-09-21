// SPDX-License-Identifier: MIT

//go:build !windows

package rsync

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"time"
)

func configureProcessGroup(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func waitCommand(ctx context.Context, command *exec.Cmd) error {
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// A peer's terminal failure can cancel this context just as rsync is
		// naturally reporting its own useful nonzero status (for example a
		// missing source). Give that exit a short chance to win before TERM.
		select {
		case err := <-done:
			if err != nil {
				return err
			}
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
		terminateProcessGroup(command.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
			// The group leader can exit while a helper survives. Retain the
			// process-group boundary until the grace period expires, then kill
			// any descendants which ignored TERM.
			if processGroupExists(command.Process.Pid) {
				time.Sleep(2 * time.Second)
				terminateProcessGroup(command.Process.Pid, syscall.SIGKILL)
			}
			return ctx.Err()
		case <-time.After(2 * time.Second):
			terminateProcessGroup(command.Process.Pid, syscall.SIGKILL)
			<-done
			return ctx.Err()
		}
	}
}

func processGroupExists(pid int) bool {
	err := syscall.Kill(-pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func terminateProcessGroup(pid int, signal syscall.Signal) {
	// A process can exit between Start and cancellation; ESRCH is harmless.
	err := syscall.Kill(-pid, signal)
	if err != nil && !errors.Is(err, syscall.ESRCH) {
		return
	}
}
