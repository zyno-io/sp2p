// SPDX-License-Identifier: MIT

//go:build !windows

package rsync

import (
	"errors"
	"syscall"
)

func (s *testStdioEndpoint) CloseWrite() error {
	raw, err := s.out.SyscallConn()
	if err != nil {
		return err
	}
	var shutdownErr error
	if err := raw.Control(func(fd uintptr) {
		shutdownErr = syscall.Shutdown(int(fd), syscall.SHUT_WR)
	}); err != nil {
		return err
	}
	if shutdownErr != nil && !errors.Is(shutdownErr, syscall.ENOTSOCK) {
		return shutdownErr
	}
	return s.out.Close()
}
