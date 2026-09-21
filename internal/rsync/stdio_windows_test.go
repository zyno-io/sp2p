// SPDX-License-Identifier: MIT

//go:build windows

package rsync

func (s *testStdioEndpoint) CloseWrite() error { return s.out.Close() }
