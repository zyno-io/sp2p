// SPDX-License-Identifier: MIT

package cli

import (
	"errors"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/windows"
)

type stdioEndpoint struct {
	in          io.ReadCloser
	out         *os.File
	mu          sync.Mutex
	closed      bool
	writeClosed bool
}

func newStdioEndpoint(input, output *os.File) (*stdioEndpoint, error) {
	var reader io.ReadCloser = input
	if isWindowsConsole(input) {
		reader = interruptibleConsoleInput(input)
	}
	return &stdioEndpoint{in: reader, out: output}, nil
}

func (s *stdioEndpoint) Read(p []byte) (int, error)  { return s.in.Read(p) }
func (s *stdioEndpoint) Write(p []byte) (int, error) { return s.out.Write(p) }

func (s *stdioEndpoint) CloseWrite() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.writeClosed {
		return nil
	}
	s.writeClosed = true
	return s.out.Close()
}

func (s *stdioEndpoint) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	inputErr := s.in.Close()
	if s.writeClosed {
		return inputErr
	}
	return errors.Join(inputErr, s.out.Close())
}

func isWindowsConsole(file *os.File) bool {
	raw, err := file.SyscallConn()
	if err != nil {
		return false
	}
	var mode uint32
	var consoleErr error
	if err := raw.Control(func(handle uintptr) {
		consoleErr = windows.GetConsoleMode(windows.Handle(handle), &mode)
	}); err != nil {
		return false
	}
	return consoleErr == nil
}
