// SPDX-License-Identifier: MIT

//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

type stdioHandle struct {
	original *os.File
	file     *os.File
	flags    int
	mode     os.FileMode
}

type stdioEndpoint struct {
	in, out      stdioHandle
	mu           sync.Mutex
	closed       bool
	writeClosed  bool
	outputClosed bool
}

// newStdioEndpoint takes ownership of input/output on success. Inherited Unix
// descriptors are normally blocking, so closing os.Stdin cannot wake its reader.
// Give Go's poller nonblocking duplicates, retaining the originals to restore
// shared flags only after all I/O on the duplicates has stopped.
func newStdioEndpoint(input, output *os.File) (*stdioEndpoint, error) {
	s := &stdioEndpoint{in: stdioHandle{original: input}, out: stdioHandle{original: output}}
	// Capture both sets of flags first: rsync can supply two descriptors for
	// the same socket, and O_NONBLOCK is shared by all its duplicates.
	for _, h := range []*stdioHandle{&s.in, &s.out} {
		if err := h.control(func(fd int) error {
			var err error
			h.flags, err = unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
			return err
		}); err != nil {
			return nil, fmt.Errorf("inspect stdio: %w", err)
		}
	}
	for _, h := range []*stdioHandle{&s.in, &s.out} {
		if err := h.prepare(); err != nil {
			for _, prepared := range []*stdioHandle{&s.in, &s.out} {
				if prepared.file != nil {
					prepared.file.Close()
				}
			}
			s.in.restore()
			s.out.restore()
			return nil, fmt.Errorf("prepare interruptible stdio: %w", err)
		}
	}
	return s, nil
}

func (h *stdioHandle) control(fn func(int) error) error {
	raw, err := h.original.SyscallConn()
	if err != nil {
		return err
	}
	var controlErr error
	if err := raw.Control(func(fd uintptr) { controlErr = fn(int(fd)) }); err != nil {
		return err
	}
	return controlErr
}

func (h *stdioHandle) prepare() error {
	info, err := h.original.Stat()
	if err != nil {
		return err
	}
	h.mode = info.Mode()
	return h.control(func(fd int) error {
		duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return err
		}
		// Regular files do not need readiness polling (and kqueue cannot
		// reliably poll them). Pipes, sockets, and terminals do.
		if !info.Mode().IsRegular() && !info.IsDir() {
			if err := unix.SetNonblock(duplicate, true); err != nil {
				unix.Close(duplicate)
				return err
			}
		}
		h.file = os.NewFile(uintptr(duplicate), h.original.Name())
		return nil
	})
}

func (h *stdioHandle) restore() error {
	return h.control(func(fd int) error {
		return unix.SetNonblock(fd, h.flags&unix.O_NONBLOCK != 0)
	})
}

func (s *stdioEndpoint) Read(p []byte) (int, error)  { return s.in.file.Read(p) }
func (s *stdioEndpoint) Write(p []byte) (int, error) { return s.out.file.Write(p) }

func (s *stdioEndpoint) CloseWrite() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.writeClosed {
		return nil
	}
	s.writeClosed = true
	err := s.out.control(func(fd int) error { return unix.Shutdown(fd, unix.SHUT_WR) })
	closeErr := s.out.file.Close()
	if errors.Is(err, unix.ENOTSOCK) {
		// A shell can duplicate one terminal description onto stdin and
		// stdout. Keep its flags until input stops; terminals need no EOF.
		if s.out.mode&os.ModeCharDevice != 0 {
			return closeErr
		}
		// A pipe needs every output descriptor closed to deliver EOF. Its
		// output description is separate from the input, so restore it now.
		s.outputClosed = true
		return errors.Join(closeErr, s.out.restore(), s.out.original.Close())
	}
	// Keep a socket's original for restoration at Close: resetting its flags
	// now would also make the still-active input direction blocking again.
	return errors.Join(err, closeErr)
}

func (s *stdioEndpoint) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	inputErr := s.in.file.Close()
	var outputErr error
	if !s.writeClosed {
		outputErr = s.out.file.Close()
	}
	// Closing pollable files joins their outstanding I/O. Restore shared flags
	// only after both directions have stopped, including duplicate sockets.
	inputErr = errors.Join(inputErr, s.in.restore(), s.in.original.Close())
	if !s.outputClosed {
		outputErr = errors.Join(outputErr, s.out.restore(), s.out.original.Close())
	}
	return errors.Join(inputErr, outputErr)
}
