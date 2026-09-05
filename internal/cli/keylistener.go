// SPDX-License-Identifier: MIT

//go:build !windows

package cli

import (
	"os"

	"golang.org/x/sys/unix"
)

// KeyListener reads single keypresses from /dev/tty in cbreak mode and
// sends them on a channel. Returns nil from NewKeyListener if the TTY
// is unavailable (e.g. Docker without -t, CI).
type KeyListener struct {
	tty      *os.File
	oldState unix.Termios
	Keys     chan byte
	done     chan struct{}
	stopped  chan struct{}
}

// NewKeyListener opens /dev/tty in cbreak mode and starts reading keys.
// Unlike full raw mode, cbreak preserves output processing (OPOST) so
// \n→\r\n translation continues working for stderr output, and keeps
// ISIG so Ctrl+C delivers SIGINT normally.
// Returns nil if the TTY cannot be opened or configured.
func NewKeyListener() *KeyListener {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return nil
	}
	fd := int(tty.Fd())

	oldState, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		tty.Close()
		return nil
	}

	cbreak := *oldState
	cbreak.Lflag &^= unix.ECHO | unix.ICANON // no echo, char-at-a-time
	// A short read timeout lets Stop wait for readLoop to exit. Closing a
	// terminal file descriptor from a different goroutine does not reliably
	// interrupt a blocked read on every Unix platform.
	cbreak.Cc[unix.VMIN] = 0
	cbreak.Cc[unix.VTIME] = 1 // deciseconds

	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &cbreak); err != nil {
		tty.Close()
		return nil
	}

	kl := &KeyListener{
		tty:      tty,
		oldState: *oldState,
		Keys:     make(chan byte, 8),
		done:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	go kl.readLoop()
	return kl
}

func (kl *KeyListener) readLoop() {
	defer close(kl.stopped)

	buf := make([]byte, 1)
	for {
		select {
		case <-kl.done:
			return
		default:
		}

		n, err := kl.tty.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		select {
		case kl.Keys <- buf[0]:
		case <-kl.done:
			return
		}
	}
}

// Done returns a channel that is closed when the key listener is stopped.
func (kl *KeyListener) Done() <-chan struct{} {
	return kl.done
}

// Stop restores the terminal state and closes the TTY file.
func (kl *KeyListener) Stop() {
	select {
	case <-kl.done:
		return // already stopped
	default:
		close(kl.done)
	}
	<-kl.stopped
	unix.IoctlSetTermios(int(kl.tty.Fd()), ioctlSetTermios, &kl.oldState)
	kl.tty.Close()
}
