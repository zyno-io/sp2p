// SPDX-License-Identifier: MIT

package cli

import (
	"errors"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestStdioTerminalHalfCloseAndCancellation(t *testing.T) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	for _, request := range []uint{unix.TIOCPTYGRANT, unix.TIOCPTYUNLK} {
		if err := unix.IoctlSetInt(int(master.Fd()), request, 0); err != nil {
			t.Fatal(err)
		}
	}
	var name [128]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, master.Fd(), unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0])))
	if errno != 0 {
		t.Fatal(errno)
	}
	fd, err := unix.Open(unix.ByteSliceToString(name[:]), unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	input := os.NewFile(uintptr(fd), "terminal-stdin")
	defer input.Close()
	var copies []*os.File
	for range 2 {
		duplicate, err := unix.Dup(fd)
		if err != nil {
			t.Fatal(err)
		}
		file := os.NewFile(uintptr(duplicate), "terminal-duplicate")
		defer file.Close()
		copies = append(copies, file)
	}
	endpoint, err := newStdioEndpoint(input, copies[0])
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	if err := endpoint.in.file.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("terminal is not interruptible: %v", err)
	}
	if err := endpoint.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(copies[1].Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		t.Fatalf("terminal input became blocking after output EOF: flags=%x err=%v", flags, err)
	}
	done := make(chan error, 1)
	go func() {
		var data [1]byte
		_, err := endpoint.Read(data[:])
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("terminal read should wait for input: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	closed := make(chan error, 1)
	go func() { closed <- endpoint.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		master.Close()
		t.Fatal("terminal close hung on idle input")
	}
	if err := <-done; !errors.Is(err, os.ErrClosed) {
		t.Fatalf("terminal read = %v", err)
	}
	flags, err = unix.FcntlInt(copies[1].Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK != 0 {
		t.Fatalf("terminal flags were not restored: flags=%x err=%v", flags, err)
	}
}
