// SPDX-License-Identifier: MIT

//go:build !windows

package cli

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/zyno-io/sp2p/internal/tunnel"
	"golang.org/x/sys/unix"
)

func TestStdioSocketHalfClosePreservesResponse(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	input := os.NewFile(uintptr(fds[0]), "helper-stdin")
	defer input.Close()
	peerFile := os.NewFile(uintptr(fds[1]), "rsync")
	defer peerFile.Close()
	outputFD, err := unix.Dup(fds[0])
	if err != nil {
		t.Fatal(err)
	}
	output := os.NewFile(uintptr(outputFD), "helper-stdout")
	defer output.Close()
	peer, err := net.FileConn(peerFile)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(2 * time.Second))
	endpoint, err := newStdioEndpoint(input, output)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	if err := endpoint.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := peer.Read(data[:]); err != io.EOF {
		t.Fatalf("peer must see EOF while stdin stays open: %v", err)
	}
	if _, err := peer.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(endpoint, data[:]); err != nil || data[0] != 'x' {
		t.Fatalf("incoming direction was closed: %v", err)
	}
}

func TestStdioPipeHalfClose(t *testing.T) {
	input, feed := inheritedStdioPipe(t)
	reader, output := inheritedStdioPipe(t)
	endpoint, err := newStdioEndpoint(input, output)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	if err := endpoint.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := reader.Read(data[:]); err != io.EOF {
		t.Fatalf("pipe did not close: %v", err)
	}
	if _, err := feed.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(endpoint, data[:]); err != nil || data[0] != 'x' {
		t.Fatalf("input after half-close: %v", err)
	}
}

// os.Pipe registers with Go's poller itself. Use raw descriptors to reproduce
// the blocking handles inherited from a shell instead.
func inheritedStdioPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatal(err)
	}
	input := os.NewFile(uintptr(fds[0]), "inherited-input")
	output := os.NewFile(uintptr(fds[1]), "inherited-output")
	t.Cleanup(func() { input.Close(); output.Close() })
	return input, output
}

type stdioTestStream struct{ net.Conn }

func (s stdioTestStream) CloseWrite() error { return nil }

func TestStdioBridgeCancellationWithIdleInput(t *testing.T) {
	input, feed := inheritedStdioPipe(t)
	_, output := inheritedStdioPipe(t)
	endpoint, err := newStdioEndpoint(input, output)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	if err := endpoint.in.file.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("input is not interruptible: %v", err)
	}
	conn, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- tunnel.Bridge(ctx, stdioTestStream{conn}, endpoint) }()
	// Observe real traffic before canceling while the input writer stays open.
	if _, err := feed.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	var data [1]byte
	if _, err := io.ReadFull(peer, data[:]); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Bridge() = %v", err)
		}
	case <-time.After(2 * time.Second):
		feed.Close()
		t.Fatal("bridge cancellation hung on idle inherited stdin")
	}
}

func TestStdioCloseInterruptsBlockedOutputAndRestoresFlags(t *testing.T) {
	input, _ := inheritedStdioPipe(t)
	_, output := inheritedStdioPipe(t)
	// Retain duplicates to inspect the flags shared with the original shell.
	var observers []*os.File
	for _, original := range []*os.File{input, output} {
		fd, err := unix.Dup(int(original.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		observer := os.NewFile(uintptr(fd), "shell-observer")
		defer observer.Close()
		observers = append(observers, observer)
	}
	endpoint, err := newStdioEndpoint(input, output)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	if err := endpoint.out.file.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("output is not interruptible: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := endpoint.Write(make([]byte, 4*1024*1024)); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("write should block on full pipe: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("blocked write = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not unblock inherited stdout")
	}
	for _, observer := range observers {
		flags, err := unix.FcntlInt(observer.Fd(), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_NONBLOCK != 0 {
			t.Fatalf("shell descriptor left nonblocking: flags=%x err=%v", flags, err)
		}
	}
}
