// SPDX-License-Identifier: MIT

package cli

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

type blockedReadCloser struct {
	started chan struct{}
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (r *blockedReadCloser) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	return 0, io.EOF
}

func (r *blockedReadCloser) Close() error {
	close(r.closed)
	return nil
}

func TestInterruptibleConsoleInputCloseDoesNotWaitForRead(t *testing.T) {
	source := &blockedReadCloser{
		started: make(chan struct{}),
		release: make(chan struct{}),
		closed:  make(chan struct{}),
	}
	input := interruptibleConsoleInput(source)
	readDone := make(chan error, 1)
	go func() {
		var data [1]byte
		_, err := input.Read(data[:])
		readDone <- err
	}()
	select {
	case <-source.started:
	case <-time.After(time.Second):
		t.Fatal("console proxy did not start its source read")
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("proxy read = %v, want closed pipe", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closing console proxy did not unblock its reader")
	}
	select {
	case <-source.closed:
		t.Fatal("console source was closed while its read was still blocked")
	default:
	}
	close(source.release)
	select {
	case <-source.closed:
	case <-time.After(time.Second):
		t.Fatal("console source was not closed after its read returned")
	}
}
