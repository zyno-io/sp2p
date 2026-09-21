// SPDX-License-Identifier: MIT

package cli

import (
	"io"
	"os"
	"testing"
)

func TestWindowsStdioRedirectedPipeHalfClose(t *testing.T) {
	input, feed, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer feed.Close()
	reader, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	endpoint, err := newStdioEndpoint(input, output)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	if endpoint.in != input {
		t.Fatal("redirected pipe was wrapped as a console")
	}
	if err := endpoint.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := reader.Read(data[:]); err != io.EOF {
		t.Fatalf("output pipe did not receive EOF: %v", err)
	}
	if _, err := feed.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(endpoint, data[:]); err != nil || data[0] != 'x' {
		t.Fatalf("input after output half-close: %v", err)
	}
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
}
