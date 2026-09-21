// SPDX-License-Identifier: MIT

package cli

import (
	"errors"
	"io"
)

// Closing a Windows console handle does not reliably interrupt ReadConsole and
// can itself wait for that read forever. Relay console input through a pipe so
// Close can release the bridge immediately without injecting a synthetic key
// into its payload. The one-shot CLI may retain this goroutine until console
// input arrives or the process exits; once its read returns, it closes the
// original handle it owns.
func interruptibleConsoleInput(input io.ReadCloser) io.ReadCloser {
	reader, writer := io.Pipe()
	go func() {
		_, copyErr := io.Copy(writer, input)
		closeErr := input.Close()
		_ = writer.CloseWithError(errors.Join(copyErr, closeErr))
	}()
	return reader
}
