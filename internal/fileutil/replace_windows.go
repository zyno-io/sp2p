// SPDX-License-Identifier: MIT

package fileutil

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// replaceRetryLimit bounds how long ReplaceFile waits for readers to close
// the target.
const replaceRetryLimit = 500 * time.Millisecond

// ReplaceFile atomically replaces to with from. Windows refuses to replace a
// file another process has open without delete sharing (Go opens files that
// way), so a concurrent reader makes the rename fail transiently; retry
// briefly, as Go's own cmd/internal/robustio does.
func ReplaceFile(from, to string) error {
	deadline := time.Now().Add(replaceRetryLimit)
	delay := time.Millisecond
	for {
		err := os.Rename(from, to)
		if err == nil || !transientReplaceError(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(delay)
		if delay < 20*time.Millisecond {
			delay *= 2
		}
	}
}

func transientReplaceError(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
