// SPDX-License-Identifier: MIT

//go:build !windows

package fileutil

import "os"

// ReplaceFile atomically replaces to with from.
func ReplaceFile(from, to string) error { return os.Rename(from, to) }
