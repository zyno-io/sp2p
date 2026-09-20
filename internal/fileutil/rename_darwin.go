// SPDX-License-Identifier: MIT

package fileutil

import "golang.org/x/sys/unix"

// RenameNoReplace atomically publishes a path without replacing any target.
func RenameNoReplace(from, to string) error { return unix.RenamexNp(from, to, unix.RENAME_EXCL) }
