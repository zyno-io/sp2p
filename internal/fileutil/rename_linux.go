// SPDX-License-Identifier: MIT

package fileutil

import "golang.org/x/sys/unix"

// RenameNoReplace atomically publishes a path without replacing any target.
func RenameNoReplace(from, to string) error {
	return unix.Renameat2(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_NOREPLACE)
}
