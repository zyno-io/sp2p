// SPDX-License-Identifier: MIT

package fileutil

import "golang.org/x/sys/windows"

// RenameNoReplace atomically publishes a path without replacing any target.
func RenameNoReplace(from, to string) error {
	f, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFile(f, t)
}
