// SPDX-License-Identifier: MIT
//go:build !linux && !darwin && !windows

package fileutil

import "fmt"

// RenameNoReplace refuses to weaken publication semantics on unsupported OSes.
func RenameNoReplace(from, to string) error {
	return fmt.Errorf("atomic no-replace publication is unsupported on this platform")
}
