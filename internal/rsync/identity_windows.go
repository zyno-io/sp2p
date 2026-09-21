// SPDX-License-Identifier: MIT

//go:build windows

package rsync

// Rsync serving is rejected on Windows before a daemon config is created.
func effectiveIdentity() (string, string) {
	return "", ""
}
