// SPDX-License-Identifier: MIT

//go:build darwin

package cli

import "golang.org/x/sys/unix"

const (
	ioctlGetTermios = unix.TIOCGETA
	ioctlSetTermios = unix.TIOCSETA
)
