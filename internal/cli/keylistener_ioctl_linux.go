// SPDX-License-Identifier: MIT

//go:build linux

package cli

import "golang.org/x/sys/unix"

const (
	ioctlGetTermios = unix.TCGETS
	ioctlSetTermios = unix.TCSETS
)
