// SPDX-License-Identifier: MIT

//go:build windows

package cli

import (
	"os"

	"golang.org/x/sys/windows"
)

func init() {
	enableVirtualTerminal(os.Stderr)
	enableVirtualTerminal(os.Stdout)
}

func enableVirtualTerminal(f *os.File) {
	handle := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return
	}
	// ENABLE_VIRTUAL_TERMINAL_PROCESSING requires ENABLE_PROCESSED_OUTPUT.
	mode |= windows.ENABLE_PROCESSED_OUTPUT | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	windows.SetConsoleMode(handle, mode)
}
