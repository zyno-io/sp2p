// SPDX-License-Identifier: MIT

package cli

import (
	"fmt"
	"strings"
	"unicode"
)

// terminalText escapes remote-origin controls while retaining ordinary Unicode.
// UI-owned ANSI sequences must never pass through this function.
func terminalText(s string) string { return SanitizeTerminalText(s) }

// SanitizeTerminalText is also used by the command's final error reporter.
func SanitizeTerminalText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			fmt.Fprintf(&b, "\\u%04x", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
