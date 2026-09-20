// SPDX-License-Identifier: MIT

package cli

import "testing"

func TestTerminalText(t *testing.T) {
	if got := terminalText("résumé\x1b]52;c;abc\a\n\u202e"); got != "résumé\\u001b]52;c;abc\\u0007\\u000a\\u202e" {
		t.Fatalf("unsafe display: %q", got)
	}
}
