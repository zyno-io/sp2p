// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestAgentPromptClearedWithShareDisplay(t *testing.T) {
	for _, qr := range []bool{false, true} {
		for _, next := range []string{"peer", "transfer", "error", "complete"} {
			t.Run(fmt.Sprintf("qr=%t/%s", qr, next), func(t *testing.T) {
				screen := &progressScreen{width: termWidth()}
				fmt.Fprintln(screen, "Sender heading")
				p := NewProgress(screen, true, false)
				p.SetPhase(PhaseRegistered)
				p.ShowCode("abcdefgh-0123456789012345678901234567890123456789012345678901", "https://sp2p.io")
				if qr {
					p.ToggleQR()
				}
				if !strings.Contains(screen.String(), "AI Agent:") {
					t.Fatal("waiting display lost the agent prompt")
				}
				// Permanent notices must not strand the prompt in scrollback.
				p.ShowWarning("Example notice")
				switch next {
				case "peer":
					p.SetPhase(PhasePeerJoined)
				case "transfer":
					p.SetPhase(PhaseConnected)
					p.SetTransfer("example.txt", 100, 1)
				case "error":
					p.SetError("Example failure")
				case "complete":
					p.ShowComplete(100, time.Second)
				}
				visible := screen.String()
				if strings.Contains(visible, "AI Agent:") || strings.Contains(visible, "/llm") || strings.Contains(visible, "0123456789") {
					t.Fatal("agent prompt remains after leaving the waiting display")
				}
				if !strings.Contains(visible, "Sender heading") || !strings.Contains(visible, "WARNING: Example notice") {
					t.Fatal("clearing the prompt erased permanent output")
				}
			})
		}
	}
}

func TestAgentPromptWrapPreservesFullText(t *testing.T) {
	prompt := "  " + agentPrompt(strings.Repeat("a", 64), "https://sp2p.io")
	for _, width := range []int{40, 80, 200} {
		var buf bytes.Buffer
		writeWrappedLine(&buf, prompt, width)
		if strings.ReplaceAll(buf.String(), "\n", "") != prompt {
			t.Fatal("wrapping truncated or changed the agent prompt")
		}
		for _, row := range strings.Split(buf.String(), "\n") {
			if utf8.RuneCountInString(row) > width {
				t.Fatal("prompt row would wrap without being counted")
			}
		}
	}
}

// progressScreen interprets the cursor movement, line clearing and deferred
// wrapping used by Progress, so assertions inspect visible text, not raw writes.
// QR blocks and the spinner each occupy one terminal cell.
type progressScreen struct {
	width, x, y int
	rows        [][]rune
}

func (s *progressScreen) Write(data []byte) (int, error) {
	text := string(data)
	for len(text) > 0 {
		if strings.HasPrefix(text, "\x1b[") {
			end := strings.IndexAny(text, "AKm")
			if end < 0 {
				panic("unsupported terminal escape")
			}
			switch text[end] {
			case 'A':
				s.y--
			case 'K':
				s.rows[s.y] = nil
			}
			text = text[end+1:]
			continue
		}
		r, size := utf8.DecodeRuneInString(text)
		text = text[size:]
		switch r {
		case '\r':
			s.x = 0
		case '\n':
			s.x = 0
			s.y++
		default:
			if s.x == s.width {
				s.x = 0
				s.y++
			}
			for len(s.rows) <= s.y {
				s.rows = append(s.rows, nil)
			}
			for len(s.rows[s.y]) <= s.x {
				s.rows[s.y] = append(s.rows[s.y], ' ')
			}
			s.rows[s.y][s.x] = r
			s.x++
		}
		for len(s.rows) <= s.y {
			s.rows = append(s.rows, nil)
		}
	}
	return len(data), nil
}

func (s *progressScreen) String() string {
	var buf strings.Builder
	for _, row := range s.rows {
		buf.WriteString(string(row))
		buf.WriteByte('\n')
	}
	return buf.String()
}
