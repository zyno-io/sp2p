// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	qrterminal "github.com/mdp/qrterminal/v3"
	"github.com/zyno-io/sp2p/internal/conn"
	"golang.org/x/term"
)

// Phase represents a step in the transfer lifecycle.
type Phase int

const (
	PhasePreparing Phase = iota
	PhaseInit
	PhaseRegistered
	PhasePeerJoined
	PhaseKeyExchange
	PhaseConnecting
	PhaseConnected
	PhaseTransferring
	PhaseDone
	PhaseError
)

var phaseLabels = map[Phase]string{
	PhasePreparing:    "Scanning files",
	PhaseInit:         "Connecting to signaling server",
	PhaseRegistered:   "Waiting for receiver",
	PhasePeerJoined:   "Receiver connected",
	PhaseKeyExchange:  "Exchanging encryption keys",
	PhaseConnecting:   "Establishing P2P connection",
	PhaseConnected:    "Secure channel established", // overridden in render() if connectedVia is set
	PhaseTransferring: "Transferring",
	PhaseDone:         "Transfer complete",
	PhaseError:        "Error",
}

var spinnerChars = []string{"◐", "◓", "◑", "◒"}

// ANSI escape sequences.
const (
	ansiCursorUp  = "\x1b[A"  // move cursor up one line
	ansiClearLine = "\x1b[2K" // clear entire current line
	ansiCR        = "\r"      // carriage return (move to column 0)
)

// Progress displays real-time transfer progress in the terminal.
type Progress struct {
	out          io.Writer
	mu           sync.Mutex
	phase        Phase
	methods      []conn.MethodStatus
	connectedVia string // connection method that won the race
	fileName     string
	fileSize     uint64
	fileCount    int
	bytes        uint64
	startTime    time.Time
	ticker       *time.Ticker
	done         chan struct{}
	spinIdx      int
	isSend       bool
	verbose      bool
	paused       bool
	errMsg       string
	showQR       bool
	qrURL        string
	shareCode    string // stored so render() can include share info
	shareBaseURL string
	lastLines    int // number of lines in last ephemeral render
}

// NewProgress creates a new progress display.
func NewProgress(out io.Writer, isSend bool, verbose bool) *Progress {
	return &Progress{
		out:     out,
		isSend:  isSend,
		verbose: verbose,
		done:    make(chan struct{}),
	}
}

// clearEphemeral moves the cursor up over the previous ephemeral render
// and clears those lines. After this call the cursor is at the start of
// where the next render should begin.
func (p *Progress) clearEphemeral() {
	if p.lastLines <= 0 {
		return
	}
	var buf bytes.Buffer
	// Move to start of current line and clear it.
	buf.WriteString(ansiCR + ansiClearLine)
	// Move up and clear each previous line.
	for i := 1; i < p.lastLines; i++ {
		buf.WriteString(ansiCursorUp + ansiClearLine)
	}
	p.out.Write(buf.Bytes())
	p.lastLines = 0
}

// SetPhase updates the current phase.
func (p *Progress) SetPhase(phase Phase) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// When transitioning to connected, finalize the connecting output
	// as permanent text so subsequent phases start with a clean slate.
	if phase == PhaseConnected {
		p.clearEphemeral()
		via := p.connectedVia
		if via == "" {
			via = "P2P"
		}
		fmt.Fprintf(p.out, "  Connected via %s\n\n", via)
	}
	// Reset QR display when leaving PhaseRegistered.
	if p.phase == PhaseRegistered && phase != PhaseRegistered {
		p.showQR = false
	}
	p.phase = phase
	p.render()
}

// SetQRURL stores the browser URL used for QR code generation.
func (p *Progress) SetQRURL(url string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.qrURL = url
}

// ToggleQR flips QR code visibility and re-renders.
func (p *Progress) ToggleQR() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.showQR = !p.showQR
	p.render()
}

// SetError sets the error state.
func (p *Progress) SetError(msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.phase = PhaseError
	p.errMsg = msg
	p.render()
}

// ResetMethods clears all method statuses for a fresh display on retry.
func (p *Progress) ResetMethods() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.methods = nil
	p.connectedVia = ""
}

// UpdateMethod updates a connection method status.
func (p *Progress) UpdateMethod(status conn.MethodStatus) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if status.State == "connected" && p.connectedVia == "" {
		p.connectedVia = status.Method
	}
	// Only update the display list while still connecting.
	if p.phase > PhaseConnecting {
		return
	}
	for i, m := range p.methods {
		if m.Method == status.Method {
			p.methods[i] = status
			p.render()
			return
		}
	}
	p.methods = append(p.methods, status)
	p.render()
}

// SetTransfer sets up the transfer display.
func (p *Progress) SetTransfer(name string, size uint64, fileCount int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fileName = name
	p.fileSize = size
	p.fileCount = fileCount
	p.startTime = time.Now()
	p.phase = PhaseTransferring
	p.render()
}

// UpdateBytes updates the byte counter.
func (p *Progress) UpdateBytes(n uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bytes = n
}

// StartTicker starts periodic screen updates for the progress bar.
func (p *Progress) StartTicker() {
	p.ticker = time.NewTicker(100 * time.Millisecond)
	go func() {
		for {
			select {
			case <-p.ticker.C:
				p.mu.Lock()
				if p.paused || p.showQR {
					p.mu.Unlock()
					continue
				}
				p.spinIdx = (p.spinIdx + 1) % len(spinnerChars)
				p.render()
				p.mu.Unlock()
			case <-p.done:
				return
			}
		}
	}()
}

// Stop stops the ticker.
func (p *Progress) Stop() {
	if p.ticker != nil {
		p.ticker.Stop()
	}
	select {
	case <-p.done:
	default:
		close(p.done)
	}
}

// ShowCode stores the transfer code and base URL. The share info will be
// rendered as part of the ephemeral display during PhaseRegistered so that
// toggling the QR code can cleanly replace it.
func (p *Progress) ShowCode(code, baseURL string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.shareCode = code
	p.shareBaseURL = baseURL
	p.qrURL = baseURL + "/r#" + code
	p.render()
}

// ShowVerifyCode displays the verification code as permanent output.
func (p *Progress) ShowVerifyCode(code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clearEphemeral()
	fmt.Fprintf(p.out, "  Verify: %s\n", code)
	p.render()
}

// ShowComplete displays the completion summary.
func (p *Progress) ShowComplete(totalBytes uint64, duration time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clearEphemeral()
	speed := float64(totalBytes) / duration.Seconds()
	verb := "sent"
	if !p.isSend {
		verb = "received"
	}
	fmt.Fprintf(p.out, "\n  Transfer complete\n")
	fmt.Fprintf(p.out, "  %s %s in %s (%s/s)\n",
		formatBytes(totalBytes), verb,
		formatDuration(duration),
		formatBytes(uint64(speed)))
	if p.isSend {
		fmt.Fprintf(p.out, "  Confirmed by receiver\n")
	}
	fmt.Fprintln(p.out)
}

// ShowUpdateNotice prints a permanent update notice above the spinner.
func (p *Progress) ShowUpdateNotice(currentVersion, serverVersion string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clearEphemeral()
	fmt.Fprintf(p.out, "  Update available: %s → %s\n", currentVersion, serverVersion)
	p.render()
}

// Log prints a timestamped verbose diagnostic line as permanent output above the spinner.
func (p *Progress) Log(msg string) {
	if !p.verbose {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clearEphemeral()
	ts := time.Now().Format("15:04:05.000")
	fmt.Fprintf(p.out, "  [%s] %s\n", ts, msg)
	p.render()
}

// Pause stops the ticker and clears the current render so the terminal
// is clean for prompts or other output.
func (p *Progress) Pause() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paused = true
	if p.ticker != nil {
		p.ticker.Stop()
	}
	p.clearEphemeral()
}

// Resume restarts the ticker and re-renders.
func (p *Progress) Resume() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paused = false
	p.ticker = time.NewTicker(100 * time.Millisecond)
	go func() {
		for {
			select {
			case <-p.ticker.C:
				p.mu.Lock()
				if p.paused {
					p.mu.Unlock()
					return
				}
				p.spinIdx = (p.spinIdx + 1) % len(spinnerChars)
				if !p.showQR {
					p.render()
				}
				p.mu.Unlock()
			case <-p.done:
				return
			}
		}
	}()
	p.render()
}

// render builds the ephemeral frame and writes it, tracking the line count
// so clearEphemeral can erase it before the next render.
func (p *Progress) render() {
	if p.paused {
		return
	}

	// Build the entire frame in a buffer, then flush in one write.
	var buf bytes.Buffer

	// Erase the previous ephemeral output.
	if p.lastLines > 0 {
		buf.WriteString(ansiCR + ansiClearLine)
		for i := 1; i < p.lastLines; i++ {
			buf.WriteString(ansiCursorUp + ansiClearLine)
		}
	}

	w := termWidth()

	// Mark where content starts so we can count lines.
	contentStart := buf.Len()

	switch p.phase {
	case PhasePreparing, PhaseInit, PhasePeerJoined, PhaseKeyExchange:
		label := phaseLabels[p.phase]
		icon := p.stateIcon(p.phase)
		fmt.Fprintf(&buf, "  %-45s %s", label, icon)

	case PhaseRegistered:
		if p.shareCode != "" {
			if p.showQR {
				renderQRTo(&buf, p.qrURL)
				fmt.Fprintf(&buf, "  (press q to hide)\n\n")
				fmt.Fprintf(&buf, "  %-45s %s", phaseLabels[p.phase], spinnerChars[p.spinIdx])
			} else {
				writeShareInfoTo(&buf, p.shareCode, p.shareBaseURL, p.qrURL != "", w)
				fmt.Fprintf(&buf, "  %-45s %s", phaseLabels[p.phase], spinnerChars[p.spinIdx])
			}
		} else {
			label := phaseLabels[p.phase]
			icon := p.stateIcon(p.phase)
			fmt.Fprintf(&buf, "  %-45s %s", label, icon)
		}

	case PhaseConnected:
		// Already printed as permanent output in SetPhase.

	case PhaseConnecting:
		fmt.Fprintf(&buf, "  Establishing P2P connection...  %s", spinnerChars[p.spinIdx])
		for _, m := range p.methods {
			icon := methodIcon(m.State)
			fmt.Fprintf(&buf, "\n    %s %s  %s", icon, m.Method, m.Detail)
		}

	case PhaseTransferring:
		renderProgressTo(&buf, p)

	case PhaseDone:
		// Handled by ShowComplete.

	case PhaseError:
		fmt.Fprintf(&buf, "  Error: %s", p.errMsg)
	}

	// Count lines in the content we just wrote.
	content := buf.Bytes()[contentStart:]
	p.lastLines = 1 + bytes.Count(content, []byte{'\n'})

	p.out.Write(buf.Bytes())
}

// writeShareInfoTo writes the share info block to a buffer.
// Lines are truncated to terminal width to prevent wrapping.
func writeShareInfoTo(buf *bytes.Buffer, code, baseURL string, hasQR bool, w int) {
	buf.WriteByte('\n')
	writeLn(buf, w, "  Receive via:")
	if hasQR {
		writeLn(buf, w, "  ▸    Browser:  %s/r#%s  (press q for QR code)", baseURL, code)
	} else {
		writeLn(buf, w, "  ▸    Browser:  %s/r#%s", baseURL, code)
	}
	writeLn(buf, w, "  ▸   Terminal:  sp2p receive %s", code)
	writeLn(buf, w, "            or:  curl -f %s/r | sh -s %s", baseURL, code)
	writeLn(buf, w, "            or:  wget -qO- %s/r | sh -s %s", baseURL, code)
	writeLn(buf, w, "  ▸ PowerShell:  & ([scriptblock]::Create((irm %s/ps/r))) '%s'", baseURL, code)
	writeLn(buf, w, "  * Terminal commands download a temporary SP2P CLI, receive the file, then clean up")
	buf.WriteByte('\n')
}

// renderQRTo renders the QR code into a buffer.
func renderQRTo(buf *bytes.Buffer, url string) {
	var qrBuf bytes.Buffer
	qrterminal.GenerateWithConfig(url, qrterminal.Config{
		Level:      qrterminal.L,
		Writer:     &qrBuf,
		QuietZone:  2,
		HalfBlocks: true,
	})
	qrStr := qrBuf.String()
	qrLines := strings.Split(strings.TrimRight(qrStr, "\n"), "\n")
	for _, line := range qrLines {
		fmt.Fprintf(buf, "%s\n", line)
	}
}

func renderProgressTo(buf *bytes.Buffer, p *Progress) {
	action := "Sending"
	if !p.isSend {
		action = "Receiving"
	}

	elapsed := time.Since(p.startTime)
	speed := float64(0)
	if elapsed > 0 {
		speed = float64(p.bytes) / elapsed.Seconds()
	}

	if p.fileSize > 0 {
		pct := float64(p.bytes) / float64(p.fileSize)
		if pct > 1 {
			pct = 1
		}
		barWidth := 32
		filled := int(pct * float64(barWidth))
		bar := "[" + strings.Repeat("#", filled) + strings.Repeat(" ", barWidth-filled) + "]"
		pctStr := fmt.Sprintf("%3.0f%%", pct*100)
		var eta string
		if speed > 0 {
			remaining := float64(p.fileSize-p.bytes) / speed
			eta = fmt.Sprintf("ETA %s", formatDuration(time.Duration(remaining)*time.Second))
		}
		sizeLabel := formatBytes(p.fileSize)
		if p.fileCount > 0 {
			sizeLabel = fmt.Sprintf("%s, %d files", sizeLabel, p.fileCount)
		}
		fmt.Fprintf(buf, "  %s: %s (%s)", action, p.fileName, sizeLabel)
		fmt.Fprintf(buf, "\n  %s  %s  %s  %s/s  %s", bar, pctStr, formatBytes(p.bytes), formatBytes(uint64(speed)), eta)
		return
	}

	// Stream mode: no percentage, single line.
	fmt.Fprintf(buf, "  %s: %s  %s  %s/s",
		action, p.fileName, formatBytes(p.bytes), formatBytes(uint64(speed)))
}

func (p *Progress) stateIcon(phase Phase) string {
	switch {
	case phase < p.phase:
		return "done"
	case phase == p.phase:
		return spinnerChars[p.spinIdx]
	default:
		return " "
	}
}

// termWidth returns the current terminal width, or 80 as fallback.
func termWidth() int {
	w, _, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || w <= 0 {
		return 80
	}
	return w
}

// truncLine truncates a string to fit within maxWidth visible characters.
func truncLine(s string, maxWidth int) string {
	if utf8.RuneCountInString(s) <= maxWidth {
		return s
	}
	runes := []rune(s)
	if maxWidth <= 1 {
		return string(runes[:maxWidth])
	}
	return string(runes[:maxWidth-1]) + "…"
}

// writeLn writes a truncated line (with trailing newline) to the buffer.
func writeLn(buf *bytes.Buffer, width int, format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	line = strings.TrimRight(line, "\n")
	buf.WriteString(truncLine(line, width))
	buf.WriteByte('\n')
}

func methodIcon(state string) string {
	switch state {
	case "connected":
		return "+"
	case "failed":
		return "x"
	case "skipped":
		return "-"
	default:
		return "~"
	}
}

func formatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "<1s"
	}
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) - m*60
	return fmt.Sprintf("%dm%ds", m, s)
}
