// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/flow"
	"github.com/zyno-io/sp2p/internal/transfer"
)

// cliHandler adapts flow.Handler to the CLI's ANSI terminal progress display.
type cliHandler struct {
	progress    *Progress
	keyListener *KeyListener
}

func (h *cliHandler) OnPhaseChanged(phase flow.Phase) {
	// Stop key listener when leaving the registered phase.
	if phase != flow.PhaseRegistered && h.keyListener != nil {
		h.keyListener.Stop()
		h.keyListener = nil
	}
	switch phase {
	case flow.PhaseConnecting:
		h.progress.SetPhase(PhaseInit)
	case flow.PhaseRegistered:
		h.progress.SetPhase(PhaseRegistered)
	case flow.PhasePeerJoined:
		h.progress.SetPhase(PhasePeerJoined)
	case flow.PhaseKeyExchange:
		h.progress.SetPhase(PhaseKeyExchange)
	case flow.PhaseP2PConnecting:
		h.progress.SetPhase(PhaseConnecting)
	case flow.PhaseP2PConnected:
		h.progress.SetPhase(PhaseConnected)
	case flow.PhaseTransferring:
		// no-op: transfer phase is set by OnMetadata/progress.SetTransfer
	case flow.PhaseDone:
		h.progress.SetPhase(PhaseDone)
	}
}

func (h *cliHandler) OnTransferCode(code, baseURL string) {
	h.progress.ShowCode(code, baseURL)

	// Start key listener for QR toggle.
	kl := NewKeyListener()
	if kl != nil {
		h.keyListener = kl
		go func() {
			for {
				select {
				case key, ok := <-kl.Keys:
					if !ok {
						return
					}
					if key == 'q' || key == 'Q' {
						h.progress.ToggleQR()
					}
				case <-kl.Done():
					return
				}
			}
		}()
	}
}

func (h *cliHandler) OnConnectionStatus(status conn.MethodStatus) {
	h.progress.UpdateMethod(status)
}

func (h *cliHandler) OnConnectionMethodsReset() {
	h.progress.ResetMethods()
}

func (h *cliHandler) OnMetadata(meta *transfer.Metadata) {
	h.progress.SetTransfer(meta.Name, meta.Size, meta.FileCount)
}

func (h *cliHandler) OnProgress(bytesTransferred uint64) {
	h.progress.UpdateBytes(bytesTransferred)
}

func (h *cliHandler) OnVerifyCode(code string) {
	h.progress.ShowVerifyCode(code)
}

func (h *cliHandler) OnComplete(totalBytes uint64, duration time.Duration) {
	h.progress.ShowComplete(totalBytes, duration)
}

func (h *cliHandler) OnUpdateAvailable(currentVersion, serverVersion string) {
	h.progress.ShowUpdateNotice(currentVersion, serverVersion)
}

func (h *cliHandler) OnError(message string) {
	h.progress.SetError(message)
}

func (h *cliHandler) OnParallelStreams(count int) {
	h.progress.SetParallelStreams(count)
}

func (h *cliHandler) OnVerbose(msg string) {
	h.progress.Log(msg)
}

// OnParallelLaneReport implements flow.ParallelLaneReporter. Progress.Log
// already gates on verbose mode, so this only ever prints when -v is set.
func (h *cliHandler) OnParallelLaneReport(report *flow.ParallelLaneReport) {
	h.progress.Log(formatLaneReport(report))
}

// formatLaneReport renders a ParallelLaneReport as a single diagnostic
// line. It only ever prints report fields, which are address-free by
// construction (see flow.ParallelLaneReport) — no IPs, ports, ICE
// ufrags/pwds, or SDP.
func formatLaneReport(report *flow.ParallelLaneReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "parallel lanes: requested=%d accepted=%d ours=%#x theirs=%#x selected=%#x setup_ms=%d",
		report.Requested, report.Accepted, report.Ours, report.Theirs, report.Selected, report.SetupMS)
	for _, f := range report.Failures {
		fmt.Fprintf(&b, " failure[id=%d stage=%s class=%s", f.ID, f.Stage, f.Class)
		if f.Pair != "" {
			fmt.Fprintf(&b, " pair=%s", f.Pair)
		}
		if len(f.Trace) > 0 {
			b.WriteString(" trace=")
			for i, ev := range f.Trace {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, "%dms:%s", ev.MS, ev.Event)
			}
		}
		b.WriteString("]")
	}
	return b.String()
}

func (h *cliHandler) OnWarning(msg string) {
	h.progress.ShowWarning(msg)
}

func (h *cliHandler) PromptRelay() bool {
	h.progress.Pause()
	result := promptRelay()
	h.progress.Resume()
	return result
}

// PromptRelayAnswer implements flow.RelayPromptHandler: a cancellable,
// richer relay prompt that flow prefers over PromptRelay above.
func (h *cliHandler) PromptRelayAnswer(ctx context.Context) conn.RelayAnswer {
	h.progress.Pause()
	defer h.progress.Resume()
	return promptRelayTTY(ctx)
}
