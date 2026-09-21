// SPDX-License-Identifier: MIT

package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/crypto"
	"github.com/zyno-io/sp2p/internal/flow"
)

// StreamConfig contains common options for CLI-only duplex applications.
type StreamConfig struct {
	ServerURL, Code, Transport, ClientVersion string
	RelayOK, Verbose                          bool
	Output                                    OutputConfig
}

// EmitStreamHelp keeps explicit help requests inside the selected JSON stream,
// without opening a peer session or suggesting that a transfer took place.
func EmitStreamHelp(w io.Writer, service, role, usage string) {
	writeMachineEvent(w, machineEvent{SchemaVersion: 1, Sequence: 1, Event: "result",
		At: time.Now().UTC().Format(time.RFC3339Nano), Service: service, Role: role,
		Mode: "help", Outcome: "completed", Message: usage})
}

// ReportStreamFailure preserves stream identity for errors that occur before
// peer setup, including command-shape validation and status snapshots.
func ReportStreamFailure(output OutputConfig, service, role, mode string, err error) error {
	if !output.IsMachine() {
		return err
	}
	r := newStreamReporter(context.Background(), StreamConfig{Output: output}, service, role, mode)
	return r.finish(err, 0, 0)
}

// streamReporter never reads stdin or emits browser receive links.
type streamReporter struct {
	machine             *machineReporter
	mu                  sync.Mutex
	service, role, mode string
	verbose             bool
	start               time.Time
}

func newStreamReporter(ctx context.Context, cfg StreamConfig, service, role, mode string) *streamReporter {
	r := &streamReporter{service: service, role: role, mode: mode, verbose: cfg.Verbose, start: time.Now()}
	if cfg.Output.IsMachine() {
		r.machine = newMachineReporter(ctx, cfg.Output, role, cfg.Verbose)
		r.machine.snapshot.Service = service
		r.machine.snapshot.Mode = mode
	}
	return r
}

func (r *streamReporter) phase(phase string) {
	if r.machine != nil {
		r.machine.OnPhaseChanged(flow.Phase(phase))
	} else if r.verbose {
		r.log(phase)
	}
}

func (r *streamReporter) code(code string) {
	if r.machine != nil {
		id, _, _ := crypto.ParseCode(code)
		r.machine.mu.Lock()
		r.machine.snapshot.SessionID = id
		r.machine.snapshot.Code = code
		r.machine.emitLocked(machineEvent{Event: "session", SessionID: id, Code: code})
		r.machine.mu.Unlock()
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintf(os.Stderr, "Code: %s\nWaiting for the peer to join…\n", code)
}

func (r *streamReporter) status(status conn.MethodStatus) {
	if r.machine != nil {
		r.machine.OnConnectionStatus(status)
	} else if r.verbose {
		r.log(fmt.Sprintf("%s: %s", status.Method, status.State))
	}
}

func (r *streamReporter) log(message string) {
	if r.machine != nil {
		r.machine.OnVerbose(message)
		return
	}
	if r.verbose {
		r.mu.Lock()
		defer r.mu.Unlock()
		fmt.Fprintln(os.Stderr, SanitizeTerminalText(message))
	}
}

func (r *streamReporter) ready(endpoint string) {
	if r.machine != nil {
		r.machine.mu.Lock()
		r.machine.snapshot.Endpoint = endpoint
		r.machine.snapshot.Phase = "ready"
		r.machine.emitLocked(machineEvent{Event: "ready", Endpoint: endpoint})
		r.machine.mu.Unlock()
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if endpoint != "" {
		fmt.Fprintf(os.Stderr, "Ready: %s (one connection)\n", SanitizeTerminalText(endpoint))
	}
}

func (r *streamReporter) protocol() {
	if r.machine != nil {
		r.machine.OnProtocolVersion(3)
	}
}

func (r *streamReporter) progress(sent, received uint64) {
	if r.machine == nil {
		return
	}
	r.machine.mu.Lock()
	defer r.machine.mu.Unlock()
	r.machine.snapshot.BytesSent, r.machine.snapshot.BytesReceived = sent, received
	if time.Since(r.machine.lastProgressAt) < time.Second {
		return
	}
	r.machine.lastProgressAt = time.Now()
	r.machine.emitLocked(machineEvent{Event: "progress", BytesSent: &sent, BytesReceived: &received})
}

func (r *streamReporter) finish(err error, sent, received uint64) error {
	if r.machine == nil {
		return err
	}
	r.machine.mu.Lock()
	r.machine.snapshot.BytesSent, r.machine.snapshot.BytesReceived = sent, received
	r.machine.mu.Unlock()
	if err == nil {
		r.machine.OnComplete(sent+received, time.Since(r.start))
	}
	r.machine.finish(err, "")
	return reportedMachineError(err)
}

func (r *streamReporter) promptRelay(ctx context.Context) bool {
	if r.machine != nil {
		return r.machine.PromptRelayContext(ctx)
	}
	tty, err := os.Open("/dev/tty")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Relay requires consent; use --allow-relay when running without a terminal.")
		return false
	}
	defer tty.Close()
	stop := context.AfterFunc(ctx, func() { tty.Close() })
	defer stop()
	fmt.Fprint(os.Stderr, "Direct connection failed. Allow the encrypted TURN relay? [y/N]: ")
	scanner := bufio.NewScanner(tty)
	if !scanner.Scan() {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
	return answer == "y" || answer == "yes"
}

func (r *streamReporter) subprocessWriter(name string, human io.Writer) io.Writer {
	if r.machine == nil {
		return human
	}
	return &subprocessEventWriter{reporter: r.machine, name: name}
}

type subprocessEventWriter struct {
	reporter *machineReporter
	name     string
}

func (w *subprocessEventWriter) Write(data []byte) (int, error) {
	total := len(data)
	for len(data) > 0 {
		n := min(len(data), 16*1024)
		w.reporter.mu.Lock()
		w.reporter.emitLocked(machineEvent{Event: "subprocess_output", OutputStream: w.name, OutputData: data[:n]})
		w.reporter.mu.Unlock()
		data = data[n:]
	}
	return total, nil
}
