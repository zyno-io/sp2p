// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyno-io/sp2p/internal/crypto"
	"github.com/zyno-io/sp2p/internal/flow"
	"github.com/zyno-io/sp2p/internal/transfer"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestMachineReporterEmitsSessionAndTerminalResult(t *testing.T) {
	var output lockedBuffer
	statusFile := filepath.Join(t.TempDir(), "status.json")
	reporter := newMachineReporter(context.Background(), OutputConfig{
		Format:      OutputJSON,
		EventWriter: &output,
		StatusFile:  statusFile,
	}, "send", false)

	seed, _, err := crypto.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	code := crypto.FormatCode("abcdefgh", seed)

	reporter.OnPhaseChanged(flow.Phase("preparing"))
	reporter.OnTransferCode(code, "https://sp2p.io")
	reporter.OnMetadata(&transfer.Metadata{Name: "report.pdf", Size: 42})
	reporter.OnProgress(42)
	reporter.OnPhaseChanged(flow.PhaseDone)
	reporter.OnComplete(42, 250*time.Millisecond)
	reporter.finish(nil, "received/report.pdf")

	var events []machineEvent
	for _, line := range bytes.Split(bytes.TrimSpace([]byte(output.String())), []byte{'\n'}) {
		var event machineEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("invalid JSON event %q: %v", line, err)
		}
		events = append(events, event)
	}
	if len(events) == 0 {
		t.Fatal("expected machine events")
	}
	if events[0].Event != "phase" || events[0].Phase != "preparing" {
		t.Fatalf("first event = %#v, want preparing phase", events[0])
	}

	var session *machineEvent
	for i := range events {
		if events[i].Event == "session" {
			session = &events[i]
			break
		}
	}
	if session == nil {
		t.Fatal("missing session event")
	}
	if session.Code != code || session.SessionID != "abcdefgh" {
		t.Fatalf("session = %#v, want code %q and session ID", session, code)
	}
	if session.AgentPrompt != "AI Agent: Please receive file session "+code+" using https://sp2p.io/llm" {
		t.Fatalf("agent prompt = %q", session.AgentPrompt)
	}

	terminal := events[len(events)-1]
	if terminal.Event != "result" || terminal.Outcome != "completed" {
		t.Fatalf("terminal event = %#v, want completed result", terminal)
	}
	if terminal.SavedPath != "received/report.pdf" {
		t.Fatalf("saved path = %q", terminal.SavedPath)
	}

	statusData, err := os.ReadFile(statusFile)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot machineSnapshot
	if err := json.Unmarshal(statusData, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Code != code || snapshot.Result == nil || snapshot.Result.Outcome != "completed" {
		t.Fatalf("status snapshot = %#v", snapshot)
	}
	info, err := os.Stat(statusFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("status file permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestMachineReporterAcceptsRelayResponse(t *testing.T) {
	var output lockedBuffer
	reporter := newMachineReporter(context.Background(), OutputConfig{
		Format:      OutputJSON,
		EventWriter: &output,
	}, "send", false)

	response := make(chan bool, 1)
	go func() {
		response <- reporter.PromptRelay()
	}()

	var responseFile string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range bytes.Split(bytes.TrimSpace([]byte(output.String())), []byte{'\n'}) {
			var event machineEvent
			if json.Unmarshal(line, &event) == nil && event.Event == "relay_required" {
				responseFile = event.ResponseFile
				break
			}
		}
		if responseFile != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if responseFile == "" {
		t.Fatalf("missing relay_required event: %s", output.String())
	}
	info, err := os.Stat(responseFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("response file permissions = %o, want 600", info.Mode().Perm())
	}
	if err := os.WriteFile(responseFile, []byte("allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	select {
	case allowed := <-response:
		if !allowed {
			t.Fatal("relay response was not accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for relay response")
	}
	if _, err := os.Stat(responseFile); !os.IsNotExist(err) {
		t.Fatalf("relay response file should be removed, stat error = %v", err)
	}
}

func TestMachineReporterCancelsRelayPrompt(t *testing.T) {
	var output lockedBuffer
	parent, cancel := context.WithCancel(context.Background())
	reporter := newMachineReporter(parent, OutputConfig{
		Format:      OutputJSON,
		EventWriter: &output,
	}, "receive", false)

	response := make(chan bool, 1)
	go func() {
		response <- reporter.PromptRelayContext(parent)
	}()

	responseFile := waitForRelayResponseFile(t, &output)
	cancel()

	select {
	case allowed := <-response:
		if allowed {
			t.Fatal("canceled relay prompt was allowed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out canceling relay prompt")
	}
	if _, err := os.Stat(responseFile); !os.IsNotExist(err) {
		t.Fatalf("relay response file should be removed, stat error = %v", err)
	}
	if !strings.Contains(output.String(), `"event":"relay_prompt_canceled"`) {
		t.Fatalf("missing relay cancellation event: %s", output.String())
	}
}

func TestMachineReporterClearsRelayStatusWhenResponseFileDisappears(t *testing.T) {
	var output lockedBuffer
	reporter := newMachineReporter(context.Background(), OutputConfig{
		Format:      OutputJSON,
		EventWriter: &output,
	}, "receive", false)

	response := make(chan bool, 1)
	go func() {
		response <- reporter.PromptRelay()
	}()

	responseFile := waitForRelayResponseFile(t, &output)
	if err := os.Remove(responseFile); err != nil {
		t.Fatal(err)
	}
	select {
	case allowed := <-response:
		if allowed {
			t.Fatal("unreadable response file was allowed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for missing response file")
	}
	if reporter.snapshot.RelayRequired {
		t.Fatal("relay status remained required after response file disappeared")
	}
}

func TestMachineReporterReportsStatusFileFailures(t *testing.T) {
	var output lockedBuffer
	reporter := newMachineReporter(context.Background(), OutputConfig{
		Format:      OutputJSON,
		EventWriter: &output,
		StatusFile:  filepath.Join(t.TempDir(), "missing", "status.json"),
	}, "send", false)

	reporter.OnPhaseChanged(flow.PhaseConnecting)
	reporter.finish(fmt.Errorf("transfer failed"), "")

	var events []machineEvent
	for _, line := range bytes.Split(bytes.TrimSpace([]byte(output.String())), []byte{'\n'}) {
		var event machineEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("invalid JSON event %q: %v", line, err)
		}
		events = append(events, event)
	}
	if !strings.Contains(output.String(), `"event":"status_file_error"`) {
		t.Fatalf("missing status file error event: %s", output.String())
	}
	if events[len(events)-1].Event != "result" {
		t.Fatalf("terminal result must be final event, got %#v", events)
	}
}

func TestSendMachineReportsPreparationFailure(t *testing.T) {
	var output lockedBuffer
	err := Send(context.Background(), SendConfig{
		Paths: []string{filepath.Join(t.TempDir(), "missing.txt")},
		Output: OutputConfig{
			Format:      OutputJSON,
			EventWriter: &output,
		},
	})
	if err == nil {
		t.Fatal("expected send failure")
	}
	if !MachineErrorReported(err) {
		t.Fatalf("expected reported machine error, got %T", err)
	}

	var events []machineEvent
	for _, line := range bytes.Split(bytes.TrimSpace([]byte(output.String())), []byte{'\n'}) {
		var event machineEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("invalid JSON event %q: %v", line, err)
		}
		events = append(events, event)
	}
	if len(events) != 2 {
		t.Fatalf("event count = %d, want phase and terminal result", len(events))
	}
	if events[0].Event != "phase" || events[len(events)-1].Event != "result" || events[len(events)-1].Outcome != "failed" {
		t.Fatalf("events = %#v", events)
	}
}

func TestNewOutputConfigRejectsMixedJSONAndFileOutput(t *testing.T) {
	if _, err := NewOutputConfig("json", "stdout", "", true); err == nil {
		t.Fatal("expected stdout conflict error")
	}
	if _, err := NewOutputConfig("json", "stderr", "", true); err != nil {
		t.Fatalf("stderr event stream: %v", err)
	}
	if _, err := NewOutputConfig("human", "stdout", "status.json", false); err == nil {
		t.Fatal("expected status file to require JSON")
	}
}

func waitForRelayResponseFile(t *testing.T, output *lockedBuffer) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range bytes.Split(bytes.TrimSpace([]byte(output.String())), []byte{'\n'}) {
			var event machineEvent
			if json.Unmarshal(line, &event) == nil && event.Event == "relay_required" {
				return event.ResponseFile
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("missing relay_required event: %s", output.String())
	return ""
}
