// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/crypto"
	"github.com/zyno-io/sp2p/internal/flow"
	"github.com/zyno-io/sp2p/internal/transfer"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func TestMachineProtocolIsUnknownUntilConfirmed(t *testing.T) {
	var output lockedBuffer
	reporter := newMachineReporter(context.Background(), OutputConfig{Format: OutputJSON, EventWriter: &output}, "send", false)
	reporter.OnPhaseChanged(flow.PhaseConnecting)
	if strings.Contains(output.String(), `"protocol"`) || reporter.snapshot.Protocol != 0 {
		t.Fatal("reported a protocol before authentication")
	}
	reporter.OnProtocolVersion(3)
	if !strings.Contains(output.String(), `"event":"protocol","protocol":3`) || reporter.snapshot.Protocol != 3 {
		t.Fatal("did not publish authenticated protocol")
	}
}

func TestLegacyProtocolNoticeIsMachineReadableWithoutVerbose(t *testing.T) {
	var output lockedBuffer
	reporter := newMachineReporter(context.Background(), OutputConfig{Format: OutputJSON, EventWriter: &output}, "send", false)
	reporter.OnProtocolVersion(2)
	output.buf.Reset()
	reporter.OnWarning(flow.LegacyProtocolWarning)
	var event machineEvent
	if err := json.Unmarshal([]byte(output.String()), &event); err != nil {
		t.Fatal(err)
	}
	if event.Event != "warning" || event.Protocol != 2 || event.Message != flow.LegacyProtocolWarning {
		t.Fatalf("warning: %+v", event)
	}
	if reporter.snapshot.Protocol != 2 {
		t.Fatal("snapshot lost selected protocol")
	}
	var display bytes.Buffer
	writeShareInfoTo(&display, "abcdefgh-1", "https://sp2p.io", false, 200)
	if !strings.Contains(display.String(), "sp2p receive abcdefgh-1") || strings.Contains(display.String(), "-protocol") {
		t.Fatalf("share command requires manual compatibility: %s", display.String())
	}
	if strings.Contains(agentPrompt("abcdefgh-1", "https://sp2p.io"), "-protocol") {
		t.Fatal("agent prompt requires manual compatibility")
	}
}

// TestMachineReporterEmitsParallelLanesEvent checks that OnParallelLaneReport
// emits its own "parallel_lanes" event (not "log", so CI diagnostics that
// skip log lines still see it — see web/tests/helpers.ts) with the report's
// fields intact, and that the encoded event never contains an IP-like
// string, matching flow.ParallelLaneReport's address-free guarantee.
func TestMachineReporterEmitsParallelLanesEvent(t *testing.T) {
	var output lockedBuffer
	reporter := newMachineReporter(context.Background(), OutputConfig{Format: OutputJSON, EventWriter: &output}, "send", false)
	report := &flow.ParallelLaneReport{
		Requested: 8, Accepted: 8, Ours: 0b11111100, Theirs: 0b01111100, Selected: 0b01111100, SetupMS: 1234,
		Failures: []flow.LaneFailure{{
			ID: 7, Stage: "connect-timeout", Class: flow.ClassTimeout,
			Trace: []conn.LaneTraceEvent{{MS: 5, Event: "conn=connecting"}, {MS: 5000, Event: "close=peer_connection_failed"}},
			Pair:  "host/prflx",
		}},
	}
	reporter.OnParallelLaneReport(report)

	raw := output.String()
	var event machineEvent
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		t.Fatal(err)
	}
	if event.Event != "parallel_lanes" {
		t.Fatalf("event = %q, want parallel_lanes", event.Event)
	}
	got := event.ParallelLanes
	if got == nil {
		t.Fatal("missing parallel_lanes payload")
	}
	if got.Requested != 8 || got.Accepted != 8 || got.Selected != 0b01111100 || got.SetupMS != 1234 {
		t.Fatalf("parallel_lanes payload = %+v", got)
	}
	if len(got.Failures) != 1 || got.Failures[0].Stage != "connect-timeout" || got.Failures[0].Class != "timeout" || got.Failures[0].Pair != "host/prflx" {
		t.Fatalf("failures = %+v", got.Failures)
	}
	if ipLikeEventPattern.MatchString(raw) {
		t.Fatalf("parallel_lanes event contains an IP-like string: %s", raw)
	}
}

func TestMachineReporterParallelLanesEventOmittedForNilReport(t *testing.T) {
	var output lockedBuffer
	reporter := newMachineReporter(context.Background(), OutputConfig{Format: OutputJSON, EventWriter: &output}, "send", false)
	reporter.OnParallelLaneReport(nil)
	if output.String() != "" {
		t.Fatalf("expected no event for a nil report, got %q", output.String())
	}
}

var ipLikeEventPattern = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)

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
	// Windows has no POSIX permission bits (os.Stat reports 0666/0444 based
	// only on the read-only attribute); the file's real protection there
	// comes from the per-user ACL on its containing directory instead.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
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
	// See the status-file permission check above: no POSIX bits on Windows.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
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

	response := make(chan conn.RelayAnswer, 1)
	go func() {
		response <- reporter.PromptRelayAnswer(parent)
	}()

	responseFile := waitForRelayResponseFile(t, &output)
	cancel()

	select {
	case answer := <-response:
		if answer != conn.RelayUnavailable {
			t.Fatalf("canceled relay prompt answer = %v, want RelayUnavailable", answer)
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

// TestMachineReporterPromptRelay_ResponseFileErrorGivesUnavailable checks
// that a response-file error (the agent's file disappeared) resolves to
// RelayUnavailable, not RelayDeny — it lets the peer-facing message say
// "could not be asked" instead of "declined".
func TestMachineReporterPromptRelay_ResponseFileErrorGivesUnavailable(t *testing.T) {
	var output lockedBuffer
	reporter := newMachineReporter(context.Background(), OutputConfig{
		Format:      OutputJSON,
		EventWriter: &output,
	}, "send", false)

	answerDone := make(chan conn.RelayAnswer, 1)
	go func() { answerDone <- reporter.promptRelay(context.Background()) }()
	responseFile := waitForRelayResponseFile(t, &output)
	if err := os.Remove(responseFile); err != nil {
		t.Fatal(err)
	}
	select {
	case answer := <-answerDone:
		if answer != conn.RelayUnavailable {
			t.Fatalf("answer = %v, want RelayUnavailable", answer)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for response-file error")
	}
}

// TestMachineReporterFinish_PeerRelayDenied checks that finish() maps a
// wrapped conn.ErrPeerDeclinedRelay to the peer_relay_denied code.
func TestMachineReporterFinish_PeerRelayDenied(t *testing.T) {
	var output lockedBuffer
	reporter := newMachineReporter(context.Background(), OutputConfig{
		Format:      OutputJSON,
		EventWriter: &output,
	}, "send", false)

	err := fmt.Errorf("relay retry failed: %w", &conn.PeerDeclinedRelayError{Reason: "declined"})
	reporter.finish(err, "")

	result := lastResultEvent(t, &output)
	if result.Error == nil || result.Error.Code != "peer_relay_denied" {
		t.Fatalf("result event = %#v, want error code peer_relay_denied", result)
	}
}

// TestMachineReporterFinish_PeerRelayUnusableIsRelayNotAllowed checks that
// finish() maps a wrapped conn.PeerRelayUnusableError — the peer gave up on
// its own direct attempt and asked to retry via relay, but this side has no
// relay to offer (no TURN, or -transport tcp) — to the same relay_not_allowed
// code as the local could-not-participate case, even though
// r.snapshot.RelayRequired was never set true (this side never reaches its
// own relay prompt in that scenario).
func TestMachineReporterFinish_PeerRelayUnusableIsRelayNotAllowed(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  *conn.PeerRelayUnusableError
	}{
		{"tcp-only", &conn.PeerRelayUnusableError{TCPOnly: true}},
		{"no turn", &conn.PeerRelayUnusableError{TCPOnly: false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output lockedBuffer
			reporter := newMachineReporter(context.Background(), OutputConfig{
				Format:      OutputJSON,
				EventWriter: &output,
			}, "send", false)

			err := fmt.Errorf("connecting: %w", tc.err)
			reporter.finish(err, "")

			result := lastResultEvent(t, &output)
			if result.Error == nil || result.Error.Code != "relay_not_allowed" {
				t.Fatalf("result event = %#v, want error code relay_not_allowed", result)
			}
		})
	}
}

// TestMachineReporterFinish_OwnDenyIsRelayDenied checks that finish() still
// reports our own deny as relay_denied (unchanged), not peer_relay_denied,
// when the returned error doesn't wrap conn.ErrPeerDeclinedRelay.
func TestMachineReporterFinish_OwnDenyIsRelayDenied(t *testing.T) {
	var output lockedBuffer
	reporter := newMachineReporter(context.Background(), OutputConfig{
		Format:      OutputJSON,
		EventWriter: &output,
	}, "send", false)

	answerDone := make(chan conn.RelayAnswer, 1)
	go func() { answerDone <- reporter.promptRelay(context.Background()) }()
	responseFile := waitForRelayResponseFile(t, &output)
	if err := os.WriteFile(responseFile, []byte("deny\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case answer := <-answerDone:
		if answer != conn.RelayDeny {
			t.Fatalf("answer = %v, want RelayDeny", answer)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for deny response")
	}

	reporter.finish(conn.ErrRelayNotAllowed, "")
	result := lastResultEvent(t, &output)
	if result.Error == nil || result.Error.Code != "relay_denied" {
		t.Fatalf("result event = %#v, want error code relay_denied", result)
	}
}

func lastResultEvent(t *testing.T, output *lockedBuffer) machineEvent {
	t.Helper()
	var result machineEvent
	found := false
	for _, line := range bytes.Split(bytes.TrimSpace([]byte(output.String())), []byte{'\n'}) {
		var event machineEvent
		if json.Unmarshal(line, &event) == nil && event.Event == "result" {
			result = event
			found = true
		}
	}
	if !found {
		t.Fatalf("no result event found: %s", output.String())
	}
	return result
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
