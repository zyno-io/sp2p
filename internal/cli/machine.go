// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/crypto"
	"github.com/zyno-io/sp2p/internal/flow"
	"github.com/zyno-io/sp2p/internal/transfer"
)

// OutputFormat controls whether the CLI renders a terminal UI or machine events.
type OutputFormat string

const (
	// OutputHuman renders the interactive terminal UI.
	OutputHuman OutputFormat = "human"
	// OutputJSON writes newline-delimited JSON events.
	OutputJSON OutputFormat = "json"
)

// OutputConfig controls CLI output. It is intentionally per-invocation: a
// machine-readable stream should never become a surprising persistent default.
type OutputConfig struct {
	Format      OutputFormat
	EventWriter io.Writer
	StatusFile  string
}

// NewOutputConfig validates output-related command flags and resolves the
// selected event stream. JSON events normally use stdout; receive -stdout
// must move them to stderr to keep file bytes unmodified.
func NewOutputConfig(format, eventOutput, statusFile string, receivesStdout bool) (OutputConfig, error) {
	cfg := OutputConfig{Format: OutputFormat(strings.ToLower(format)), StatusFile: statusFile}
	switch cfg.Format {
	case OutputHuman:
		if statusFile != "" {
			return OutputConfig{}, fmt.Errorf("-status-file requires -format json")
		}
		return cfg, nil
	case OutputJSON:
	default:
		return OutputConfig{}, fmt.Errorf("format must be human or json, got %q", format)
	}

	switch strings.ToLower(eventOutput) {
	case "", "stdout":
		if receivesStdout {
			return OutputConfig{}, fmt.Errorf("-format json with -stdout requires -event-output stderr")
		}
		cfg.EventWriter = os.Stdout
	case "stderr":
		cfg.EventWriter = os.Stderr
	default:
		return OutputConfig{}, fmt.Errorf("event-output must be stdout or stderr, got %q", eventOutput)
	}
	if statusFile != "" {
		parentInfo, err := os.Stat(filepath.Dir(statusFile))
		if err != nil {
			return OutputConfig{}, fmt.Errorf("status-file parent directory: %w", err)
		}
		if !parentInfo.IsDir() {
			return OutputConfig{}, fmt.Errorf("status-file parent is not a directory: %s", filepath.Dir(statusFile))
		}
		if statusInfo, err := os.Stat(statusFile); err == nil && statusInfo.IsDir() {
			return OutputConfig{}, fmt.Errorf("status-file is a directory: %s", statusFile)
		} else if err != nil && !os.IsNotExist(err) {
			return OutputConfig{}, fmt.Errorf("status-file: %w", err)
		}
	}
	return cfg, nil
}

func (c OutputConfig) isMachine() bool {
	return c.Format == OutputJSON
}

// IsMachine reports whether this config emits machine-readable JSON events.
func (c OutputConfig) IsMachine() bool {
	return c.isMachine()
}

// MachineErrorReported reports whether the command already emitted a terminal
// JSON result for err. It lets main preserve JSON-only output on failure.
func MachineErrorReported(err error) bool {
	var reported *machineReportedError
	return errors.As(err, &reported)
}

type machineReportedError struct {
	err error
}

func (e *machineReportedError) Error() string {
	return e.err.Error()
}

func (e *machineReportedError) Unwrap() error {
	return e.err
}

func reportedMachineError(err error) error {
	if err == nil {
		return nil
	}
	return &machineReportedError{err: err}
}

// EmitMachineFailure writes a standalone terminal result when an error occurs
// before a send or receive flow can create its reporter (for example, flag or
// configuration validation failures).
func EmitMachineFailure(w io.Writer, role string, err error) {
	event := machineEvent{
		SchemaVersion: 1,
		Sequence:      1,
		Event:         "result",
		At:            time.Now().UTC().Format(time.RFC3339Nano),
		Role:          role,
		Outcome:       "failed",
		Error: &machineError{
			Code:    "command_failed",
			Message: err.Error(),
		},
	}
	writeMachineEvent(w, event)
}

// ReportMachineFailure writes a terminal JSON result and status snapshot for a
// failure that occurs after JSON output configuration was successfully parsed.
// The returned wrapper prevents main from emitting a duplicate terminal event.
func ReportMachineFailure(cfg OutputConfig, role string, err error) error {
	if !cfg.isMachine() {
		return err
	}
	reporter := newMachineReporter(context.Background(), cfg, role, false)
	reporter.finish(err, "")
	return reportedMachineError(err)
}

type machineReporter struct {
	mu              sync.Mutex
	ctx             context.Context
	writer          io.Writer
	role            string
	verbose         bool
	statusFile      string
	sequence        uint64
	lastProgressAt  time.Time
	lastError       string
	statusFileError string
	completion      *machineCompletion
	relayResponse   string
	snapshot        machineSnapshot
}

type machineEvent struct {
	SchemaVersion    int                `json:"schema_version"`
	Sequence         uint64             `json:"sequence"`
	Event            string             `json:"event"`
	At               string             `json:"at"`
	Role             string             `json:"role"`
	Phase            string             `json:"phase,omitempty"`
	SessionID        string             `json:"session_id,omitempty"`
	Code             string             `json:"code,omitempty"`
	ShareURL         string             `json:"share_url,omitempty"`
	AgentPrompt      string             `json:"agent_prompt,omitempty"`
	Metadata         *transfer.Metadata `json:"metadata,omitempty"`
	Connection       *machineConnection `json:"connection,omitempty"`
	BytesTransferred *uint64            `json:"bytes_transferred,omitempty"`
	TotalBytes       *uint64            `json:"total_bytes,omitempty"`
	DurationMS       *int64             `json:"duration_ms,omitempty"`
	ParallelStreams  int                `json:"parallel_streams,omitempty"`
	Message          string             `json:"message,omitempty"`
	Error            *machineError      `json:"error,omitempty"`
	Outcome          string             `json:"outcome,omitempty"`
	SavedPath        string             `json:"saved_path,omitempty"`
	ResponseFile     string             `json:"response_file,omitempty"`
	AllowedResponses []string           `json:"allowed_responses,omitempty"`
	Response         string             `json:"response,omitempty"`
}

type machineConnection struct {
	Method string `json:"method"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

type machineError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type machineCompletion struct {
	TotalBytes uint64
	Duration   time.Duration
}

type machineResult struct {
	Outcome    string        `json:"outcome"`
	TotalBytes uint64        `json:"total_bytes,omitempty"`
	DurationMS int64         `json:"duration_ms,omitempty"`
	SavedPath  string        `json:"saved_path,omitempty"`
	Error      *machineError `json:"error,omitempty"`
}

type machineSnapshot struct {
	SchemaVersion    int                `json:"schema_version"`
	Role             string             `json:"role"`
	UpdatedAt        string             `json:"updated_at"`
	Phase            string             `json:"phase,omitempty"`
	SessionID        string             `json:"session_id,omitempty"`
	Code             string             `json:"code,omitempty"`
	ShareURL         string             `json:"share_url,omitempty"`
	Metadata         *transfer.Metadata `json:"metadata,omitempty"`
	BytesTransferred uint64             `json:"bytes_transferred,omitempty"`
	TotalBytes       uint64             `json:"total_bytes,omitempty"`
	Connection       *machineConnection `json:"connection,omitempty"`
	RelayRequired    bool               `json:"relay_required,omitempty"`
	Result           *machineResult     `json:"result,omitempty"`
}

func newMachineReporter(ctx context.Context, cfg OutputConfig, role string, verbose bool) *machineReporter {
	return &machineReporter{
		ctx:        ctx,
		writer:     cfg.EventWriter,
		role:       role,
		verbose:    verbose,
		statusFile: cfg.StatusFile,
		snapshot: machineSnapshot{
			SchemaVersion: 1,
			Role:          role,
		},
	}
}

func (r *machineReporter) OnPhaseChanged(phase flow.Phase) {
	r.mu.Lock()
	r.snapshot.Phase = string(phase)
	r.emitLocked(machineEvent{Event: "phase", Phase: string(phase)})
	r.mu.Unlock()
}

func (r *machineReporter) OnTransferCode(code, baseURL string) {
	sessionID, _, err := crypto.ParseCode(code)
	if err != nil {
		sessionID = ""
	}
	shareURL := strings.TrimRight(baseURL, "/") + "/r#" + code
	prompt := agentPrompt(code, baseURL)

	r.mu.Lock()
	r.snapshot.SessionID = sessionID
	r.snapshot.Code = code
	r.snapshot.ShareURL = shareURL
	r.emitLocked(machineEvent{
		Event:       "session",
		SessionID:   sessionID,
		Code:        code,
		ShareURL:    shareURL,
		AgentPrompt: prompt,
	})
	r.mu.Unlock()
}

func (r *machineReporter) OnConnectionStatus(status conn.MethodStatus) {
	connection := &machineConnection{
		Method: machineConnectionMethod(status.Method),
		State:  status.State,
	}
	if r.verbose {
		connection.Detail = status.Detail
	}

	r.mu.Lock()
	r.snapshot.Connection = connection
	r.emitLocked(machineEvent{Event: "connection", Connection: connection})
	r.mu.Unlock()
}

func (r *machineReporter) OnConnectionMethodsReset() {
	r.mu.Lock()
	r.snapshot.Connection = nil
	r.emitLocked(machineEvent{Event: "connection_reset"})
	r.mu.Unlock()
}

func (r *machineReporter) OnMetadata(meta *transfer.Metadata) {
	metadata := cloneMetadata(meta)
	r.mu.Lock()
	r.snapshot.Metadata = metadata
	r.snapshot.TotalBytes = metadata.Size
	totalBytes := metadata.Size
	r.emitLocked(machineEvent{Event: "metadata", Metadata: metadata, TotalBytes: &totalBytes})
	r.mu.Unlock()
}

func (r *machineReporter) OnProgress(bytesTransferred uint64) {
	r.mu.Lock()
	r.snapshot.BytesTransferred = bytesTransferred
	if !r.lastProgressAt.IsZero() && time.Since(r.lastProgressAt) < time.Second {
		r.mu.Unlock()
		return
	}
	r.lastProgressAt = time.Now()
	totalBytes := r.snapshot.TotalBytes
	r.emitLocked(machineEvent{
		Event:            "progress",
		BytesTransferred: &bytesTransferred,
		TotalBytes:       &totalBytes,
	})
	r.mu.Unlock()
}

func (r *machineReporter) OnVerifyCode(code string) {
	r.mu.Lock()
	r.emitLocked(machineEvent{Event: "verification", Message: code})
	r.mu.Unlock()
}

func (r *machineReporter) OnComplete(totalBytes uint64, duration time.Duration) {
	r.mu.Lock()
	r.completion = &machineCompletion{TotalBytes: totalBytes, Duration: duration}
	r.snapshot.BytesTransferred = totalBytes
	r.snapshot.TotalBytes = totalBytes
	r.writeSnapshotLocked()
	r.mu.Unlock()
}

func (r *machineReporter) OnUpdateAvailable(currentVersion, serverVersion string) {
	r.mu.Lock()
	r.emitLocked(machineEvent{Event: "update_available", Message: currentVersion + " -> " + serverVersion})
	r.mu.Unlock()
}

func (r *machineReporter) OnError(message string) {
	r.mu.Lock()
	r.lastError = message
	r.emitLocked(machineEvent{
		Event: "error",
		Error: &machineError{
			Code:    "operation_failed",
			Message: message,
		},
	})
	r.mu.Unlock()
}

func (r *machineReporter) OnParallelStreams(count int) {
	r.mu.Lock()
	r.emitLocked(machineEvent{Event: "parallel_streams", ParallelStreams: count})
	r.mu.Unlock()
}

func (r *machineReporter) OnVerbose(message string) {
	if !r.verbose {
		return
	}
	r.mu.Lock()
	r.emitLocked(machineEvent{Event: "log", Message: message})
	r.mu.Unlock()
}

// PromptRelay emits an actionable event instead of reading a terminal. It
// creates the response file itself so an agent cannot accidentally approve a
// later transfer with a stale file. The file is removed after a response.
func (r *machineReporter) PromptRelay() bool {
	return r.promptRelay(r.ctx)
}

// PromptRelayContext lets flow stop a machine relay prompt when the peer has
// already declined or disconnected.
func (r *machineReporter) PromptRelayContext(ctx context.Context) bool {
	return r.promptRelay(ctx)
}

func (r *machineReporter) promptRelay(ctx context.Context) bool {
	responseFile, err := os.CreateTemp("", "sp2p-relay-response-")
	if err != nil {
		r.OnError("Could not create relay response file")
		return false
	}
	path := responseFile.Name()
	if err := responseFile.Chmod(0o600); err != nil {
		responseFile.Close()
		os.Remove(path)
		r.OnError("Could not secure relay response file")
		return false
	}
	if err := responseFile.Close(); err != nil {
		os.Remove(path)
		r.OnError("Could not prepare relay response file")
		return false
	}
	defer os.Remove(path)

	r.mu.Lock()
	r.snapshot.RelayRequired = true
	r.emitLocked(machineEvent{
		Event:            "relay_required",
		ResponseFile:     path,
		AllowedResponses: []string{"allow", "deny"},
	})
	r.mu.Unlock()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	lastInvalid := ""
	for {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			r.mu.Lock()
			r.relayResponse = "unavailable"
			r.snapshot.RelayRequired = false
			r.mu.Unlock()
			r.OnError("Could not read relay response file")
			return false
		}
		response := strings.ToLower(strings.TrimSpace(string(data)))
		switch response {
		case "allow", "deny":
			r.mu.Lock()
			r.relayResponse = response
			r.snapshot.RelayRequired = false
			r.emitLocked(machineEvent{Event: "relay_response", Response: response})
			r.mu.Unlock()
			return response == "allow"
		case "":
			// Still waiting for the agent.
		default:
			if response != lastInvalid {
				lastInvalid = response
				r.mu.Lock()
				r.emitLocked(machineEvent{
					Event: "relay_response_invalid",
					Error: &machineError{
						Code:    "invalid_relay_response",
						Message: "Relay response must be allow or deny",
					},
				})
				r.mu.Unlock()
			}
		}

		select {
		case <-ctx.Done():
			r.mu.Lock()
			r.relayResponse = "canceled"
			r.snapshot.RelayRequired = false
			r.emitLocked(machineEvent{Event: "relay_prompt_canceled"})
			r.mu.Unlock()
			return false
		case <-ticker.C:
		}
	}
}

func (r *machineReporter) finish(err error, savedPath string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	event := machineEvent{Event: "result"}
	result := &machineResult{SavedPath: savedPath}
	if err == nil {
		event.Outcome = "completed"
		result.Outcome = "completed"
		if r.completion != nil {
			totalBytes := r.completion.TotalBytes
			durationMS := r.completion.Duration.Milliseconds()
			event.TotalBytes = &totalBytes
			event.DurationMS = &durationMS
			result.TotalBytes = totalBytes
			result.DurationMS = durationMS
		}
		if savedPath != "" {
			event.SavedPath = savedPath
		}
	} else {
		errorCode := "operation_failed"
		if errors.Is(err, context.Canceled) {
			errorCode = "canceled"
		} else if r.relayResponse == "deny" {
			errorCode = "relay_denied"
		} else if r.snapshot.RelayRequired {
			errorCode = "relay_not_allowed"
		}
		message := r.lastError
		if message == "" {
			message = err.Error()
		}
		machineErr := &machineError{Code: errorCode, Message: message}
		event.Outcome = "failed"
		event.Error = machineErr
		result.Outcome = "failed"
		result.Error = machineErr
	}
	r.snapshot.Result = result
	r.emitLocked(event)
}

func (r *machineReporter) emitLocked(event machineEvent) {
	if event.Event == "result" {
		// The result is terminal. Persist it before writing it to the event
		// stream so a status-file failure is reported before, never after, the
		// terminal record.
		r.snapshot.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		r.writeSnapshotLocked()
	}
	r.sequence++
	event.SchemaVersion = 1
	event.Sequence = r.sequence
	event.At = time.Now().UTC().Format(time.RFC3339Nano)
	event.Role = r.role
	writeMachineEvent(r.writer, event)
	r.snapshot.UpdatedAt = event.At
	if event.Event != "result" {
		r.writeSnapshotLocked()
	}
}

func (r *machineReporter) writeSnapshotLocked() {
	if r.statusFile == "" {
		return
	}
	data, err := json.Marshal(r.snapshot)
	if err != nil {
		r.reportStatusFileErrorLocked(fmt.Errorf("marshal status snapshot: %w", err))
		return
	}
	dir := filepath.Dir(r.statusFile)
	tmp, err := os.CreateTemp(dir, ".sp2p-status-")
	if err != nil {
		r.reportStatusFileErrorLocked(fmt.Errorf("create status snapshot: %w", err))
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		r.reportStatusFileErrorLocked(fmt.Errorf("secure status snapshot: %w", err))
		return
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		r.reportStatusFileErrorLocked(fmt.Errorf("write status snapshot: %w", err))
		return
	}
	if err := tmp.Close(); err != nil {
		r.reportStatusFileErrorLocked(fmt.Errorf("close status snapshot: %w", err))
		return
	}
	if err := os.Rename(tmpPath, r.statusFile); err != nil {
		r.reportStatusFileErrorLocked(fmt.Errorf("replace status snapshot: %w", err))
		return
	}
	r.statusFileError = ""
}

func (r *machineReporter) reportStatusFileErrorLocked(err error) {
	message := err.Error()
	if message == r.statusFileError {
		return
	}
	r.statusFileError = message
	r.sequence++
	event := machineEvent{
		SchemaVersion: 1,
		Sequence:      r.sequence,
		Event:         "status_file_error",
		At:            time.Now().UTC().Format(time.RFC3339Nano),
		Role:          r.role,
		Error: &machineError{
			Code:    "status_file_unavailable",
			Message: message,
		},
	}
	writeMachineEvent(r.writer, event)
}

func writeMachineEvent(w io.Writer, event machineEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	data = append(data, '\n')
	w.Write(data)
}

func cloneMetadata(meta *transfer.Metadata) *transfer.Metadata {
	if meta == nil {
		return nil
	}
	clone := *meta
	return &clone
}

func machineConnectionMethod(method string) string {
	method = strings.ToLower(strings.TrimSpace(method))
	return strings.ReplaceAll(method, " ", "_")
}

func agentPrompt(code, baseURL string) string {
	return fmt.Sprintf("AI Agent: Please receive file session %s using %s/llm", code, strings.TrimRight(baseURL, "/"))
}
