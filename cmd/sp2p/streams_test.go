// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zyno-io/sp2p/internal/cli"
)

func TestStreamJSONHelpIsClean(t *testing.T) {
	if args := os.Getenv("SP2P_STREAM_HELP_TEST"); args != "" {
		if err := json.Unmarshal([]byte(args), &os.Args); err != nil {
			t.Fatal(err)
		}
		main()
		os.Exit(0)
	}
	for _, args := range [][]string{
		{"sp2p", "rsync", "recv", "--format", "json", "--event-output", "stderr", "--help"},
		{"sp2p", "rsync", "help", "--format=json"},
		{"sp2p", "tunnel", "connect", "--help", "--format=json", "--event-output=stderr"},
		{"sp2p", "tunnel", "help", "--format=json"},
	} {
		t.Run(args[1]+"-"+args[2], func(t *testing.T) {
			encoded, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestStreamJSONHelpIsClean$")
			cmd.Env = append(os.Environ(), "SP2P_STREAM_HELP_TEST="+string(encoded))
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("help failed: %v; %s", err, stderr.String())
			}
			_, destination := requestedMachineOutput(args)
			events, other := &stdout, &stderr
			if destination == "stderr" {
				events, other = &stderr, &stdout
			}
			var event struct{ Event, Service, Mode, Outcome, Message string }
			if err := json.Unmarshal(events.Bytes(), &event); err != nil {
				t.Fatalf("non-JSON help: %v; %s", err, events.String())
			}
			if other.Len() != 0 || event.Event != "result" || event.Service != args[1] || event.Mode != "help" || event.Outcome != "completed" || !strings.Contains(event.Message, "Usage:") {
				t.Fatalf("incorrect help result: other=%q event=%+v", other.String(), event)
			}
		})
	}
}

func TestStreamJSONFlagFailureIsClean(t *testing.T) {
	if os.Getenv("SP2P_STREAM_FLAG_TEST") == "1" {
		os.Args = []string{"sp2p", "rsync", "recv", "--format", "json", "--event-output", "stderr", "--nonsense"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStreamJSONFlagFailureIsClean$")
	cmd.Env = append(os.Environ(), "SP2P_STREAM_FLAG_TEST=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("invalid flag succeeded")
	}
	var event struct{ Event, Role, Service, Mode, Outcome string }
	if err := json.Unmarshal(stderr.Bytes(), &event); err != nil {
		t.Fatalf("non-JSON stderr: %v; %s", err, stderr.String())
	}
	if stdout.Len() != 0 || event.Event != "result" || event.Outcome != "failed" || event.Service != "rsync" || event.Role != "recv" || event.Mode != "recv-daemon" {
		t.Fatalf("incorrect early failure: stdout=%q event=%+v", stdout.String(), event)
	}
}

func TestStreamInvalidTransportWritesStatusFile(t *testing.T) {
	if statusFile := os.Getenv("SP2P_STREAM_STATUS_TEST"); statusFile != "" {
		os.Args = []string{
			"sp2p", "tunnel", "connect", "--format", "json", "--event-output", "stderr",
			"--status-file", statusFile, "--transport", "invalid", "--stdio", "test-code",
		}
		main()
		return
	}
	statusFile := filepath.Join(t.TempDir(), "status.json")
	cmd := exec.Command(os.Args[0], "-test.run=^TestStreamInvalidTransportWritesStatusFile$")
	cmd.Env = append(os.Environ(), "SP2P_STREAM_STATUS_TEST="+statusFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("invalid transport succeeded")
	}
	if stdout.Len() != 0 {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
	var event struct {
		Event, Role, Service, Mode, Outcome string
		Error                               *struct{ Message string }
	}
	if err := json.Unmarshal(stderr.Bytes(), &event); err != nil {
		t.Fatalf("non-JSON stderr: %v; %s", err, stderr.String())
	}
	if event.Event != "result" || event.Outcome != "failed" || event.Service != "tunnel" || event.Role != "connect" || event.Mode != "connect" || event.Error == nil || !strings.Contains(event.Error.Message, "transport") {
		t.Fatalf("incorrect failure event: %+v", event)
	}
	statusData, err := os.ReadFile(statusFile)
	if err != nil {
		t.Fatalf("read status file: %v", err)
	}
	var snapshot struct {
		Role, Service, Mode string
		Result              *struct {
			Outcome string
			Error   *struct{ Message string }
		}
	}
	if err := json.Unmarshal(statusData, &snapshot); err != nil {
		t.Fatalf("invalid status file: %v; %s", err, statusData)
	}
	if snapshot.Role != "connect" || snapshot.Service != "tunnel" || snapshot.Mode != "connect" || snapshot.Result == nil || snapshot.Result.Outcome != "failed" || snapshot.Result.Error == nil || !strings.Contains(snapshot.Result.Error.Message, "transport") {
		t.Fatalf("incorrect status snapshot: %+v", snapshot)
	}
}

func TestStreamCommandFailureKeepsIdentity(t *testing.T) {
	var output bytes.Buffer
	err := streamCommandFailure(cli.OutputConfig{Format: cli.OutputJSON, EventWriter: &output}, "rsync", "recv", false, errors.New("missing directory"))
	if !cli.MachineErrorReported(err) {
		t.Fatal("failure not marked reported")
	}
	var event struct{ Event, Role, Service, Mode, Outcome string }
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.Event != "result" || event.Outcome != "failed" || event.Role != "recv" || event.Service != "rsync" || event.Mode != "recv-daemon" {
		t.Fatalf("unexpected failure identity: %+v", event)
	}
}

func TestRsyncArgumentBoundary(t *testing.T) {
	args := []string{"--server", "https://example.test", "--format", "json", "--", "-av", "--filter", "- *.tmp", "a path/", "sp2p::share/", "--format=human"}
	options, forwarded, client := splitRsyncArgs(args)
	if !client || !reflect.DeepEqual(options, args[:4]) || !reflect.DeepEqual(forwarded, args[5:]) {
		t.Fatalf("lost rsync argument boundaries: %#v %#v %v", options, forwarded, client)
	}
	machine, _ := requestedMachineOutput(args)
	if !machine {
		t.Fatal("rsync arguments changed SP2P output mode")
	}
	machine, _ = requestedMachineOutput([]string{"--", "--format=json", "source", "sp2p::share/"})
	if machine {
		t.Fatal("rsync arguments incorrectly enabled SP2P JSON output")
	}
}
