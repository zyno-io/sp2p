// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeriveWSURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"http to ws", "http://localhost:8080", "ws://localhost:8080/ws"},
		{"https to wss", "https://sp2p.io", "wss://sp2p.io/ws"},
		{"ws passthrough", "ws://localhost:8080/ws", "ws://localhost:8080/ws"},
		{"wss passthrough", "wss://sp2p.io/ws", "wss://sp2p.io/ws"},
		{"ws custom path passthrough", "ws://relay.example.com:9090/custom", "ws://relay.example.com:9090/custom"},
		{"https with path", "https://sp2p.io/prefix", "wss://sp2p.io/prefix/ws"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveWSURL(tt.in); got != tt.want {
				t.Errorf("deriveWSURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDeriveBaseURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ws to http", "ws://localhost:8080/ws", "http://localhost:8080"},
		{"wss to https", "wss://sp2p.io/ws", "https://sp2p.io"},
		{"http passthrough", "http://localhost:8080", "http://localhost:8080"},
		{"https passthrough", "https://sp2p.io", "https://sp2p.io"},
		{"wss no /ws suffix", "wss://relay.example.com:9090", "https://relay.example.com:9090"},
		{"ws with trailing /ws", "ws://10.0.0.5:8080/ws", "http://10.0.0.5:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveBaseURL(tt.in); got != tt.want {
				t.Errorf("deriveBaseURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDeriveWSURL_RoundTrip(t *testing.T) {
	// Verify that deriveBaseURL(deriveWSURL(url)) returns the original URL
	// for standard http(s) inputs.
	urls := []string{
		"http://localhost:8080",
		"https://sp2p.io",
		"http://10.0.0.5:9090",
	}
	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			if got := deriveBaseURL(deriveWSURL(u)); got != u {
				t.Errorf("round-trip failed: %q -> deriveWSURL -> %q -> deriveBaseURL -> %q", u, deriveWSURL(u), got)
			}
		})
	}
}

func TestReorderArgs(t *testing.T) {
	// Create a FlagSet matching the send command flags.
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("server", "", "")
	fs.String("url", "", "")
	fs.String("name", "", "")
	fs.Int("compress", 3, "")
	fs.Bool("allow-relay", false, "")
	fs.Bool("v", false, "")
	fs.String("format", "human", "")
	fs.String("event-output", "stdout", "")
	fs.String("status-file", "", "")

	tests := []struct {
		name string
		args []string
		want string // space-joined result
	}{
		{
			"flags before positional",
			[]string{"-server", "ws://example.com", "file.txt"},
			"-server ws://example.com file.txt",
		},
		{
			"positional before flags",
			[]string{"file.txt", "-server", "ws://example.com"},
			"-server ws://example.com file.txt",
		},
		{
			"boolean flag with positional",
			[]string{"file.txt", "-allow-relay"},
			"-allow-relay file.txt",
		},
		{
			"double dash boolean",
			[]string{"file.txt", "--allow-relay"},
			"--allow-relay file.txt",
		},
		{
			"flag=value syntax",
			[]string{"file.txt", "-server=ws://example.com"},
			"-server=ws://example.com file.txt",
		},
		{
			"boolean flag=value",
			[]string{"file.txt", "-allow-relay=true"},
			"-allow-relay=true file.txt",
		},
		{
			"mixed flags and positionals",
			[]string{"a.txt", "-v", "b.txt", "-server", "ws://x", "c.txt"},
			"-v -server ws://x a.txt b.txt c.txt",
		},
		{
			"no args",
			[]string{},
			"",
		},
		{
			"only positional",
			[]string{"a.txt", "b.txt"},
			"a.txt b.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(reorderArgs(fs, tt.args), " ")
			if got != tt.want {
				t.Errorf("reorderArgs(%v) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

func TestRequestedMachineOutput(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		wantMachine     bool
		wantEventOutput string
	}{
		{"default", []string{"report.pdf"}, false, "stdout"},
		{"equals syntax", []string{"-format=json", "report.pdf"}, true, "stdout"},
		{"separate value and stderr", []string{"report.pdf", "--format", "json", "--event-output", "stderr"}, true, "stderr"},
		{"positional named format is ignored", []string{"format", "json"}, false, "stdout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine, eventOutput := requestedMachineOutput(tt.args)
			if machine != tt.wantMachine || eventOutput != tt.wantEventOutput {
				t.Fatalf("requestedMachineOutput(%v) = (%v, %q), want (%v, %q)", tt.args, machine, eventOutput, tt.wantMachine, tt.wantEventOutput)
			}
		})
	}
}

func TestJSONHelpWritesHumanHelpToStderr(t *testing.T) {
	if os.Getenv("SP2P_HELP_SUBPROCESS") == "1" {
		os.Args = []string{"sp2p", "send", "-format", "json", "--help"}
		main()
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestJSONHelpWritesHumanHelpToStderr$")
	command.Env = append(os.Environ(), "SP2P_HELP_SUBPROCESS=1")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("JSON help subprocess: %v\nstderr: %s", err, stderr.String())
	}
	if strings.Contains(stdout.String(), `"schema_version"`) {
		t.Fatalf("JSON help wrote a machine event to stdout: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage: sp2p send") || !strings.Contains(stderr.String(), "-format") {
		t.Fatalf("JSON help did not write flag help to stderr: %s", stderr.String())
	}
}

func TestHumanHelpIsPrintedOnce(t *testing.T) {
	if os.Getenv("SP2P_HUMAN_HELP_SUBPROCESS") == "1" {
		os.Args = []string{"sp2p", os.Getenv("SP2P_HELP_COMMAND"), "--help"}
		main()
		return
	}

	for _, commandName := range []string{"send", "receive"} {
		t.Run(commandName, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestHumanHelpIsPrintedOnce$")
			command.Env = append(os.Environ(), "SP2P_HUMAN_HELP_SUBPROCESS=1", "SP2P_HELP_COMMAND="+commandName)
			var stderr bytes.Buffer
			command.Stderr = &stderr
			if err := command.Run(); err != nil {
				t.Fatalf("human help subprocess: %v\nstderr: %s", err, stderr.String())
			}
			if count := strings.Count(stderr.String(), "Usage: sp2p "+commandName); count != 1 {
				t.Fatalf("usage count = %d, want 1\nstderr: %s", count, stderr.String())
			}
		})
	}
}

func TestJSONValidationFailureWritesStatusSnapshot(t *testing.T) {
	if os.Getenv("SP2P_STATUS_FAILURE_SUBPROCESS") == "1" {
		os.Args = []string{
			"sp2p", "send", "-format", "json", "-status-file", os.Getenv("SP2P_STATUS_FILE"),
		}
		main()
		return
	}

	statusFile := filepath.Join(t.TempDir(), "status.json")
	command := exec.Command(os.Args[0], "-test.run=^TestJSONValidationFailureWritesStatusSnapshot$")
	command.Env = append(os.Environ(), "SP2P_STATUS_FAILURE_SUBPROCESS=1", "SP2P_STATUS_FILE="+statusFile)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err == nil {
		t.Fatal("validation-failure subprocess unexpectedly succeeded")
	}

	var event struct {
		Event   string `json:"event"`
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &event); err != nil {
		t.Fatalf("validation failure did not emit JSON: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	if event.Event != "result" || event.Outcome != "failed" {
		t.Fatalf("event = %#v, want failed result", event)
	}

	data, err := os.ReadFile(statusFile)
	if err != nil {
		t.Fatalf("read status snapshot: %v", err)
	}
	var snapshot struct {
		Role   string `json:"role"`
		Result struct {
			Outcome string `json:"outcome"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("decode status snapshot: %v", err)
	}
	if snapshot.Role != "send" || snapshot.Result.Outcome != "failed" {
		t.Fatalf("snapshot = %#v, want failed send result", snapshot)
	}
}
