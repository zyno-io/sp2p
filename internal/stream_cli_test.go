// SPDX-License-Identifier: MIT

package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	rsyncadapter "github.com/zyno-io/sp2p/internal/rsync"
)

type streamCLIEvent struct {
	Event, Code, Endpoint, Outcome string
	Error                          *struct{ Message string }
	BytesSent                      uint64 `json:"bytes_sent"`
	BytesReceived                  uint64 `json:"bytes_received"`
	OutputData                     []byte `json:"output_data"`
}

type streamCLIOutput struct {
	mu          sync.Mutex
	pending     []byte
	events      chan streamCLIEvent
	results     []streamCLIEvent
	err         error
	childOutput []byte
}

func (w *streamCLIOutput) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending = append(w.pending, data...)
	for {
		index := bytes.IndexByte(w.pending, '\n')
		if index < 0 {
			break
		}
		var event streamCLIEvent
		if err := json.Unmarshal(w.pending[:index], &event); err != nil {
			w.err = err
		}
		w.pending = w.pending[index+1:]
		if event.Event == "result" {
			w.results = append(w.results, event)
		}
		if event.Event == "subprocess_output" && len(w.childOutput) < 32768 {
			w.childOutput = append(w.childOutput, event.OutputData...)
		}
		select {
		case w.events <- event:
		default:
		}
	}
	return len(data), nil
}

type streamCLIProcess struct {
	output  *streamCLIOutput
	stderr  bytes.Buffer
	process *os.Process
	done    chan struct{}
	err     error
}

func startStreamCLI(t *testing.T, ctx context.Context, binary string, args ...string) *streamCLIProcess {
	t.Helper()
	return startStreamCLIWithIO(t, ctx, binary, nil, nil, args...)
}

func startStreamCLIWithIO(t *testing.T, ctx context.Context, binary string, stdin io.Reader, payload io.Writer, args ...string) *streamCLIProcess {
	t.Helper()
	p := &streamCLIProcess{output: &streamCLIOutput{events: make(chan streamCLIEvent, 128)}, done: make(chan struct{})}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = stdin
	cmd.Stdout, cmd.Stderr = p.output, &p.stderr
	if payload != nil {
		cmd.Stdout, cmd.Stderr = payload, p.output
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p.process = cmd.Process
	go func() { p.err = cmd.Wait(); close(p.done) }()
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			cmd.Process.Kill()
			<-p.done
		}
	})
	return p
}

func (p *streamCLIProcess) event(t *testing.T, ctx context.Context, name string) streamCLIEvent {
	t.Helper()
	for {
		select {
		case event := <-p.output.events:
			if event.Event == name {
				return event
			}
			if event.Event == "result" && event.Outcome == "failed" {
				t.Fatalf("stream failed waiting for %s: %v", name, event.Error)
			}
		case <-p.done:
			t.Fatalf("stream command exited waiting for %s: %v; %s", name, p.err, p.stderr.String())
		case <-ctx.Done():
			t.Fatalf("waiting for %s: %v", name, ctx.Err())
		}
	}
}

func (p *streamCLIProcess) completed(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-p.done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if p.err != nil {
		t.Fatalf("stream command: %v; %s; %s", p.err, p.stderr.String(), p.failureDetails())
	}
	p.output.mu.Lock()
	defer p.output.mu.Unlock()
	if p.output.err != nil {
		t.Fatalf("invalid JSON output: %v", p.output.err)
	}
	if len(p.output.results) != 1 || p.output.results[0].Outcome != "completed" {
		t.Fatalf("expected one successful terminal event; got %d", len(p.output.results))
	}
}

func (p *streamCLIProcess) failed(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-p.done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	p.output.mu.Lock()
	defer p.output.mu.Unlock()
	if p.err == nil || p.output.err != nil || len(p.output.results) != 1 || p.output.results[0].Outcome != "failed" {
		t.Fatalf("expected nonzero exit with one failed JSON result: exit=%v JSON=%v results=%d", p.err, p.output.err, len(p.output.results))
	}
}

func (p *streamCLIProcess) failureDetails() string {
	p.output.mu.Lock()
	defer p.output.mu.Unlock()
	for _, event := range p.output.results {
		if event.Error != nil {
			return event.Error.Message + "; child output: " + string(p.output.childOutput)
		}
	}
	return "no terminal error received; child output: " + string(p.output.childOutput)
}

func TestStreamCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess integration")
	}
	binary := buildBinary(t)
	wsURL := startSignalServer(t)
	for _, scenario := range []struct{ name, transport, target, listener string }{
		{"tcp", "tcp", "tcp", "tcp"},
		{"webrtc", "webrtc", "tcp", "tcp"},
		{"tcp-to-unix", "tcp", "unix", "tcp"},
		{"unix-to-tcp", "tcp", "tcp", "unix"},
		{"unix-to-unix", "tcp", "unix", "unix"},
	} {
		t.Run("tunnel-"+scenario.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
			defer cancel()
			targetAddr := "127.0.0.1:0"
			listenAddr := "tcp://127.0.0.1:0"
			if scenario.target == "unix" || scenario.listener == "unix" {
				// Keep socket paths under macOS's short Unix socket path limit.
				dir, err := os.MkdirTemp("", "sp2p-sock-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(dir) })
				if scenario.target == "unix" {
					targetAddr = filepath.Join(dir, "target")
				}
				if scenario.listener == "unix" {
					listenAddr = "unix://" + filepath.Join(dir, "local")
				}
			}
			target, err := net.Listen(scenario.target, targetAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			accepted := make(chan struct{})
			targetDone := make(chan error, 1)
			payload := bytes.Repeat([]byte("duplex-data\x00"), 200000)
			go func() {
				conn, err := target.Accept()
				if err != nil {
					targetDone <- err
					return
				}
				defer conn.Close()
				close(accepted)
				conn.SetDeadline(time.Now().Add(35 * time.Second))
				data, err := io.ReadAll(conn)
				if err == nil && !bytes.Equal(data, payload) {
					err = fmt.Errorf("target payload mismatch")
				}
				if err == nil {
					_, err = conn.Write(append([]byte("reply:"), data...))
				}
				targetDone <- err
			}()
			provider := startStreamCLI(t, ctx, binary, "tunnel", "serve", "--server", wsURL, "--transport", scenario.transport, "--format", "json", "--to", scenario.target+"://"+target.Addr().String())
			code := provider.event(t, ctx, "session").Code
			connector := startStreamCLI(t, ctx, binary, "tunnel", "connect", "--server", wsURL, "--transport", scenario.transport, "--format", "json", "--listen", listenAddr, code)
			endpoint := connector.event(t, ctx, "ready").Endpoint
			select {
			case <-accepted:
				t.Fatal("target dialed before local client connected")
			default:
			}
			local, err := net.Dial(scenario.listener, strings.TrimPrefix(endpoint, scenario.listener+"://"))
			if err != nil {
				t.Fatal(err)
			}
			defer local.Close()
			local.SetDeadline(time.Now().Add(35 * time.Second))
			if _, err := local.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := local.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(local)
			if err != nil {
				t.Fatalf("%v; provider: %s; connector: %s", err, provider.failureDetails(), connector.failureDetails())
			}
			if !bytes.Equal(reply, append([]byte("reply:"), payload...)) {
				t.Fatalf("half-close response truncated: %d", len(reply))
			}
			if err := <-targetDone; err != nil {
				t.Fatal(err)
			}
			provider.completed(t, ctx)
			connector.completed(t, ctx)
			if scenario.listener == "unix" {
				if _, err := os.Lstat(strings.TrimPrefix(listenAddr, "unix://")); !os.IsNotExist(err) {
					t.Fatalf("owned Unix listener was not removed: %v", err)
				}
			}
		})
	}
	t.Run("tunnel-stdio", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		payload := []byte("binary stdin\x00\xff\n")
		var output bytes.Buffer
		provider := startStreamCLIWithIO(t, ctx, binary, bytes.NewReader(payload), &output,
			"tunnel", "serve", "--server", wsURL, "--transport", "tcp", "--format", "json", "--event-output", "stderr", "--stdio")
		code := provider.event(t, ctx, "session").Code
		connector := startStreamCLI(t, ctx, binary, "tunnel", "connect", "--server", wsURL, "--transport", "tcp", "--format", "json", "--listen", "tcp://127.0.0.1:0", code)
		endpoint := connector.event(t, ctx, "ready").Endpoint
		local, err := net.Dial("tcp", strings.TrimPrefix(endpoint, "tcp://"))
		if err != nil {
			t.Fatal(err)
		}
		defer local.Close()
		local.SetDeadline(time.Now().Add(20 * time.Second))
		got, err := io.ReadAll(local)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("stdio request: bytes=%d err=%v", len(got), err)
		}
		// Respond only after observing EOF in the opposite direction.
		if _, err := local.Write([]byte("response after EOF\x00")); err != nil {
			t.Fatal(err)
		}
		local.(*net.TCPConn).CloseWrite()
		provider.completed(t, ctx)
		connector.completed(t, ctx)
		if !bytes.Equal(output.Bytes(), []byte("response after EOF\x00")) {
			t.Fatalf("stdout was truncated or contaminated: %q", output.Bytes())
		}
	})
	t.Run("tunnel-accept-timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		provider := startStreamCLI(t, ctx, binary, "tunnel", "serve", "--server", wsURL, "--transport", "tcp", "--format", "json", "--to", "tcp://127.0.0.1:1")
		code := provider.event(t, ctx, "session").Code
		connector := startStreamCLI(t, ctx, binary, "tunnel", "connect", "--server", wsURL, "--transport", "tcp", "--format", "json", "--accept-timeout", "100ms", "--listen", "tcp://127.0.0.1:0", code)
		connector.event(t, ctx, "ready")
		connector.failed(t, ctx)
		provider.failed(t, ctx)
	})
	t.Run("rsync", func(t *testing.T) {
		path := os.Getenv("SP2P_TEST_RSYNC")
		if path == "" {
			path = "rsync"
		}
		rsyncBin, _, err := rsyncadapter.FindBinary(path)
		if err != nil {
			if os.Getenv("SP2P_TEST_RSYNC") != "" {
				t.Fatalf("configured rsync fixture is invalid: %v", err)
			}
			t.Skipf("supported real rsync unavailable (set SP2P_TEST_RSYNC): %v", err)
		}
		pairs := []struct{ name, sender, receiver string }{{"same", rsyncBin, rsyncBin}}
		if peerPath := os.Getenv("SP2P_TEST_RSYNC_PEER"); peerPath != "" {
			peerBin, _, err := rsyncadapter.FindBinary(peerPath)
			if err != nil {
				t.Fatalf("configured peer rsync fixture is invalid: %v", err)
			}
			pairs = append(pairs,
				struct{ name, sender, receiver string }{"peer", peerBin, peerBin},
				struct{ name, sender, receiver string }{"send-peer", peerBin, rsyncBin},
				struct{ name, sender, receiver string }{"recv-peer", rsyncBin, peerBin})
		}
		for _, pair := range pairs {
			t.Run(pair.name, func(t *testing.T) {
				// Each matrix pair gets an independent rate-limit budget. A
				// larger compatibility matrix must not weaken production limits.
				testStreamCLIRsync(t, binary, startSignalServer(t), pair.sender, pair.receiver)
				t.Run("helper-path", func(t *testing.T) {
					// Exercise both the upstream shell hook and Apple's rsync
					// argument parser without relying on a conveniently simple path.
					helperPath := filepath.Join(t.TempDir(), "sp2p 'single' \"double\" %")
					if err := os.Link(binary, helperPath); err != nil {
						t.Fatal(err)
					}
					testStreamCLIRsync(t, helperPath, startSignalServer(t), pair.sender, pair.receiver, "push")
				})
			})
		}
	})
}

// Run the same role/policy/delta checks for both homogeneous and mixed rsync
// implementations. SP2P_TEST_RSYNC_PEER lets CI cover the OS-provided binary
// alongside a pinned upstream fixture without changing PATH.
func testStreamCLIRsync(t *testing.T, binary, wsURL, senderBin, receiverBin string, modes ...string) {
	t.Helper()
	source, destination := t.TempDir(), t.TempDir()
	data := bytes.Repeat([]byte("rsync delta test data\n"), 90000)
	if err := os.WriteFile(filepath.Join(source, "a file.txt"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	unicodeName := "café-雪.txt"
	unicodeData := []byte("Unicode filenames survive daemon locale normalization.\n")
	if err := os.WriteFile(filepath.Join(source, unicodeName), unicodeData, 0o600); err != nil {
		t.Fatal(err)
	}
	var initialBytes uint64
	if len(modes) == 0 {
		modes = []string{"push", "noop", "delta", "pull", "compress", "webrtc", "deny-delete", "allow-delete", "missing-source"}
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
			defer cancel()
			if mode == "delta" {
				copy(data[100:110], []byte("small edit"))
				if err := os.WriteFile(filepath.Join(source, "a file.txt"), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "deny-delete" {
				if err := os.WriteFile(filepath.Join(destination, "keep.txt"), []byte("keep until authorized"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			transport, recvDir := "tcp", destination
			if mode == "webrtc" {
				transport, recvDir = "webrtc", t.TempDir()
			} else if mode == "compress" {
				recvDir = t.TempDir()
			}
			common := []string{"--server", wsURL, "--transport", transport, "--format", "json"}
			sendArgs := append([]string{"rsync", "send"}, common...)
			sendArgs = append(sendArgs, "--rsync-binary", senderBin)
			if mode == "pull" {
				sendArgs = append(sendArgs, source)
			} else {
				sendArgs = append(sendArgs, "--", "-avc", "--partial")
				if mode == "compress" {
					sendArgs = append(sendArgs, "-z")
				}
				if mode == "deny-delete" || mode == "allow-delete" {
					sendArgs = append(sendArgs, "--delete")
				}
				if mode == "missing-source" {
					sendArgs = append(sendArgs, filepath.Join(source, "does-not-exist"), "sp2p::share/")
				} else {
					sendArgs = append(sendArgs, source+"/", "sp2p::share/")
				}
			}
			sender := startStreamCLI(t, ctx, binary, sendArgs...)
			code := sender.event(t, ctx, "session").Code
			recvArgs := append([]string{"rsync", "recv"}, common...)
			recvArgs = append(recvArgs, "--rsync-binary", receiverBin)
			if mode == "allow-delete" {
				recvArgs = append(recvArgs, "--allow-delete")
			}
			recvArgs = append(recvArgs, code)
			if mode == "pull" {
				recvArgs = append(recvArgs, "--", "-avc", "sp2p::share/", recvDir+"/")
			} else {
				recvArgs = append(recvArgs, recvDir)
			}
			receiver := startStreamCLI(t, ctx, binary, recvArgs...)
			defer func() {
				if t.Failed() {
					t.Logf("sender: %s; receiver: %s", sender.failureDetails(), receiver.failureDetails())
				}
			}()
			if mode == "deny-delete" || mode == "missing-source" {
				// A local rsync error must fail both peers, never become clean EOF.
				sender.failed(t, ctx)
				receiver.failed(t, ctx)
				if mode == "deny-delete" {
					if _, err := os.Stat(filepath.Join(destination, "keep.txt")); err != nil {
						t.Fatal("receiver's deletion policy was bypassed")
					}
				} else if exit, ok := sender.err.(*exec.ExitError); !ok || exit.ExitCode() != 23 {
					t.Fatalf("missing source must preserve rsync exit23: %v; %s", sender.err, sender.failureDetails())
				}
				return
			}
			sender.completed(t, ctx)
			receiver.completed(t, ctx)
			if mode == "allow-delete" {
				if _, err := os.Stat(filepath.Join(destination, "keep.txt")); !os.IsNotExist(err) {
					t.Fatalf("authorized deletion did not happen: %v", err)
				}
			}
			sent := sender.output.results[0].BytesSent
			if mode == "push" {
				initialBytes = sent
			} else if mode == "noop" || mode == "delta" {
				if sent >= initialBytes/2 || initialBytes == 0 {
					t.Fatalf("%s did not reuse destination data: sent=%d initial=%d", mode, sent, initialBytes)
				}
			}
			got, err := os.ReadFile(filepath.Join(recvDir, "a file.txt"))
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("rsync contents: %v", err)
			}
			unicodeGot, err := os.ReadFile(filepath.Join(recvDir, unicodeName))
			if err != nil || !bytes.Equal(unicodeGot, unicodeData) {
				t.Fatalf("rsync Unicode filename or contents: %v", err)
			}
		})
	}
}
