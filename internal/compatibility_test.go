// SPDX-License-Identifier: MIT

package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type compatibilityOutput struct {
	mu           sync.Mutex
	all, pending bytes.Buffer
	code         chan string
}

func (out *compatibilityOutput) Write(data []byte) (int, error) {
	out.mu.Lock()
	defer out.mu.Unlock()
	out.all.Write(data)
	out.pending.Write(data)
	for {
		line := out.pending.Bytes()
		end := bytes.IndexByte(line, '\n')
		if end < 0 {
			break
		}
		var event struct{ Event, Code string }
		if json.Unmarshal(line[:end], &event) == nil && event.Event == "session" {
			select {
			case out.code <- event.Code:
			default:
			}
		}
		out.pending.Next(end + 1)
	}
	return len(data), nil
}
func (out *compatibilityOutput) String() string {
	out.mu.Lock()
	defer out.mu.Unlock()
	return out.all.String()
}

// Set SP2P_TEST_LEGACY_BINARY to a CLI built from the unmodified v0.4.0 tag
// to extend the normal v2/v3 regressions with real cross-release wire tests.
// SP2P_TEST_LEGACY_SERVER_BINARY additionally exercises the old signaling server.
func TestE2E_ProtocolCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping protocol e2e in short mode")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	current := buildBinary(t)
	servers := map[string]string{"new-server": startSignalServer(t)}
	if binary := os.Getenv("SP2P_TEST_LEGACY_SERVER_BINARY"); binary != "" {
		servers["old-server"] = startLegacyCompatibilityServer(t, binary)
	}
	type pair struct {
		name, sender, receiver string
		version                int
		senderOld, receiverOld bool
	}
	pairs := []pair{{"new-new", current, current, 3, false, false}}
	if old := os.Getenv("SP2P_TEST_LEGACY_BINARY"); old != "" {
		pairs = append(pairs, pair{"old-new", old, current, 2, true, false}, pair{"new-old", current, old, 2, false, true}, pair{"old-old", old, old, 2, true, true})
	}
	for serverName, url := range servers {
		for _, peers := range pairs {
			for _, transport := range []string{"tcp", "webrtc", "auto"} {
				for _, compression := range []int{0, 3, 9} {
					if transport == "auto" && compression != 3 {
						continue
					}
					t.Run(fmt.Sprintf("%s/%s/%s/compress%d", serverName, peers.name, transport, compression), func(t *testing.T) {
						// More than sixteen 256-KiB chunks detects accidental v3 credit waits.
						data := bytes.Repeat([]byte("compatibility-0123456789\n"), 240000)
						src := filepath.Join(t.TempDir(), "compatibility.bin")
						if err := os.WriteFile(src, data, 0600); err != nil {
							t.Fatal(err)
						}
						dest := t.TempDir()
						ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
						defer cancel()
						sendArgs := []string{"send", "-format", "json", "-server", url, "-transport", transport, "-compress", fmt.Sprint(compression)}
						// Exercise forced parallel requests too: mixed peers must
						// still connect automatically using a single TCP stream.
						if transport == "tcp" && compression == 9 && !peers.senderOld {
							sendArgs = append(sendArgs, "-parallel", "6")
						}
						sendArgs = append(sendArgs, src)
						sender := exec.CommandContext(ctx, peers.sender, sendArgs...)
						out := &compatibilityOutput{code: make(chan string, 1)}
						sender.Stdout, sender.Stderr = out, out
						if err := sender.Start(); err != nil {
							t.Fatal(err)
						}
						done := make(chan error, 1)
						go func() { done <- sender.Wait() }()
						var code string
						select {
						case code = <-out.code:
						case err := <-done:
							t.Fatalf("sender exited: %v\n%s", err, out.String())
						case <-ctx.Done():
							t.Fatalf("registration timeout\n%s", out.String())
						}
						recvArgs := []string{"receive", "-format", "json", "-server", url, "-transport", transport, "-output", dest}
						if transport == "tcp" && compression == 9 && !peers.receiverOld {
							recvArgs = append(recvArgs, "-parallel", "6")
						}
						recvArgs = append(recvArgs, code)
						receiver := exec.CommandContext(ctx, peers.receiver, recvArgs...)
						recvOutput, recvErr := receiver.CombinedOutput()
						if recvErr != nil {
							cancel()
						}
						sendErr := <-done
						if recvErr != nil || sendErr != nil {
							t.Fatalf("sender: %v\n%s\nreceiver: %v\n%s", sendErr, out.String(), recvErr, recvOutput)
						}
						got, err := os.ReadFile(filepath.Join(dest, "compatibility.bin"))
						if err != nil || !bytes.Equal(got, data) {
							t.Fatalf("content mismatch: %v", err)
						}
						if peers.version == 2 {
							if !peers.senderOld && !strings.Contains(out.String(), `"event":"warning"`) {
								t.Fatal("missing sender warning")
							}
							if !peers.receiverOld && !bytes.Contains(recvOutput, []byte(`"event":"warning"`)) {
								t.Fatal("missing receiver warning")
							}
						}
						protocolEvent := fmt.Sprintf(`"event":"protocol","protocol":%d`, peers.version)
						if !peers.senderOld && !strings.Contains(out.String(), protocolEvent) {
							t.Fatalf("wrong sender protocol: %s", out.String())
						}
						if !peers.receiverOld && !bytes.Contains(recvOutput, []byte(protocolEvent)) {
							t.Fatalf("wrong receiver protocol: %s", recvOutput)
						}
					})
				}
			}
		}
	}
}

func startLegacyCompatibilityServer(t *testing.T, binary string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, "-addr", addr, "-base-url", "http://"+addr)
	out := &compatibilityOutput{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { cancel(); <-done })
	client := &http.Client{Timeout: time.Second}
	for until := time.Now().Add(10 * time.Second); time.Now().Before(until); {
		resp, err := client.Get("http://" + addr + "/health")
		if err == nil {
			resp.Body.Close()
			return "ws://" + addr + "/ws"
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("old server did not start: %s", out.String())
	return ""
}
