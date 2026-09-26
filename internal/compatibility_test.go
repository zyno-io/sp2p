// SPDX-License-Identifier: MIT

package internal

import (
	"bytes"
	"context"
	"crypto/rand"
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
//
// Set SP2P_TEST_PREVIOUS_BINARY, SP2P_TEST_PREVIOUS_SERVER_BINARY, and
// SP2P_TEST_PREVIOUS_VERSION to a CLI/server/version built from the release
// immediately before this one (see scripts/ci/previous-release.sh) to add
// protocol-3 new<->previous coverage, including the >4-lane WebRTC count/max
// split encoding that a v0.4.0-only fixture can never exercise (the previous
// release already speaks protocol 3, just with fewer WebRTC lanes).
func TestE2E_ProtocolCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping protocol e2e in short mode")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	current := buildBinary(t)

	prevBinary := os.Getenv("SP2P_TEST_PREVIOUS_BINARY")
	prevServerBinary := os.Getenv("SP2P_TEST_PREVIOUS_SERVER_BINARY")
	prevVersion := os.Getenv("SP2P_TEST_PREVIOUS_VERSION")

	if prevBinary != "" {
		// Identity check: guard against a stale cache or misconfigured job
		// silently testing "previous" against a binary that isn't actually
		// the version the capabilities table and lane-count math assume.
		t.Run("previous-binary-identity", func(t *testing.T) {
			if prevVersion == "" {
				t.Skip("SP2P_TEST_PREVIOUS_VERSION not set")
			}
			out, err := exec.Command(prevBinary, "version").CombinedOutput()
			if err != nil {
				t.Fatalf("running previous binary version: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), prevVersion) {
				t.Fatalf("previous binary version output %q does not contain expected version %q", out, prevVersion)
			}
		})
	}

	type compatibilityServer struct {
		name  string
		start func(*testing.T) string
	}
	servers := []compatibilityServer{{"new-server", startSignalServer}}
	if binary := os.Getenv("SP2P_TEST_LEGACY_SERVER_BINARY"); binary != "" {
		servers = append(servers, compatibilityServer{"old-server", func(t *testing.T) string {
			return startLegacyCompatibilityServer(t, binary)
		}})
	}
	if prevServerBinary != "" {
		servers = append(servers, compatibilityServer{"previous-server", func(t *testing.T) string {
			return startLegacyCompatibilityServer(t, prevServerBinary)
		}})
	}

	type pair struct {
		name, sender, receiver string
		version                int
		senderOld, receiverOld bool
		// servers restricts which of the servers above this pair runs
		// against. old-server is the immutable v0.4.0 fixture, so protocol-3
		// new/previous pairs never run against it — only new-server and
		// previous-server understand protocol 3.
		servers map[string]bool
	}
	legacyAndNewServers := map[string]bool{"new-server": true, "old-server": true}
	previousAndNewServers := map[string]bool{"new-server": true, "previous-server": true}

	pairs := []pair{{"new-new", current, current, 3, false, false, legacyAndNewServers}}
	if old := os.Getenv("SP2P_TEST_LEGACY_BINARY"); old != "" {
		pairs = append(pairs,
			pair{"old-new", old, current, 2, true, false, legacyAndNewServers},
			pair{"new-old", current, old, 2, false, true, legacyAndNewServers},
			pair{"old-old", old, old, 2, true, true, legacyAndNewServers},
		)
	}
	if prevBinary != "" {
		protocol := previousReleaseCapabilities(t, prevVersion).Protocol
		pairs = append(pairs,
			pair{"new-prev", current, prevBinary, protocol, false, false, previousAndNewServers},
			pair{"prev-new", prevBinary, current, protocol, false, false, previousAndNewServers},
		)
	}
	for _, server := range servers {
		for _, peers := range pairs {
			if !peers.servers[server.name] {
				continue
			}
			// A peer pair opens 14 WebSockets across its seven cases, below the
			// production server's 30-connection-per-minute limit.
			t.Run(fmt.Sprintf("%s/%s", server.name, peers.name), func(t *testing.T) {
				url := server.start(t)
				for _, transport := range []string{"tcp", "webrtc", "auto"} {
					for _, compression := range []int{0, 3, 9} {
						if transport == "auto" && compression != 3 {
							continue
						}
						t.Run(fmt.Sprintf("%s/compress%d", transport, compression), func(t *testing.T) {
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
							if transport == "webrtc" && compression == 9 && !peers.senderOld {
								sendArgs = append(sendArgs, "-parallel", "4")
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
							if transport == "webrtc" && compression == 9 && !peers.receiverOld {
								recvArgs = append(recvArgs, "-parallel", "4")
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
							if transport == "webrtc" && compression == 9 && peers.version == 3 {
								if !strings.Contains(out.String(), `"event":"parallel_streams","protocol":3`) ||
									!strings.Contains(out.String(), `"parallel_streams":4`) || !bytes.Contains(recvOutput, []byte(`"parallel_streams":4`)) {
									t.Fatal("updated CLI peers did not negotiate four WebRTC lanes")
								}
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
			})
		}
	}

	// WebRTC lane counts above the legacy 4-lane hello.count field only
	// exist from v0.6.0 onward (see internal/flow/webrtc_parallel.go
	// helloCountAndMax): the sender caps hello.count at 4 and carries a
	// larger request in the optional hello.max field, which an old receiver
	// silently ignores. Nothing in the matrix above ever requests more than
	// 4 lanes, so it cannot catch a regression in that split encoding — these
	// cases specifically exercise 5-8 lane requests against both a current
	// and a previous-release peer.
	t.Run("webrtc-lanes", func(t *testing.T) {
		small := bytes.Repeat([]byte("lane-test-0123456789\n"), 6000) // well under the 64 MiB auto threshold
		large := make([]byte, 64*1024*1024)
		if _, err := rand.Read(large); err != nil {
			t.Fatal(err)
		}

		t.Run("new-new/explicit-6", func(t *testing.T) {
			url := startSignalServer(t)
			senderStreams, receiverStreams := runWebRTCLaneCase(t, url, current, current,
				[]string{"-parallel", "6"}, nil, small, "lane6.bin")
			if senderStreams != 6 || receiverStreams != 6 {
				t.Fatalf("expected 6 negotiated lanes new<->new, got sender=%d receiver=%d", senderStreams, receiverStreams)
			}
		})
		t.Run("new-new/auto-64MiB", func(t *testing.T) {
			url := startSignalServer(t)
			senderStreams, receiverStreams := runWebRTCLaneCase(t, url, current, current, nil, nil, large, "lane-auto.bin")
			if senderStreams != 8 || receiverStreams != 8 {
				t.Fatalf("expected 8 negotiated lanes new<->new, got sender=%d receiver=%d", senderStreams, receiverStreams)
			}
		})

		if prevBinary == "" {
			return
		}
		caps := previousReleaseCapabilities(t, prevVersion)
		// Force the previous binary's own max explicitly. A previous-release
		// sender in true auto mode (no -parallel) also caps a small file to a
		// single stream (the same size gate exists as far back as v0.5.0), so
		// leaving it on auto would test that gate instead of lane negotiation.
		// This is a no-op for a previous-release receiver, whose accepted
		// limit is already its own max regardless of file size.
		// The CLI flag accepts at most 6 even where auto mode negotiates more.
		prevMax := []string{"-parallel", fmt.Sprint(min(caps.WebRTCLanes, 6))}

		t.Run("new-prev/explicit-6", func(t *testing.T) {
			url := startSignalServer(t)
			want := min(6, caps.WebRTCLanes)
			senderStreams, receiverStreams := runWebRTCLaneCase(t, url, current, prevBinary,
				[]string{"-parallel", "6"}, prevMax, small, "lane6.bin")
			if senderStreams != want || receiverStreams != want {
				t.Fatalf("expected %d negotiated lanes new->prev, got sender=%d receiver=%d", want, senderStreams, receiverStreams)
			}
		})
		t.Run("prev-new/explicit-6", func(t *testing.T) {
			url := startSignalServer(t)
			want := min(6, caps.WebRTCLanes)
			senderStreams, receiverStreams := runWebRTCLaneCase(t, url, prevBinary, current,
				prevMax, []string{"-parallel", "6"}, small, "lane6.bin")
			if senderStreams != want || receiverStreams != want {
				t.Fatalf("expected %d negotiated lanes prev->new, got sender=%d receiver=%d", want, senderStreams, receiverStreams)
			}
		})
		t.Run("new-prev/auto-64MiB", func(t *testing.T) {
			url := startSignalServer(t)
			senderStreams, receiverStreams := runWebRTCLaneCase(t, url, current, prevBinary, nil, nil, large, "lane-auto.bin")
			if senderStreams != caps.WebRTCLanes || receiverStreams != caps.WebRTCLanes {
				t.Fatalf("expected %d negotiated lanes new->prev, got sender=%d receiver=%d", caps.WebRTCLanes, senderStreams, receiverStreams)
			}
		})
		t.Run("prev-new/auto-64MiB", func(t *testing.T) {
			url := startSignalServer(t)
			senderStreams, receiverStreams := runWebRTCLaneCase(t, url, prevBinary, current, nil, nil, large, "lane-auto.bin")
			if senderStreams != caps.WebRTCLanes || receiverStreams != caps.WebRTCLanes {
				t.Fatalf("expected %d negotiated lanes prev->new, got sender=%d receiver=%d", caps.WebRTCLanes, senderStreams, receiverStreams)
			}
		})
	})
}

// releaseCapabilities is one entry of testdata/release-capabilities.json.
type releaseCapabilities struct {
	Protocol    int `json:"protocol"`
	WebRTCLanes int `json:"webrtcLanes"`
}

// previousReleaseCapabilities looks up the previous release's capabilities.
// Resolution fails closed: an unlisted version fails the test rather than
// silently assuming some default lane count.
func previousReleaseCapabilities(t *testing.T, version string) releaseCapabilities {
	t.Helper()
	path := filepath.Join(projectRoot(t), "testdata", "release-capabilities.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading release capabilities: %v", err)
	}
	var table map[string]releaseCapabilities
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatalf("parsing release capabilities: %v", err)
	}
	caps, ok := table[version]
	if !ok {
		t.Fatalf("no release-capabilities.json entry for previous version %q; add one before testing against it", version)
	}
	return caps
}

// parallelStreamsFromOutput extracts the parallel_streams count from JSON
// event output, or 0 if the peer never negotiated more than one stream (no
// parallel_streams event is emitted for a single-stream connection).
func parallelStreamsFromOutput(output string) int {
	for _, line := range strings.Split(output, "\n") {
		var event struct {
			Event           string `json:"event"`
			ParallelStreams int    `json:"parallel_streams"`
		}
		if json.Unmarshal([]byte(line), &event) == nil && event.Event == "parallel_streams" {
			return event.ParallelStreams
		}
	}
	return 0
}

// runWebRTCLaneCase runs one WebRTC transfer between the given binaries with
// the given extra CLI arguments, verifies the transferred content, and
// returns the parallel_streams count each side reported.
func runWebRTCLaneCase(t *testing.T, url, senderBin, receiverBin string, extraSenderArgs, extraReceiverArgs []string, data []byte, fileName string) (senderStreams, receiverStreams int) {
	t.Helper()
	src := filepath.Join(t.TempDir(), fileName)
	if err := os.WriteFile(src, data, 0600); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sendArgs := append([]string{"send", "-format", "json", "-server", url, "-transport", "webrtc"}, extraSenderArgs...)
	sendArgs = append(sendArgs, src)
	sender := exec.CommandContext(ctx, senderBin, sendArgs...)
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

	recvArgs := append([]string{"receive", "-format", "json", "-server", url, "-transport", "webrtc", "-output", dest}, extraReceiverArgs...)
	recvArgs = append(recvArgs, code)
	receiver := exec.CommandContext(ctx, receiverBin, recvArgs...)
	recvOutput, recvErr := receiver.CombinedOutput()
	if recvErr != nil {
		cancel()
	}
	sendErr := <-done
	if recvErr != nil || sendErr != nil {
		t.Fatalf("sender: %v\n%s\nreceiver: %v\n%s", sendErr, out.String(), recvErr, recvOutput)
	}
	got, err := os.ReadFile(filepath.Join(dest, fileName))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("content mismatch: %v", err)
	}
	return parallelStreamsFromOutput(out.String()), parallelStreamsFromOutput(string(recvOutput))
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
