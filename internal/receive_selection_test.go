// SPDX-License-Identifier: MIT

package internal

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/zyno-io/sp2p/internal/signal"
)

func TestE2E_LargeAutoTransferUsesAuthenticatedWebRTCSelection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping protocol e2e in short mode")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	bin := buildBinary(t)
	upstreamURL := startSignalServer(t)
	var droppedDirect atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downstream, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer downstream.CloseNow()
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		upstream, _, err := websocket.Dial(ctx, upstreamURL, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer upstream.CloseNow()

		done := make(chan struct{}, 2)
		forward := func(src, dst *websocket.Conn) {
			defer func() {
				cancel()
				done <- struct{}{}
			}()
			for {
				kind, data, err := src.Read(ctx)
				if err != nil {
					return
				}
				var env signal.Envelope
				if err := json.Unmarshal(data, &env); err != nil {
					t.Error(err)
					return
				}
				if env.Type == signal.TypeDirect {
					droppedDirect.Add(1)
					continue
				}
				if err := dst.Write(ctx, kind, data); err != nil {
					return
				}
			}
		}
		go forward(upstream, downstream)
		go forward(downstream, upstream)
		<-done
		<-done
	}))
	defer proxy.Close()
	proxyURL := "ws" + strings.TrimPrefix(proxy.URL, "http")

	const sourceSize = 64 * 1024 * 1024
	src := filepath.Join(t.TempDir(), "large-zero.bin")
	srcFile, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := srcFile.Truncate(sourceSize); err != nil {
		srcFile.Close()
		t.Fatal(err)
	}
	if err := srcFile.Close(); err != nil {
		t.Fatal(err)
	}
	wantHash := receiveSelectionSHA256(t, src)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	sender := exec.CommandContext(ctx, bin, "send", "-v", "-format", "json", "-server", proxyURL, "-transport", "auto", "-compress", "3", src)
	senderOutput := &compatibilityOutput{code: make(chan string, 1)}
	sender.Stdout, sender.Stderr = senderOutput, senderOutput
	if err := sender.Start(); err != nil {
		t.Fatal(err)
	}
	senderDone := make(chan error, 1)
	go func() { senderDone <- sender.Wait() }()

	var code string
	select {
	case code = <-senderOutput.code:
	case err := <-senderDone:
		t.Fatalf("sender exited before registration: %v\n%s", err, senderOutput.String())
	case <-ctx.Done():
		t.Fatalf("sender registration timed out: %s", senderOutput.String())
	}

	dest := t.TempDir()
	receiver := exec.CommandContext(ctx, bin, "receive", "-v", "-format", "json", "-server", proxyURL, "-transport", "auto", "-output", dest, code)
	receiverOutput, receiverErr := receiver.CombinedOutput()
	if receiverErr != nil {
		cancel()
	}
	senderErr := <-senderDone
	if ctx.Err() != nil {
		t.Fatalf("large WebRTC transfer timed out: dropped direct=%d\nsender: %s\nreceiver: %s", droppedDirect.Load(), senderOutput.String(), receiverOutput)
	}
	if senderErr != nil || receiverErr != nil {
		t.Fatalf("large WebRTC transfer failed: dropped direct=%d\nsender: %v\n%s\nreceiver: %v\n%s", droppedDirect.Load(), senderErr, senderOutput.String(), receiverErr, receiverOutput)
	}
	if droppedDirect.Load() == 0 {
		t.Fatal("signaling proxy did not drop any TCP direct endpoints")
	}
	for role, output := range map[string]string{
		"sender":   senderOutput.String(),
		"receiver": string(receiverOutput),
	} {
		if !strings.Contains(output, `"event":"protocol","protocol":3`) {
			t.Fatalf("%s did not negotiate v3: %s", role, output)
		}
		if !strings.Contains(output, `"method":"webrtc","state":"connected"`) {
			t.Fatalf("%s did not connect through WebRTC: %s", role, output)
		}
	}
	gotHash := receiveSelectionSHA256(t, filepath.Join(dest, "large-zero.bin"))
	if gotHash != wantHash {
		t.Fatalf("received content hash = %x, want %x", gotHash, wantHash)
	}
}

func receiveSelectionSHA256(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		t.Fatal(err)
	}
	var sum [sha256.Size]byte
	copy(sum[:], hash.Sum(nil))
	return sum
}
