// SPDX-License-Identifier: MIT

package internal

import (
	"context"
	"encoding/json"
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

func TestE2E_StrippedCapabilitiesFailBeforeTransfer(t *testing.T) {
	testSignalingTamper(t, false, false)
}

func TestE2E_ClientTypeCannotDisableCandidateAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name             string
		sender, receiver bool
	}{{"sender", true, false}, {"receiver", false, true}, {"both", true, true}} {
		t.Run(tc.name, func(t *testing.T) { testSignalingTamper(t, tc.sender, tc.receiver) })
	}
}

func testSignalingTamper(t *testing.T, spoofSender, spoofReceiver bool) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping protocol e2e in short mode")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	bin := buildBinary(t)
	upstreamURL := startSignalServer(t)
	var stripped atomic.Int32
	var spoofed atomic.Int32
	stripMarkers := !spoofSender && !spoofReceiver
	// Either strip the bound key markers (must fail authentication) or forge
	// unbound client-type hints (must NOT disable v3 candidate authentication).
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
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer cancel()
			for {
				kind, data, err := upstream.Read(ctx)
				if err != nil {
					return
				}
				var env signal.Envelope
				if err := json.Unmarshal(data, &env); err != nil {
					t.Error(err)
					return
				}
				var replacement *signal.Envelope
				if spoofSender && env.Type == signal.TypeWelcome {
					var welcome signal.Welcome
					if err := env.ParsePayload(&welcome); err != nil {
						t.Error(err)
						return
					}
					if welcome.PeerClientType != "" {
						welcome.PeerClientType = signal.ClientTypeBrowser
						replacement, err = signal.NewEnvelope(signal.TypeWelcome, welcome)
					}
				}
				if spoofReceiver && env.Type == signal.TypePeerJoined {
					replacement, err = signal.NewEnvelope(signal.TypePeerJoined, signal.PeerJoined{ClientType: signal.ClientTypeBrowser})
				}
				if err != nil {
					t.Error(err)
					return
				}
				if replacement != nil {
					spoofed.Add(1)
					data, err = json.Marshal(replacement)
					if err != nil {
						t.Error(err)
						return
					}
				}
				if err := downstream.Write(ctx, kind, data); err != nil {
					return
				}
			}
		}()
		defer func() { cancel(); <-done }()
		for {
			kind, data, err := downstream.Read(ctx)
			if err != nil {
				return
			}
			var env signal.Envelope
			if err := json.Unmarshal(data, &env); err != nil {
				t.Error(err)
				return
			}
			if stripMarkers && env.Type == signal.TypeCrypto {
				var exchange signal.CryptoExchange
				if err := env.ParsePayload(&exchange); err != nil {
					t.Error(err)
					return
				}
				if len(exchange.PublicKey) != 32 || exchange.PublicKey[31]&0x80 == 0 {
					t.Error("missing capability to strip")
					return
				}
				exchange.PublicKey[31] &^= 0x80
				stripped.Add(1)
				modified, err := signal.NewEnvelope(signal.TypeCrypto, exchange)
				if err != nil {
					t.Error(err)
					return
				}
				data, err = json.Marshal(modified)
				if err != nil {
					t.Error(err)
					return
				}
			}
			if err := upstream.Write(ctx, kind, data); err != nil {
				return
			}
		}
	}))
	defer proxy.Close()
	url := "ws" + strings.TrimPrefix(proxy.URL, "http")
	src := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(src, []byte("must not be transferred"), 0600); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	transport := "webrtc"
	if stripMarkers {
		transport = "tcp"
	}
	sender := exec.CommandContext(ctx, bin, "send", "-v", "-format", "json", "-server", url, "-transport", transport, src)
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
		cancel()
		<-done
		t.Fatalf("registration timed out: %s", out.String())
	}
	receiver := exec.CommandContext(ctx, bin, "receive", "-v", "-format", "json", "-server", url, "-transport", transport, "-output", dest, code)
	recvOutput, recvErr := receiver.CombinedOutput()
	sendErr := <-done
	if ctx.Err() != nil {
		t.Fatalf("tamper rejection timed out: %s\n%s", out.String(), recvOutput)
	}
	if !stripMarkers {
		wantSpoofed := int32(1)
		if spoofSender && spoofReceiver {
			wantSpoofed = 2
		}
		if sendErr != nil || recvErr != nil || spoofed.Load() != wantSpoofed {
			t.Fatalf("client-type tampering interrupted authenticated transfer: spoofed=%d sender=%v receiver=%v\n%s\n%s", spoofed.Load(), sendErr, recvErr, out.String(), recvOutput)
		}
		for _, output := range []string{out.String(), string(recvOutput)} {
			if !strings.Contains(output, "authenticating v3 connection candidate") || !strings.Contains(output, `"event":"protocol","protocol":3`) {
				t.Fatalf("skipped candidate authentication: %s", output)
			}
			if strings.Contains(output, `"event":"warning"`) {
				t.Fatalf("downgraded transfer: %s", output)
			}
		}
		got, err := os.ReadFile(filepath.Join(dest, "secret.txt"))
		if err != nil || string(got) != "must not be transferred" {
			t.Fatalf("content mismatch: %v", err)
		}
		return
	}
	if stripped.Load() != 2 || sendErr == nil || recvErr == nil {
		t.Fatalf("tampered session accepted: stripped=%d sender=%v receiver=%v", stripped.Load(), sendErr, recvErr)
	}
	for _, output := range []string{out.String(), string(recvOutput)} {
		if !strings.Contains(strings.ToLower(output), "key confirmation failed") {
			t.Fatalf("unexpected failure: %s", output)
		}
		for _, forbidden := range []string{`"event":"protocol"`, `"event":"warning"`, `"phase":"transferring"`} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("accepted unauthenticated downgrade: %s", output)
			}
		}
	}
	entries, err := os.ReadDir(dest)
	if err != nil || len(entries) != 0 {
		t.Fatalf("output created before authentication: %v %v", entries, err)
	}
}
