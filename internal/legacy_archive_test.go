// SPDX-License-Identifier: MIT

package internal

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestE2E_LegacyPAXArchive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping protocol e2e in short mode")
	}
	legacy := os.Getenv("SP2P_TEST_LEGACY_BINARY")
	if legacy == "" {
		t.Skip("set SP2P_TEST_LEGACY_BINARY to an unmodified v0.4.0 CLI")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	current := buildBinary(t)
	url := startSignalServer(t)
	src := filepath.Join(t.TempDir(), "legacy-folder")
	if err := os.Mkdir(src, 0700); err != nil {
		t.Fatal(err)
	}
	// Both names require extended TAR headers, omitted by v0.4.0's size
	// estimate. Exercise the actual old sender and automatic v2 negotiation.
	files := map[string][]byte{
		"日本語.txt":                        []byte("Unicode archive entry\n"),
		strings.Repeat("long-name-", 15): []byte("Long archive entry\n"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(src, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, transport := range []string{"tcp", "webrtc"} {
		for _, compression := range []int{0, 3} {
			t.Run(fmt.Sprintf("%s/compress%d", transport, compression), func(t *testing.T) {
				dest := t.TempDir()
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()
				sender := exec.CommandContext(ctx, legacy, "send", "-format", "json",
					"-server", url, "-transport", transport, "-compress", fmt.Sprint(compression), src)
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
				receiver := exec.CommandContext(ctx, current, "receive", "-format", "json",
					"-server", url, "-transport", transport, "-output", dest, code)
				recvOutput, recvErr := receiver.CombinedOutput()
				if recvErr != nil {
					cancel()
				}
				sendErr := <-done
				if recvErr != nil || sendErr != nil {
					t.Fatalf("sender: %v\n%s\nreceiver: %v\n%s", sendErr, out.String(), recvErr, recvOutput)
				}
				if !bytes.Contains(recvOutput, []byte(`"event":"protocol","protocol":2`)) {
					t.Fatalf("legacy protocol was not negotiated: %s", recvOutput)
				}
				for name, want := range files {
					got, err := os.ReadFile(filepath.Join(dest, filepath.Base(src), name))
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("archive entry %q mismatch: %v", name, err)
					}
				}
			})
		}
	}
}
