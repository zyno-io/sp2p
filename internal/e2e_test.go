// SPDX-License-Identifier: MIT

package internal

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyno-io/sp2p/internal/server"
)

// codePattern matches the transfer code printed by the sender.
// Session ID: 8 chars from the unambiguous alphabet, followed by - and base62 seed.
var codePattern = regexp.MustCompile(`[23456789a-hj-np-z]{8}-[0-9A-Za-z]+`)

// buildBinary builds the sp2p CLI binary and returns its path.
func buildBinary(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "sp2p")
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/sp2p")
	cmd.Dir = projectRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building sp2p binary: %v\n%s", err, out)
	}
	return binPath
}

// projectRoot returns the project root directory.
func projectRoot(t *testing.T) string {
	t.Helper()
	// We're in internal/, so go up one level.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(wd)
}

// startSignalServer starts an httptest signaling server and returns its WebSocket URL.
func startSignalServer(t *testing.T) string {
	t.Helper()
	srv, err := server.New(server.Config{Addr: ":0", BaseURL: "http://localhost"})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
}

func TestE2E_SendReceiveFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	bin := buildBinary(t)
	wsURL := startSignalServer(t)

	// Create a test file with random data (128 KB).
	srcDir := t.TempDir()
	srcFile := filepath.Join(srcDir, "testfile.bin")
	fileData := make([]byte, 128*1024)
	rand.Read(fileData)
	if err := os.WriteFile(srcFile, fileData, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start sender.
	senderCmd := exec.CommandContext(ctx, bin, "send", srcFile)
	senderCmd.Env = append(os.Environ(), "SP2P_SERVER="+wsURL, "SP2P_URL=http://localhost")

	// Capture stderr to extract the transfer code.
	senderStderr, err := senderCmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}

	if err := senderCmd.Start(); err != nil {
		t.Fatalf("starting sender: %v", err)
	}

	// Read sender stderr until we find the transfer code.
	codeCh := make(chan string, 1)
	var senderOutput bytes.Buffer
	go func() {
		scanner := bufio.NewScanner(senderStderr)
		for scanner.Scan() {
			line := scanner.Text()
			senderOutput.WriteString(line + "\n")
			if code := codePattern.FindString(line); code != "" {
				select {
				case codeCh <- code:
				default:
				}
			}
		}
	}()

	var code string
	select {
	case code = <-codeCh:
		t.Logf("transfer code: %s", code)
	case <-time.After(15 * time.Second):
		senderCmd.Process.Kill()
		t.Fatalf("timeout waiting for transfer code\nsender output:\n%s", senderOutput.String())
	}

	// Start receiver.
	recvDir := t.TempDir()
	receiverCmd := exec.CommandContext(ctx, bin, "receive", "-output", recvDir, code)
	receiverCmd.Env = append(os.Environ(), "SP2P_SERVER="+wsURL)
	var receiverStderr bytes.Buffer
	receiverCmd.Stderr = &receiverStderr

	if err := receiverCmd.Start(); err != nil {
		senderCmd.Process.Kill()
		t.Fatalf("starting receiver: %v", err)
	}

	// Wait for both to complete.
	var wg sync.WaitGroup
	errs := make([]error, 2)

	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = senderCmd.Wait()
	}()
	go func() {
		defer wg.Done()
		errs[1] = receiverCmd.Wait()
	}()
	wg.Wait()

	if errs[0] != nil {
		t.Logf("sender stderr:\n%s", senderOutput.String())
		t.Fatalf("sender failed: %v", errs[0])
	}
	if errs[1] != nil {
		t.Logf("receiver stderr:\n%s", receiverStderr.String())
		t.Fatalf("receiver failed: %v", errs[1])
	}

	// Compare files.
	recvFile := filepath.Join(recvDir, "testfile.bin")
	recvData, err := os.ReadFile(recvFile)
	if err != nil {
		// Try to list what was created.
		entries, _ := os.ReadDir(recvDir)
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("reading received file: %v\nfiles in output dir: %v", err, names)
	}

	if !bytes.Equal(fileData, recvData) {
		t.Fatalf("file mismatch: sent %d bytes, received %d bytes", len(fileData), len(recvData))
	}
	t.Logf("e2e file transfer passed: %d bytes", len(fileData))
}

func TestE2E_SendReceiveStdin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	bin := buildBinary(t)
	wsURL := startSignalServer(t)

	// Test data for stdin transfer.
	stdinData := []byte("Hello from stdin! This is a test of piped transfers.\n")
	stdinData = bytes.Repeat(stdinData, 100) // ~5 KB

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start sender with stdin input.
	senderCmd := exec.CommandContext(ctx, bin, "send", "-")
	senderCmd.Env = append(os.Environ(), "SP2P_SERVER="+wsURL, "SP2P_URL=http://localhost")
	senderCmd.Stdin = bytes.NewReader(stdinData)

	senderStderr, err := senderCmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}

	if err := senderCmd.Start(); err != nil {
		t.Fatalf("starting sender: %v", err)
	}

	// Read sender stderr for the code.
	codeCh := make(chan string, 1)
	var senderOutput bytes.Buffer
	go func() {
		scanner := bufio.NewScanner(senderStderr)
		for scanner.Scan() {
			line := scanner.Text()
			senderOutput.WriteString(line + "\n")
			if code := codePattern.FindString(line); code != "" {
				select {
				case codeCh <- code:
				default:
				}
			}
		}
	}()

	var code string
	select {
	case code = <-codeCh:
		t.Logf("transfer code: %s", code)
	case <-time.After(15 * time.Second):
		senderCmd.Process.Kill()
		t.Fatalf("timeout waiting for transfer code\nsender output:\n%s", senderOutput.String())
	}

	// Start receiver with --stdout to capture output.
	receiverCmd := exec.CommandContext(ctx, bin, "receive", "-stdout", code)
	receiverCmd.Env = append(os.Environ(), "SP2P_SERVER="+wsURL)
	var receiverStdout bytes.Buffer
	var receiverStderr bytes.Buffer
	receiverCmd.Stdout = &receiverStdout
	receiverCmd.Stderr = &receiverStderr

	if err := receiverCmd.Start(); err != nil {
		senderCmd.Process.Kill()
		t.Fatalf("starting receiver: %v", err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = senderCmd.Wait()
	}()
	go func() {
		defer wg.Done()
		errs[1] = receiverCmd.Wait()
	}()
	wg.Wait()

	if errs[0] != nil {
		t.Logf("sender stderr:\n%s", senderOutput.String())
		t.Fatalf("sender failed: %v", errs[0])
	}
	if errs[1] != nil {
		t.Logf("receiver stderr:\n%s", receiverStderr.String())
		t.Fatalf("receiver failed: %v", errs[1])
	}

	if !bytes.Equal(stdinData, receiverStdout.Bytes()) {
		t.Fatalf("stdin data mismatch: sent %d bytes, received %d bytes", len(stdinData), len(receiverStdout.Bytes()))
	}
	t.Logf("e2e stdin transfer passed: %d bytes", len(stdinData))
}

func TestE2E_SendReceiveLargeFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	bin := buildBinary(t)
	wsURL := startSignalServer(t)

	// Create a larger test file (5 MB) to test chunked transfer.
	srcDir := t.TempDir()
	srcFile := filepath.Join(srcDir, "large.dat")
	fileData := make([]byte, 5*1024*1024)
	rand.Read(fileData)
	if err := os.WriteFile(srcFile, fileData, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	senderCmd := exec.CommandContext(ctx, bin, "send", srcFile)
	senderCmd.Env = append(os.Environ(), "SP2P_SERVER="+wsURL, "SP2P_URL=http://localhost")
	senderStderr, err := senderCmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := senderCmd.Start(); err != nil {
		t.Fatalf("starting sender: %v", err)
	}

	codeCh := make(chan string, 1)
	var senderOutput bytes.Buffer
	go func() {
		scanner := bufio.NewScanner(senderStderr)
		for scanner.Scan() {
			line := scanner.Text()
			senderOutput.WriteString(line + "\n")
			if code := codePattern.FindString(line); code != "" {
				select {
				case codeCh <- code:
				default:
				}
			}
		}
	}()

	var code string
	select {
	case code = <-codeCh:
	case <-time.After(15 * time.Second):
		senderCmd.Process.Kill()
		t.Fatalf("timeout waiting for transfer code\nsender output:\n%s", senderOutput.String())
	}

	recvDir := t.TempDir()
	receiverCmd := exec.CommandContext(ctx, bin, "receive", "-output", recvDir, code)
	receiverCmd.Env = append(os.Environ(), "SP2P_SERVER="+wsURL)
	var receiverStderr bytes.Buffer
	receiverCmd.Stderr = &receiverStderr
	if err := receiverCmd.Start(); err != nil {
		senderCmd.Process.Kill()
		t.Fatalf("starting receiver: %v", err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = senderCmd.Wait()
	}()
	go func() {
		defer wg.Done()
		errs[1] = receiverCmd.Wait()
	}()
	wg.Wait()

	if errs[0] != nil {
		t.Logf("sender stderr:\n%s", senderOutput.String())
		t.Fatalf("sender failed: %v", errs[0])
	}
	if errs[1] != nil {
		t.Logf("receiver stderr:\n%s", receiverStderr.String())
		t.Fatalf("receiver failed: %v", errs[1])
	}

	recvData, err := os.ReadFile(filepath.Join(recvDir, "large.dat"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fileData, recvData) {
		t.Fatalf("large file mismatch: sent %d bytes, received %d bytes", len(fileData), len(recvData))
	}
	t.Logf("e2e large file transfer passed: %s", formatTestBytes(len(fileData)))
}

func TestE2E_SendReceiveFolder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	bin := buildBinary(t)
	wsURL := startSignalServer(t)

	// Create a folder with multiple files.
	srcDir := t.TempDir()
	folderPath := filepath.Join(srcDir, "testfolder")
	os.MkdirAll(filepath.Join(folderPath, "sub"), 0o755)
	os.WriteFile(filepath.Join(folderPath, "a.txt"), []byte("file a contents"), 0o644)
	os.WriteFile(filepath.Join(folderPath, "b.txt"), []byte("file b contents"), 0o644)
	os.WriteFile(filepath.Join(folderPath, "sub", "c.txt"), []byte("nested file c"), 0o644)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	senderCmd := exec.CommandContext(ctx, bin, "send", folderPath)
	senderCmd.Env = append(os.Environ(), "SP2P_SERVER="+wsURL, "SP2P_URL=http://localhost")
	senderStderr, err := senderCmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := senderCmd.Start(); err != nil {
		t.Fatalf("starting sender: %v", err)
	}

	codeCh := make(chan string, 1)
	var senderOutput bytes.Buffer
	go func() {
		scanner := bufio.NewScanner(senderStderr)
		for scanner.Scan() {
			line := scanner.Text()
			senderOutput.WriteString(line + "\n")
			if code := codePattern.FindString(line); code != "" {
				select {
				case codeCh <- code:
				default:
				}
			}
		}
	}()

	var code string
	select {
	case code = <-codeCh:
	case <-time.After(15 * time.Second):
		senderCmd.Process.Kill()
		t.Fatalf("timeout waiting for transfer code\nsender output:\n%s", senderOutput.String())
	}

	recvDir := t.TempDir()
	receiverCmd := exec.CommandContext(ctx, bin, "receive", "-output", recvDir, code)
	receiverCmd.Env = append(os.Environ(), "SP2P_SERVER="+wsURL)
	var receiverStderr bytes.Buffer
	receiverCmd.Stderr = &receiverStderr
	if err := receiverCmd.Start(); err != nil {
		senderCmd.Process.Kill()
		t.Fatalf("starting receiver: %v", err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = senderCmd.Wait()
	}()
	go func() {
		defer wg.Done()
		errs[1] = receiverCmd.Wait()
	}()
	wg.Wait()

	if errs[0] != nil {
		t.Logf("sender stderr:\n%s", senderOutput.String())
		t.Fatalf("sender failed: %v", errs[0])
	}
	if errs[1] != nil {
		t.Logf("receiver stderr:\n%s", receiverStderr.String())
		t.Fatalf("receiver failed: %v", errs[1])
	}

	// Verify extracted folder contents.
	checkFile := func(rel, want string) {
		t.Helper()
		got, err := os.ReadFile(filepath.Join(recvDir, "testfolder", rel))
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		if string(got) != want {
			t.Fatalf("%s: got %q, want %q", rel, got, want)
		}
	}
	checkFile("a.txt", "file a contents")
	checkFile("b.txt", "file b contents")
	checkFile(filepath.Join("sub", "c.txt"), "nested file c")

	t.Log("e2e folder transfer passed")
}

func formatTestBytes(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func TestE2E_SendReceiveMultiFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	bin := buildBinary(t)
	wsURL := startSignalServer(t)

	// Create 3 separate files.
	srcDir := t.TempDir()
	files := map[string]string{
		"alpha.txt": "Contents of alpha file\n",
		"beta.dat":  "Contents of beta file — with some binary-safe data: \x00\x01\x02\n",
		"gamma.log": strings.Repeat("log line\n", 500),
	}
	var paths []string
	for name, data := range files {
		p := filepath.Join(srcDir, name)
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start sender with multiple files.
	args := append([]string{"send"}, paths...)
	senderCmd := exec.CommandContext(ctx, bin, args...)
	senderCmd.Env = append(os.Environ(), "SP2P_SERVER="+wsURL, "SP2P_URL=http://localhost")

	senderStderr, err := senderCmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := senderCmd.Start(); err != nil {
		t.Fatalf("starting sender: %v", err)
	}

	codeCh := make(chan string, 1)
	var senderOutput bytes.Buffer
	go func() {
		scanner := bufio.NewScanner(senderStderr)
		for scanner.Scan() {
			line := scanner.Text()
			senderOutput.WriteString(line + "\n")
			if code := codePattern.FindString(line); code != "" {
				select {
				case codeCh <- code:
				default:
				}
			}
		}
	}()

	var code string
	select {
	case code = <-codeCh:
		t.Logf("transfer code: %s", code)
	case <-time.After(15 * time.Second):
		senderCmd.Process.Kill()
		t.Fatalf("timeout waiting for transfer code\nsender output:\n%s", senderOutput.String())
	}

	// Receiver gets a tar archive (IsFolder=true).
	recvDir := t.TempDir()
	receiverCmd := exec.CommandContext(ctx, bin, "receive", "-output", recvDir, code)
	receiverCmd.Env = append(os.Environ(), "SP2P_SERVER="+wsURL)
	var receiverStderr bytes.Buffer
	receiverCmd.Stderr = &receiverStderr
	if err := receiverCmd.Start(); err != nil {
		senderCmd.Process.Kill()
		t.Fatalf("starting receiver: %v", err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = senderCmd.Wait() }()
	go func() { defer wg.Done(); errs[1] = receiverCmd.Wait() }()
	wg.Wait()

	if errs[0] != nil {
		t.Logf("sender stderr:\n%s", senderOutput.String())
		t.Fatalf("sender failed: %v", errs[0])
	}
	if errs[1] != nil {
		t.Logf("receiver stderr:\n%s", receiverStderr.String())
		t.Fatalf("receiver failed: %v", errs[1])
	}

	// Verify all files unpacked correctly. Multi-file sends produce a folder
	// named like "3-files/" in the output dir.
	for name, want := range files {
		// The file could be at recvDir/<name> or recvDir/<folder>/<name>.
		got, err := os.ReadFile(filepath.Join(recvDir, name))
		if err != nil {
			// Try looking in subdirectories.
			entries, _ := os.ReadDir(recvDir)
			var found bool
			for _, e := range entries {
				if e.IsDir() {
					got2, err2 := os.ReadFile(filepath.Join(recvDir, e.Name(), name))
					if err2 == nil {
						got = got2
						found = true
						break
					}
				}
			}
			if !found {
				names := make([]string, len(entries))
				for i, e := range entries {
					names[i] = e.Name()
				}
				t.Fatalf("reading %s: %v\nfiles in output dir: %v", name, err, names)
			}
		}
		if string(got) != want {
			t.Fatalf("%s: content mismatch: got %d bytes, want %d", name, len(got), len(want))
		}
	}
	t.Log("e2e multi-file transfer passed")
}

func TestE2E_SendReceiveStdinWithName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	bin := buildBinary(t)
	wsURL := startSignalServer(t)

	stdinData := []byte("This file should be named custom.txt on the receiver side.\n")
	stdinData = bytes.Repeat(stdinData, 50)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Sender with -name flag.
	senderCmd := exec.CommandContext(ctx, bin, "send", "-name", "custom.txt", "-")
	senderCmd.Env = append(os.Environ(), "SP2P_SERVER="+wsURL, "SP2P_URL=http://localhost")
	senderCmd.Stdin = bytes.NewReader(stdinData)

	senderStderr, err := senderCmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := senderCmd.Start(); err != nil {
		t.Fatalf("starting sender: %v", err)
	}

	codeCh := make(chan string, 1)
	var senderOutput bytes.Buffer
	go func() {
		scanner := bufio.NewScanner(senderStderr)
		for scanner.Scan() {
			line := scanner.Text()
			senderOutput.WriteString(line + "\n")
			if code := codePattern.FindString(line); code != "" {
				select {
				case codeCh <- code:
				default:
				}
			}
		}
	}()

	var code string
	select {
	case code = <-codeCh:
		t.Logf("transfer code: %s", code)
	case <-time.After(15 * time.Second):
		senderCmd.Process.Kill()
		t.Fatalf("timeout waiting for transfer code\nsender output:\n%s", senderOutput.String())
	}

	// Receiver writes to output dir.
	recvDir := t.TempDir()
	receiverCmd := exec.CommandContext(ctx, bin, "receive", "-output", recvDir, code)
	receiverCmd.Env = append(os.Environ(), "SP2P_SERVER="+wsURL)
	var receiverStderr bytes.Buffer
	receiverCmd.Stderr = &receiverStderr
	if err := receiverCmd.Start(); err != nil {
		senderCmd.Process.Kill()
		t.Fatalf("starting receiver: %v", err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = senderCmd.Wait() }()
	go func() { defer wg.Done(); errs[1] = receiverCmd.Wait() }()
	wg.Wait()

	if errs[0] != nil {
		t.Logf("sender stderr:\n%s", senderOutput.String())
		t.Fatalf("sender failed: %v", errs[0])
	}
	if errs[1] != nil {
		t.Logf("receiver stderr:\n%s", receiverStderr.String())
		t.Fatalf("receiver failed: %v", errs[1])
	}

	// Verify the output file is named "custom.txt".
	recvFile := filepath.Join(recvDir, "custom.txt")
	got, err := os.ReadFile(recvFile)
	if err != nil {
		entries, _ := os.ReadDir(recvDir)
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("reading custom.txt: %v\nfiles in output dir: %v", err, names)
	}
	if !bytes.Equal(got, stdinData) {
		t.Fatalf("content mismatch: got %d bytes, want %d", len(got), len(stdinData))
	}
	t.Log("e2e stdin with -name flag passed")
}

func TestE2E_InvalidCode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	bin := buildBinary(t)
	wsURL := startSignalServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	receiverCmd := exec.CommandContext(ctx, bin, "receive", "BADCODE#BADSEED")
	receiverCmd.Env = append(os.Environ(), "SP2P_SERVER="+wsURL)
	var stderr bytes.Buffer
	receiverCmd.Stderr = &stderr

	err := receiverCmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit code for invalid code")
	}

	stderrStr := stderr.String()
	t.Logf("receiver stderr: %s", stderrStr)

	// Should contain an error message, not a panic.
	if strings.Contains(stderrStr, "panic") || strings.Contains(stderrStr, "goroutine") {
		t.Fatalf("receiver panicked:\n%s", stderrStr)
	}
	// Should contain some indication of error.
	stderrLower := strings.ToLower(stderrStr)
	if !strings.Contains(stderrLower, "error") && !strings.Contains(stderrLower, "not found") && !strings.Contains(stderrLower, "invalid") {
		t.Fatalf("expected error message in stderr, got:\n%s", stderrStr)
	}
	t.Log("e2e invalid code test passed")
}
