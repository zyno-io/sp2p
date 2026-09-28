// SPDX-License-Identifier: MIT

package archive

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestTarAndUntar(t *testing.T) {
	// Create a temp directory with test files.
	srcDir := t.TempDir()
	os.MkdirAll(filepath.Join(srcDir, "testdir", "sub"), 0o755)
	os.WriteFile(filepath.Join(srcDir, "testdir", "file1.txt"), []byte("hello"), 0o644)
	os.WriteFile(filepath.Join(srcDir, "testdir", "sub", "file2.txt"), []byte("world"), 0o644)

	// Create tar reader.
	tarReader, err := NewTarReader(filepath.Join(srcDir, "testdir"))
	if err != nil {
		t.Fatal(err)
	}
	defer tarReader.Close()

	// Extract to a new directory.
	destDir := t.TempDir()
	if err := Untar(tarReader, destDir); err != nil {
		t.Fatal(err)
	}

	// Verify extracted files.
	data, err := os.ReadFile(filepath.Join(destDir, "testdir", "file1.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("expected 'hello', got '%s'", data)
	}

	data, err = os.ReadFile(filepath.Join(destDir, "testdir", "sub", "file2.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "world" {
		t.Fatalf("expected 'world', got '%s'", data)
	}
}

func TestTarAndUntarSkipsSockets(t *testing.T) {
	srcDir := t.TempDir()
	source := filepath.Join(srcDir, "source")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "file.txt"), []byte("contents"), 0o644); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(source, "service.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("Unix sockets are unavailable: %v", err)
	}
	defer listener.Close()

	tarReader, err := NewTarReader(source)
	if err != nil {
		t.Fatal(err)
	}
	defer tarReader.Close()

	destDir := t.TempDir()
	if err := Untar(tarReader, destDir); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(destDir, "source", "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "contents" {
		t.Fatalf("expected %q, got %q", "contents", data)
	}
	if _, err := os.Lstat(filepath.Join(destDir, "source", "service.sock")); !os.IsNotExist(err) {
		t.Fatalf("socket was archived: %v", err)
	}
}

func TestValidateTarPath(t *testing.T) {
	tests := []struct {
		path        string
		wantErr     bool
		windowsOnly bool // meaningful only under Windows' volume/separator rules
	}{
		{"file.txt", false, false},
		{"dir/file.txt", false, false},
		{"/absolute/path", true, false},
		{"../escape", true, false},
		{"dir/../escape", true, false},
		// A Windows receiver: filepath.IsAbs requires a volume name, so
		// these forms only reach the volume/rooted-form checks added
		// alongside this test — see validateTarPath.
		{`C:x`, true, true},
		{`\x`, true, true},
		{`\\srv\share\x`, true, true},
		// Reserved device names and alternate data streams on Windows.
		{"NUL", true, true},
		{"dir/con.txt", true, true},
		{"COM1", true, true},
		{"file.txt:stream", true, true},
		{"", true, false},
	}

	for _, tt := range tests {
		if tt.windowsOnly && runtime.GOOS != "windows" {
			continue
		}
		err := validateTarPath(tt.path)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateTarPath(%q): got err=%v, wantErr=%v", tt.path, err, tt.wantErr)
		}
	}
}
