// SPDX-License-Identifier: MIT

package archive

import (
	"net"
	"os"
	"path/filepath"
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
		path    string
		wantErr bool
	}{
		{"file.txt", false},
		{"dir/file.txt", false},
		{"/absolute/path", true},
		{"../escape", true},
		{"dir/../escape", true},
	}

	for _, tt := range tests {
		err := validateTarPath(tt.path)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateTarPath(%q): got err=%v, wantErr=%v", tt.path, err, tt.wantErr)
		}
	}
}
