// SPDX-License-Identifier: MIT

package archive

import (
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
