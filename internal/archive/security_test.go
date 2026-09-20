// SPDX-License-Identifier: MIT

package archive

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchiveExpansionQuotaAndAtomicWrapper(t *testing.T) {
	var input bytes.Buffer
	tw := tar.NewWriter(&input)
	for _, name := range []string{"a", "b"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: 3}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("abc")); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if _, err := Extract(bytes.NewReader(input.Bytes()), dest, 5); err == nil {
		t.Fatal("ignored aggregate expanded byte limit")
	}
	entries, err := os.ReadDir(dest)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed extraction left files: %v %v", entries, err)
	}
	staged, err := Extract(bytes.NewReader(input.Bytes()), dest, 6)
	if err != nil {
		t.Fatal(err)
	}
	defer staged.Rollback()
	if err := os.Mkdir(filepath.Join(dest, "batch"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := staged.CommitAs("batch"); err == nil {
		t.Fatal("replaced existing directory")
	}
	if _, err := os.Stat(filepath.Join(dest, "a")); !os.IsNotExist(err) {
		t.Fatal("partially published multi-root archive")
	}
	path, err := staged.CommitAs("received")
	if err != nil {
		t.Fatal(err)
	}
	staged.Rollback() // acknowledgement loss must not remove committed content
	for _, name := range []string{"a", "b"} {
		data, err := os.ReadFile(filepath.Join(path, name))
		if err != nil || string(data) != "abc" {
			t.Fatalf("missing published file: %s %v", data, err)
		}
	}
}

func TestTarInfoIncludesPAXHeaders(t *testing.T) {
	dir := t.TempDir()
	name := strings.Repeat("é", 100) + ".txt"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := ComputeTarInfo([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewTarReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	n, err := io.Copy(io.Discard, r)
	if err != nil {
		t.Fatal(err)
	}
	if uint64(n) != info.Size {
		t.Fatalf("serialized size %d, declared %d", n, info.Size)
	}
}
