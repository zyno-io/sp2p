// SPDX-License-Identifier: MIT

package fileutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A reader holding the target open must not make replacement fail: the
// status file is written for other processes to poll.
func TestReplaceFileWaitsForOpenReader(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "status.json")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		reader.Close()
	}()
	next := filepath.Join(dir, "next.json")
	if err := os.WriteFile(next, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(next, target); err != nil {
		t.Fatalf("ReplaceFile with an open reader: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "new" {
		t.Fatalf("target = %q, %v; want new", data, err)
	}
}
