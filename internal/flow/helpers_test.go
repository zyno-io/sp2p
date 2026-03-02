// SPDX-License-Identifier: MIT

package flow

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/signal"
)

// ── iceServersToConn ─────────────────────────────────────────────────────────

func TestIceServersToConn_STUNOnly(t *testing.T) {
	servers := []signal.ICEServer{
		{URLs: []string{"stun:stun.example.com:3478"}},
	}
	stun, turn := iceServersToConn(servers)
	if len(stun) != 1 || stun[0] != "stun:stun.example.com:3478" {
		t.Fatalf("stun = %v, want [stun:stun.example.com:3478]", stun)
	}
	if len(turn) != 0 {
		t.Fatalf("turn = %v, want empty", turn)
	}
}

func TestIceServersToConn_TURNOnly(t *testing.T) {
	servers := []signal.ICEServer{
		{URLs: []string{"turn:relay.example.com:3478"}, Username: "user", Credential: "pass"},
	}
	stun, turn := iceServersToConn(servers)
	// No STUN provided, should fall back to defaults.
	if len(stun) == 0 {
		t.Fatal("expected default STUN servers")
	}
	defaults := conn.DefaultSTUNServers()
	if len(stun) != len(defaults) {
		t.Fatalf("stun = %v, want defaults %v", stun, defaults)
	}
	if len(turn) != 1 {
		t.Fatalf("turn count = %d, want 1", len(turn))
	}
	if turn[0].Username != "user" || turn[0].Credential != "pass" {
		t.Fatalf("turn creds = %s/%s, want user/pass", turn[0].Username, turn[0].Credential)
	}
}

func TestIceServersToConn_Mixed(t *testing.T) {
	servers := []signal.ICEServer{
		{URLs: []string{"stun:stun1.example.com"}},
		{URLs: []string{"turns:relay.example.com:5349"}, Username: "u", Credential: "c"},
		{URLs: []string{"stun:stun2.example.com"}},
	}
	stun, turn := iceServersToConn(servers)
	if len(stun) != 2 {
		t.Fatalf("stun count = %d, want 2", len(stun))
	}
	if len(turn) != 1 {
		t.Fatalf("turn count = %d, want 1", len(turn))
	}
}

func TestIceServersToConn_Empty(t *testing.T) {
	stun, turn := iceServersToConn(nil)
	defaults := conn.DefaultSTUNServers()
	if len(stun) != len(defaults) {
		t.Fatalf("stun = %v, want defaults", stun)
	}
	if len(turn) != 0 {
		t.Fatalf("turn = %v, want empty", turn)
	}
}

// ── safeRename ───────────────────────────────────────────────────────────────

func TestSafeRename_Basic(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "tmp-file")
	os.WriteFile(tmp, []byte("hello"), 0o644)

	dest, err := safeRename(tmp, "file.txt", dir)
	if err != nil {
		t.Fatalf("safeRename: %v", err)
	}
	if filepath.Base(dest) != "file.txt" {
		t.Fatalf("dest = %q, want file.txt", filepath.Base(dest))
	}
	data, _ := os.ReadFile(dest)
	if string(data) != "hello" {
		t.Fatalf("content = %q, want hello", data)
	}
	// Temp file should be removed.
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("tmp file should be removed")
	}
}

func TestSafeRename_CollisionAddsNumber(t *testing.T) {
	dir := t.TempDir()

	// Create existing file.
	os.WriteFile(filepath.Join(dir, "file.txt"), []byte("existing"), 0o644)

	tmp := filepath.Join(dir, "tmp-file")
	os.WriteFile(tmp, []byte("new"), 0o644)

	dest, err := safeRename(tmp, "file.txt", dir)
	if err != nil {
		t.Fatalf("safeRename: %v", err)
	}
	if filepath.Base(dest) != "file (1).txt" {
		t.Fatalf("dest = %q, want file (1).txt", filepath.Base(dest))
	}
}

func TestSafeRename_MultipleCollisions(t *testing.T) {
	dir := t.TempDir()

	// Create file.txt and file (1).txt.
	os.WriteFile(filepath.Join(dir, "file.txt"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(dir, "file (1).txt"), []byte("b"), 0o644)

	tmp := filepath.Join(dir, "tmp-file")
	os.WriteFile(tmp, []byte("c"), 0o644)

	dest, err := safeRename(tmp, "file.txt", dir)
	if err != nil {
		t.Fatalf("safeRename: %v", err)
	}
	if filepath.Base(dest) != "file (2).txt" {
		t.Fatalf("dest = %q, want file (2).txt", filepath.Base(dest))
	}
}

func TestSafeRename_NoExtension(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "README"), []byte("a"), 0o644)

	tmp := filepath.Join(dir, "tmp-file")
	os.WriteFile(tmp, []byte("b"), 0o644)

	dest, err := safeRename(tmp, "README", dir)
	if err != nil {
		t.Fatalf("safeRename: %v", err)
	}
	if filepath.Base(dest) != "README (1)" {
		t.Fatalf("dest = %q, want README (1)", filepath.Base(dest))
	}
}

// ── PrepareInput ─────────────────────────────────────────────────────────────

func TestPrepareInput_SingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	os.WriteFile(path, []byte("hello world"), 0o644)

	meta, r, cleanup, err := PrepareInput([]string{path}, "")
	if err != nil {
		t.Fatalf("PrepareInput: %v", err)
	}
	defer cleanup()

	if meta.Name != "hello.txt" {
		t.Errorf("name = %q, want hello.txt", meta.Name)
	}
	if meta.Size != 11 {
		t.Errorf("size = %d, want 11", meta.Size)
	}
	if meta.IsFolder {
		t.Error("isFolder should be false")
	}
	if meta.StreamMode {
		t.Error("streamMode should be false")
	}

	data, _ := io.ReadAll(r)
	if string(data) != "hello world" {
		t.Errorf("content = %q", data)
	}
}

func TestPrepareInput_Stdin(t *testing.T) {
	meta, _, cleanup, err := PrepareInput([]string{"-"}, "")
	if err != nil {
		t.Fatalf("PrepareInput: %v", err)
	}
	defer cleanup()

	if meta.Name != "stdin" {
		t.Errorf("name = %q, want stdin", meta.Name)
	}
	if !meta.StreamMode {
		t.Error("streamMode should be true")
	}
}

func TestPrepareInput_StdinWithName(t *testing.T) {
	meta, _, cleanup, err := PrepareInput([]string{"-"}, "data.csv")
	if err != nil {
		t.Fatalf("PrepareInput: %v", err)
	}
	defer cleanup()

	if meta.Name != "data.csv" {
		t.Errorf("name = %q, want data.csv", meta.Name)
	}
}

func TestPrepareInput_Folder(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0o644)
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("bbb"), 0o644)

	meta, r, cleanup, err := PrepareInput([]string{dir}, "")
	if err != nil {
		t.Fatalf("PrepareInput: %v", err)
	}
	defer cleanup()

	if !meta.IsFolder {
		t.Error("isFolder should be true")
	}
	if meta.FileCount < 2 {
		t.Errorf("fileCount = %d, want >= 2", meta.FileCount)
	}
	if meta.Size == 0 {
		t.Error("size should be > 0")
	}
	// Should be readable.
	data, _ := io.ReadAll(r)
	if len(data) == 0 {
		t.Error("expected tar data")
	}
}

func TestPrepareInput_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "one.txt")
	f2 := filepath.Join(dir, "two.txt")
	os.WriteFile(f1, []byte("111"), 0o644)
	os.WriteFile(f2, []byte("222"), 0o644)

	meta, r, cleanup, err := PrepareInput([]string{f1, f2}, "")
	if err != nil {
		t.Fatalf("PrepareInput: %v", err)
	}
	defer cleanup()

	if !meta.IsFolder {
		t.Error("isFolder should be true for multi-file")
	}
	if !strings.HasSuffix(meta.Name, "-files") {
		t.Errorf("name = %q, want N-files suffix", meta.Name)
	}
	data, _ := io.ReadAll(r)
	if len(data) == 0 {
		t.Error("expected tar data")
	}
}

func TestPrepareInput_NonexistentFile(t *testing.T) {
	_, _, _, err := PrepareInput([]string{"/nonexistent/file.txt"}, "")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestPrepareInput_MIMEType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image.png")
	os.WriteFile(path, []byte("fake png"), 0o644)

	meta, _, cleanup, err := PrepareInput([]string{path}, "")
	if err != nil {
		t.Fatalf("PrepareInput: %v", err)
	}
	defer cleanup()

	if meta.Type != "image/png" {
		t.Errorf("type = %q, want image/png", meta.Type)
	}
}
