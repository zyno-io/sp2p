// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"testing"
	"time"
	"unsafe"

	"github.com/coder/websocket"
)

// dummyConn returns a non-nil *websocket.Conn for use in tests that only need
// to store the pointer without actually using the connection.
func dummyConn() *websocket.Conn {
	return (*websocket.Conn)(unsafe.Pointer(uintptr(1)))
}

func TestSession_CreateAndGetFields(t *testing.T) {
	sm := NewSessionManager(0, 0)
	defer sm.Stop()

	s, err := sm.Create(nil, "10.0.0.1")
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}
	if s.ID == "" {
		t.Fatal("session ID should be non-empty")
	}
	if s.IP != "10.0.0.1" {
		t.Fatalf("session IP = %q, want %q", s.IP, "10.0.0.1")
	}

	got := sm.Get(s.ID)
	if got == nil {
		t.Fatal("Get returned nil for existing session")
	}
	if got.ID != s.ID {
		t.Fatalf("Get returned session with ID %q, want %q", got.ID, s.ID)
	}
}

func TestSession_JoinAndReceiver(t *testing.T) {
	sm := NewSessionManager(0, 0)
	defer sm.Stop()

	s, err := sm.Create(nil, "10.0.0.1")
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}

	if s.Receiver() != nil {
		t.Fatal("Receiver should be nil before join")
	}
	if !s.JoinedAt().IsZero() {
		t.Fatal("JoinedAt should be zero before join")
	}

	recv := dummyConn()
	joined, err := sm.Join(s.ID, recv)
	if err != nil {
		t.Fatalf("Join: unexpected error: %v", err)
	}
	if joined.ID != s.ID {
		t.Fatalf("Join returned session with ID %q, want %q", joined.ID, s.ID)
	}
	if s.Receiver() != recv {
		t.Fatal("Receiver should be set after join")
	}
	if s.JoinedAt().IsZero() {
		t.Fatal("JoinedAt should be non-zero after join")
	}
}

func TestSession_JoinNonexistent(t *testing.T) {
	sm := NewSessionManager(0, 0)
	defer sm.Stop()

	_, err := sm.Join("nonexistent", nil)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Join nonexistent: got error %v, want %v", err, ErrSessionNotFound)
	}
}

func TestSession_JoinTwice(t *testing.T) {
	sm := NewSessionManager(0, 0)
	defer sm.Stop()

	s, err := sm.Create(nil, "10.0.0.1")
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}

	if _, err := sm.Join(s.ID, dummyConn()); err != nil {
		t.Fatalf("first Join: unexpected error: %v", err)
	}

	_, err = sm.Join(s.ID, dummyConn())
	if !errors.Is(err, ErrSessionFull) {
		t.Fatalf("second Join: got error %v, want %v", err, ErrSessionFull)
	}
}

func TestSession_RemoveDecrementsIP(t *testing.T) {
	sm := NewSessionManager(0, 0)
	defer sm.Stop()

	s, err := sm.Create(nil, "10.0.0.1")
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}

	sm.Remove(s.ID)

	if got := sm.Get(s.ID); got != nil {
		t.Fatal("Get should return nil after Remove")
	}

	// IP count should be decremented: creating DefaultMaxSessionsPerIP sessions
	// for the same IP should succeed since the original was removed.
	for i := 0; i < DefaultMaxSessionsPerIP; i++ {
		if _, err := sm.Create(nil, "10.0.0.1"); err != nil {
			t.Fatalf("Create after Remove (iter %d): unexpected error: %v", i, err)
		}
	}
}

func TestSession_PerIPLimit(t *testing.T) {
	sm := NewSessionManager(0, 0)
	defer sm.Stop()

	ip := "192.168.1.1"
	for i := 0; i < DefaultMaxSessionsPerIP; i++ {
		if _, err := sm.Create(nil, ip); err != nil {
			t.Fatalf("Create %d: unexpected error: %v", i, err)
		}
	}

	_, err := sm.Create(nil, ip)
	if !errors.Is(err, ErrTooManySessionsForIP) {
		t.Fatalf("Create beyond limit: got error %v, want %v", err, ErrTooManySessionsForIP)
	}

	// A different IP should still be allowed.
	if _, err := sm.Create(nil, "10.0.0.1"); err != nil {
		t.Fatalf("Create for different IP: unexpected error: %v", err)
	}
}

func TestSession_FileInfo(t *testing.T) {
	sm := NewSessionManager(0, 0)
	defer sm.Stop()

	s, err := sm.Create(nil, "10.0.0.1")
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}

	if data := s.FileInfoData(); data != "" {
		t.Fatalf("FileInfoData before set = %q, want empty", data)
	}

	s.SetFileInfo("encrypted-metadata-payload")

	if data := s.FileInfoData(); data != "encrypted-metadata-payload" {
		t.Fatalf("FileInfoData = %q, want %q", data, "encrypted-metadata-payload")
	}
}

func TestSession_TouchUpdatesLastSeen(t *testing.T) {
	sm := NewSessionManager(0, 0)
	defer sm.Stop()

	s, err := sm.Create(nil, "10.0.0.1")
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}

	before := s.LastSeen
	time.Sleep(10 * time.Millisecond)
	sm.Touch(s.ID)

	got := sm.Get(s.ID)
	if !got.LastSeen.After(before) {
		t.Fatalf("LastSeen was not updated by Touch: before=%v, after=%v", before, got.LastSeen)
	}
}
