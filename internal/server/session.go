// SPDX-License-Identifier: MIT

package server

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

const (
	sessionIDLength         = 8
	sessionMaxAge           = 1 * time.Hour
	sessionIdleMax          = 5 * time.Minute
	reapInterval            = 30 * time.Second
	DefaultMaxSessionsPerIP = 10   // max concurrent sessions per client IP
	DefaultMaxTotalSessions = 1000 // global session cap
)

var (
	ErrTooManySessions      = errors.New("server at session capacity")
	ErrTooManySessionsForIP = errors.New("too many sessions for this IP")
	ErrSessionNotFound      = errors.New("session not found")
	ErrSessionFull          = errors.New("session already has a receiver")
)

// Unambiguous alphabet: excludes 0, 1, i, l, o to avoid confusion.
const alphabet = "23456789abcdefghjkmnpqrstuvwxyz"

// Session represents a signaling session between a sender and receiver.
type Session struct {
	ID               string
	IP               string // client IP for rate limiting
	SenderClientType string // "cli", "browser", or ""
	CreatedAt        time.Time
	LastSeen         time.Time
	Sender           *websocket.Conn
	receiver         atomic.Pointer[websocket.Conn]
	joinedAt         atomic.Int64           // unix nanos when receiver joined (0 = not yet joined)
	fileInfo         atomic.Pointer[string] // encrypted file metadata (set by sender, read via HTTP)
}

// CloseConns closes both sender and receiver WebSocket connections (best-effort).
func (s *Session) CloseConns() {
	if s.Sender != nil {
		s.Sender.Close(websocket.StatusGoingAway, "session ended")
	}
	if recv := s.Receiver(); recv != nil {
		recv.Close(websocket.StatusGoingAway, "session ended")
	}
}

// Receiver returns the receiver connection (safe for concurrent access).
func (s *Session) Receiver() *websocket.Conn {
	return s.receiver.Load()
}

// SetReceiver sets the receiver connection (safe for concurrent access).
func (s *Session) SetReceiver(conn *websocket.Conn) {
	s.receiver.Store(conn)
	s.joinedAt.Store(time.Now().UnixNano())
}

// JoinedAt returns when the receiver joined, or zero time if not yet joined.
func (s *Session) JoinedAt() time.Time {
	if ns := s.joinedAt.Load(); ns != 0 {
		return time.Unix(0, ns)
	}
	return time.Time{}
}

// FileInfoData returns the encrypted file metadata (safe for concurrent access).
func (s *Session) FileInfoData() string {
	if p := s.fileInfo.Load(); p != nil {
		return *p
	}
	return ""
}

// SetFileInfo stores the encrypted file metadata (safe for concurrent access).
func (s *Session) SetFileInfo(data string) {
	s.fileInfo.Store(&data)
}

// SessionManager manages in-memory signaling sessions.
type SessionManager struct {
	mu               sync.RWMutex
	sessions         map[string]*Session
	ipCounts         map[string]int // per-IP active session count
	maxTotalSessions int
	maxSessionsPerIP int
	done             chan struct{}
	stopOnce         sync.Once
}

// NewSessionManager creates a new session manager and starts the reaper.
// Pass 0 for either limit to use the default.
func NewSessionManager(maxTotal, maxPerIP int) *SessionManager {
	if maxTotal <= 0 {
		maxTotal = DefaultMaxTotalSessions
	}
	if maxPerIP <= 0 {
		maxPerIP = DefaultMaxSessionsPerIP
	}
	sm := &SessionManager{
		sessions:         make(map[string]*Session),
		ipCounts:         make(map[string]int),
		maxTotalSessions: maxTotal,
		maxSessionsPerIP: maxPerIP,
		done:             make(chan struct{}),
	}
	go sm.reapLoop()
	return sm
}

// Create creates a new session for the given sender connection.
// Returns ErrTooManySessions or ErrTooManySessionsForIP if limits are exceeded.
func (sm *SessionManager) Create(sender *websocket.Conn, ip string) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if len(sm.sessions) >= sm.maxTotalSessions {
		return nil, ErrTooManySessions
	}
	if sm.ipCounts[ip] >= sm.maxSessionsPerIP {
		return nil, ErrTooManySessionsForIP
	}

	var id string
	for {
		var err error
		id, err = generateID(sessionIDLength)
		if err != nil {
			return nil, err
		}
		if _, exists := sm.sessions[id]; !exists {
			break
		}
	}

	s := &Session{
		ID:        id,
		IP:        ip,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Sender:    sender,
	}
	sm.sessions[id] = s
	sm.ipCounts[ip]++
	return s, nil
}

// Join adds a receiver to an existing session.
// Returns ErrSessionNotFound if the session does not exist,
// or ErrSessionFull if a receiver has already joined.
func (sm *SessionManager) Join(id string, receiver *websocket.Conn) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	s, ok := sm.sessions[id]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if s.Receiver() != nil {
		return nil, ErrSessionFull
	}
	s.SetReceiver(receiver)
	s.LastSeen = time.Now()
	return s, nil
}

// Get retrieves a session by ID.
func (sm *SessionManager) Get(id string) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[id]
}

// Touch updates the last-seen timestamp for a session.
func (sm *SessionManager) Touch(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if s, ok := sm.sessions[id]; ok {
		s.LastSeen = time.Now()
	}
}

// Remove deletes a session and closes peer connections.
func (sm *SessionManager) Remove(id string) {
	sm.mu.Lock()
	s, ok := sm.sessions[id]
	if ok {
		delete(sm.sessions, id)
		sm.decIP(s.IP)
	}
	sm.mu.Unlock()
	// Close connections outside the lock to avoid blocking.
	if ok {
		s.CloseConns()
	}
}

func (sm *SessionManager) decIP(ip string) {
	if ip == "" {
		return
	}
	sm.ipCounts[ip]--
	if sm.ipCounts[ip] <= 0 {
		delete(sm.ipCounts, ip)
	}
}

// Stop stops the reaper goroutine. Safe to call multiple times.
func (sm *SessionManager) Stop() {
	sm.stopOnce.Do(func() { close(sm.done) })
}

func (sm *SessionManager) reapLoop() {
	ticker := time.NewTicker(reapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			sm.reap()
		case <-sm.done:
			return
		}
	}
}

func (sm *SessionManager) reap() {
	sm.mu.Lock()
	now := time.Now()
	var expired []*Session
	for id, s := range sm.sessions {
		if now.Sub(s.CreatedAt) > sessionMaxAge || now.Sub(s.LastSeen) > sessionIdleMax {
			expired = append(expired, s)
			delete(sm.sessions, id)
			sm.decIP(s.IP)
		}
	}
	sm.mu.Unlock()
	// Close connections outside the lock to avoid blocking.
	for _, s := range expired {
		slog.Info("session reaped", "session", s.ID, "age", time.Since(s.CreatedAt).Round(time.Second), "idle", time.Since(s.LastSeen).Round(time.Second))
		s.CloseConns()
	}
}

func generateID(length int) (string, error) {
	// Use rejection sampling to avoid modulo bias.
	// alphabet has 29 chars; we reject bytes >= 29*8=232 to ensure uniform distribution.
	maxValid := byte(256 - 256%len(alphabet))
	id := make([]byte, length)
	buf := make([]byte, 1)
	for i := 0; i < length; i++ {
		for {
			if _, err := rand.Read(buf); err != nil {
				return "", fmt.Errorf("crypto/rand: %w", err)
			}
			if buf[0] < maxValid {
				break
			}
		}
		id[i] = alphabet[int(buf[0])%len(alphabet)]
	}
	return string(id), nil
}
