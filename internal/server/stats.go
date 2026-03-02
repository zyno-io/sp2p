// SPDX-License-Identifier: MIT

package server

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Stats tracks server-wide transfer statistics.
type Stats struct {
	AttemptedSends uint64 `json:"attemptedSends"`
	ConnectedSends uint64 `json:"connectedSends"`
	CompletedSends uint64 `json:"completedSends"`
	BytesTransferred uint64 `json:"bytesTransferred"`
}

// StatsTracker manages stats with debounced persistence.
type StatsTracker struct {
	mu    sync.Mutex
	stats Stats
	path  string
	dirty bool
	done  chan struct{}
}

// NewStatsTracker creates a stats tracker that persists to the given directory.
// It loads existing stats from disk if available.
func NewStatsTracker(configDir string) *StatsTracker {
	path := filepath.Join(configDir, "stats.json")
	st := &StatsTracker{
		path: path,
		done: make(chan struct{}),
	}

	// Load existing stats.
	if data, err := os.ReadFile(path); err == nil {
		json.Unmarshal(data, &st.stats)
	}

	// Start background flush loop.
	go st.flushLoop()

	return st
}

// RecordAttempt increments the attempted sends counter.
func (st *StatsTracker) RecordAttempt() {
	st.mu.Lock()
	st.stats.AttemptedSends++
	st.dirty = true
	st.mu.Unlock()
}

// RecordConnected increments the connected sends counter.
func (st *StatsTracker) RecordConnected() {
	st.mu.Lock()
	st.stats.ConnectedSends++
	st.dirty = true
	st.mu.Unlock()
}

// RecordComplete increments the completed sends counter and adds bytes.
func (st *StatsTracker) RecordComplete(bytes uint64) {
	st.mu.Lock()
	st.stats.CompletedSends++
	st.stats.BytesTransferred += bytes
	st.dirty = true
	st.mu.Unlock()
}

// Stop flushes pending stats and stops the background loop.
func (st *StatsTracker) Stop() {
	close(st.done)
	st.flush()
}

func (st *StatsTracker) flushLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			st.flush()
		case <-st.done:
			return
		}
	}
}

func (st *StatsTracker) flush() {
	st.mu.Lock()
	if !st.dirty {
		st.mu.Unlock()
		return
	}
	data, err := json.MarshalIndent(st.stats, "", "  ")
	st.dirty = false
	st.mu.Unlock()

	if err != nil {
		return
	}

	if err := os.MkdirAll(filepath.Dir(st.path), 0o755); err != nil {
		slog.Debug("stats: mkdir failed", "err", err)
		return
	}
	if err := os.WriteFile(st.path, data, 0o644); err != nil {
		slog.Debug("stats: write failed", "err", err)
	}
}
