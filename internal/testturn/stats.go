// SPDX-License-Identifier: MIT

package testturn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// SnapshotVersion is bumped whenever the Snapshot JSON shape changes in a
// way a reader (web/tests/relay.spec.ts, web/tests/relay-summary.mjs) needs
// to know about.
const SnapshotVersion = 1

// UserStats holds per-user (per TURN userID, i.e. per sp2p session) TURN
// allocation counters.
type UserStats struct {
	Created               uint64 `json:"created"`
	Deleted               uint64 `json:"deleted"`
	Live                  int64  `json:"live"`
	PeakLive              int64  `json:"peakLive"`
	QuotaRejected         uint64 `json:"quotaRejected"`
	RelayedBytesFromPeers uint64 `json:"relayedBytesFromPeers"`
	RelayedBytesToPeers   uint64 `json:"relayedBytesToPeers"`
	// Allocations is a leak-debugging aid: one record per allocation this
	// user has ever made, in creation order. Numbers only -- the client UDP
	// port (unique per lane/attempt on this single test host, never a
	// secret) plus creation/deletion timestamps -- so a test can correlate
	// a still-live allocation back to the specific local process/socket
	// that owns it (e.g. via `ss -uanp` inside the netns) without needing
	// any session identifier. DeletedAtMs is 0 while still live.
	Allocations []AllocationRecord `json:"allocations,omitempty"`
}

// AllocationRecord is one allocation's client-side identity and lifecycle,
// for leak debugging only (see UserStats.Allocations).
type AllocationRecord struct {
	ClientPort  int   `json:"clientPort"`
	CreatedAtMs int64 `json:"createdAtMs"`
	DeletedAtMs int64 `json:"deletedAtMs,omitempty"`
}

// Snapshot is the full stats.json document written by Server. TURN
// usernames (and the sp2p session IDs embedded in them) are never written
// to disk in the clear -- Users is keyed by userKey(userID) instead, so
// stats.json can never be used to join or identify a live session (see
// AGENTS.md: never log transfer codes or TURN secrets).
type Snapshot struct {
	Version   int    `json:"version"`
	Seq       uint64 `json:"seq"`
	Ready     bool   `json:"ready"`
	Closed    bool   `json:"closed"`
	UserQuota int    `json:"userQuota"`

	Created            uint64 `json:"created"`
	Deleted            uint64 `json:"deleted"`
	Live               int64  `json:"live"`
	PeakLive           int64  `json:"peakLive"`
	QuotaRejected      uint64 `json:"quotaRejected"`
	AuthFailures       uint64 `json:"authFailures"`
	RelayAllocFailures uint64 `json:"relayAllocFailures"`
	Anomalies          uint64 `json:"anomalies"`

	// PionLive is turn.Server.AllocationCount() sampled at snapshot time --
	// an independent cross-check against this package's own Live counter.
	PionLive int `json:"pionLive"`

	RelayedBytesFromPeers uint64 `json:"relayedBytesFromPeers"`
	RelayedBytesToPeers   uint64 `json:"relayedBytesToPeers"`

	Users map[string]UserStats `json:"users"`
}

// userKeySecret is a random key generated once per process and used to key
// userKey's HMAC below, rather than hashing the raw TURN userID with a
// fixed, well-known function. A TURN username's userID is only an 8-char
// session code drawn from a modest alphabet (internal/server/session.go),
// so an unsalted hash of it would be brute-forceable from stats.json alone;
// keying it with a value that exists only in this process's memory removes
// that even though the practical exposure (a dead, already-expired session
// visible only in a failed CI run's artifact) is low.
var userKeySecret = randomUserKeySecret()

func randomUserKeySecret() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// No system entropy source is effectively unrecoverable; fail loudly
		// rather than silently keying with a predictable value.
		panic("testturn: failed to generate a random user-key secret: " + err.Error())
	}
	return b
}

// userKey derives a stats.json-safe identifier for a TURN userID (the sp2p
// session ID) so stats.json never carries a usable session identifier or a
// value a reader could brute-force back to one (see userKeySecret above).
// Stable for the lifetime of one process, which is all callers need: a
// snapshot's Users map and a test's own userKey(id) computation always
// agree within the same test run. 16 hex characters (64 bits) is ample to
// distinguish the handful of concurrent sessions a test run creates.
func userKey(userID string) string {
	mac := hmac.New(sha256.New, userKeySecret)
	mac.Write([]byte(userID))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// relayBytes counts bytes relayed for one user's allocation(s). Reads
// happen from the per-allocation relay-socket goroutine (ReadFrom, "from
// peers") and the shared control-loop goroutine (WriteTo, "to peers") --
// see countingPacketConn -- concurrently with stats snapshotting, so both
// fields are atomic.
type relayBytes struct {
	fromPeers atomic.Uint64
	toPeers   atomic.Uint64
}

type userState struct {
	created, deleted uint64
	live, peakLive   int64
	quotaRejected    uint64
	bytes            relayBytes
	// allocs is a leak-debugging aid keyed by client UDP port (see
	// AllocationRecord) -- unique per lane/attempt on this single test
	// host for the short lifetime of one test.
	allocs map[int]*AllocationRecord
}

// tracker holds live TURN allocation accounting, guarded by mu. allow and
// recordCreated (the pair the quota-exactness property depends on -- see
// allow's doc comment) are always called synchronously, back to back, from
// pion's single control-plane read-loop goroutine (see the invariant
// comment above the turn.NewServer call in Server.New, in turn.go).
// recordDeleted does NOT share that guarantee: pion also deletes
// allocations from a per-allocation lifetime-expiry timer and from each
// allocation's own relay-socket read-error path, both different goroutines
// from the read loop and from each other. This is safe regardless, since
// mu serializes every call here and a delete only ever decreases Live --
// it just means recordDeleted (unlike allow/recordCreated) cannot be
// reasoned about as single-goroutine. relayBytes fields are a further
// exception (see above) and use atomics instead of mu.
type tracker struct {
	mu     sync.Mutex
	quota  int
	closed bool
	users  map[string]*userState // keyed by the raw userID -- never persisted

	created, deleted   uint64
	live, peakLive     int64
	quotaRejected      uint64
	authFailures       uint64
	relayAllocFailures uint64
	anomalies          uint64

	writer *statsWriter
}

func newTracker(quota int) *tracker {
	return &tracker{quota: quota, users: make(map[string]*userState)}
}

func (t *tracker) userLocked(userID string) *userState {
	u := t.users[userID]
	if u == nil {
		u = &userState{}
		t.users[userID] = u
	}
	return u
}

// allow reports whether a new allocation for userID is within quota. Called
// by turn.QuotaHandler immediately before turn.Manager.CreateAllocation, on
// the same goroutine -- see the invariant comment in turn.go for why this
// check-then-increment is race-free despite no reservation step.
func (t *tracker) allow(userID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.quota <= 0 {
		return true
	}
	u := t.userLocked(userID)
	if u.live >= int64(t.quota) {
		u.quotaRejected++
		t.quotaRejected++
		t.poke()
		return false
	}
	return true
}

// recordCreated records a new allocation for userID, keyed by its client
// UDP port (see AllocationRecord). Called from
// turn.EventHandler.OnAllocationCreated.
func (t *tracker) recordCreated(userID string, clientPort int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	u := t.userLocked(userID)
	u.created++
	u.live++
	if u.live > u.peakLive {
		u.peakLive = u.live
	}
	if u.allocs == nil {
		u.allocs = make(map[int]*AllocationRecord)
	}
	u.allocs[clientPort] = &AllocationRecord{ClientPort: clientPort, CreatedAtMs: time.Now().UnixMilli()}
	t.created++
	t.live++
	if t.live > t.peakLive {
		t.peakLive = t.live
	}
	t.poke()
}

// recordDeleted records an allocation's removal for userID, keyed by the
// same client UDP port passed to recordCreated. Called from
// turn.EventHandler.OnAllocationDeleted. A delete with no matching create
// (userID unknown, or already at zero live) is recorded as an anomaly and
// never drives Live negative -- this should not happen given the single
// read-loop invariant, but stats.json must stay trustworthy even if it did.
func (t *tracker) recordDeleted(userID string, clientPort int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	u := t.users[userID]
	if u == nil || u.live <= 0 {
		t.anomalies++
		t.poke()
		return
	}
	u.deleted++
	u.live--
	if rec, ok := u.allocs[clientPort]; ok && rec.DeletedAtMs == 0 {
		rec.DeletedAtMs = time.Now().UnixMilli()
	}
	t.deleted++
	t.live--
	t.poke()
}

func (t *tracker) authFailed() {
	t.mu.Lock()
	t.authFailures++
	t.poke()
	t.mu.Unlock()
}

func (t *tracker) relayAllocFailed() {
	t.mu.Lock()
	t.relayAllocFailures++
	t.poke()
	t.mu.Unlock()
}

// markClosed records that the server has shut down. Snapshots taken after
// this point report Closed:true; see Server.Close's doc comment for why
// Live is not forced to zero here.
func (t *tracker) markClosed() {
	t.mu.Lock()
	t.closed = true
	t.poke()
	t.mu.Unlock()
}

// relayBytesFor returns the byte counters for userID, creating the user's
// entry if necessary. Called from the relay generator wrapper, which may
// run on a different goroutine than the control loop -- see relayBytes.
func (t *tracker) relayBytesFor(userID string) *relayBytes {
	t.mu.Lock()
	defer t.mu.Unlock()
	return &t.userLocked(userID).bytes
}

// poke must be called with mu held; it schedules a stats.json write without
// blocking the caller (a pion event-handler callback) on file IO.
func (t *tracker) poke() {
	if t.writer != nil {
		t.writer.poke()
	}
}

// snapshot builds a Snapshot from the current counters. pionLive is
// turn.Server.AllocationCount(), sampled by the caller immediately before
// or after acquiring the lock (an independent cross-check, not required to
// be perfectly synchronized with the counters below). Ready is always true:
// a tracker only exists once its Server has been fully constructed (see
// Server.New), so there is no meaningful "not ready" state to report.
func (t *tracker) snapshot(pionLive int) Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	users := make(map[string]UserStats, len(t.users))
	for id, u := range t.users {
		var allocs []AllocationRecord
		if len(u.allocs) > 0 {
			allocs = make([]AllocationRecord, 0, len(u.allocs))
			for _, rec := range u.allocs {
				allocs = append(allocs, *rec)
			}
			sort.Slice(allocs, func(i, j int) bool { return allocs[i].CreatedAtMs < allocs[j].CreatedAtMs })
		}
		users[userKey(id)] = UserStats{
			Created:               u.created,
			Deleted:               u.deleted,
			Live:                  u.live,
			PeakLive:              u.peakLive,
			QuotaRejected:         u.quotaRejected,
			RelayedBytesFromPeers: u.bytes.fromPeers.Load(),
			RelayedBytesToPeers:   u.bytes.toPeers.Load(),
			Allocations:           allocs,
		}
	}
	var fromPeers, toPeers uint64
	for _, u := range users {
		fromPeers += u.RelayedBytesFromPeers
		toPeers += u.RelayedBytesToPeers
	}
	return Snapshot{
		Version:               SnapshotVersion,
		Ready:                 true,
		Closed:                t.closed,
		UserQuota:             t.quota,
		Created:               t.created,
		Deleted:               t.deleted,
		Live:                  t.live,
		PeakLive:              t.peakLive,
		QuotaRejected:         t.quotaRejected,
		AuthFailures:          t.authFailures,
		RelayAllocFailures:    t.relayAllocFailures,
		Anomalies:             t.anomalies,
		PionLive:              pionLive,
		RelayedBytesFromPeers: fromPeers,
		RelayedBytesToPeers:   toPeers,
		Users:                 users,
	}
}

// statsWriter coalesces poke()s from pion's callback goroutines into a
// serialized sequence of atomic stats.json writes on its own goroutine, so
// no callback ever blocks on file IO.
type statsWriter struct {
	path   string
	build  func() Snapshot
	notify chan struct{}
	stop   chan struct{}
	done   chan struct{}
	seq    atomic.Uint64
}

func newStatsWriter(path string, build func() Snapshot) *statsWriter {
	return &statsWriter{
		path:   path,
		build:  build,
		notify: make(chan struct{}, 1),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
}

func (w *statsWriter) start() {
	if w.path == "" {
		close(w.done)
		return
	}
	go w.run()
}

func (w *statsWriter) run() {
	defer close(w.done)
	for {
		select {
		case <-w.notify:
			w.writeOnce()
		case <-w.stop:
			return
		}
	}
}

// poke schedules a write without blocking; if one is already pending, this
// is a no-op (the pending write will pick up the latest state).
func (w *statsWriter) poke() {
	if w.path == "" {
		return
	}
	select {
	case w.notify <- struct{}{}:
	default:
	}
}

// flush writes the current snapshot synchronously, bypassing the
// notify channel. Used for the first write (before New returns, so
// stats.json exists with ready:true) and the final write in Close.
func (w *statsWriter) flush() {
	if w.path == "" {
		return
	}
	w.writeOnce()
}

func (w *statsWriter) writeOnce() {
	snap := w.build()
	snap.Seq = w.seq.Add(1)
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return // stats are best-effort diagnostics, never fatal to the server
	}
	_ = writeFileAtomic(w.path, data, 0o600)
}

func (w *statsWriter) close() {
	if w.path == "" {
		return
	}
	close(w.stop)
	<-w.done
}

// writeFileAtomic writes data to path by creating a temp file in the same
// directory, then renaming it into place, so a concurrent reader never
// observes a partially written stats.json. Mirrors the pattern in
// internal/cli/machine.go's writeSnapshotLocked.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".testturn-stats-*")
	if err != nil {
		return fmt.Errorf("create temp stats file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp stats file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp stats file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp stats file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename stats file: %w", err)
	}
	return nil
}
