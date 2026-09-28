// SPDX-License-Identifier: MIT

package testturn

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTracker_CreatedDeleted(t *testing.T) {
	tr := newTracker(0)
	tr.recordCreated("user-a")
	tr.recordCreated("user-a")
	tr.recordCreated("user-b")
	tr.recordDeleted("user-a")

	snap := tr.snapshot(0)
	if snap.Created != 3 || snap.Deleted != 1 || snap.Live != 2 || snap.PeakLive != 3 {
		t.Fatalf("totals: got Created=%d Deleted=%d Live=%d PeakLive=%d", snap.Created, snap.Deleted, snap.Live, snap.PeakLive)
	}
	if len(snap.Users) != 2 {
		t.Fatalf("expected 2 users, got %d: %+v", len(snap.Users), snap.Users)
	}
	a := snap.Users[userKey("user-a")]
	if a.Created != 2 || a.Deleted != 1 || a.Live != 1 || a.PeakLive != 2 {
		t.Fatalf("user-a: got %+v", a)
	}
	b := snap.Users[userKey("user-b")]
	if b.Created != 1 || b.Deleted != 0 || b.Live != 1 || b.PeakLive != 1 {
		t.Fatalf("user-b: got %+v", b)
	}
}

func TestTracker_UsersKeyedByHash_NeverRawID(t *testing.T) {
	tr := newTracker(0)
	const secretSessionID = "super-secret-session-id-should-never-appear-on-disk"
	tr.recordCreated(secretSessionID)

	snap := tr.snapshot(0)
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), secretSessionID) {
		t.Fatalf("marshaled snapshot leaked the raw user ID: %s", data)
	}
	for key := range snap.Users {
		if len(key) != 16 {
			t.Fatalf("expected a 16-hex-char user key, got %q (len %d)", key, len(key))
		}
		if key != userKey(secretSessionID) {
			t.Fatalf("unexpected user key %q", key)
		}
	}
}

func TestTracker_DeleteWithoutCreate_NeverGoesNegative(t *testing.T) {
	tr := newTracker(0)
	tr.recordDeleted("ghost")
	tr.recordDeleted("ghost")

	snap := tr.snapshot(0)
	if snap.Anomalies != 2 {
		t.Fatalf("expected 2 anomalies, got %d", snap.Anomalies)
	}
	if snap.Live != 0 || snap.Deleted != 0 {
		t.Fatalf("a delete with no matching create must not move Live/Deleted: got Live=%d Deleted=%d", snap.Live, snap.Deleted)
	}

	// Now create one, delete it twice: the second delete is the anomaly.
	tr.recordCreated("real")
	tr.recordDeleted("real")
	tr.recordDeleted("real")
	snap = tr.snapshot(0)
	if snap.Anomalies != 3 {
		t.Fatalf("expected 3 anomalies total, got %d", snap.Anomalies)
	}
	real := snap.Users[userKey("real")]
	if real.Live != 0 || real.Deleted != 1 {
		t.Fatalf("real user: got %+v", real)
	}
}

func TestTracker_QuotaBoundary(t *testing.T) {
	tr := newTracker(3)
	for i := 0; i < 3; i++ {
		if !tr.allow("u") {
			t.Fatalf("allocation %d should be within quota 3", i+1)
		}
		tr.recordCreated("u")
	}
	if tr.allow("u") {
		t.Fatal("4th allocation should be rejected at quota 3")
	}
	snap := tr.snapshot(0)
	if snap.QuotaRejected != 1 || snap.Users[userKey("u")].QuotaRejected != 1 {
		t.Fatalf("expected exactly 1 quota rejection, got total=%d user=%d", snap.QuotaRejected, snap.Users[userKey("u")].QuotaRejected)
	}

	// A different user is unaffected by u's quota.
	if !tr.allow("other") {
		t.Fatal("a different user must not be blocked by u's quota")
	}

	// Freeing one slot allows exactly one more.
	tr.recordDeleted("u")
	if !tr.allow("u") {
		t.Fatal("allocation should succeed again after freeing a slot")
	}
	tr.recordCreated("u")
	if tr.allow("u") {
		t.Fatal("should be back at quota after re-filling the freed slot")
	}
}

func TestTracker_ZeroQuotaNeverRejects(t *testing.T) {
	tr := newTracker(0)
	for i := 0; i < 50; i++ {
		if !tr.allow("u") {
			t.Fatalf("quota 0 must never reject (iteration %d)", i)
		}
		tr.recordCreated("u")
	}
}

// TestTracker_Concurrency exercises created/deleted/allow from many
// goroutines at once. This does not claim pion's real callback pattern is
// this concurrent (see the invariant comment in turn.go: in practice, every
// mutating call arrives serialized on pion's single control-plane read-loop
// goroutine) -- it instead proves the tracker's own locking is correct
// regardless, so a future change to that invariant (e.g. adding a
// TCP/TLS listener, which does add per-connection goroutines) fails safe.
func TestTracker_Concurrency(t *testing.T) {
	tr := newTracker(0)
	const goroutines = 32
	const perGoroutine = 1000
	const users = 4

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			user := userIDForGoroutine(g, users)
			for i := 0; i < perGoroutine; i++ {
				tr.recordCreated(user)
				tr.recordDeleted(user)
			}
		}(g)
	}
	wg.Wait()

	snap := tr.snapshot(0)
	const total = goroutines * perGoroutine
	if snap.Created != total || snap.Deleted != total || snap.Live != 0 {
		t.Fatalf("got Created=%d Deleted=%d Live=%d, want Created=Deleted=%d Live=0", snap.Created, snap.Deleted, snap.Live, total)
	}
	if snap.Anomalies != 0 {
		t.Fatalf("expected 0 anomalies (every delete had a matching create), got %d", snap.Anomalies)
	}
	var sumCreated, sumDeleted uint64
	for _, u := range snap.Users {
		sumCreated += u.Created
		sumDeleted += u.Deleted
	}
	if sumCreated != total || sumDeleted != total {
		t.Fatalf("per-user sums don't match totals: sumCreated=%d sumDeleted=%d want %d", sumCreated, sumDeleted, total)
	}
}

func userIDForGoroutine(g, users int) string {
	return "user-" + string(rune('a'+g%users))
}

func TestWriteFileAtomic_ConcurrentReadersNeverSeePartialWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")

	type payload struct {
		Seq int `json:"seq"`
		// Pad varies the write size across iterations to make a torn write
		// more likely to be caught if writeFileAtomic were not actually atomic.
		Pad string `json:"pad"`
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			data, err := json.Marshal(payload{Seq: i, Pad: strings.Repeat("x", i%200)})
			if err != nil {
				t.Errorf("marshal: %v", err)
				return
			}
			if err := writeFileAtomic(path, data, 0o600); err != nil {
				t.Errorf("writeFileAtomic: %v", err)
				return
			}
		}
		close(stop)
	}()

	readErrs := 0
	reads := 0
	for {
		select {
		case <-stop:
			wg.Wait()
			if readErrs != 0 {
				t.Fatalf("%d/%d reads observed invalid JSON while writes were in flight", readErrs, reads)
			}
			if reads == 0 {
				t.Fatal("no reads happened before the writer finished -- test didn't exercise concurrency")
			}
			// No leftover temp files.
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".testturn-stats-") {
					t.Fatalf("leftover temp file: %s", e.Name())
				}
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("Stat: %v", err)
			}
			// Windows has no POSIX permission bits — see the equivalent guard
			// in internal/cli/machine_test.go.
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
				t.Fatalf("expected mode 0600, got %v", info.Mode().Perm())
			}
			return
		default:
		}
		reads++
		data, err := os.ReadFile(path)
		if err != nil {
			// The file may not exist yet on the very first iterations.
			continue
		}
		var p payload
		if err := json.Unmarshal(data, &p); err != nil {
			readErrs++
			t.Logf("invalid JSON read: %v (data=%q)", err, data)
		}
	}
}

func TestStatsWriter_CoalescesAndFlushReflectsLatest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")

	tr := newTracker(0)
	w := newStatsWriter(path, func() Snapshot { return tr.snapshot(0) })
	tr.writer = w
	w.start()
	defer w.close()

	for i := 0; i < 100; i++ {
		tr.recordCreated("u")
	}
	w.flush()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if snap.Created != 100 || snap.Live != 100 {
		t.Fatalf("flush should reflect the latest state: got Created=%d Live=%d", snap.Created, snap.Live)
	}
}

func TestStatsWriter_DisabledWhenPathEmpty(t *testing.T) {
	tr := newTracker(0)
	w := newStatsWriter("", func() Snapshot { return tr.snapshot(0) })
	tr.writer = w
	w.start() // must not spawn a goroutine that blocks close()
	tr.recordCreated("u")
	w.flush()
	w.close()
	// No panic, no hang, and nothing written -- there is no path to check.
	select {
	case <-w.done:
	case <-time.After(time.Second):
		t.Fatal("writer with an empty path did not shut down promptly")
	}
}
