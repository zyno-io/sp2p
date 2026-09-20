// SPDX-License-Identifier: MIT

package conn

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recordingUPnPDeleter struct {
	t         *testing.T
	deletions atomic.Int64
}

func (d *recordingUPnPDeleter) DeletePortMappingCtx(ctx context.Context, remote string, port uint16, protocol string) error {
	d.deletions.Add(1)
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > upnpTimeout || ctx.Err() != nil {
		d.t.Errorf("cleanup must have a fresh bounded context")
	}
	if remote != "" || port != 12345 || protocol != "TCP" {
		d.t.Errorf("incorrect deletion target")
	}
	return nil
}

func TestUPnPCleanupOwnsLateMapping(t *testing.T) {
	var owner mappingOwner
	deleter := &recordingUPnPDeleter{t: t}
	owner.close() // successful transfer ends before discovery returns
	if owner.register(&UPnPMapping{ExternalPort: 12345, client: deleter}) {
		t.Fatal("accepted a mapping after cleanup")
	}
	owner.close()
	if got := deleter.deletions.Load(); got != 1 {
		t.Fatalf("deleted %d times", got)
	}
}

func TestUPnPCleanupRacesRegistration(t *testing.T) {
	for i := 0; i < 100; i++ {
		var owner mappingOwner
		deleter := &recordingUPnPDeleter{t: t}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); owner.register(&UPnPMapping{ExternalPort: 12345, client: deleter}) }()
		go func() { defer wg.Done(); owner.close() }()
		wg.Wait()
		owner.close()
		if got := deleter.deletions.Load(); got != 1 {
			t.Fatalf("deleted %d times", got)
		}
	}
}
