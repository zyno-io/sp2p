// SPDX-License-Identifier: MIT

package peer

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAskRelayCancelsPromptWhenPeerDisconnects(t *testing.T) {
	peerGone := make(chan struct{})
	peerDenied := make(chan struct{})
	promptStopped := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := askRelay(context.Background(), peerGone, peerDenied, func(ctx context.Context) bool {
			<-ctx.Done()
			close(promptStopped)
			return false
		})
		result <- err
	}()
	close(peerGone)
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "peer disconnected") {
			t.Fatalf("askRelay error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("askRelay did not return after peer disconnect")
	}
	select {
	case <-promptStopped:
	case <-time.After(time.Second):
		t.Fatal("relay prompt did not receive cancellation")
	}
}
