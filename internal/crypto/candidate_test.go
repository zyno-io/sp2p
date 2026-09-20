// SPDX-License-Identifier: MIT

package crypto

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestCandidateSelection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	keys := &DerivedKeys{Confirm: make([]byte, 32)}
	result := make(chan error, 1)
	go func() {
		_, err := AuthenticateCandidate(ctx, b, keys, []byte("sender"), []byte("receiver"), false)
		result <- err
	}()
	choose, err := AuthenticateCandidate(ctx, a, keys, []byte("sender"), []byte("receiver"), true)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		t.Fatalf("receiver returned before selection: %v", err)
	default:
	}
	if err := choose(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestCandidateWrongKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	result := make(chan error, 1)
	go func() {
		_, err := AuthenticateCandidate(ctx, b, &DerivedKeys{Confirm: []byte("wrong")}, nil, nil, false)
		result <- err
	}()
	_, err := AuthenticateCandidate(ctx, a, &DerivedKeys{Confirm: []byte("correct")}, nil, nil, true)
	if err == nil {
		t.Fatal("authenticated wrong key")
	}
	if err := <-result; err == nil {
		t.Fatal("receiver authenticated wrong key")
	}
}
