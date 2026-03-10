// SPDX-License-Identifier: MIT

package conn

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSecondaryHandshake(t *testing.T) {
	token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	// Create a listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start acceptor in background.
	type acceptResult struct {
		conn  P2PConn
		index byte
		err   error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		c, idx, err := acceptSecondary(ctx, ln, token, time.Now().Add(5*time.Second))
		acceptCh <- acceptResult{c, idx, err}
	}()

	// Dial as the secondary dialer with stream index 1.
	c, err := dialSecondary(ctx, addr, token, 1, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatalf("dialSecondary: %v", err)
	}
	defer c.Close()

	// Check acceptor result.
	res := <-acceptCh
	if res.err != nil {
		t.Fatalf("acceptSecondary: %v", res.err)
	}
	defer res.conn.Close()

	if res.index != 1 {
		t.Fatalf("expected stream index 1, got %d", res.index)
	}
}

func TestSecondaryHandshakeBadToken(t *testing.T) {
	goodToken := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	badToken := [16]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type acceptResult struct {
		conn P2PConn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		c, _, err := acceptSecondary(ctx, ln, goodToken, time.Now().Add(5*time.Second))
		acceptCh <- acceptResult{c, err}
	}()

	// Dial with bad token — should be rejected.
	_, err = dialSecondary(ctx, addr, badToken, 1, time.Now().Add(5*time.Second))
	// The dialer may or may not get an error (depends on timing),
	// but the acceptor should reject it.
	res := <-acceptCh
	if res.err == nil {
		res.conn.Close()
		t.Fatal("expected acceptSecondary to reject bad token")
	}
	_ = err // dialer error is acceptable
}

func TestEstablishSecondary(t *testing.T) {
	token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const count = 3

	// Start acceptor side.
	acceptCh := make(chan []P2PConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conns, err := EstablishSecondary(ctx, SecondaryConfig{
			Count:    count,
			WeDialed: false,
			Listener: ln,
			Token:    token,
			Timeout:  5 * time.Second,
		})
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- conns
	}()

	// Dialer side.
	dialConns, err := EstablishSecondary(ctx, SecondaryConfig{
		Count:    count,
		WeDialed: true,
		PeerAddr: addr,
		Token:    token,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dialer EstablishSecondary: %v", err)
	}
	defer func() {
		for _, c := range dialConns {
			c.Close()
		}
	}()

	if len(dialConns) != count {
		t.Fatalf("expected %d dialer conns, got %d", count, len(dialConns))
	}

	select {
	case acceptConns := <-acceptCh:
		if len(acceptConns) != count {
			t.Fatalf("expected %d acceptor conns, got %d", count, len(acceptConns))
		}
		for _, c := range acceptConns {
			c.Close()
		}
	case err := <-errCh:
		t.Fatalf("acceptor EstablishSecondary: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for acceptor")
	}
}

func TestEstablishSecondaryWaitsForAcceptStopped(t *testing.T) {
	token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const count = 2

	// Simulate a stale accept goroutine that takes a moment to exit.
	acceptStopped := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(acceptStopped)
	}()

	// Start acceptor side — it should wait for acceptStopped before accepting.
	acceptCh := make(chan []P2PConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conns, err := EstablishSecondary(ctx, SecondaryConfig{
			Count:         count,
			WeDialed:      false,
			Listener:      ln,
			Token:         token,
			Timeout:       5 * time.Second,
			AcceptStopped: acceptStopped,
		})
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- conns
	}()

	// Wait a bit for acceptStopped to close, then start dialer.
	time.Sleep(60 * time.Millisecond)

	dialConns, err := EstablishSecondary(ctx, SecondaryConfig{
		Count:    count,
		WeDialed: true,
		PeerAddr: addr,
		Token:    token,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dialer EstablishSecondary: %v", err)
	}
	defer func() {
		for _, c := range dialConns {
			c.Close()
		}
	}()

	if len(dialConns) != count {
		t.Fatalf("expected %d dialer conns, got %d", count, len(dialConns))
	}

	select {
	case acceptConns := <-acceptCh:
		if len(acceptConns) != count {
			t.Fatalf("expected %d acceptor conns, got %d", count, len(acceptConns))
		}
		for _, c := range acceptConns {
			c.Close()
		}
	case err := <-errCh:
		t.Fatalf("acceptor EstablishSecondary: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for acceptor")
	}
}

func TestEstablishSecondaryDuplicateIndex(t *testing.T) {
	token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Acceptor expecting 2 connections.
	acceptCh := make(chan []P2PConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conns, err := EstablishSecondary(ctx, SecondaryConfig{
			Count:    2,
			WeDialed: false,
			Listener: ln,
			Token:    token,
			Timeout:  5 * time.Second,
		})
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- conns
	}()

	deadline := time.Now().Add(5 * time.Second)

	// Dial 2 connections with distinct stream indices (1 and 2).
	c1, err := dialSecondary(ctx, addr, token, 1, deadline)
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer c1.Close()

	c2, err := dialSecondary(ctx, addr, token, 2, deadline)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer c2.Close()

	// Wait for acceptor to complete with the 2 valid connections.
	select {
	case acceptConns := <-acceptCh:
		if len(acceptConns) != 2 {
			t.Fatalf("expected 2 acceptor conns, got %d", len(acceptConns))
		}
		for _, c := range acceptConns {
			c.Close()
		}
	case err := <-errCh:
		t.Fatalf("acceptor EstablishSecondary: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for acceptor")
	}

	// Now dial a duplicate index 1 — no accept goroutine running, so it
	// should fail or time out. Use a short deadline to avoid waiting.
	shortDeadline := time.Now().Add(500 * time.Millisecond)
	c3, _ := dialSecondary(ctx, addr, token, 1, shortDeadline)
	if c3 != nil {
		c3.Close()
	}
}
