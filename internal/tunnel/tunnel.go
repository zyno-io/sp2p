// SPDX-License-Identifier: MIT

// Package tunnel adapts an authenticated SP2P byte stream to one local socket
// or to stdio. It deliberately has no knowledge of peer setup or CLI output.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Stream is the portion of stream.Stream required by this package.
// CloseWrite closes only the outbound stream direction.
type Stream interface {
	io.Reader
	io.Writer
	io.Closer
	CloseWrite() error
}

// Endpoint is a TCP or Unix-domain socket endpoint.
type Endpoint struct {
	Network string
	Address string
}

// ParseEndpoint parses an endpoint accepted by --to or --listen. A TCP
// listener with an omitted host is made loopback-only rather than public.
func ParseEndpoint(raw string, listener bool) (Endpoint, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Endpoint{}, fmt.Errorf("parse endpoint: %w", err)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return Endpoint{}, errors.New("endpoint must not contain user, query, or fragment")
	}
	switch u.Scheme {
	case "tcp":
		if u.Path != "" || u.Host == "" {
			return Endpoint{}, errors.New("TCP endpoint must be tcp://HOST:PORT")
		}
		host, port, err := net.SplitHostPort(u.Host)
		if err != nil || port == "" {
			return Endpoint{}, errors.New("TCP endpoint must include a host and port")
		}
		if listener && host == "" {
			host = "127.0.0.1"
		}
		return Endpoint{Network: "tcp", Address: net.JoinHostPort(host, port)}, nil
	case "unix":
		if u.Host != "" || u.Path == "" || !filepath.IsAbs(u.Path) {
			return Endpoint{}, errors.New("Unix endpoint must be an absolute unix:///path")
		}
		if strings.ContainsRune(u.Path, 0) {
			return Endpoint{}, errors.New("Unix endpoint contains NUL")
		}
		return Endpoint{Network: "unix", Address: u.Path}, nil
	default:
		return Endpoint{}, errors.New("endpoint scheme must be tcp or unix")
	}
}

// Dial connects to the fixed target chosen by the serving peer.
func Dial(ctx context.Context, endpoint Endpoint) (net.Conn, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, endpoint.Network, endpoint.Address)
	if err != nil {
		return nil, fmt.Errorf("dial %s://%s: %w", endpoint.Network, endpoint.Address, err)
	}
	return conn, nil
}

// Listen creates a listener for a single connector. Unix socket paths must not
// already exist. The returned cleanup removes only the socket created here.
func Listen(endpoint Endpoint) (net.Listener, func() error, error) {
	if endpoint.Network != "tcp" && endpoint.Network != "unix" {
		return nil, nil, fmt.Errorf("unsupported listener network %q", endpoint.Network)
	}
	if endpoint.Network == "unix" {
		_, err := os.Lstat(endpoint.Address)
		if err == nil {
			return nil, nil, fmt.Errorf("Unix socket path already exists: %s", endpoint.Address)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("inspect Unix socket path: %w", err)
		}
	}

	var ln net.Listener
	var err error
	if endpoint.Network == "unix" {
		ln, err = listenUnix(endpoint.Address)
	} else {
		ln, err = net.Listen(endpoint.Network, endpoint.Address)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("listen %s://%s: %w", endpoint.Network, endpoint.Address, err)
	}
	if endpoint.Network != "unix" {
		return ln, func() error { return ln.Close() }, nil
	}
	// The Go Unix listener normally unlinks on Close. Disable that behavior so
	// cleanup can check that the original socket has not been replaced first.
	unixListener, ok := ln.(*net.UnixListener)
	if !ok {
		_ = ln.Close()
		return nil, nil, errors.New("Unix listener has unexpected type")
	}
	unixListener.SetUnlinkOnClose(false)
	if err := os.Chmod(endpoint.Address, 0o600); err != nil {
		_ = ln.Close()
		return nil, nil, fmt.Errorf("protect Unix socket: %w", err)
	}
	created, err := os.Lstat(endpoint.Address)
	if err != nil {
		_ = ln.Close()
		return nil, nil, fmt.Errorf("inspect created Unix socket: %w", err)
	}
	var once sync.Once
	cleanup := func() error {
		var cleanupErr error
		once.Do(func() {
			if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				cleanupErr = err
			}
			current, err := os.Lstat(endpoint.Address)
			if errors.Is(err, os.ErrNotExist) {
				return
			}
			if err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("inspect Unix socket cleanup: %w", err))
				return
			}
			if !os.SameFile(created, current) {
				cleanupErr = errors.Join(cleanupErr, errors.New("refusing to remove replaced Unix socket"))
				return
			}
			if err := os.Remove(endpoint.Address); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove Unix socket: %w", err))
			}
		})
		return cleanupErr
	}
	return ln, cleanup, nil
}

// Bridge relays bytes bidirectionally and preserves directional EOF. An EOF on
// either input closes only the opposite output direction; the other direction
// remains available until it too completes.
func Bridge(ctx context.Context, stream Stream, local io.ReadWriteCloser) error {
	type result struct{ err error }
	done := make(chan result, 2)
	pump := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		if err == nil {
			err = closeWrite(dst)
		}
		done <- result{err: err}
	}
	go pump(stream, local)
	go pump(local, stream)

	var first error
	completed := 0
	aborted := false
	for completed < 2 {
		select {
		case result := <-done:
			completed++
			if result.err != nil && first == nil {
				first = result.err
				abortStream(stream, result.err)
				aborted = true
				_ = local.Close()
				_ = stream.Close()
			}
		case <-ctx.Done():
			if !aborted {
				abortStream(stream, ctx.Err())
				aborted = true
			}
			_ = local.Close()
			_ = stream.Close()
			for completed < 2 {
				<-done
				completed++
			}
			return ctx.Err()
		}
	}
	return first
}

type closeWriter interface{ CloseWrite() error }

type aborter interface{ Abort(error) error }

// abortStream gives streams that support an authenticated abort control an
// opportunity to report a local bridge failure before their transport is
// closed. The structural Stream interface stays small for socket tests and
// alternate callers.
func abortStream(stream Stream, err error) {
	if abort, ok := stream.(aborter); ok {
		_ = abort.Abort(err)
	}
}

func closeWrite(w io.Writer) error {
	if closer, ok := w.(closeWriter); ok {
		return closer.CloseWrite()
	}
	return nil
}

// Serve dials endpoint and bridges its connection to stream.
func Serve(ctx context.Context, stream Stream, endpoint Endpoint) error {
	conn, err := Dial(ctx, endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()
	return Bridge(ctx, stream, conn)
}

// Connect listens for exactly one local connection, closes the listener before
// relaying it, and then bridges it to stream. onReady receives the actual bound
// endpoint (important when TCP port 0 was requested).
func Connect(ctx context.Context, stream Stream, endpoint Endpoint, onReady func(Endpoint)) error {
	ln, cleanup, err := Listen(endpoint)
	if err != nil {
		return err
	}
	defer cleanup()
	if onReady != nil {
		onReady(Endpoint{Network: endpoint.Network, Address: ln.Addr().String()})
	}
	conn, err := Accept(ctx, ln)
	if err != nil {
		return err
	}
	if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		_ = conn.Close()
		return fmt.Errorf("close one-shot listener: %w", err)
	}
	defer conn.Close()
	return Bridge(ctx, stream, conn)
}

// Accept waits for one local client and returns promptly when ctx is canceled.
// Callers that need a separately bounded connection wait can use this directly.
func Accept(ctx context.Context, ln net.Listener) (net.Conn, error) {
	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- accepted{conn: conn, err: err}
	}()
	select {
	case accepted := <-ch:
		if accepted.err != nil {
			return nil, fmt.Errorf("accept local connection: %w", accepted.err)
		}
		return accepted.conn, nil
	case <-ctx.Done():
		_ = ln.Close()
		accepted := <-ch
		if accepted.conn != nil {
			_ = accepted.conn.Close()
		}
		return nil, ctx.Err()
	}
}
