// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/zyno-io/sp2p/internal/peer"
	"github.com/zyno-io/sp2p/internal/stream"
	"github.com/zyno-io/sp2p/internal/tunnel"
)

func openDuplex(ctx context.Context, cfg StreamConfig, create bool, service, mode, counterpart string, r *streamReporter) (*stream.Stream, func(), error) {
	p, err := peer.Open(ctx, peer.Config{ServerURL: cfg.ServerURL, Code: cfg.Code, Create: create,
		RelayOK: cfg.RelayOK, ClientVersion: cfg.ClientVersion, Transport: cfg.Transport,
		OnCode: r.code, OnPhase: r.phase, OnStatus: r.status, OnLog: r.log, PromptRelay: r.promptRelay})
	if err != nil {
		return nil, nil, err
	}
	s := stream.New(ctx, p.Frames, p)
	if err := s.Handshake(ctx, stream.Config{Service: service, Mode: mode, ExpectedService: service, ExpectedMode: counterpart}); err != nil {
		s.Close()
		p.Close()
		return nil, nil, err
	}
	r.protocol()
	stopProgress := make(chan struct{})
	progressDone := make(chan struct{})
	go func() {
		defer close(progressDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopProgress:
				return
			case <-ticker.C:
				sent, received := s.Stats()
				r.progress(sent, received)
			}
		}
	}()
	var once sync.Once
	cleanup := func() { once.Do(func() { close(stopProgress); <-progressDone; s.Close(); p.Close() }) }
	return s, cleanup, nil
}

func completeDuplex(s *stream.Stream, err error) error {
	finishErr := s.Finish(err)
	if err != nil {
		return err
	}
	if finishErr != nil {
		return finishErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.Wait(ctx)
}

// TunnelConfig selects one local endpoint for a single authenticated session.
type TunnelConfig struct {
	StreamConfig
	Create         bool
	Target, Listen string
	Stdio          bool
	AcceptTimeout  time.Duration
}

func Tunnel(ctx context.Context, cfg TunnelConfig) (err error) {
	role, counterpart := "connect", "serve"
	if cfg.Create {
		role, counterpart = "serve", "connect"
	}
	r := newStreamReporter(ctx, cfg.StreamConfig, "tunnel", role, role)
	var s *stream.Stream
	defer func() {
		var sent, received uint64
		if s != nil {
			sent, received = s.Stats()
		}
		err = r.finish(err, sent, received)
	}()
	if cfg.AcceptTimeout <= 0 {
		return fmt.Errorf("accept-timeout must be positive")
	}
	endpointText := cfg.Listen
	if cfg.Create {
		if cfg.Listen != "" {
			return fmt.Errorf("tunnel serve accepts --to, not --listen")
		}
		endpointText = cfg.Target
	} else if cfg.Target != "" {
		return fmt.Errorf("tunnel connect accepts --listen, not --to")
	}
	if cfg.Stdio == (endpointText != "") {
		return fmt.Errorf("choose exactly one socket endpoint or --stdio")
	}
	var endpoint tunnel.Endpoint
	if !cfg.Stdio {
		endpoint, err = tunnel.ParseEndpoint(endpointText, !cfg.Create)
		if err != nil {
			return err
		}
	}
	var cleanup func()
	s, cleanup, err = openDuplex(ctx, cfg.StreamConfig, cfg.Create, "tunnel", role, counterpart, r)
	if err != nil {
		return err
	}
	defer cleanup()
	ctx = s.Context()
	var local io.ReadWriteCloser
	if !cfg.Create {
		if cfg.Stdio {
			local, err = newStdioEndpoint(os.Stdin, os.Stdout)
			if err != nil {
				return completeDuplex(s, err)
			}
		} else {
			listener, remove, listenErr := tunnel.Listen(endpoint)
			if listenErr != nil {
				return completeDuplex(s, listenErr)
			}
			defer remove()
			r.ready(endpoint.Network + "://" + listener.Addr().String())
			acceptCtx, cancel := context.WithTimeout(ctx, cfg.AcceptTimeout)
			local, err = acceptLocal(acceptCtx, listener)
			cancel()
			listener.Close()
			if err != nil {
				return completeDuplex(s, err)
			}
		}
		defer local.Close()
		if err := s.Ready(); err != nil {
			return err
		}
		if err := s.WaitReady(ctx); err != nil {
			return err
		}
	} else {
		if err := s.WaitReady(ctx); err != nil {
			return err
		}
		if cfg.Stdio {
			local, err = newStdioEndpoint(os.Stdin, os.Stdout)
			if err != nil {
				return completeDuplex(s, err)
			}
		} else {
			dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			local, err = tunnel.Dial(dialCtx, endpoint)
			cancel()
			if err != nil {
				return completeDuplex(s, err)
			}
		}
		defer local.Close()
		if err := s.Ready(); err != nil {
			return err
		}
	}
	r.phase("transferring")
	err = tunnel.Bridge(ctx, s, local)
	return completeDuplex(s, err)
}

// acceptLocal closes and joins the accept on cancellation, including the race
// where a connection was accepted just as its context was canceled.
func acceptLocal(ctx context.Context, listener net.Listener) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() { conn, err := listener.Accept(); ch <- result{conn, err} }()
	select {
	case got := <-ch:
		if ctx.Err() != nil && got.conn != nil {
			got.conn.Close()
			return nil, ctx.Err()
		}
		return got.conn, got.err
	case <-ctx.Done():
		listener.Close()
		got := <-ch
		if got.conn != nil {
			got.conn.Close()
		}
		return nil, ctx.Err()
	}
}
