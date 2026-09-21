// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/zyno-io/sp2p/internal/rsync"
	"github.com/zyno-io/sp2p/internal/stream"
	"github.com/zyno-io/sp2p/internal/tunnel"
	"golang.org/x/sync/errgroup"
)

const rsyncBridgeEnv = "SP2P_INTERNAL_RSYNC_BRIDGE"

// RsyncConfig keeps SP2P's file roles independent from the rsync process role.
type RsyncConfig struct {
	StreamConfig
	Send, Client      bool
	Directory, Binary string
	Args              []string
	AllowDelete       bool
}

func Rsync(ctx context.Context, cfg RsyncConfig) (err error) {
	role, other := "recv", "send"
	if cfg.Send {
		role, other = "send", "recv"
	}
	mode, opposite := role+"-daemon", other+"-client"
	if cfg.Client {
		mode, opposite = role+"-client", other+"-daemon"
	}
	r := newStreamReporter(ctx, cfg.StreamConfig, "rsync", role, mode)
	var s *stream.Stream
	defer func() {
		var sent, received uint64
		if s != nil {
			sent, received = s.Stats()
		}
		err = r.finish(err, sent, received)
	}()
	binary, _, err := rsync.FindBinary(cfg.Binary)
	if err != nil {
		return err
	}
	direction := rsync.Download
	if cfg.Send {
		direction = rsync.Upload
	}
	if cfg.Client {
		if err := rsync.ValidateClientArgs(cfg.Args, direction); err != nil {
			return err
		}
	} else {
		directory, validateErr := rsync.ValidateDirectory(ctx, cfg.Directory)
		if validateErr != nil {
			return fmt.Errorf("rsync directory: %w", validateErr)
		}
		cfg.Directory = directory
	}
	var cleanup func()
	s, cleanup, err = openDuplex(ctx, cfg.StreamConfig, cfg.Send, "rsync", mode, opposite, r)
	if err != nil {
		return err
	}
	defer cleanup()
	ctx = s.Context()
	if err := s.Ready(); err != nil {
		return err
	}
	if err := s.WaitReady(ctx); err != nil {
		return err
	}
	r.ready(cfg.Directory)
	r.phase("transferring")
	if cfg.Client {
		err = runRsyncClient(ctx, s, binary, cfg.Args, direction, r)
	} else {
		err = rsync.Serve(ctx, s, cfg.Directory, rsync.ServeOptions{Binary: binary, Writable: !cfg.Send,
			AllowDelete: cfg.AllowDelete, Stderr: r.subprocessWriter("stderr", os.Stderr)})
	}
	return completeDuplex(s, err)
}

type rsyncBridgeConfig struct {
	Address string `json:"address"`
	Token   string `json:"token"`
}

// runRsyncClient retains session/event ownership in this process. The helper
// created by rsync can access only this one authenticated local connection.
func runRsyncClient(ctx context.Context, s *stream.Stream, binary string, args []string, direction rsync.Direction, r *streamReporter) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("create local rsync bridge: %w", err)
	}
	defer listener.Close()
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return fmt.Errorf("create local bridge credential: %w", err)
	}
	bridge := rsyncBridgeConfig{Address: listener.Addr().String(), Token: hex.EncodeToString(token[:])}
	encoded, err := json.Marshal(bridge)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate SP2P helper: %w", err)
	}
	client, err := rsync.NewClient(rsync.ClientConfig{Binary: binary, Args: args, Direction: direction,
		ConnectArgs: []string{executable, "__rsync-stdio"},
		ExtraEnv:    []string{rsyncBridgeEnv + "=" + string(encoded)}, Stdin: os.Stdin,
		Stdout: r.subprocessWriter("stdout", os.Stdout), Stderr: r.subprocessWriter("stderr", os.Stderr)})
	if err != nil {
		return err
	}
	g, childCtx := errgroup.WithContext(ctx)
	var childErr error
	g.Go(func() error { childErr = client.Run(childCtx); return childErr })
	g.Go(func() error {
		acceptCtx, cancel := context.WithTimeout(childCtx, 15*time.Second)
		conn, err := acceptRsyncBridge(acceptCtx, listener, token[:])
		cancel()
		if err != nil {
			return fmt.Errorf("accept rsync helper: %w", err)
		}
		defer conn.Close()
		listener.Close()
		return tunnel.Bridge(childCtx, s, conn)
	})
	err = g.Wait()
	if childErr != nil && !errors.Is(childErr, context.Canceled) {
		return childErr
	}
	return err
}

func acceptRsyncBridge(ctx context.Context, listener net.Listener, token []byte) (net.Conn, error) {
	for attempt := 0; attempt < 8; attempt++ {
		conn, err := acceptLocal(ctx, listener)
		if err != nil {
			return nil, err
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		var presented [32]byte
		_, readErr := io.ReadFull(conn, presented[:])
		valid := readErr == nil && subtle.ConstantTimeCompare(token, presented[:]) == 1
		if valid {
			_, err = conn.Write([]byte{1})
			if err == nil {
				err = conn.SetDeadline(time.Time{})
			}
		}
		stopped := stop()
		if valid && err == nil && stopped && ctx.Err() == nil {
			return conn, nil
		}
		conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("local rsync bridge authentication failed")
}

// RsyncStdioHelper is an internal transport program, not a remote-exec command.
// It receives its private local bridge capability only in the child environment.
func RsyncStdioHelper(ctx context.Context) error {
	value := os.Getenv(rsyncBridgeEnv)
	os.Unsetenv(rsyncBridgeEnv)
	var cfg rsyncBridgeConfig
	if value == "" || json.Unmarshal([]byte(value), &cfg) != nil {
		return fmt.Errorf("missing or invalid local bridge configuration")
	}
	host, _, err := net.SplitHostPort(cfg.Address)
	if err != nil || host != "127.0.0.1" {
		return fmt.Errorf("invalid local bridge address")
	}
	token, err := hex.DecodeString(cfg.Token)
	if err != nil || len(token) != 32 {
		return fmt.Errorf("invalid local bridge credential")
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return fmt.Errorf("connect local bridge: %w", err)
	}
	defer raw.Close()
	conn, ok := raw.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("local bridge is not TCP")
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(token); err != nil {
		return fmt.Errorf("authenticate local bridge: %w", err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != 1 {
		return fmt.Errorf("local bridge rejected connection")
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	local, err := newStdioEndpoint(os.Stdin, os.Stdout)
	if err != nil {
		return err
	}
	defer local.Close()
	return tunnel.Bridge(ctx, conn, local)
}
