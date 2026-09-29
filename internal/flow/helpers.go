// SPDX-License-Identifier: MIT

package flow

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zyno-io/sp2p/internal/archive"
	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/fileutil"
	"github.com/zyno-io/sp2p/internal/signal"
	"github.com/zyno-io/sp2p/internal/transfer"
)

const (
	// tcpPreferThreshold is the file size above which auto mode prefers TCP
	// over WebRTC. Kernel TCP and optional parallel streams can improve bulk
	// throughput; actual speeds depend on the path, latency, loss, and sinks.
	tcpPreferThreshold = 64 * 1024 * 1024 // 64 MiB

	// tcpPreferWait is how long to hold a WebRTC connection to let TCP
	// (via UPnP or direct) catch up before accepting WebRTC.
	tcpPreferWait = 6 * time.Second
)

// iceServersToConn converts signal ICE servers to conn STUN/TURN server lists.
// If the server provides no ICE servers, falls back to default STUN servers.
func iceServersToConn(servers []signal.ICEServer) ([]string, []conn.TURNServer) {
	var stun []string
	var turn []conn.TURNServer
	for _, s := range servers {
		hasTURN := false
		for _, u := range s.URLs {
			if strings.HasPrefix(u, "turn:") || strings.HasPrefix(u, "turns:") {
				hasTURN = true
				break
			}
		}
		if hasTURN {
			turn = append(turn, conn.TURNServer{
				URLs:       s.URLs,
				Username:   s.Username,
				Credential: s.Credential,
			})
		} else {
			stun = append(stun, s.URLs...)
		}
	}
	if len(stun) == 0 {
		stun = conn.DefaultSTUNServers()
	}
	return stun, turn
}

// retryWithRelay attempts to establish a connection using TURN relay servers
// after direct methods have failed. It is a thin wrapper around
// conn.RetryWithRelay: it builds a RelayOptions from h, then maps the
// returned error to the right user-facing text (naming the peer's role) and
// reports it via h.OnError. It never calls h.OnError for a context
// cancellation — that's the caller's (or the user's Ctrl+C's) business, not
// a relay-consent outcome.
func retryWithRelay(ctx context.Context, sigClient *signal.Client, w *conn.RelayWatch, relayOK bool, h Handler, cfg conn.ConnectConfig, peerRole string) (*conn.EstablishResult, error) {
	h.OnVerbose("direct connection failed, attempting TURN relay fallback")

	result, err := conn.RetryWithRelay(ctx, sigClient, w, cfg, conn.RelayOptions{
		RelayOK: relayOK,
		Prompt:  buildRelayPrompt(h),
		OnLog:   h.OnVerbose,
		OnReset: h.OnConnectionMethodsReset,
	})
	if err == nil {
		return result, nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}

	var declined *conn.PeerDeclinedRelayError
	switch {
	case errors.As(err, &declined):
		if declined.Reason == signal.RelayDeniedUnavailable {
			h.OnError(fmt.Sprintf("Direct connection failed and the %s could not be asked to allow the relay. They can rerun sp2p with -allow-relay.", peerRole))
		} else {
			h.OnError(fmt.Sprintf("Direct connection failed and the %s declined the relay.", peerRole))
		}
	case errors.Is(err, conn.ErrPeerLeft):
		h.OnError("Peer disconnected")
	case errors.Is(err, conn.ErrPeerRelayTimeout):
		h.OnError(fmt.Sprintf("Timed out waiting for the %s to allow the relay.", peerRole))
	case errors.Is(err, conn.ErrSignalingLost):
		h.OnError("Signaling server disconnected")
	case errors.Is(err, conn.ErrRelayNotAllowed):
		h.OnError("Could not establish direct connection. Use -allow-relay to route encrypted data through a TURN relay.")
	}
	return nil, err
}

// buildRelayPrompt adapts h's relay prompt to conn.RelayOptions.Prompt,
// preferring the cancellable, richer RelayPromptHandler when h implements
// it and falling back to the plain Handler.PromptRelay otherwise.
func buildRelayPrompt(h Handler) func(context.Context) conn.RelayAnswer {
	if rph, ok := h.(RelayPromptHandler); ok {
		return rph.PromptRelayAnswer
	}
	return func(context.Context) conn.RelayAnswer {
		if h.PromptRelay() {
			return conn.RelayAllow
		}
		return conn.RelayDeny
	}
}

// safeRename moves a temp file to a destination, avoiding overwrites.
// Uses os.Link for atomic creation (fails if dest exists) to prevent TOCTOU races.
func safeRename(tmpPath, name, dir string) (string, error) {
	ext := filepath.Ext(name)
	base := name[:len(name)-len(ext)]

	for i := 0; i <= 1000; i++ {
		destName := name
		if i > 0 {
			destName = fmt.Sprintf("%s (%d)%s", base, i, ext)
		}
		destPath := filepath.Join(dir, destName)

		// os.Link is atomic: it fails if destPath already exists,
		// preventing TOCTOU races between existence check and creation.
		err := os.Link(tmpPath, destPath)
		if err == nil {
			if err := os.Remove(tmpPath); err != nil {
				return destPath, fmt.Errorf("published %s but could not remove staging %s: %w", destPath, tmpPath, err)
			}
			return destPath, nil
		}
		if !os.IsExist(err) {
			err = fileutil.RenameNoReplace(tmpPath, destPath)
			if os.IsExist(err) {
				continue
			}
			if err != nil {
				return "", fmt.Errorf("publishing output without replacement: %w", err)
			}
			return destPath, nil
		}
	}

	return "", fmt.Errorf("could not find available filename for %s", name)
}

// logVerbose calls f with a formatted message if f is non-nil.
func logVerbose(f func(string), msg string, args ...any) {
	if f != nil {
		f(fmt.Sprintf(msg, args...))
	}
}

// PrepareInput prepares the file/folder/stdin for sending.
func PrepareInput(paths []string, name string) (*transfer.Metadata, io.Reader, func(), error) {
	noop := func() {}

	if len(paths) == 1 && paths[0] == "-" {
		n := "stdin"
		if name != "" {
			n = name
		}
		return &transfer.Metadata{
			Name:       n,
			StreamMode: true,
		}, os.Stdin, noop, nil
	}

	// Multiple paths: tar them together as a folder.
	if len(paths) > 1 {
		tarInfo, err := archive.ComputeTarInfo(paths)
		if err != nil {
			return nil, nil, noop, fmt.Errorf("scanning files: %w", err)
		}
		tarReader, err := archive.NewTarReaderFromPaths(paths)
		if err != nil {
			return nil, nil, noop, fmt.Errorf("preparing files: %w", err)
		}
		return &transfer.Metadata{
			Name:      fmt.Sprintf("%d-files", len(paths)),
			Size:      tarInfo.Size,
			IsFolder:  true,
			FileCount: tarInfo.FileCount,
		}, tarReader, func() { tarReader.Close() }, nil
	}

	path := paths[0]

	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, noop, fmt.Errorf("cannot access %s: %w", path, err)
	}

	if info.IsDir() {
		tarInfo, err := archive.ComputeTarInfo([]string{path})
		if err != nil {
			return nil, nil, noop, fmt.Errorf("scanning folder: %w", err)
		}
		tarReader, err := archive.NewTarReader(path)
		if err != nil {
			return nil, nil, noop, fmt.Errorf("preparing folder: %w", err)
		}
		return &transfer.Metadata{
			Name:      filepath.Base(path),
			Size:      tarInfo.Size,
			IsFolder:  true,
			FileCount: tarInfo.FileCount,
		}, tarReader, func() { tarReader.Close() }, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, nil, noop, err
	}

	mimeType := mime.TypeByExtension(filepath.Ext(path))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	return &transfer.Metadata{
		Name: filepath.Base(path),
		Size: uint64(info.Size()),
		Type: mimeType,
	}, f, func() { f.Close() }, nil
}
