// SPDX-License-Identifier: MIT

package flow

import (
	"context"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zyno-io/sp2p/internal/archive"
	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/signal"
	"github.com/zyno-io/sp2p/internal/transfer"
)

const (
	// tcpPreferThreshold is the file size above which auto mode prefers TCP
	// over WebRTC. SCTP congestion control in pion limits WebRTC throughput
	// to ~3-15 MB/s, while OS-stack TCP easily does 50-100+ MB/s.
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
// after direct methods have failed. It checks for user consent, coordinates
// the relay retry with the peer via signaling, receives TURN credentials
// from the server, and retries the connection.
// peerWantsRelay is closed if the peer already signaled relay-retry (consumed from relayCh).
func retryWithRelay(ctx context.Context, sigClient *signal.Client, relayCh chan *signal.Envelope, deniedCh chan *signal.Envelope, peerWantsRelay <-chan struct{}, relayOK bool, h Handler, cfg conn.ConnectConfig) (conn.P2PConn, error) {
	h.OnVerbose("direct connection failed, attempting TURN relay fallback")

	// Subscribe to server-delivered TURN credentials.
	// relayCh is pre-subscribed by the caller to avoid losing messages
	// consumed by processSignaling during connection attempts.
	turnCh := sigClient.Subscribe(signal.TypeTURNCredentials)
	defer sigClient.Unsubscribe(signal.TypeTURNCredentials, turnCh)

	// Signal relay-retry BEFORE prompting the user so the peer learns
	// immediately and can show their own relay prompt in parallel,
	// rather than waiting for our user to decide first.
	h.OnVerbose("requesting TURN relay credentials from server")
	if err := sigClient.Send(ctx, signal.TypeRelayRetry, struct{}{}); err != nil {
		return nil, fmt.Errorf("sending relay retry signal: %w", err)
	}

	// Wait for TURN credentials from the server.
	select {
	case env := <-turnCh:
		if env == nil {
			return nil, fmt.Errorf("connection lost waiting for TURN credentials")
		}
		var tc signal.TURNCredentials
		if err := env.ParsePayload(&tc); err != nil {
			return nil, fmt.Errorf("invalid TURN credentials: %w", err)
		}
		if len(tc.ICEServers) == 0 {
			return nil, fmt.Errorf("server returned empty TURN credentials")
		}
		h.OnVerbose(fmt.Sprintf("received %d TURN servers from signaling server", len(tc.ICEServers)))
		for _, s := range tc.ICEServers {
			cfg.TURNServers = append(cfg.TURNServers, conn.TURNServer{
				URLs:       s.URLs,
				Username:   s.Username,
				Credential: s.Credential,
			})
		}
	case <-time.After(30 * time.Second):
		h.OnError("Server did not provide TURN credentials")
		return nil, fmt.Errorf("timeout waiting for TURN credentials")
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Now prompt the user for consent (peer is already being notified).
	if !relayOK && !h.PromptRelay() {
		h.OnVerbose("relay denied: user declined or no TTY available")
		sigClient.Send(ctx, signal.TypeRelayDenied, struct{}{})
		h.OnError("Could not establish direct connection. Use -allow-relay to route encrypted data through a TURN relay.")
		return nil, fmt.Errorf("direct connection failed and relay not allowed")
	}

	// Wait for peer to agree to relay retry.
	// peerWantsRelay is already closed if the peer's relay-retry signal
	// arrived during conn.Establish and cancelled our attempt early.
	select {
	case <-peerWantsRelay:
		h.OnVerbose("peer already requested relay retry")
	case <-relayCh:
		h.OnVerbose("peer agreed to relay retry")
	case <-deniedCh:
		h.OnError("Receiver denied relay connection")
		return nil, fmt.Errorf("peer denied relay")
	case <-time.After(30 * time.Second):
		h.OnError("Peer did not agree to relay retry")
		return nil, fmt.Errorf("peer did not agree to relay retry")
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	time.Sleep(500 * time.Millisecond)
	h.OnConnectionMethodsReset()
	return conn.Establish(ctx, cfg)
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
			os.Remove(tmpPath)
			return destPath, nil
		}
		if !os.IsExist(err) {
			// Hard links not supported (e.g., EPERM on network FS).
			// Only fall back to rename if dest doesn't already exist,
			// to preserve no-overwrite semantics.
			if _, statErr := os.Lstat(destPath); statErr == nil {
				continue // dest exists, try next suffix
			}
			return destPath, os.Rename(tmpPath, destPath)
		}
	}

	return "", fmt.Errorf("could not find available filename for %s", name)
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
