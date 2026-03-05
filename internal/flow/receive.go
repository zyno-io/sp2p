// SPDX-License-Identifier: MIT

package flow

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/zyno-io/sp2p/internal/archive"
	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/crypto"
	"github.com/zyno-io/sp2p/internal/semver"
	"github.com/zyno-io/sp2p/internal/signal"
	"github.com/zyno-io/sp2p/internal/transfer"
)

// ReceiveConfig holds configuration for the receive flow.
type ReceiveConfig struct {
	ServerURL     string    // WebSocket URL for signaling server
	Code          string    // Transfer code "SESSION_ID-SEED"
	OutputDir     string    // Directory to save received files
	Writer        io.Writer // Alternative: write to this instead of OutputDir (e.g., stdout)
	RelayOK       bool      // Allow TURN relay without prompting
	ClientVersion string    // Client version for update check
}

// ReceiveResult holds the outcome of a receive flow.
type ReceiveResult struct {
	Metadata   *transfer.Metadata
	TotalBytes uint64
	Duration   time.Duration
	SavedPath  string // Path to saved file (empty if Writer was used)
}

// Receive runs the complete receive orchestration.
func Receive(ctx context.Context, cfg ReceiveConfig, h Handler) (*ReceiveResult, error) {
	// Parse transfer code.
	h.OnVerbose(fmt.Sprintf("parsing transfer code: %s", cfg.Code))
	sessionID, seedEncoded, err := crypto.ParseCode(cfg.Code)
	if err != nil {
		h.OnError("Invalid transfer code — check that you copied it correctly")
		return nil, err
	}
	seedRaw, err := crypto.DecodeSeed(seedEncoded)
	if err != nil {
		h.OnError("Invalid transfer code — check that you copied it correctly")
		return nil, err
	}

	// Connect to signaling server.
	h.OnVerbose(fmt.Sprintf("connecting to signaling server: %s", cfg.ServerURL))
	h.OnPhaseChanged(PhaseConnecting)
	sigClient, err := signal.Connect(ctx, cfg.ServerURL)
	if err != nil {
		h.OnError("Cannot reach signaling server — check your connection")
		return nil, err
	}
	defer sigClient.Close()

	// Join session.
	if err := sigClient.Send(ctx, signal.TypeJoin, signal.Join{
		Version:    signal.ProtocolVersion,
		SessionID:  sessionID,
		ClientType: signal.ClientTypeCLI,
		ClientOS:   runtime.GOOS,
		ClientArch: runtime.GOARCH,
	}); err != nil {
		return nil, fmt.Errorf("sending join: %w", err)
	}

	h.OnVerbose(fmt.Sprintf("joined session %s", sessionID))

	// Generate key pair and send immediately.
	h.OnVerbose("generating X25519 key pair")
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	h.OnPhaseChanged(PhaseKeyExchange)
	if err := sigClient.Send(ctx, signal.TypeCrypto, signal.CryptoExchange{PublicKey: kp.Public}); err != nil {
		return nil, fmt.Errorf("sending public key: %w", err)
	}

	// Wait for sender's public key and Welcome.
	var senderPub []byte
	var iceServers []signal.ICEServer
	var turnAvailable bool
	var peerClientType string
	for senderPub == nil {
		select {
		case env := <-sigClient.Incoming:
			if env == nil {
				return nil, fmt.Errorf("signaling connection lost")
			}
			switch env.Type {
			case signal.TypeWelcome:
				var w signal.Welcome
				if err := env.ParsePayload(&w); err == nil {
					iceServers = w.ICEServers
					turnAvailable = w.TURNAvailable
					peerClientType = w.PeerClientType
					if semver.IsNewer(cfg.ClientVersion, w.ServerVersion) {
						h.OnUpdateAvailable(cfg.ClientVersion, w.ServerVersion)
					}
					h.OnVerbose(fmt.Sprintf("received welcome: %d ICE servers, TURN available: %v, peer: %s", len(iceServers), turnAvailable, peerClientType))
				}
			case signal.TypeCrypto:
				var ce signal.CryptoExchange
				if err := env.ParsePayload(&ce); err != nil {
					return nil, fmt.Errorf("parsing crypto: %w", err)
				}
				senderPub = ce.PublicKey
			case signal.TypePeerLeft:
				h.OnError("Sender disconnected")
				return nil, fmt.Errorf("peer disconnected")
			case signal.TypeError:
				var e signal.Error
				if err := env.ParsePayload(&e); err != nil {
					h.OnError("Server returned an invalid error")
					return nil, fmt.Errorf("server error (malformed payload)")
				}
				switch e.Code {
				case signal.ErrCodeSessionNotFound:
					h.OnError("Transfer session not found — the link may have expired or is invalid")
				case signal.ErrCodeSessionFull:
					h.OnError("Someone has already connected to this transfer session")
				default:
					h.OnError(e.Message)
				}
				return nil, fmt.Errorf("server error: %s", e.Message)
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Derive keys.
	h.OnVerbose("public keys exchanged, deriving session keys")
	keys, err := crypto.DeriveKeys(kp.Private, senderPub, seedRaw, sessionID, senderPub, kp.Public)
	if err != nil {
		h.OnError("Encryption handshake failed")
		return nil, err
	}
	h.OnVerifyCode(keys.VerifyCode)

	// Establish P2P connection.
	h.OnPhaseChanged(PhaseP2PConnecting)
	stunServers, _ := iceServersToConn(iceServers)
	h.OnVerbose(fmt.Sprintf("starting P2P connection with %d STUN servers", len(stunServers)))
	onStatus := func(s conn.MethodStatus) { h.OnConnectionStatus(s) }
	onLog := func(msg string) { h.OnVerbose(msg) }

	// Pre-subscribe to relay-retry, relay-denied, and peer-left before
	// conn.Establish so these signals aren't consumed by processSignaling.
	relayCh := sigClient.Subscribe(signal.TypeRelayRetry)
	defer sigClient.Unsubscribe(signal.TypeRelayRetry, relayCh)
	deniedCh := sigClient.Subscribe(signal.TypeRelayDenied)
	defer sigClient.Unsubscribe(signal.TypeRelayDenied, deniedCh)
	peerLeftCh := sigClient.Subscribe(signal.TypePeerLeft)
	defer sigClient.Unsubscribe(signal.TypePeerLeft, peerLeftCh)

	// Cancel connection attempt early if peer signals relay-retry or disconnects,
	// so both sides reach the relay prompt around the same time.
	attemptCtx, attemptCancel := context.WithCancel(ctx)
	peerWantsRelay := make(chan struct{})
	peerLeft := make(chan struct{})
	go func() {
		select {
		case <-relayCh:
			close(peerWantsRelay)
			attemptCancel()
		case <-peerLeftCh:
			close(peerLeft)
			attemptCancel()
		case <-attemptCtx.Done():
		}
	}()

	connCfg := conn.ConnectConfig{
		SignalClient:   sigClient,
		IsSender:       false,
		STUNServers:    stunServers,
		PeerClientType: peerClientType,
		OnStatus:       onStatus,
		OnLog:          onLog,
		DevMode:        cfg.ClientVersion == "dev",
	}
	p2pConn, err := conn.Establish(attemptCtx, connCfg)
	attemptCancel()
	select {
	case <-peerLeft:
		if p2pConn != nil {
			p2pConn.Close()
		}
		h.OnError("Sender disconnected")
		return nil, fmt.Errorf("peer disconnected")
	default:
	}
	if err != nil && turnAvailable {
		p2pConn, err = retryWithRelay(ctx, sigClient, relayCh, deniedCh, peerWantsRelay, cfg.RelayOK, h, connCfg)
	}
	if err != nil {
		return nil, err
	}
	defer p2pConn.Close()
	h.OnPhaseChanged(PhaseP2PConnected)

	// Key confirmation.
	h.OnVerbose("performing key confirmation over P2P channel")
	if err := crypto.SendConfirmation(ctx, p2pConn, keys, senderPub, kp.Public, false); err != nil {
		h.OnError("Key confirmation failed — wrong code?")
		return nil, err
	}
	h.OnVerbose("key confirmation successful")

	// Encrypted stream (receiver writes with k_r2s, reads with k_s2r).
	h.OnVerbose("establishing encrypted stream")
	encStream, err := crypto.NewEncryptedStream(p2pConn, keys.ReceiverToSender, keys.SenderToReceiver)
	if err != nil {
		return nil, err
	}

	// Monitor signaling connection — if the peer disconnects unexpectedly,
	// close the P2P connection to unblock any in-progress Read/Write.
	// A short grace period avoids racing with normal transfer completion
	// (peer may close signaling right after sending the final ack).
	transferDone := make(chan struct{})
	go func() {
		select {
		case <-sigClient.Done():
			select {
			case <-transferDone:
			case <-time.After(2 * time.Second):
				p2pConn.Close()
			}
		case <-transferDone:
		case <-ctx.Done():
		}
	}()

	// Receive via pipe.
	startTime := time.Now()
	h.OnPhaseChanged(PhaseTransferring)
	pr, pw := io.Pipe()

	receiver := transfer.NewReceiver(encStream)
	receiver.SetIdleTimeout(p2pConn, 2*time.Minute)
	receiver.OnMetadata = func(meta *transfer.Metadata) {
		h.OnMetadata(meta)
	}

	type recvResult struct {
		meta *transfer.Metadata
		err  error
	}
	recvCh := make(chan recvResult, 1)
	go func() {
		meta, err := receiver.Receive(ctx, pw, func(recv uint64) {
			h.OnProgress(recv)
		})
		pw.CloseWithError(err)
		recvCh <- recvResult{meta, err}
	}()

	// Write output.
	outDir := cfg.OutputDir
	if outDir == "" {
		outDir = "."
	}

	var tmpPath string
	var copyErr error
	if cfg.Writer != nil {
		// Caller-provided writer (e.g., stdout).
		_, copyErr = io.Copy(cfg.Writer, pr)
	} else {
		// Write to temp file.
		tmpFile, ferr := os.CreateTemp(outDir, "sp2p-recv-*")
		if ferr != nil {
			pr.CloseWithError(ferr)
			return nil, fmt.Errorf("creating temp file: %w", ferr)
		}
		tmpPath = tmpFile.Name()
		_, copyErr = io.Copy(tmpFile, pr)
		tmpFile.Close()
		if copyErr != nil {
			os.Remove(tmpPath)
		}
	}

	if copyErr != nil {
		pr.CloseWithError(copyErr)
	} else {
		pr.Close()
	}

	result := <-recvCh
	close(transferDone)
	if result.err != nil {
		if tmpPath != "" {
			os.Remove(tmpPath)
		}
		select {
		case <-sigClient.Done():
			return nil, fmt.Errorf("peer disconnected")
		default:
		}
		h.OnError(result.err.Error())
		return nil, result.err
	}
	if copyErr != nil {
		if tmpPath != "" {
			os.Remove(tmpPath)
		}
		return nil, fmt.Errorf("writing output: %w", copyErr)
	}

	meta := result.meta
	totalBytes, _ := receiver.Stats()
	duration := time.Since(startTime)

	// Sanitize filename.
	meta.Name = filepath.Base(meta.Name)
	if meta.Name == "." || meta.Name == "/" || meta.Name == ".." {
		meta.Name = "received-file"
	}

	// Handle file output (temp file → final location).
	var savedPath string
	if tmpPath != "" {
		if meta.IsFolder {
			f, err := os.Open(tmpPath)
			if err != nil {
				os.Remove(tmpPath)
				return nil, fmt.Errorf("opening temp file for untar: %w", err)
			}
			if err := archive.Untar(f, outDir); err != nil {
				f.Close()
				os.Remove(tmpPath)
				return nil, fmt.Errorf("extracting folder: %w", err)
			}
			f.Close()
			os.Remove(tmpPath)
			savedPath = filepath.Join(outDir, meta.Name)
		} else {
			sp, err := safeRename(tmpPath, meta.Name, outDir)
			if err != nil {
				os.Remove(tmpPath)
				return nil, fmt.Errorf("renaming output: %w", err)
			}
			savedPath = sp
		}
	}

	h.OnPhaseChanged(PhaseDone)
	h.OnComplete(totalBytes, duration)

	return &ReceiveResult{
		Metadata:   meta,
		TotalBytes: totalBytes,
		Duration:   duration,
		SavedPath:  savedPath,
	}, nil
}
