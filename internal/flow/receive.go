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
	Transport     string    // conn.TransportAuto, conn.TransportTCP, or conn.TransportWebRTC
	Parallel      int       // parallel TCP connections: 0=auto, 1=single, 2-6=force count
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
	// Advertise ParallelTCP unless explicitly disabled (parallel=1).
	// The sender will only echo it back for CLI-to-CLI transfers (after
	// seeing PeerJoined with clientType), so browser receivers will never
	// enter parallel negotiation.
	if err := sigClient.Send(ctx, signal.TypeCrypto, signal.CryptoExchange{
		PublicKey:   kp.Public,
		ParallelTCP: cfg.Parallel != 1,
	}); err != nil {
		return nil, fmt.Errorf("sending public key: %w", err)
	}

	// Wait for sender's public key and Welcome.
	var senderPub []byte
	var senderPreferTCP bool
	var senderParallelTCP bool
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
				senderPreferTCP = ce.PreferTCP
				senderParallelTCP = ce.ParallelTCP
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
		Transport:      cfg.Transport,
		OnStatus:       onStatus,
		OnLog:          onLog,
		DevMode:        cfg.ClientVersion == "dev",
	}
	if senderPreferTCP && cfg.Transport == conn.TransportAuto {
		connCfg.TCPPreferWait = tcpPreferWait
		h.OnVerbose(fmt.Sprintf("sender indicated large transfer — TCP preferred, will wait %v for TCP if WebRTC connects first", tcpPreferWait))
	}
	estResult, err := conn.Establish(attemptCtx, connCfg)
	attemptCancel()
	select {
	case <-peerLeft:
		if estResult != nil {
			estResult.Conn.Close()
			if estResult.TCPResult != nil && estResult.TCPResult.Cleanup != nil {
				estResult.TCPResult.Cleanup()
			}
		}
		h.OnError("Sender disconnected")
		return nil, fmt.Errorf("peer disconnected")
	default:
	}
	if err != nil && turnAvailable && cfg.Transport != conn.TransportTCP {
		// TURN relay requires WebRTC; do not re-enable TCP or keep its preference delay.
		connCfg.Transport = conn.TransportWebRTC
		connCfg.TCPPreferWait = 0
		estResult, err = retryWithRelay(ctx, sigClient, relayCh, deniedCh, peerWantsRelay, cfg.RelayOK, h, connCfg)
	}
	if err != nil {
		return nil, err
	}
	p2pConn := estResult.Conn
	defer p2pConn.Close()
	// Ensure TCP resources (listener, UPnP) are cleaned up.
	if estResult.TCPResult != nil && estResult.TCPResult.Cleanup != nil {
		defer estResult.TCPResult.Cleanup()
	}
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

	// Parallel TCP negotiation: if both sides support it and TCP won.
	// The receiver echoes RTT probes and exchanges counts with the sender.
	var frw transfer.FrameReadWriter = encStream
	var deadliner transfer.DeadlineSetter = p2pConn
	var multiStream *transfer.MultiStream
	canParallel := senderParallelTCP && estResult.TCPResult != nil && cfg.Parallel != 1
	if canParallel {
		h.OnVerbose("negotiating parallel TCP connections")
		sharedSecret, ssErr := crypto.ComputeSharedSecret(kp.Private, senderPub)
		if ssErr != nil {
			h.OnVerbose(fmt.Sprintf("shared secret computation failed: %v — using single connection", ssErr))
		} else {
			pfrw, pd, negErr := negotiateReceiver(ctx, encStream, p2pConn, estResult.TCPResult,
				sharedSecret, seedRaw, cfg.Parallel,
				sessionID, senderPub, kp.Public,
				func(msg string) { h.OnVerbose(msg) })
			if negErr != nil {
				h.OnVerbose(fmt.Sprintf("parallel negotiation failed: %v — using single connection", negErr))
			} else {
				frw = pfrw
				deadliner = pd
				if ms, ok := pfrw.(*transfer.MultiStream); ok {
					multiStream = ms
					h.OnParallelStreams(ms.StreamCount())
					defer ms.Close()
				}
			}
		}
	}

	// Close signaling — no longer needed after P2P + key confirmation.
	h.OnVerbose("closing signaling connection (P2P established)")
	sigClient.Close()

	// Start heartbeat for peer liveness detection over P2P.
	hb := transfer.StartHeartbeat()
	defer hb.Stop()

	// Monitor heartbeat timeout — close P2P to unblock transfer I/O.
	transferDone := make(chan struct{})
	defer close(transferDone)
	go func() {
		select {
		case <-hb.Done():
			if multiStream != nil {
				multiStream.Close() // also closes p2pConn (conns[0])
			} else {
				p2pConn.Close()
			}
		case <-transferDone:
		}
	}()

	// Receive via pipe.
	startTime := time.Now()
	h.OnPhaseChanged(PhaseTransferring)
	pr, pw := io.Pipe()

	receiver := transfer.NewReceiver(frw)
	receiver.SetIdleTimeout(deadliner, 2*time.Minute)
	receiver.SetHeartbeat(hb)

	// Channel to learn metadata before consuming the pipe.
	metaCh := make(chan *transfer.Metadata, 1)
	receiver.OnMetadata = func(meta *transfer.Metadata) {
		metaCh <- meta
		h.OnMetadata(meta)
	}

	type recvResult struct {
		meta *transfer.Metadata
		err  error
	}
	errCh := make(chan recvResult, 1)
	go func() {
		meta, err := receiver.Receive(ctx, pw, func(recv uint64) {
			h.OnProgress(recv)
		})
		pw.CloseWithError(err)
		errCh <- recvResult{meta, err}
	}()

	// Write output.
	outDir := cfg.OutputDir
	if outDir == "" {
		outDir = "."
	}

	// Wait for metadata to decide consumption strategy.
	var meta *transfer.Metadata
	select {
	case meta = <-metaCh:
	case res := <-errCh:
		// Receiver failed before sending metadata.
		if res.err != nil {
			h.OnError(res.err.Error())
			return nil, res.err
		}
		// Unexpected: completed with no error but no metadata either.
		return nil, fmt.Errorf("transfer completed without metadata")
	case <-ctx.Done():
		// Close the pipe so the receiver goroutine unblocks and exits.
		pr.CloseWithError(ctx.Err())
		return nil, ctx.Err()
	}

	var tmpPath string
	var staged *archive.StagedExtraction
	var copyErr error

	if cfg.Writer != nil {
		// Caller-provided writer (e.g., stdout).
		_, copyErr = io.Copy(cfg.Writer, pr)
	} else if meta.IsFolder {
		// Stream tar directly into staging directory — no temp file needed.
		staged, copyErr = archive.Extract(pr, outDir)
	} else {
		// Single file: write to temp file.
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

	result := <-errCh
	// Send cancel if we errored out (best-effort).
	if result.err != nil {
		if ctx.Err() != nil {
			transfer.WriteCancel(frw, transfer.CancelUserAbort)
		} else {
			transfer.WriteCancel(frw, transfer.CancelError)
		}
		if tmpPath != "" {
			os.Remove(tmpPath)
		}
		if staged != nil {
			staged.Rollback()
		}
		h.OnError(result.err.Error())
		return nil, result.err
	}
	if copyErr != nil {
		transfer.WriteCancel(frw, transfer.CancelError)
		if tmpPath != "" {
			os.Remove(tmpPath)
		}
		if staged != nil {
			staged.Rollback()
		}
		return nil, fmt.Errorf("writing output: %w", copyErr)
	}

	totalBytes, _ := receiver.Stats()
	duration := time.Since(startTime)

	// Sanitize filename.
	meta.Name = filepath.Base(meta.Name)
	if meta.Name == "." || meta.Name == "/" || meta.Name == ".." {
		meta.Name = "received-file"
	}

	// Handle file output → final location.
	var savedPath string
	if staged != nil {
		// Folder: hash verified, commit from staging to destination.
		if err := staged.Commit(); err != nil {
			staged.Rollback()
			return nil, fmt.Errorf("extracting folder: %w", err)
		}
		savedPath = filepath.Join(outDir, meta.Name)
	} else if tmpPath != "" {
		sp, err := safeRename(tmpPath, meta.Name, outDir)
		if err != nil {
			os.Remove(tmpPath)
			return nil, fmt.Errorf("renaming output: %w", err)
		}
		savedPath = sp
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
