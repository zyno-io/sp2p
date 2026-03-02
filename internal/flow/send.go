// SPDX-License-Identifier: MIT

package flow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/crypto"
	"github.com/zyno-io/sp2p/internal/semver"
	"github.com/zyno-io/sp2p/internal/signal"
	"github.com/zyno-io/sp2p/internal/transfer"
)

// SendConfig holds configuration for the send flow.
type SendConfig struct {
	ServerURL     string             // WebSocket URL for signaling server
	BaseURL       string             // Public base URL for share links
	Meta          *transfer.Metadata // File metadata (from PrepareInput)
	Reader        io.Reader          // File data source
	RelayOK       bool               // Allow TURN relay without prompting
	ClientVersion string             // Client version for update check
	CompressLevel int                // zstd compression level (0=disabled, 1-9)
}

// Send runs the complete send orchestration.
func Send(ctx context.Context, cfg SendConfig, h Handler) error {
	meta := cfg.Meta

	// Generate encryption seed.
	seedEncoded, seedRaw, err := crypto.GenerateSeed()
	if err != nil {
		return fmt.Errorf("generating seed: %w", err)
	}

	// Connect to signaling server.
	h.OnVerbose(fmt.Sprintf("connecting to signaling server: %s", cfg.ServerURL))
	h.OnPhaseChanged(PhaseConnecting)
	sigClient, err := signal.Connect(ctx, cfg.ServerURL)
	if err != nil {
		h.OnError("Cannot reach signaling server — check your connection")
		return err
	}
	defer sigClient.Close()

	// Hello → Welcome.
	if err := sigClient.Send(ctx, signal.TypeHello, signal.Hello{
		Version:    signal.ProtocolVersion,
		ClientType: signal.ClientTypeCLI,
	}); err != nil {
		return fmt.Errorf("sending hello: %w", err)
	}

	var sessionID string
	var iceServers []signal.ICEServer
	var turnAvailable bool
	var baseURL string
	select {
	case env := <-sigClient.Incoming:
		if env == nil {
			return fmt.Errorf("signaling connection lost")
		}
		if env.Type == signal.TypeError {
			var e signal.Error
			if err := env.ParsePayload(&e); err != nil {
				return fmt.Errorf("server error (malformed payload)")
			}
			return fmt.Errorf("server error: %s", e.Message)
		}
		if env.Type != signal.TypeWelcome {
			return fmt.Errorf("unexpected message: %s", env.Type)
		}
		var welcome signal.Welcome
		if err := env.ParsePayload(&welcome); err != nil {
			return fmt.Errorf("parsing welcome: %w", err)
		}
		sessionID = welcome.SessionID
		iceServers = welcome.ICEServers
		turnAvailable = welcome.TURNAvailable
		// Prefer client-configured URL (from -server or -url flag) over the
		// server's canonical URL, since the client knows the address it
		// actually connected to (e.g., LAN IP vs localhost).
		baseURL = cfg.BaseURL
		if baseURL == "" {
			baseURL = welcome.BaseURL
		}
		if semver.IsNewer(cfg.ClientVersion, welcome.ServerVersion) {
			h.OnUpdateAvailable(cfg.ClientVersion, welcome.ServerVersion)
		}
		h.OnVerbose(fmt.Sprintf("session %s: %d ICE servers, TURN available: %v", sessionID, len(iceServers), turnAvailable))
	case <-ctx.Done():
		return ctx.Err()
	}

	// Encrypt and send file-info preview (best-effort).
	if metaJSON, err := json.Marshal(meta); err == nil {
		if encBlob, err := crypto.EncryptFileInfo(seedRaw, metaJSON); err == nil {
			encoded := base64.StdEncoding.EncodeToString(encBlob)
			sigClient.Send(ctx, signal.TypeFileInfo, signal.FileInfo{Data: encoded})
		}
	}

	// Display transfer code.
	h.OnPhaseChanged(PhaseRegistered)
	code := crypto.FormatCode(sessionID, seedEncoded)
	h.OnTransferCode(code, baseURL)

	// Generate key pair.
	h.OnVerbose("generating X25519 key pair")
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return err
	}

	// Wait for peer, exchange keys.
	var receiverPub []byte
	var peerClientType string
	for receiverPub == nil {
		select {
		case env := <-sigClient.Incoming:
			if env == nil {
				return fmt.Errorf("signaling connection lost")
			}
			switch env.Type {
			case signal.TypePeerJoined:
				var pj signal.PeerJoined
				if err := env.ParsePayload(&pj); err == nil {
					peerClientType = pj.ClientType
				}
				h.OnVerbose(fmt.Sprintf("peer joined (clientType=%s)", peerClientType))
				h.OnPhaseChanged(PhasePeerJoined)
				h.OnPhaseChanged(PhaseKeyExchange)
				if err := sigClient.Send(ctx, signal.TypeCrypto, signal.CryptoExchange{PublicKey: kp.Public}); err != nil {
					return fmt.Errorf("sending public key: %w", err)
				}
			case signal.TypeCrypto:
				var ce signal.CryptoExchange
				if err := env.ParsePayload(&ce); err != nil {
					return fmt.Errorf("parsing crypto: %w", err)
				}
				receiverPub = ce.PublicKey
			case signal.TypePeerLeft:
				h.OnError("Receiver disconnected")
				return fmt.Errorf("peer disconnected")
			case signal.TypeError:
				var e signal.Error
				if err := env.ParsePayload(&e); err != nil {
					return fmt.Errorf("server error (malformed payload)")
				}
				return fmt.Errorf("server error: %s", e.Message)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Derive keys.
	h.OnVerbose("public keys exchanged, deriving session keys")
	keys, err := crypto.DeriveKeys(kp.Private, receiverPub, seedRaw, sessionID, kp.Public, receiverPub)
	if err != nil {
		h.OnError("Encryption handshake failed")
		return err
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
		IsSender:       true,
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
		h.OnError("Receiver disconnected")
		return fmt.Errorf("peer disconnected")
	default:
	}
	if err != nil && turnAvailable {
		p2pConn, err = retryWithRelay(ctx, sigClient, relayCh, deniedCh, peerWantsRelay, cfg.RelayOK, h, connCfg)
	}
	if err != nil {
		return err
	}
	defer p2pConn.Close()
	h.OnPhaseChanged(PhaseP2PConnected)

	// Key confirmation.
	h.OnVerbose("performing key confirmation over P2P channel")
	if err := crypto.SendConfirmation(ctx, p2pConn, keys, kp.Public, receiverPub, true); err != nil {
		h.OnError("Key confirmation failed — wrong code?")
		return err
	}
	h.OnVerbose("key confirmation successful")

	// Encrypted stream.
	h.OnVerbose("establishing encrypted stream")
	encStream, err := crypto.NewEncryptedStream(p2pConn, keys.SenderToReceiver, keys.ReceiverToSender)
	if err != nil {
		return err
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

	// Transfer.
	startTime := time.Now()
	h.OnMetadata(meta)
	h.OnPhaseChanged(PhaseTransferring)
	sender := transfer.NewSender(encStream, meta)
	sender.SetIdleTimeout(p2pConn, 2*time.Minute)
	if cfg.CompressLevel > 0 {
		if err := sender.SetCompression(cfg.CompressLevel); err != nil {
			return fmt.Errorf("setting compression: %w", err)
		}
		h.OnVerbose(fmt.Sprintf("compression enabled (zstd, level %d)", cfg.CompressLevel))
	}
	if err := sender.Send(ctx, cfg.Reader, func(sent uint64) {
		h.OnProgress(sent)
	}); err != nil {
		close(transferDone)
		select {
		case <-sigClient.Done():
			return fmt.Errorf("peer disconnected")
		default:
		}
		h.OnError(err.Error())
		return err
	}
	close(transferDone)

	totalBytes, _ := sender.Stats()

	// Report completion (best-effort).
	sigClient.Send(ctx, signal.TypeTransferComplete, signal.TransferComplete{
		BytesTransferred: totalBytes,
	})

	duration := time.Since(startTime)
	h.OnPhaseChanged(PhaseDone)
	h.OnComplete(totalBytes, duration)
	return nil
}
