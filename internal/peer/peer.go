// SPDX-License-Identifier: MIT

// Package peer establishes an authenticated v3 peer connection for stream
// applications.  It deliberately has no file-transfer concepts: callers add
// their own encrypted application protocol on Result.Frames.
package peer

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/crypto"
	"github.com/zyno-io/sp2p/internal/signal"
)

// Config describes one side of an authenticated stream session.  Create
// creates and displays a capability; otherwise Code joins an existing one.
// PromptRelay must be safe without a terminal.  A nil callback means relay is
// denied unless RelayOK is set.
type Config struct {
	ServerURL     string
	Code          string
	Create        bool
	RelayOK       bool
	ClientVersion string
	Transport     string
	OnCode        func(string)
	OnPhase       func(string)
	OnStatus      func(conn.MethodStatus)
	OnLog         func(string)
	PromptRelay   func(context.Context) bool
}

// Result owns the established physical connection and its encrypted frame
// layer.  Close is idempotent and releases the selected transport resources.
type Result struct {
	Conn     conn.P2PConn
	Frames   *crypto.EncryptedStream
	Protocol int

	closeOnce sync.Once
	closeFn   func()
}

// Close releases the P2P connection and all resources retained by the chosen
// connection method.
func (r *Result) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(r.closeFn)
	return nil
}

// SetDeadline forwards to the selected physical transport. It lets the stream
// handshake bound a blocked TCP/WebRTC read even when Result itself is passed
// as the stream's lifecycle closer.
func (r *Result) SetDeadline(t time.Time) error {
	if r == nil || r.Conn == nil {
		return io.ErrClosedPipe
	}
	return r.Conn.SetDeadline(t)
}

// Drain waits for a WebRTC DataChannel's buffered bytes to be acknowledged by
// SCTP. TCP has kernel FIN semantics and does not expose a comparable buffer,
// so it returns immediately there. Stream uses this only for graceful terminal
// controls before cleanup closes the physical connection.
func (r *Result) Drain(ctx context.Context) error {
	if r == nil || r.Conn == nil {
		return io.ErrClosedPipe
	}
	buffered, ok := r.Conn.(interface{ BufferedAmount() uint64 })
	if !ok {
		return nil
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for buffered.BufferedAmount() != 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	return nil
}

// Open creates or joins a session, verifies the candidate and transcript, and
// returns only an authenticated v3 encrypted transport.  In particular it
// never downgrades a stream session to the legacy file protocol.
func Open(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("signaling server URL is required")
	}
	if !cfg.Create && cfg.Code == "" {
		return nil, fmt.Errorf("stream code is required when joining")
	}
	logf := func(format string, args ...any) {
		if cfg.OnLog != nil {
			cfg.OnLog(fmt.Sprintf(format, args...))
		}
	}
	phase := func(name string) {
		if cfg.OnPhase != nil {
			cfg.OnPhase(name)
		}
	}

	var sessionID string
	var seedEncoded string
	var seedRaw []byte
	var err error
	if cfg.Create {
		seedEncoded, seedRaw, err = crypto.GenerateSeed()
		if err != nil {
			return nil, fmt.Errorf("generating stream seed: %w", err)
		}
	} else {
		sessionID, seedEncoded, err = crypto.ParseCode(cfg.Code)
		if err != nil {
			return nil, fmt.Errorf("parsing stream code: %w", err)
		}
		seedRaw, err = crypto.DecodeSeed(seedEncoded)
		if err != nil {
			return nil, fmt.Errorf("decoding stream seed: %w", err)
		}
	}

	phase("connecting")
	client, err := signal.Connect(ctx, cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("connecting to signaling server: %w", err)
	}
	defer client.Close()

	var welcome signal.Welcome
	if cfg.Create {
		if err := client.Send(ctx, signal.TypeHello, signal.Hello{
			Version: signal.ProtocolVersion, ClientType: signal.ClientTypeCLI,
			ClientOS: runtime.GOOS, ClientArch: runtime.GOARCH,
		}); err != nil {
			return nil, fmt.Errorf("sending hello: %w", err)
		}
		welcome, err = waitWelcome(ctx, client)
		if err != nil {
			return nil, err
		}
		sessionID = welcome.SessionID
		code := crypto.FormatCode(sessionID, seedEncoded)
		phase("registered")
		if cfg.OnCode != nil {
			cfg.OnCode(code)
		}
	} else {
		if err := client.Send(ctx, signal.TypeJoin, signal.Join{
			Version: signal.ProtocolVersion, SessionID: sessionID, ClientType: signal.ClientTypeCLI,
			ClientOS: runtime.GOOS, ClientArch: runtime.GOARCH,
		}); err != nil {
			return nil, fmt.Errorf("joining session: %w", err)
		}
		welcome, err = waitWelcome(ctx, client)
		if err != nil {
			return nil, err
		}
	}

	kp, err := crypto.GenerateTransferKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generating key pair: %w", err)
	}
	phase("key_exchange")

	var peerPub []byte
	var peerType string
	if cfg.Create {
		peerPub, peerType, err = creatorExchange(ctx, client, kp.Public)
	} else {
		peerPub, peerType, err = joinerExchange(ctx, client, kp.Public, welcome.PeerClientType)
	}
	if err != nil {
		return nil, err
	}
	if cfg.Create {
		phase("peer_joined")
	}

	var senderPub, receiverPub []byte
	if cfg.Create {
		senderPub, receiverPub = kp.Public, peerPub
	} else {
		senderPub, receiverPub = peerPub, kp.Public
	}
	protocol, err := crypto.TransferProtocol(senderPub, receiverPub)
	if err != nil {
		return nil, err
	}
	if protocol != 3 {
		return nil, fmt.Errorf("stream peer does not support authenticated protocol v3")
	}
	keys, err := crypto.DeriveKeys(kp.Private, peerPub, seedRaw, sessionID, senderPub, receiverPub)
	if err != nil {
		return nil, fmt.Errorf("deriving stream keys: %w", err)
	}

	// TURN credentials, even if present in Welcome, are never used for the
	// initial direct race. Relay must remain behind the explicit authenticated
	// retry and local-consent path below.
	stun, _ := iceServers(welcome.ICEServers)
	phase("p2p_connecting")
	connCfg := conn.ConnectConfig{
		SignalClient: client, IsSender: cfg.Create, STUNServers: stun,
		PeerClientType: peerType, Transport: cfg.Transport,
		DevMode: cfg.ClientVersion == "dev", OnStatus: cfg.OnStatus, OnLog: cfg.OnLog,
		Authenticate: func(attempt context.Context, candidate conn.P2PConn) (func(context.Context) error, error) {
			return crypto.AuthenticateCandidate(attempt, candidate, keys, senderPub, receiverPub, cfg.Create)
		},
	}
	result, err := establish(ctx, client, cfg, connCfg, welcome.TURNAvailable, logf)
	if err != nil {
		return nil, err
	}
	cleanup := func() {
		result.Conn.Close()
		if result.TCPResult != nil && result.TCPResult.Cleanup != nil {
			result.TCPResult.Cleanup()
		}
	}
	if err := crypto.SendConfirmation(ctx, result.Conn, keys, senderPub, receiverPub, cfg.Create); err != nil {
		cleanup()
		return nil, fmt.Errorf("confirming stream keys: %w", err)
	}
	var writeKey, readKey []byte
	if cfg.Create {
		writeKey, readKey = keys.SenderToReceiver, keys.ReceiverToSender
	} else {
		writeKey, readKey = keys.ReceiverToSender, keys.SenderToReceiver
	}
	frames, err := crypto.NewEncryptedStream(result.Conn, writeKey, readKey)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("creating encrypted stream: %w", err)
	}
	phase("p2p_connected")
	return &Result{Conn: result.Conn, Frames: frames, Protocol: protocol, closeFn: cleanup}, nil
}

func waitWelcome(ctx context.Context, client *signal.Client) (signal.Welcome, error) {
	select {
	case env := <-client.Incoming:
		if env == nil {
			return signal.Welcome{}, fmt.Errorf("signaling connection lost")
		}
		if env.Type == signal.TypeError {
			return signal.Welcome{}, signalError(env)
		}
		if env.Type != signal.TypeWelcome {
			return signal.Welcome{}, fmt.Errorf("unexpected signaling message: %s", env.Type)
		}
		var welcome signal.Welcome
		if err := env.ParsePayload(&welcome); err != nil {
			return signal.Welcome{}, fmt.Errorf("parsing welcome: %w", err)
		}
		return welcome, nil
	case <-ctx.Done():
		return signal.Welcome{}, ctx.Err()
	}
}

func creatorExchange(ctx context.Context, client *signal.Client, public []byte) ([]byte, string, error) {
	var peerType string
	for {
		select {
		case env := <-client.Incoming:
			if env == nil {
				return nil, "", fmt.Errorf("signaling connection lost")
			}
			switch env.Type {
			case signal.TypePeerJoined:
				var joined signal.PeerJoined
				if err := env.ParsePayload(&joined); err != nil {
					return nil, "", fmt.Errorf("parsing peer join: %w", err)
				}
				if err := client.Send(ctx, signal.TypeCrypto, signal.CryptoExchange{PublicKey: public}); err != nil {
					return nil, "", fmt.Errorf("sending public key: %w", err)
				}
				// Wait for the corresponding crypto exchange below.
				peerType = joined.ClientType
			case signal.TypeCrypto:
				var exchange signal.CryptoExchange
				if err := env.ParsePayload(&exchange); err != nil {
					return nil, "", fmt.Errorf("parsing peer key: %w", err)
				}
				if len(exchange.PublicKey) != crypto.KeySize {
					return nil, "", fmt.Errorf("invalid peer public key")
				}
				return exchange.PublicKey, peerType, nil
			case signal.TypePeerLeft:
				return nil, "", fmt.Errorf("peer disconnected")
			case signal.TypeError:
				return nil, "", signalError(env)
			}
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
}

func joinerExchange(ctx context.Context, client *signal.Client, public []byte, peerType string) ([]byte, string, error) {
	if err := client.Send(ctx, signal.TypeCrypto, signal.CryptoExchange{PublicKey: public}); err != nil {
		return nil, "", fmt.Errorf("sending public key: %w", err)
	}
	for {
		select {
		case env := <-client.Incoming:
			if env == nil {
				return nil, "", fmt.Errorf("signaling connection lost")
			}
			switch env.Type {
			case signal.TypeCrypto:
				var exchange signal.CryptoExchange
				if err := env.ParsePayload(&exchange); err != nil {
					return nil, "", fmt.Errorf("parsing peer key: %w", err)
				}
				if len(exchange.PublicKey) != crypto.KeySize {
					return nil, "", fmt.Errorf("invalid peer public key")
				}
				return exchange.PublicKey, peerType, nil
			case signal.TypePeerLeft:
				return nil, "", fmt.Errorf("peer disconnected")
			case signal.TypeError:
				return nil, "", signalError(env)
			}
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
}

func establish(ctx context.Context, client *signal.Client, cfg Config, connCfg conn.ConnectConfig, turnAvailable bool, logf func(string, ...any)) (*conn.EstablishResult, error) {
	peerLeft := client.Subscribe(signal.TypePeerLeft)
	defer client.Unsubscribe(signal.TypePeerLeft, peerLeft)
	relay := client.Subscribe(signal.TypeRelayRetry)
	defer client.Unsubscribe(signal.TypeRelayRetry, relay)
	denied := client.Subscribe(signal.TypeRelayDenied)
	defer client.Unsubscribe(signal.TypeRelayDenied, denied)

	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	monitorCtx, stopMonitor := context.WithCancel(ctx)
	peerRequestedRelay := make(chan struct{})
	peerDisconnected := make(chan struct{})
	peerDeniedRelay := make(chan struct{})
	monitorDone := make(chan struct{})
	defer func() { stopMonitor(); <-monitorDone }()
	go func() {
		defer close(monitorDone)
		for {
			select {
			case <-relay:
				select {
				case <-peerRequestedRelay:
				default:
					close(peerRequestedRelay)
				}
				cancel()
			case <-peerLeft:
				select {
				case <-peerDisconnected:
				default:
					close(peerDisconnected)
				}
				cancel()
			case <-denied:
				select {
				case <-peerDeniedRelay:
				default:
					close(peerDeniedRelay)
				}
			case <-client.Done():
				select {
				case <-peerDisconnected:
				default:
					close(peerDisconnected)
				}
				cancel()
				return
			case <-monitorCtx.Done():
				return
			}
		}
	}()
	result, err := conn.Establish(attemptCtx, connCfg)
	if err == nil {
		select {
		case <-peerDisconnected:
			closeEstablishResult(result)
			return nil, fmt.Errorf("peer disconnected")
		default:
			return result, nil
		}
	}
	select {
	case <-peerDisconnected:
		return nil, fmt.Errorf("peer disconnected")
	default:
	}
	if !turnAvailable || cfg.Transport == conn.TransportTCP {
		return nil, err
	}
	logf("direct connection failed; requesting TURN relay")
	// Subscribe before requesting credentials: a local/fast signaling server
	// may reply before Send returns.
	turnCh := client.Subscribe(signal.TypeTURNCredentials)
	defer client.Unsubscribe(signal.TypeTURNCredentials, turnCh)
	if sendErr := client.Send(ctx, signal.TypeRelayRetry, struct{}{}); sendErr != nil {
		return nil, fmt.Errorf("requesting relay: %w", sendErr)
	}
	select {
	case env := <-turnCh:
		if env == nil {
			return nil, fmt.Errorf("signaling connection lost waiting for relay credentials")
		}
		var credentials signal.TURNCredentials
		if err := env.ParsePayload(&credentials); err != nil {
			return nil, fmt.Errorf("parsing relay credentials: %w", err)
		}
		_, turns := iceServers(credentials.ICEServers)
		connCfg.TURNServers = append(connCfg.TURNServers, turns...)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-peerDisconnected:
		return nil, fmt.Errorf("peer disconnected")
	case <-peerDeniedRelay:
		return nil, fmt.Errorf("peer denied relay")
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timeout waiting for relay credentials")
	}
	select {
	case <-peerDisconnected:
		return nil, fmt.Errorf("peer disconnected")
	default:
	}
	if !cfg.RelayOK {
		allowed, promptErr := askRelay(ctx, peerDisconnected, peerDeniedRelay, cfg.PromptRelay)
		if promptErr != nil {
			return nil, promptErr
		}
		if !allowed {
			client.Send(ctx, signal.TypeRelayDenied, struct{}{})
			return nil, fmt.Errorf("direct connection failed and relay was not allowed")
		}
	}
	select {
	case <-peerRequestedRelay:
	case <-peerDeniedRelay:
		return nil, fmt.Errorf("peer denied relay")
	case <-peerDisconnected:
		return nil, fmt.Errorf("peer disconnected")
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("peer did not agree to relay")
	}
	connCfg.Transport = conn.TransportWebRTC
	return conn.Establish(ctx, connCfg)
}

func closeEstablishResult(result *conn.EstablishResult) {
	if result == nil {
		return
	}
	if result.Conn != nil {
		_ = result.Conn.Close()
	}
	if result.TCPResult != nil && result.TCPResult.Cleanup != nil {
		result.TCPResult.Cleanup()
	}
}

// askRelay gives a terminal-independent relay prompt a context which is
// canceled when the peer goes away or refuses relay. PromptRelay is required
// to honor its context; waiting for its result after cancellation keeps this
// helper from leaving a prompt goroutine behind.
func askRelay(ctx context.Context, peerDisconnected, peerDenied <-chan struct{}, prompt func(context.Context) bool) (bool, error) {
	if prompt == nil {
		return false, nil
	}
	promptCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan bool, 1)
	go func() { result <- prompt(promptCtx) }()
	select {
	case allowed := <-result:
		return allowed, nil
	case <-peerDisconnected:
		cancel()
		<-result
		return false, fmt.Errorf("peer disconnected")
	case <-peerDenied:
		cancel()
		<-result
		return false, fmt.Errorf("peer denied relay")
	case <-ctx.Done():
		cancel()
		<-result
		return false, ctx.Err()
	}
}

func iceServers(servers []signal.ICEServer) ([]string, []conn.TURNServer) {
	var stun []string
	var turn []conn.TURNServer
	for _, server := range servers {
		isTurn := false
		for _, url := range server.URLs {
			if strings.HasPrefix(url, "turn:") || strings.HasPrefix(url, "turns:") {
				isTurn = true
				break
			}
		}
		if isTurn {
			turn = append(turn, conn.TURNServer{URLs: server.URLs, Username: server.Username, Credential: server.Credential})
		} else {
			stun = append(stun, server.URLs...)
		}
	}
	if len(stun) == 0 {
		stun = conn.DefaultSTUNServers()
	}
	return stun, turn
}

func signalError(env *signal.Envelope) error {
	var message signal.Error
	if err := env.ParsePayload(&message); err != nil {
		return fmt.Errorf("malformed signaling error")
	}
	if message.Code == signal.ErrCodeVersionMismatch {
		return fmt.Errorf("unsupported signaling protocol; upgrade the peer/server")
	}
	return fmt.Errorf("signaling server error: %s", message.Message)
}

// Ensure conn.P2PConn remains the only transport requirement exposed here.
var _ io.Closer = (*Result)(nil)
