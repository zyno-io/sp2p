// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/zyno-io/sp2p/internal/signal"
)

// SignalHandler handles WebSocket signaling connections.
type SignalHandler struct {
	sessions       *SessionManager
	serverVersion  string             // app version to include in Welcome
	baseURL        string             // public base URL for share links
	stunServers    []signal.ICEServer // STUN-only servers (sent in Welcome)
	staticTURN     []signal.ICEServer // static TURN servers (delivered on relay-retry)
	turnGen        *TURNCredentialGenerator // ephemeral TURN credential generator (mutually exclusive with staticTURN)
	releases       *ReleaseResolver   // platform-aware version lookup (nil in dev mode)
	originPatterns []string
	trustProxy     bool // trust X-Forwarded-For for client IP extraction
	stats          *StatsTracker
}

// NewSignalHandler creates a new signaling WebSocket handler.
func NewSignalHandler(sessions *SessionManager, serverVersion string, baseURL string, stunServers []signal.ICEServer, staticTURN []signal.ICEServer, turnGen *TURNCredentialGenerator, releases *ReleaseResolver, originPatterns []string, trustProxy bool, stats *StatsTracker) *SignalHandler {
	return &SignalHandler{
		sessions:       sessions,
		serverVersion:  serverVersion,
		baseURL:        baseURL,
		stunServers:    stunServers,
		staticTURN:     staticTURN,
		turnGen:        turnGen,
		releases:       releases,
		originPatterns: originPatterns,
		trustProxy:     trustProxy,
		stats:          stats,
	}
}

func (h *SignalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: h.originPatterns,
	})
	if err != nil {
		return
	}
	conn.SetReadLimit(64 * 1024)

	ctx, cancel := context.WithTimeout(r.Context(), sessionMaxAge)
	defer cancel()

	h.handleConnection(ctx, conn, extractIP(r, h.trustProxy))
}

func (h *SignalHandler) handleConnection(ctx context.Context, conn *websocket.Conn, ip string) {
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Start ping/pong keepalive to detect dead connections.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go keepAlive(ctx, conn, 30*time.Second)

	// Read the first message to determine if this is a sender or receiver.
	_, data, err := conn.Read(ctx)
	if err != nil {
		return
	}

	var env signal.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		sendError(ctx, conn, signal.ErrCodeInvalidMessage, "invalid message format")
		return
	}

	switch env.Type {
	case signal.TypeHello:
		h.handleSender(ctx, conn, &env, ip)
	case signal.TypeJoin:
		h.handleReceiver(ctx, conn, &env)
	default:
		sendError(ctx, conn, signal.ErrCodeInvalidMessage, "expected hello or join")
	}
}

func (h *SignalHandler) handleSender(ctx context.Context, conn *websocket.Conn, env *signal.Envelope, ip string) {
	var hello signal.Hello
	if err := env.ParsePayload(&hello); err != nil {
		sendError(ctx, conn, signal.ErrCodeInvalidMessage, "invalid hello payload")
		return
	}
	if hello.Version != signal.ProtocolVersion {
		sendError(ctx, conn, signal.ErrCodeVersionMismatch, "unsupported protocol version")
		return
	}

	session, err := h.sessions.Create(conn, ip)
	if err != nil {
		if errors.Is(err, ErrTooManySessionsForIP) {
			sendError(ctx, conn, "rate_limited", "too many active sessions from this IP")
		} else if errors.Is(err, ErrTooManySessions) {
			sendError(ctx, conn, "server_busy", "server is at capacity, try again later")
		} else {
			sendError(ctx, conn, "internal_error", "failed to create session")
		}
		return
	}
	session.SenderClientType = hello.ClientType
	slog.Info("peer connected", "session", session.ID, "role", "sender", "clientType", hello.ClientType)
	h.stats.RecordAttempt()

	// Send welcome with session ID, STUN servers, and TURN availability flag.
	sendMessage(ctx, conn, signal.TypeWelcome, signal.Welcome{
		SessionID:     session.ID,
		ICEServers:    h.stunServers,
		TURNAvailable: h.hasTURN(),
		ServerVersion: h.versionForPlatform(hello.ClientOS, hello.ClientArch),
		BaseURL:       h.baseURL,
	})

	// Relay messages until disconnect.
	h.relayLoop(ctx, session, conn, true)
}

func (h *SignalHandler) handleReceiver(ctx context.Context, conn *websocket.Conn, env *signal.Envelope) {
	var join signal.Join
	if err := env.ParsePayload(&join); err != nil {
		sendError(ctx, conn, signal.ErrCodeInvalidMessage, "invalid join payload")
		return
	}
	if join.Version != signal.ProtocolVersion {
		sendError(ctx, conn, signal.ErrCodeVersionMismatch, "unsupported protocol version")
		return
	}

	session, err := h.sessions.Join(join.SessionID, conn)
	if err != nil {
		if errors.Is(err, ErrSessionFull) {
			sendError(ctx, conn, signal.ErrCodeSessionFull, "someone has already connected to this session")
		} else {
			sendError(ctx, conn, signal.ErrCodeSessionNotFound, "transfer session not found")
		}
		return
	}
	slog.Info("peer connected", "session", session.ID, "role", "receiver", "clientType", join.ClientType)

	// Send welcome with STUN servers, TURN availability, and sender's client type.
	sendMessage(ctx, conn, signal.TypeWelcome, signal.Welcome{
		SessionID:      session.ID,
		ICEServers:     h.stunServers,
		TURNAvailable:  h.hasTURN(),
		PeerClientType: session.SenderClientType,
		ServerVersion:  h.versionForPlatform(join.ClientOS, join.ClientArch),
		BaseURL:        h.baseURL,
	})

	// Notify sender that receiver has joined (include receiver's client type).
	sendMessage(ctx, session.Sender, signal.TypePeerJoined, signal.PeerJoined{
		ClientType: join.ClientType,
	})
	h.stats.RecordConnected()

	// Relay messages until disconnect.
	h.relayLoop(ctx, session, conn, false)
}

func (h *SignalHandler) relayLoop(ctx context.Context, session *Session, conn *websocket.Conn, isSender bool) {
	defer func() {
		// Notify the other peer before tearing down the session.
		var peer *websocket.Conn
		if isSender {
			peer = session.Receiver()
		} else {
			peer = session.Sender
		}
		if peer != nil {
			// Use a fresh context since the original may already be cancelled.
			notifyCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			sendMessage(notifyCtx, peer, signal.TypePeerLeft, signal.PeerLeft{})
			cancel()
		}
		h.sessions.Remove(session.ID)
		slog.Info("peer disconnected", "session", session.ID, "role", role(isSender))
	}()

	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		h.sessions.Touch(session.ID)

		var env signal.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			continue
		}

		// Handle file-info from sender (store on session, don't relay).
		// Must be before the peer-nil check since sender sends this before receiver joins.
		if env.Type == signal.TypeFileInfo && isSender {
			var fi signal.FileInfo
			if err := env.ParsePayload(&fi); err == nil {
				session.SetFileInfo(fi.Data)
			}
			continue
		}

		// Handle transfer-complete stats (not relayed).
		if env.Type == signal.TypeTransferComplete {
			var tc signal.TransferComplete
			if err := env.ParsePayload(&tc); err == nil {
				h.stats.RecordComplete(tc.BytesTransferred)
			}
			continue
		}

		// Determine the peer to relay to.
		var peer *websocket.Conn
		if isSender {
			peer = session.Receiver()
		} else {
			peer = session.Sender
		}
		if peer == nil {
			continue // peer not yet connected
		}

		// Deliver TURN credentials when a peer signals relay-retry.
		// Credentials are sent back to the requesting peer (not relayed).
		// A minimum elapsed time since the receiver joined is enforced to
		// make scripted credential extraction impractical.
		if env.Type == signal.TypeRelayRetry && h.hasTURN() {
			if joinedAt := session.JoinedAt(); !joinedAt.IsZero() {
				if wait := turnMinWait - time.Since(joinedAt); wait > 0 {
					time.Sleep(wait)
				}
			}
			sendMessage(ctx, conn, signal.TypeTURNCredentials, signal.TURNCredentials{
				ICEServers: h.generateTURNServers(),
			})
		}

		// Relay allowed message types.
		switch env.Type {
		case signal.TypeOffer, signal.TypeAnswer, signal.TypeCandidate,
			signal.TypeCrypto, signal.TypeDirect, signal.TypeConnected,
			signal.TypeRetry, signal.TypeRelayRetry, signal.TypeRelayDenied:
			relayMessage(ctx, peer, data)
		}
	}
}

// versionForPlatform returns the latest release version for the client's platform,
// falling back to the server's own version if the resolver is unavailable or has no data.
func (h *SignalHandler) versionForPlatform(clientOS, clientArch string) string {
	if h.releases != nil && clientOS != "" {
		if v := h.releases.LatestVersionForPlatform(clientOS, clientArch); v != "" {
			return v
		}
	}
	return h.serverVersion
}

// hasTURN reports whether the server has TURN relay capability.
func (h *SignalHandler) hasTURN() bool {
	return h.turnGen != nil || len(h.staticTURN) > 0
}

// generateTURNServers returns TURN ICE servers, using ephemeral credentials
// if a generator is configured, otherwise returning static TURN servers.
func (h *SignalHandler) generateTURNServers() []signal.ICEServer {
	if h.turnGen != nil {
		return []signal.ICEServer{h.turnGen.Generate()}
	}
	return h.staticTURN
}

func sendMessage(ctx context.Context, conn *websocket.Conn, msgType string, payload any) {
	env, err := signal.NewEnvelope(msgType, payload)
	if err != nil {
		return
	}
	data, err := json.Marshal(env)
	if err != nil {
		return
	}
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := conn.Write(writeCtx, websocket.MessageText, data); err != nil {
		slog.Debug("sendMessage write failed", "type", msgType, "err", err)
	}
}

func sendError(ctx context.Context, conn *websocket.Conn, code, message string) {
	sendMessage(ctx, conn, signal.TypeError, signal.Error{Code: code, Message: message})
}

func relayMessage(ctx context.Context, conn *websocket.Conn, data []byte) {
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := conn.Write(writeCtx, websocket.MessageText, data); err != nil {
		slog.Debug("relay write failed", "err", err)
	}
}

func role(isSender bool) string {
	if isSender {
		return "sender"
	}
	return "receiver"
}

// keepAlive sends periodic WebSocket pings. If a pong is not received
// within the interval, the connection's context is cancelled.
func keepAlive(ctx context.Context, conn *websocket.Conn, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, interval)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}
