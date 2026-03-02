// SPDX-License-Identifier: MIT

package signal

import "encoding/json"

const ProtocolVersion = 1

// Message types exchanged over the signaling WebSocket.
const (
	TypeHello      = "hello"
	TypeWelcome    = "welcome"
	TypeJoin       = "join"
	TypePeerJoined = "peer-joined"
	TypeOffer      = "offer"
	TypeAnswer     = "answer"
	TypeCandidate  = "candidate"
	TypeCrypto     = "crypto"
	TypeDirect     = "direct" // Direct connection endpoint exchange
	TypeConnected  = "connected"
	TypeRetry            = "retry"             // Signals willingness to retry P2P with swapped roles
	TypeRelayRetry       = "relay-retry"       // Signals willingness to retry with TURN relay
	TypeRelayDenied      = "relay-denied"      // Signals that the peer denied TURN relay
	TypeTURNCredentials  = "turn-credentials"  // Server delivers TURN credentials on relay-retry
	TypeFileInfo         = "file-info"         // Encrypted file metadata for receiver preview
	TypeTransferComplete = "transfer-complete" // Client reports transfer stats to server
	TypePeerLeft         = "peer-left"         // Server notifies that the other peer disconnected
	TypeError            = "error"
)

// Envelope wraps every signaling message with a type discriminator.
type Envelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Client type constants.
const (
	ClientTypeCLI     = "cli"
	ClientTypeBrowser = "browser"
)

// Hello is sent by the sender to register a new session.
type Hello struct {
	Version    int    `json:"version"`
	ClientType string `json:"clientType,omitempty"`
}

// Welcome is the server's response to Hello, containing the session ID.
// For receivers, PeerClientType is set to the sender's client type.
type Welcome struct {
	SessionID      string      `json:"sessionId"`
	ICEServers     []ICEServer `json:"iceServers,omitempty"`
	TURNAvailable  bool        `json:"turnAvailable,omitempty"`
	PeerClientType string      `json:"peerClientType,omitempty"`
	ServerVersion  string      `json:"serverVersion,omitempty"`
	BaseURL        string      `json:"baseUrl,omitempty"`
}

// TURNCredentials delivers TURN relay credentials to a client.
// Sent by the server in response to a relay-retry signal.
type TURNCredentials struct {
	ICEServers []ICEServer `json:"iceServers"`
}

// ICEServer describes a STUN or TURN server for WebRTC.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// Join is sent by the receiver to join an existing session.
type Join struct {
	Version    int    `json:"version"`
	SessionID  string `json:"sessionId"`
	ClientType string `json:"clientType,omitempty"`
}

// PeerJoined notifies the sender that a receiver has joined.
type PeerJoined struct {
	ClientType string `json:"clientType,omitempty"`
}

// SDP carries an SDP offer or answer.
type SDP struct {
	SDP  string `json:"sdp"`
	Type string `json:"type"` // "offer" or "answer"
}

// Candidate carries an ICE candidate.
type Candidate struct {
	Candidate     string `json:"candidate"`
	SDPMid        string `json:"sdpMid"`
	SDPMLineIndex uint16 `json:"sdpMLineIndex"`
}

// CryptoExchange carries a DH public key for the key exchange.
type CryptoExchange struct {
	PublicKey []byte `json:"publicKey"` // 32-byte X25519 public key
}

// DirectEndpoint carries direct connection addresses for TCP.
type DirectEndpoint struct {
	TCP string `json:"tcp,omitempty"` // host:port for direct TCP
}

// Connected signals that the peer has established a P2P connection.
type Connected struct{}

// TransferComplete reports transfer stats to the server.
type TransferComplete struct {
	BytesTransferred uint64 `json:"bytesTransferred"`
}

// FileInfo carries encrypted file metadata for receiver preview.
type FileInfo struct {
	Data string `json:"data"` // base64(nonce || ciphertext || tag)
}

// PeerLeft notifies a client that the other peer has disconnected.
type PeerLeft struct{}

// Error carries an error message.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error codes used in signaling.
const (
	ErrCodeInvalidMessage  = "invalid_message"
	ErrCodeSessionNotFound = "session_not_found"
	ErrCodeSessionFull     = "session_full"
	ErrCodeVersionMismatch = "version_mismatch"
	ErrCodeInternal        = "internal"
)

// NewEnvelope creates an Envelope from a typed payload.
func NewEnvelope(msgType string, payload any) (*Envelope, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &Envelope{Type: msgType, Payload: data}, nil
}

// ParsePayload unmarshals the envelope payload into the given target.
func (e *Envelope) ParsePayload(target any) error {
	return json.Unmarshal(e.Payload, target)
}
