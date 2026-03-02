// SPDX-License-Identifier: MIT

package flow

import (
	"time"

	"github.com/zyno-io/sp2p/internal/conn"
	"github.com/zyno-io/sp2p/internal/transfer"
)

// Handler receives events during a send or receive flow.
// Implement this interface to adapt the flow to different UIs.
type Handler interface {
	// OnPhaseChanged reports a lifecycle transition.
	OnPhaseChanged(phase Phase)

	// OnTransferCode provides the transfer code and base URL (send only).
	OnTransferCode(code string, baseURL string)

	// OnConnectionStatus reports P2P connection method status.
	OnConnectionStatus(status conn.MethodStatus)

	// OnConnectionMethodsReset signals that connection methods should be
	// cleared (e.g., before a retry attempt).
	OnConnectionMethodsReset()

	// OnMetadata provides file metadata before transfer begins (receive only).
	OnMetadata(meta *transfer.Metadata)

	// OnProgress reports transfer progress.
	OnProgress(bytesTransferred uint64)

	// OnVerifyCode provides the verification code for optional manual verification.
	OnVerifyCode(code string)

	// OnComplete reports successful completion.
	OnComplete(totalBytes uint64, duration time.Duration)

	// OnUpdateAvailable notifies that a newer server version exists.
	OnUpdateAvailable(currentVersion, serverVersion string)

	// OnError reports a user-facing error message.
	OnError(message string)

	// OnVerbose reports a diagnostic message (only called if verbose mode is on).
	OnVerbose(msg string)

	// PromptRelay asks whether to allow TURN relay.
	// Blocks until the user responds. Return true to allow.
	PromptRelay() bool
}

// Phase represents a lifecycle phase of the transfer flow.
type Phase string

const (
	PhaseConnecting    Phase = "connecting"     // connecting to signaling
	PhaseRegistered    Phase = "registered"     // session registered, waiting for peer (send)
	PhasePeerJoined    Phase = "peer_joined"    // peer connected (send)
	PhaseKeyExchange   Phase = "key_exchange"   // exchanging encryption keys
	PhaseP2PConnecting Phase = "p2p_connecting" // establishing P2P connection
	PhaseP2PConnected  Phase = "p2p_connected"  // P2P connection established
	PhaseTransferring  Phase = "transferring"   // transfer in progress
	PhaseDone          Phase = "done"           // transfer complete
	PhaseError         Phase = "error"          // error occurred
)
