// SPDX-License-Identifier: MIT

package flow

import (
	"fmt"

	"github.com/zyno-io/sp2p/internal/signal"
)

const LegacyProtocolWarning = "Peer uses legacy transfer v2; compatibility was selected automatically. No v3 receiver credits or authenticated transport selection; parallel TCP disabled. Upgrade the older peer for v3 protections."

func signalingError(e signal.Error) error {
	if e.Code == signal.ErrCodeVersionMismatch {
		return fmt.Errorf("unsupported signaling protocol; upgrade the peer/server")
	}
	return fmt.Errorf("server error: %s", e.Message)
}

// Report only after the public-key transcript has been authenticated.
func reportProtocol(version int, h Handler) {
	if handler, ok := h.(interface{ OnProtocolVersion(int) }); ok {
		handler.OnProtocolVersion(version)
	}
	if version == 2 {
		if warnings, ok := h.(interface{ OnWarning(string) }); ok {
			warnings.OnWarning(LegacyProtocolWarning)
		} else {
			h.OnVerbose(LegacyProtocolWarning)
		}
	}
}
