// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/zyno-io/sp2p/internal/signal"
)

func TestSignalStableVersionRelaysTransferCapabilities(t *testing.T) {
	_, url := startTestServer(t)
	// Transfer capabilities are opaque to signaling, including the key marker.
	for _, capability := range []byte{0, 0x80} {
		t.Run(fmt.Sprint(capability), func(t *testing.T) {
			sender := wsConnect(t, url)
			wsSend(t, sender, signal.TypeHello, signal.Hello{Version: 2})
			env := wsRead(t, sender)
			if env.Type != signal.TypeWelcome {
				t.Fatalf("hello: %+v", env)
			}
			var welcome signal.Welcome
			if err := env.ParsePayload(&welcome); err != nil {
				t.Fatal(err)
			}
			wrong := wsConnect(t, url)
			wsSend(t, wrong, signal.TypeJoin, signal.Join{Version: 3, SessionID: welcome.SessionID})
			env = wsRead(t, wrong)
			var rejected signal.Error
			if err := env.ParsePayload(&rejected); err != nil {
				t.Fatal(err)
			}
			if env.Type != signal.TypeError || rejected.Code != signal.ErrCodeVersionMismatch {
				t.Fatalf("mismatch: %+v / %+v", env, rejected)
			}
			// Rejection must not reserve the receiver slot or evict the sender.
			receiver := wsConnect(t, url)
			wsSend(t, receiver, signal.TypeJoin, signal.Join{Version: 2, SessionID: welcome.SessionID})
			if env := wsRead(t, receiver); env.Type != signal.TypeWelcome {
				t.Fatalf("join: %+v", env)
			}
			if env := wsRead(t, sender); env.Type != signal.TypePeerJoined {
				t.Fatalf("peer joined: %+v", env)
			}
			key := make([]byte, 32)
			key[31] = capability
			wsSend(t, sender, signal.TypeCrypto, signal.CryptoExchange{PublicKey: key, ParallelTCPV3: capability != 0})
			env = wsRead(t, receiver)
			if env.Type != signal.TypeCrypto {
				t.Fatalf("relay: %+v", env)
			}
			var exchange signal.CryptoExchange
			if err := env.ParsePayload(&exchange); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(exchange.PublicKey, key) || exchange.ParallelTCPV3 != (capability != 0) {
				t.Fatalf("capability changed during relay: %+v", exchange)
			}
		})
	}
}
