// SPDX-License-Identifier: MIT

package testturn

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pion/stun/v4"
)

// refreshDebugConn is TEMPORARY instrumentation for the relay leak
// investigation: it logs every TURN Refresh request and response (client
// port, requested lifetime, response class and error code). Never usernames,
// nonces or payloads.
type refreshDebugConn struct {
	net.PacketConn
}

func refreshDebugEnabled() bool { return os.Getenv("SP2P_DEBUG_TURN_REFRESH") == "1" }

func logRefresh(direction string, b []byte, addr net.Addr) {
	msg := &stun.Message{Raw: append([]byte(nil), b...)}
	if err := msg.Decode(); err != nil || msg.Type.Method != stun.MethodRefresh {
		return
	}
	port := 0
	if udp, ok := addr.(*net.UDPAddr); ok {
		port = udp.Port
	}
	detail := ""
	var lifetime stun.RawAttribute
	if raw, err := msg.Get(stun.AttrLifetime); err == nil && len(raw) == 4 {
		lifetime = stun.RawAttribute{Value: raw}
		detail = fmt.Sprintf(" lifetime=%ds", uint32(lifetime.Value[0])<<24|uint32(lifetime.Value[1])<<16|uint32(lifetime.Value[2])<<8|uint32(lifetime.Value[3]))
	}
	var code stun.ErrorCodeAttribute
	if err := code.GetFrom(msg); err == nil {
		detail += fmt.Sprintf(" error=%d", code.Code)
	}
	fmt.Fprintf(os.Stderr, "[turn-debug] %s refresh %s port=%d%s at=%d\n",
		direction, msg.Type.Class, port, detail, time.Now().UnixMilli())
}

func (c *refreshDebugConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil {
		logRefresh("rx", p[:n], addr)
	}
	return n, addr, err
}

func (c *refreshDebugConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	logRefresh("tx", p, addr)
	return c.PacketConn.WriteTo(p, addr)
}
