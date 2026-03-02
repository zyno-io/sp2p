// SPDX-License-Identifier: MIT

package conn

import (
	"context"
	"fmt"
	"net"
	"time"
)

const directTimeout = 5 * time.Second

// ListenTCP starts a TCP listener on a random port and returns the address.
func ListenTCP(ctx context.Context, onStatus StatusCallback) (net.Listener, string, error) {
	if onStatus != nil {
		onStatus(MethodStatus{Method: "Direct TCP", State: "trying", Detail: "listening..."})
	}

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		reportFailed(onStatus, "Direct TCP", err)
		return nil, "", fmt.Errorf("listen TCP: %w", err)
	}

	addr := ln.Addr().String()
	if onStatus != nil {
		onStatus(MethodStatus{Method: "Direct TCP", State: "trying", Detail: "listening on " + addr})
	}

	return ln, addr, nil
}

// AcceptTCP accepts a single connection from a TCP listener with a timeout.
func AcceptTCP(ctx context.Context, ln net.Listener, onStatus StatusCallback) (P2PConn, error) {
	type result struct {
		conn net.Conn
		err  error
	}

	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			reportFailed(onStatus, "Direct TCP", r.err)
			return nil, r.err
		}
		if onStatus != nil {
			onStatus(MethodStatus{Method: "Direct TCP", State: "connected", Detail: r.conn.RemoteAddr().String()})
		}
		return &netConnAdapter{Conn: r.conn}, nil
	case <-ctx.Done():
		ln.Close()
		reportFailed(onStatus, "Direct TCP", ctx.Err())
		return nil, ctx.Err()
	}
}

// ConnectTCP attempts to connect to a remote TCP address.
func ConnectTCP(ctx context.Context, addr string, onStatus StatusCallback) (P2PConn, error) {
	if onStatus != nil {
		onStatus(MethodStatus{Method: "Direct TCP", State: "trying", Detail: "connecting to " + addr})
	}

	dialer := net.Dialer{Timeout: directTimeout}
	c, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		reportFailed(onStatus, "Direct TCP", err)
		return nil, err
	}

	if onStatus != nil {
		onStatus(MethodStatus{Method: "Direct TCP", State: "connected", Detail: addr})
	}
	return &netConnAdapter{Conn: c}, nil
}

// GetLocalIPs returns all non-loopback IPv4 addresses on this machine.
func GetLocalIPs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var ips []string
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
			continue
		}
		ips = append(ips, ipNet.IP.String())
	}
	return ips
}

// isSensitiveAddr returns true if addr ("host:port") resolves to a
// loopback or link-local address. Used to prevent peer-provided
// endpoints from targeting localhost services or cloud metadata endpoints.
func isSensitiveAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return true // malformed → reject
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true // hostname (could resolve to anything) → reject
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
