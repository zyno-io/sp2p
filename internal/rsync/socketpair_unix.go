// SPDX-License-Identifier: MIT

//go:build !windows

package rsync

import (
	"fmt"
	"net"
	"os"
	"time"
)

// daemonSocketPair supplies openrsync an actual connected TCP socket on stdin.
// openrsync uses this to select its inetd-style one-client daemon path; a pipe
// would incorrectly start a standalone listener. It specifically expects an
// Internet-family peer address, so an AF_UNIX socketpair is insufficient.
func daemonSocketPair() (*os.File, net.Conn, error) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, fmt.Errorf("listen for daemon socket pair: %w", err)
	}
	defer listener.Close()
	bridgeConn, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		return nil, nil, fmt.Errorf("dial daemon socket pair: %w", err)
	}
	if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		_ = bridgeConn.Close()
		return nil, nil, fmt.Errorf("bound daemon socket pair accept: %w", err)
	}
	var daemonConn *net.TCPConn
	for attempts := 0; attempts < 8; attempts++ {
		candidate, acceptErr := listener.AcceptTCP()
		if acceptErr != nil {
			_ = bridgeConn.Close()
			return nil, nil, fmt.Errorf("accept daemon socket pair: %w", acceptErr)
		}
		if candidate.RemoteAddr().String() == bridgeConn.LocalAddr().String() {
			daemonConn = candidate
			break
		}
		_ = candidate.Close()
	}
	if daemonConn == nil {
		_ = bridgeConn.Close()
		return nil, nil, fmt.Errorf("authenticate daemon socket pair peer")
	}
	daemonFile, err := daemonConn.File()
	closeErr := daemonConn.Close()
	if err != nil {
		_ = bridgeConn.Close()
		return nil, nil, fmt.Errorf("duplicate daemon socket: %w", err)
	}
	if closeErr != nil {
		_ = daemonFile.Close()
		_ = bridgeConn.Close()
		return nil, nil, fmt.Errorf("close duplicate daemon connection: %w", closeErr)
	}
	return daemonFile, bridgeConn, nil
}
