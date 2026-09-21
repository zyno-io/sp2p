// SPDX-License-Identifier: MIT

//go:build windows

package rsync

import (
	"errors"
	"net"
	"os"
)

func daemonSocketPair() (*os.File, net.Conn, error) {
	return nil, nil, errors.New("openrsync socket daemon is unavailable on Windows")
}
