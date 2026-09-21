// SPDX-License-Identifier: MIT

//go:build windows

package tunnel

import "net"

func listenUnix(address string) (net.Listener, error) {
	return net.Listen("unix", address)
}
