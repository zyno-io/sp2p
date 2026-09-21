// SPDX-License-Identifier: MIT

//go:build !windows

package tunnel

import (
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

var umaskMu sync.Mutex

// listenUnix prevents a permissive inherited umask from exposing the socket
// between bind and the caller's chmod. Umask is process-wide, so serialize our
// changes and restore it before returning. A concurrent file creation can only
// become more restrictive during this short window.
func listenUnix(address string) (net.Listener, error) {
	umaskMu.Lock()
	defer umaskMu.Unlock()

	oldUmask := unix.Umask(0o077)
	defer unix.Umask(oldUmask)

	return net.Listen("unix", address)
}
