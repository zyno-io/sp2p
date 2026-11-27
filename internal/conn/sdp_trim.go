// SPDX-License-Identifier: MIT

package conn

import (
	"net"
	"strings"

	"github.com/pion/webrtc/v4"
)

// stripRTCPCandidates removes component-2 (RTCP) "a=candidate:" lines from an
// outgoing SDP. pion writes every candidate for components 1 and 2 for RTCP
// compatibility, but sp2p only uses data channels over BUNDLE, so component 2
// is dead weight. All other lines, and the line endings, are preserved
// byte-for-byte. Apply this only to SDP sent to the peer, never to what is
// given to SetLocalDescription.
func stripRTCPCandidates(sdp string) string {
	if !strings.Contains(sdp, "a=candidate:") {
		return sdp
	}
	var b strings.Builder
	b.Grow(len(sdp))
	rest := sdp
	for len(rest) > 0 {
		end := strings.IndexByte(rest, '\n')
		var line string
		if end < 0 {
			line, rest = rest, ""
		} else {
			line, rest = rest[:end+1], rest[end+1:]
		}
		if !isRTCPCandidateLine(line) {
			b.WriteString(line)
		}
	}
	return b.String()
}

func isRTCPCandidateLine(line string) bool {
	const prefix = "a=candidate:"
	if !strings.HasPrefix(line, prefix) {
		return false
	}
	// a=candidate:<foundation> <component> <transport> ...
	fields := strings.Fields(line[len(prefix):])
	return len(fields) >= 2 && fields[1] == "2"
}

// ifaceAddrs is the testable input of ipv6DropSet.
type ifaceAddrs struct {
	name  string
	addrs []net.Addr
}

// ipv6DropSet returns the IPv6 global unicast addresses that are redundant
// because another address in the same (interface, prefix) group is kept. The
// first address of each group in OS order is kept. On macOS Go returns the
// stable "secured" address first and the deprecated temporary addresses after
// it; on Linux the current temporary address usually comes first. Either way,
// one address per group reaches the same network. IPv4, link-local and
// loopback addresses are never dropped.
func ipv6DropSet(ifaces []ifaceAddrs) map[string]struct{} {
	drop := map[string]struct{}{}
	seen := map[string]struct{}{}
	for _, ifc := range ifaces {
		for _, a := range ifc.addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() != nil || !ipn.IP.IsGlobalUnicast() {
				continue
			}
			ip16 := ipn.IP.To16()
			if ip16 == nil {
				continue
			}
			if _, bits := ipn.Mask.Size(); bits != 128 {
				continue
			}
			prefix := (&net.IPNet{IP: ip16.Mask(ipn.Mask), Mask: ipn.Mask}).String()
			key := ifc.name + "|" + prefix
			if _, dup := seen[key]; dup {
				drop[string(ip16)] = struct{}{}
				continue
			}
			seen[key] = struct{}{}
		}
	}
	return drop
}

func systemIfaceAddrs() ([]ifaceAddrs, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]ifaceAddrs, 0, len(ifs))
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		out = append(out, ifaceAddrs{name: ifc.Name, addrs: addrs})
	}
	return out, nil
}

// ipFilterFromDropSet returns a fail-open filter: only IPs in the drop set
// are rejected; unknown addresses are allowed.
func ipFilterFromDropSet(drop map[string]struct{}) func(net.IP) bool {
	return func(ip net.IP) bool {
		if ip16 := ip.To16(); ip16 != nil {
			if _, dropped := drop[string(ip16)]; dropped {
				return false
			}
		}
		return true
	}
}

// installRedundantIPv6Filter drops redundant IPv6 privacy addresses from ICE
// gathering. If enumeration fails or nothing is redundant, no filter is set.
func installRedundantIPv6Filter(se *webrtc.SettingEngine) {
	ifaces, err := systemIfaceAddrs()
	if err != nil {
		return
	}
	drop := ipv6DropSet(ifaces)
	if len(drop) == 0 {
		return
	}
	se.SetIPFilter(ipFilterFromDropSet(drop))
}
