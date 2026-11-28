// SPDX-License-Identifier: MIT

package conn

import (
	"net"
	"strings"
)

// trimOutgoingSDP shrinks an SDP before it is sent to the peer. Apply it only
// to SDP that leaves the process, never to what is given to
// SetLocalDescription. It removes:
//
//   - component-2 (RTCP) candidate lines: pion writes every candidate for
//     components 1 and 2 for RTCP compatibility, but sp2p only uses data
//     channels over BUNDLE with rtcp-mux, so component 2 is dead weight;
//   - redundant IPv6 host candidates: hosts with IPv6 privacy extensions
//     (notably macOS) keep many temporary addresses per interface and
//     prefix, and one address per (interface, prefix) reaches the same
//     network.
//
// This is deliberately a text pass over the outgoing SDP rather than a pion
// IP or interface filter: setting either filter switches pion's STUN and
// TURN gathering from wildcard sockets to one socket per local address,
// which slows gathering by seconds and multiplies TURN allocations.
func trimOutgoingSDP(sdp string) string {
	var groups map[string]v6Group
	if ifaces, err := systemIfaceAddrs(); err == nil {
		groups = ipv6Groups(ifaces)
	}
	return trimSDP(sdp, groups)
}

// trimSDP is trimOutgoingSDP with the interface data injected. All lines it
// keeps, and their line endings, are preserved byte-for-byte.
func trimSDP(sdp string, groups map[string]v6Group) string {
	if !strings.Contains(sdp, "a=candidate:") {
		return sdp
	}
	lines := splitLinesKeepEnds(sdp)

	// For each (interface, prefix, transport) group, find the best-ranked
	// address that pion actually gathered, so a group never loses all of its
	// candidates (e.g. when the OS-preferred address failed to bind, or a
	// TCP mux is bound to a different address than UDP).
	best := map[string]int{}
	for _, line := range lines {
		c, ok := parseCandidateLine(line)
		if !ok || c.component == "2" || c.typ != "host" {
			continue
		}
		if g, ok := groups[c.ip16]; ok {
			k := g.key + "|" + c.transport
			if r, seen := best[k]; !seen || g.rank < r {
				best[k] = g.rank
			}
		}
	}

	var b strings.Builder
	b.Grow(len(sdp))
	for _, line := range lines {
		if c, ok := parseCandidateLine(line); ok {
			if c.component == "2" {
				continue
			}
			if g, grouped := groups[c.ip16]; c.typ == "host" && grouped && best[g.key+"|"+c.transport] != g.rank {
				continue
			}
		}
		b.WriteString(line)
	}
	return b.String()
}

func splitLinesKeepEnds(s string) []string {
	var lines []string
	for len(s) > 0 {
		end := strings.IndexByte(s, '\n')
		if end < 0 {
			lines = append(lines, s)
			break
		}
		lines = append(lines, s[:end+1])
		s = s[end+1:]
	}
	return lines
}

type candidateLine struct {
	component string
	transport string
	ip16      string // 16-byte form of the address, or "" if not an IP
	typ       string
}

// parseCandidateLine parses
// "a=candidate:<foundation> <component> <transport> <priority> <address> <port> typ <type> ...".
func parseCandidateLine(line string) (candidateLine, bool) {
	const prefix = "a=candidate:"
	if !strings.HasPrefix(line, prefix) {
		return candidateLine{}, false
	}
	f := strings.Fields(line[len(prefix):])
	if len(f) < 2 {
		return candidateLine{}, false
	}
	c := candidateLine{component: f[1]}
	if len(f) >= 3 {
		c.transport = strings.ToLower(f[2])
	}
	if len(f) >= 8 && f[6] == "typ" {
		c.typ = f[7]
		if ip := net.ParseIP(f[4]); ip != nil {
			c.ip16 = string(ip.To16())
		}
	}
	return c, true
}

// ifaceAddrs is the testable input of ipv6Groups.
type ifaceAddrs struct {
	name  string
	addrs []net.Addr
}

// v6Group identifies an address's (interface, prefix) group and its rank in
// OS order within that group (0 = first).
type v6Group struct {
	key  string
	rank int
}

// ipv6Groups maps each IPv6 global unicast address to its (interface,
// prefix) group and its OS-order rank within it. OS order is the preference:
// on macOS Go returns the stable "secured" address first and the deprecated
// temporary addresses after it; on Linux the current temporary address
// usually comes first. IPv4, IPv4-mapped, link-local, loopback, and
// unexpected mask shapes are left out, so their candidates are never
// dropped. An address seen on several interfaces keeps its first group.
func ipv6Groups(ifaces []ifaceAddrs) map[string]v6Group {
	groups := map[string]v6Group{}
	next := map[string]int{}
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
			if _, dup := groups[string(ip16)]; dup {
				continue
			}
			key := ifc.name + "|" + (&net.IPNet{IP: ip16.Mask(ipn.Mask), Mask: ipn.Mask}).String()
			groups[string(ip16)] = v6Group{key: key, rank: next[key]}
			next[key]++
		}
	}
	return groups
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
