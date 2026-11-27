// SPDX-License-Identifier: MIT

package conn

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
)

func TestStripRTCPCandidates(t *testing.T) {
	in := "v=0\r\n" +
		"a=candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host\r\n" +
		"a=candidate:1 2 udp 2130706431 10.0.0.1 5000 typ host\r\n" +
		"a=candidate:22 1 udp 1694498815 1.2.3.4 5001 typ srflx raddr 0.0.0.0 rport 5001\r\n" +
		"a=candidate:22 2 udp 1694498815 1.2.3.4 5001 typ srflx raddr 0.0.0.0 rport 5001\r\n" +
		"a=end-of-candidates\r\n" +
		"a=ice-ufrag:x2 2\r\n" +
		"a=candidate:3 2 udp 1 10.0.0.2 1 typ host"
	want := "v=0\r\n" +
		"a=candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host\r\n" +
		"a=candidate:22 1 udp 1694498815 1.2.3.4 5001 typ srflx raddr 0.0.0.0 rport 5001\r\n" +
		"a=end-of-candidates\r\n" +
		"a=ice-ufrag:x2 2\r\n"
	got := stripRTCPCandidates(in)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if stripRTCPCandidates(got) != got {
		t.Fatal("not idempotent")
	}
	none := "v=0\r\na=group:BUNDLE 0\r\na=end-of-candidates"
	if stripRTCPCandidates(none) != none {
		t.Fatal("changed SDP without candidates")
	}
	tail := "v=0\r\na=candidate:1 1 udp 1 10.0.0.1 1 typ host"
	if stripRTCPCandidates(tail) != tail {
		t.Fatal("changed trailing component-1 line")
	}
}

func ipnet(s string) net.Addr {
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	n.IP = ip
	return n
}

func TestIPv6DropSet(t *testing.T) {
	ifaces := []ifaceAddrs{
		{name: "en0", addrs: []net.Addr{
			ipnet("192.168.1.5/24"),
			ipnet("fe80::1/64"),
			ipnet("2001:db8:1::a/64"),   // kept (first)
			ipnet("2001:db8:1::b/64"),   // dropped
			ipnet("2001:db8:1::c/64"),   // dropped
			ipnet("2001:db8:2::a/64"),   // different prefix: kept
			ipnet("2001:db8:3::a/48"),   // kept
			ipnet("2001:db8:3:1::b/48"), // same /48: dropped
			ipnet("::1/128"),
		}},
		{name: "en9", addrs: []net.Addr{
			ipnet("2001:db8:1::d/64"), // same prefix, other interface: kept
			ipnet("2001:db8:1::e/64"), // dropped
			ipnet("fd7a:115c:a1e0::1/48"),
			ipnet("fd7a:115c:a1e0::2/48"), // dropped
		}},
	}
	drop := ipv6DropSet(ifaces)
	f := ipFilterFromDropSet(drop)
	for ip, keep := range map[string]bool{
		"192.168.1.5": true, "fe80::1": true, "::1": true,
		"2001:db8:1::a": true, "2001:db8:1::b": false, "2001:db8:1::c": false,
		"2001:db8:2::a": true, "2001:db8:3::a": true, "2001:db8:3:1::b": false,
		"2001:db8:1::d": true, "2001:db8:1::e": false,
		"fd7a:115c:a1e0::1": true, "fd7a:115c:a1e0::2": false,
		"2001:db8:9::9": true, // unknown address fails open
	} {
		if got := f(net.ParseIP(ip)); got != keep {
			t.Errorf("filter(%s) = %v, want %v", ip, got, keep)
		}
	}
	if len(drop) != 5 {
		t.Errorf("drop set size %d, want 5", len(drop))
	}
}

func TestOutgoingLaneSDPHasNoRTCPCandidates(t *testing.T) {
	primary := newTestPrimary(t, true)
	lane, err := primary.NewLane(true)
	if err != nil {
		t.Fatal(err)
	}
	defer lane.Conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := lane.Description(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	var parsed sdp.SessionDescription
	if err := parsed.Unmarshal([]byte(out)); err != nil {
		t.Fatalf("outgoing SDP does not parse: %v", err)
	}
	n := 0
	for _, line := range strings.Split(out, "\r\n") {
		if strings.HasPrefix(line, "a=candidate:") {
			n++
			if f := strings.Fields(line); f[1] != "1" {
				t.Fatalf("component %s candidate in outgoing SDP: %s", f[1], line)
			}
		}
	}
	if !strings.Contains(lane.Conn.pc.LocalDescription().SDP, "a=candidate:") {
		t.Skip("no host candidates on this machine")
	}
	if n == 0 {
		t.Fatal("all candidates stripped")
	}
	_ = webrtc.SDPTypeOffer
}
