// SPDX-License-Identifier: MIT

package conn

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/sdp/v3"
)

func TestTrimSDPStripsRTCPCandidates(t *testing.T) {
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
	got := trimSDP(in, nil)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if trimSDP(got, nil) != got {
		t.Fatal("not idempotent")
	}
	none := "v=0\r\na=group:BUNDLE 0\r\na=end-of-candidates"
	if trimSDP(none, nil) != none {
		t.Fatal("changed SDP without candidates")
	}
	tail := "v=0\r\na=candidate:1 1 udp 1 10.0.0.1 1 typ host"
	if trimSDP(tail, nil) != tail {
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

func testIfaces() []ifaceAddrs {
	return []ifaceAddrs{
		{name: "en0", addrs: []net.Addr{
			ipnet("192.168.1.5/24"),
			ipnet("fe80::1/64"),
			ipnet("2001:db8:1::a/64"), // rank 0
			ipnet("2001:db8:1::b/64"), // rank 1
			ipnet("2001:db8:1::c/64"), // rank 2
			ipnet("2001:db8:2::a/64"), // different prefix
			ipnet("2001:db8:3::a/48"),
			ipnet("2001:db8:3:1::b/48"), // same /48
			ipnet("::1/128"),
		}},
		{name: "en9", addrs: []net.Addr{
			ipnet("2001:db8:1::d/64"), // same prefix, other interface
			ipnet("2001:db8:1::e/64"),
			ipnet("fd7a:115c:a1e0::1/48"),
			ipnet("fd7a:115c:a1e0::2/48"),
		}},
	}
}

func TestIPv6Groups(t *testing.T) {
	groups := ipv6Groups(testIfaces())
	for _, ip := range []string{"192.168.1.5", "fe80::1", "::1"} {
		if _, ok := groups[string(net.ParseIP(ip).To16())]; ok {
			t.Errorf("%s must not be grouped", ip)
		}
	}
	g := func(ip string) v6Group { return groups[string(net.ParseIP(ip).To16())] }
	if a, b := g("2001:db8:1::a"), g("2001:db8:1::c"); a.key != b.key || a.rank != 0 || b.rank != 2 {
		t.Errorf("same-prefix grouping: %+v %+v", a, b)
	}
	if a, d := g("2001:db8:1::a"), g("2001:db8:1::d"); a.key == d.key || d.rank != 0 {
		t.Errorf("other interface must be its own group: %+v %+v", a, d)
	}
	if a, b := g("2001:db8:3::a"), g("2001:db8:3:1::b"); a.key != b.key || b.rank != 1 {
		t.Errorf("/48 grouping: %+v %+v", a, b)
	}
	if g("2001:db8:2::a").rank != 0 {
		t.Error("distinct prefix must start its own group")
	}
}

func TestTrimSDPDropsRedundantIPv6Hosts(t *testing.T) {
	groups := ipv6Groups(testIfaces())
	host := func(ip string) string {
		return "a=candidate:7 1 udp 2130706431 " + ip + " 5000 typ host\r\n"
	}
	srflx := "a=candidate:9 1 udp 1694498815 2001:db8:1::c 6000 typ srflx raddr :: rport 0\r\n"
	in := "v=0\r\n" +
		host("192.168.1.5") +
		host("2001:db8:1::c") + // dropped: ::a (rank 0) is present
		host("2001:db8:1::a") +
		host("2001:db8:1::b") + // dropped
		host("2001:db8:1::e") + // en9 group: ::d absent, so ::e is the best present
		host("fd7a:115c:a1e0::1") +
		host("fd7a:115c:a1e0::2") + // dropped
		host("2001:db8:9::9") + // unknown address: kept
		srflx + // non-host candidates are never dropped
		"a=end-of-candidates\r\n"
	want := "v=0\r\n" +
		host("192.168.1.5") +
		host("2001:db8:1::a") +
		host("2001:db8:1::e") +
		host("fd7a:115c:a1e0::1") +
		host("2001:db8:9::9") +
		srflx +
		"a=end-of-candidates\r\n"
	if got := trimSDP(in, groups); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	// Only a lower-ranked address was gathered: it must survive.
	only := "v=0\r\n" + host("2001:db8:1::b")
	if got := trimSDP(only, groups); got != only {
		t.Fatalf("sole gathered address of a group was dropped: %q", got)
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
}
