// SPDX-License-Identifier: MIT

package conn

import (
	"net"
	"testing"
	"time"
)

// TestGetLocalIPs verifies that GetLocalIPs returns valid non-loopback IPv4 addresses.
func TestGetLocalIPs(t *testing.T) {
	ips := GetLocalIPs()
	// Should have at least one IP on any machine running tests.
	if len(ips) == 0 {
		t.Skip("no local IPs found (may be in a sandboxed environment)")
	}

	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Fatalf("invalid IP: %s", ip)
		}
		if parsed.IsLoopback() {
			t.Fatalf("GetLocalIPs returned loopback address: %s", ip)
		}
		// Should be IPv4.
		if parsed.To4() == nil {
			t.Fatalf("GetLocalIPs returned non-IPv4 address: %s", ip)
		}
	}
}

// TestDefaultSTUNServers verifies that default STUN servers are returned.
func TestDefaultSTUNServers(t *testing.T) {
	servers := DefaultSTUNServers()
	if len(servers) == 0 {
		t.Fatal("expected at least one default STUN server")
	}
	for _, s := range servers {
		if len(s) < 5 || s[:5] != "stun:" {
			t.Fatalf("expected stun: prefix, got %s", s)
		}
	}
}

// TestListenAndAcceptTCP verifies TCP listen/accept/connect.
func TestListenAndAcceptTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	// Accept in a goroutine.
	type result struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		acceptCh <- result{c, err}
	}()

	// Connect.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Verify accept succeeded.
	r := <-acceptCh
	if r.err != nil {
		t.Fatal(r.err)
	}
	defer r.conn.Close()

	// Verify bidirectional communication.
	testData := []byte("hello from client")
	if _, err := conn.Write(testData); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 100)
	n, err := r.conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(testData) {
		t.Fatalf("data mismatch: got %q, want %q", string(buf[:n]), string(testData))
	}
}

// TestNetConnAdapterImplementsP2PConn verifies netConnAdapter satisfies P2PConn.
func TestNetConnAdapterImplementsP2PConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Write([]byte("pong"))
			c.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Wrap in adapter.
	var p2p P2PConn = &netConnAdapter{Conn: conn}

	// Test Write.
	if _, err := p2p.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}

	// Test Read.
	buf := make([]byte, 10)
	n, err := p2p.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("expected pong, got %q", string(buf[:n]))
	}

	// Test Close.
	if err := p2p.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestNetConnAdapterOnClose verifies the onClose callback fires on Close.
func TestNetConnAdapterOnClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	called := false
	adapter := &netConnAdapter{
		Conn:    conn,
		onClose: func() { called = true },
	}

	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("onClose callback was not invoked")
	}

	// Second close should not panic (onClose is nil after first call).
	adapter.Close()
}

// TestIsSensitiveAddr verifies loopback/link-local address filtering.
func TestIsSensitiveAddr(t *testing.T) {
	tests := []struct {
		name      string
		addr      string
		sensitive bool
	}{
		{"loopback IPv4", "127.0.0.1:8080", true},
		{"IPv6 loopback", "[::1]:8080", true},
		{"link-local unicast IPv4", "169.254.1.1:8080", true},
		{"link-local unicast IPv6", "[fe80::1]:80", true},
		{"link-local IPv6 with zone ID", "[fe80::1%25eth0]:80", true},
		{"private 192.168 not sensitive", "192.168.1.1:8080", false},
		{"private 10.x not sensitive", "10.0.0.1:8080", false},
		{"public IP", "8.8.8.8:443", false},
		{"hostname rejected", "example.com:80", true},
		{"localhost hostname rejected", "localhost:80", true},
		{"malformed no port", "malformed", true},
		{"empty string", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSensitiveAddr(tt.addr)
			if got != tt.sensitive {
				t.Errorf("isSensitiveAddr(%q) = %v, want %v", tt.addr, got, tt.sensitive)
			}
		})
	}
}

// TestMethodStatus verifies MethodStatus structure.
func TestMethodStatus(t *testing.T) {
	s := MethodStatus{
		Method: "WebRTC",
		State:  "trying",
		Detail: "STUN gathering...",
	}
	if s.Method != "WebRTC" || s.State != "trying" {
		t.Fatal("MethodStatus fields mismatch")
	}
}

// TestConnectConfigDefaults verifies ConnectConfig structure.
func TestConnectConfigDefaults(t *testing.T) {
	cfg := ConnectConfig{
		IsSender:    true,
		STUNServers: DefaultSTUNServers(),
	}
	if !cfg.IsSender {
		t.Fatal("expected IsSender true")
	}
	if len(cfg.STUNServers) == 0 {
		t.Fatal("expected STUN servers")
	}
}

// TestWebRTCConnReadWrite verifies that WebRTCConn's Read/Write/Close work
// correctly with the channel-based buffer.
func TestWebRTCConnReadWrite(t *testing.T) {
	conn := &WebRTCConn{
		readBuf: make(chan []byte, 256),
		closed:  make(chan struct{}),
	}

	// Simulate receiving data.
	conn.readBuf <- []byte("hello")
	conn.readBuf <- []byte(" world")

	// Read should return the first chunk.
	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("expected 'hello', got %q", string(buf[:n]))
	}

	// Read second chunk.
	buf2 := make([]byte, 10)
	n, err = conn.Read(buf2)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf2[:n]) != " world" {
		t.Fatalf("expected ' world', got %q", string(buf2[:n]))
	}

	// Close and verify Read returns EOF.
	close(conn.closed)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected EOF after close")
	}
}

// TestWebRTCConnPartialRead verifies that partial reads work correctly
// with the readLeft buffer.
func TestWebRTCConnPartialRead(t *testing.T) {
	conn := &WebRTCConn{
		readBuf: make(chan []byte, 256),
		closed:  make(chan struct{}),
	}

	// Send a 10-byte message.
	conn.readBuf <- []byte("0123456789")

	// Read only 3 bytes at a time.
	buf := make([]byte, 3)

	n, _ := conn.Read(buf)
	if string(buf[:n]) != "012" {
		t.Fatalf("expected '012', got %q", string(buf[:n]))
	}

	n, _ = conn.Read(buf)
	if string(buf[:n]) != "345" {
		t.Fatalf("expected '345', got %q", string(buf[:n]))
	}

	n, _ = conn.Read(buf)
	if string(buf[:n]) != "678" {
		t.Fatalf("expected '678', got %q", string(buf[:n]))
	}

	n, _ = conn.Read(buf)
	if string(buf[:n]) != "9" {
		t.Fatalf("expected '9', got %q", string(buf[:n]))
	}
}

// TestWebRTCConnSetDeadline verifies SetDeadline returns nil (no-op).
func TestWebRTCConnSetDeadline(t *testing.T) {
	conn := &WebRTCConn{
		readBuf: make(chan []byte, 1),
		closed:  make(chan struct{}),
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("SetDeadline should return nil: %v", err)
	}
}

// TestMaxDirectAddrs verifies the cap constant is reasonable.
func TestMaxDirectAddrs(t *testing.T) {
	if maxDirectAddrs < 4 || maxDirectAddrs > 32 {
		t.Fatalf("maxDirectAddrs=%d seems unreasonable", maxDirectAddrs)
	}
}

// TestTURNServerStructure verifies TURNServer fields.
func TestTURNServerStructure(t *testing.T) {
	ts := TURNServer{
		URLs:       []string{"turn:turn.example.com:3478"},
		Username:   "user",
		Credential: "pass",
	}
	if len(ts.URLs) != 1 || ts.Username != "user" || ts.Credential != "pass" {
		t.Fatal("TURNServer fields mismatch")
	}
}
