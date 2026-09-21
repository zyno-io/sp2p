// SPDX-License-Identifier: MIT

package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		raw      string
		listener bool
		want     Endpoint
		wantErr  bool
	}{
		{"tcp://127.0.0.1:5432", false, Endpoint{"tcp", "127.0.0.1:5432"}, false},
		{"tcp://:15432", true, Endpoint{"tcp", "127.0.0.1:15432"}, false},
		{"unix:///tmp/sp2p.sock", false, Endpoint{"unix", "/tmp/sp2p.sock"}, false},
		{"tcp://example:1/path", false, Endpoint{}, true},
		{"unix://host/tmp/sock", false, Endpoint{}, true},
		{"unix://relative", false, Endpoint{}, true},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			got, err := ParseEndpoint(test.raw, test.listener)
			if (err != nil) != test.wantErr {
				t.Fatalf("ParseEndpoint() error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr && got != test.want {
				t.Fatalf("ParseEndpoint() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestUnixCleanupDoesNotRemoveReplacement(t *testing.T) {
	file, err := os.CreateTemp("", "sp2p-tunnel-")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name() + ".sock"
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file.Name()); err != nil {
		t.Fatal(err)
	}
	listener, cleanup, err := Listen(Endpoint{Network: "unix", Address: path})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = cleanup()
	if err == nil {
		t.Fatal("cleanup removed or accepted replacement path")
	}
	contents, readErr := os.ReadFile(path)
	if readErr != nil || string(contents) != "replacement" {
		t.Fatalf("replacement was not preserved: contents=%q err=%v", contents, readErr)
	}
}

func TestBridgePreservesHalfClose(t *testing.T) {
	stream, streamPeer := tcpPair(t)
	local, localPeer := tcpPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bridgeDone := make(chan error, 1)
	go func() { bridgeDone <- Bridge(ctx, stream, local) }()

	if _, err := streamPeer.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := streamPeer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(localPeer)
	if err != nil {
		t.Fatal(err)
	}
	if string(request) != "request" {
		t.Fatalf("request = %q", request)
	}
	if _, err := localPeer.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := localPeer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(streamPeer)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response" {
		t.Fatalf("response = %q", response)
	}
	if err := <-bridgeDone; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Bridge() = %v", err)
	}
}

func TestServeBridgesTCPStreamToUnixTarget(t *testing.T) {
	file, err := os.CreateTemp("", "sp2p-tunnel-")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name() + ".sock"
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file.Name()); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer os.Remove(path)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	stream, peer := tcpPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- Serve(ctx, stream, Endpoint{Network: "unix", Address: path}) }()
	target := <-accepted
	defer target.Close()
	if _, err := peer.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(request) != "request" {
		t.Fatalf("request = %q", request)
	}
	if _, err := target.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if closer, ok := target.(interface{ CloseWrite() error }); ok {
		if err := closer.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Fatal("Unix target lacks CloseWrite")
	}
	response, err := io.ReadAll(peer)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response" {
		t.Fatalf("response = %q", response)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve() = %v", err)
	}
}

func TestBridgeAbortsBeforeClosingStream(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	stream := &abortRecordingStream{readErr: errors.New("stream read failed")}
	err := Bridge(context.Background(), stream, local)
	if err == nil || err.Error() != "stream read failed" {
		t.Fatalf("Bridge() = %v, want stream read error", err)
	}
	if got, want := stream.events, []string{"abort:stream read failed", "close"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("stream events = %v, want %v", got, want)
	}
}

type abortRecordingStream struct {
	readErr error
	events  []string
}

func (s *abortRecordingStream) Read([]byte) (int, error) { return 0, s.readErr }
func (s *abortRecordingStream) Write(data []byte) (int, error) {
	return len(data), nil
}
func (s *abortRecordingStream) CloseWrite() error { return nil }
func (s *abortRecordingStream) Abort(err error) error {
	s.events = append(s.events, "abort:"+err.Error())
	return nil
}
func (s *abortRecordingStream) Close() error { s.events = append(s.events, "close"); return nil }

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	server := <-accepted
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return server, client
}
