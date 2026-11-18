// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type upstreamRecorder struct {
	calls     atomic.Int32
	body      []byte
	signature string
	length    int64
	encoding  []string
}

func newGate(t *testing.T) (*httptest.Server, *upstreamRecorder) {
	t.Helper()
	rec := &upstreamRecorder{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.calls.Add(1)
		rec.body, _ = io.ReadAll(r.Body)
		rec.signature = r.Header.Get("X-Sp2p-Signature")
		rec.length = r.ContentLength
		rec.encoding = r.TransferEncoding
		if r.URL.Path != hookPath {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, "accepted\n")
	}))
	t.Cleanup(upstream.Close)
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	gate := httptest.NewServer(newHandler(target))
	t.Cleanup(gate.Close)
	return gate, rec
}

func post(t *testing.T, url string, body io.Reader, length int64) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = length
	req.Header.Set("X-Sp2p-Signature", "sha256=abc")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestForwardsBodyAtLimit(t *testing.T) {
	gate, rec := newGate(t)
	body := bytes.Repeat([]byte("a"), maxBodyBytes)
	resp := post(t, gate.URL+hookPath, bytes.NewReader(body), int64(len(body)))
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted || string(got) != "accepted\n" {
		t.Fatalf("status %d body %q, want upstream's 202", resp.StatusCode, got)
	}
	if !bytes.Equal(rec.body, body) || rec.length != int64(len(body)) || rec.signature != "sha256=abc" {
		t.Fatalf("upstream got %d bytes (Content-Length %d, signature %q)", len(rec.body), rec.length, rec.signature)
	}
}

func TestForwardsChunkedBodyWithFixedLength(t *testing.T) {
	gate, rec := newGate(t)
	resp := post(t, gate.URL+hookPath, io.MultiReader(strings.NewReader(`{"version":`), strings.NewReader(`"0.7.4"}`)), -1)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d, want 202", resp.StatusCode)
	}
	if string(rec.body) != `{"version":"0.7.4"}` || rec.length != int64(len(rec.body)) || len(rec.encoding) != 0 {
		t.Fatalf("upstream got %q (Content-Length %d, Transfer-Encoding %v)", rec.body, rec.length, rec.encoding)
	}
}

func TestRejectsOversizedBodies(t *testing.T) {
	gate, rec := newGate(t)
	body := bytes.Repeat([]byte("a"), maxBodyBytes+1)
	for name, length := range map[string]int64{"declared": int64(len(body)), "chunked": -1} {
		resp := post(t, gate.URL+hookPath, io.MultiReader(bytes.NewReader(body)), length)
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("%s: status %d, want 413", name, resp.StatusCode)
		}
	}
	if n := rec.calls.Load(); n != 0 {
		t.Fatalf("upstream called %d times", n)
	}
}

func TestRejectsUpgrades(t *testing.T) {
	gate, rec := newGate(t)
	req, err := http.NewRequest(http.MethodPost, gate.URL+hookPath, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || rec.calls.Load() != 0 {
		t.Fatalf("status %d with %d upstream calls, want 400 and none", resp.StatusCode, rec.calls.Load())
	}
}

func TestLimitListenerCapsOpenConnections(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newLimitListener(inner, 1)
	defer l.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	for range 2 {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	first := <-accepted
	select {
	case <-accepted:
		t.Fatal("accepted a second connection while the first was open")
	case <-time.After(100 * time.Millisecond):
	}
	first.Close()
	first.Close() // Releases its slot only once.
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("second connection not accepted after the first closed")
	}
}

func TestRejectsOtherMethodsAndPaths(t *testing.T) {
	gate, rec := newGate(t)
	resp, err := http.Get(gate.URL + hookPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodPost {
		t.Errorf("GET: status %d Allow %q, want 405 POST", resp.StatusCode, resp.Header.Get("Allow"))
	}
	for _, path := range []string{"/", "/hooks/other", hookPath + "/", "/hooks/sp2p-deploy/../other"} {
		if resp := post(t, gate.URL+path, strings.NewReader("{}"), 2); resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s: status %d, want 404", path, resp.StatusCode)
		}
	}
	if n := rec.calls.Load(); n != 0 {
		t.Fatalf("upstream called %d times", n)
	}
}
