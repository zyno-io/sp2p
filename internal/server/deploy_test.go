// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDeployProxyPreservesSignedRequestThroughTLS(t *testing.T) {
	const body = "{ \"version\": \"0.7.2\", \"timestamp\": \"1794890000\" }\n"
	mac := hmac.New(sha256.New, []byte("generated-test-secret"))
	mac.Write([]byte(body))
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	var calls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		payload, err := io.ReadAll(r.Body)
		if err != nil || string(payload) != body || r.Header.Get("X-Sp2p-Signature") != signature || r.URL.Path != "/hooks/sp2p-deploy" {
			t.Error("signed request changed in transit")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer backend.Close()
	srv, err := New(Config{DeployWebhookURL: backend.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())
	front := httptest.NewTLSServer(srv.Handler())
	defer front.Close()
	request, err := http.NewRequest(http.MethodPost, front.URL+"/hooks/sp2p-deploy", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Sp2p-Signature", signature)
	response, err := front.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted || calls.Load() != 1 || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d calls=%d cache=%q", response.StatusCode, calls.Load(), response.Header.Get("Cache-Control"))
	}
}

func TestDeployProxyRejectsInvalidRequestsBeforeForwarding(t *testing.T) {
	var calls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer backend.Close()
	handler, err := newDeployProxy(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method string
		body   string
		status int
	}{
		{http.MethodGet, "", http.StatusMethodNotAllowed},
		{http.MethodPost, strings.Repeat("x", 4097), http.StatusRequestEntityTooLarge},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(tc.method, "/hooks/sp2p-deploy", strings.NewReader(tc.body)))
		if response.Code != tc.status {
			t.Fatalf("%s: got %d, want %d", tc.method, response.Code, tc.status)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached the deployment worker")
	}
}

func TestDeployProxyDisabledByDefaultAndNoOtherPathsForwarded(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg := Config{}
		if enabled {
			cfg.DeployWebhookURL = "http://127.0.0.1:1"
		}
		srv, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/hooks/sp2p-deploy", "/hooks/anything-else"} {
			response := httptest.NewRecorder()
			srv.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
			expected := http.StatusNotFound
			if enabled && path == "/hooks/sp2p-deploy" {
				expected = http.StatusBadGateway
			}
			if response.Code != expected {
				t.Fatalf("enabled=%v path=%s: got %d, want %d", enabled, path, response.Code, expected)
			}
		}
		srv.Shutdown(context.Background())
	}
}

func TestDeployProxyRejectsNonOriginConfiguration(t *testing.T) {
	for _, target := range []string{"file:///tmp/hook", "http://", "http://user:password@host", "http://host/path", "http://host?", "http://host?x=1", "http://host/#fragment", "%"} {
		if _, err := New(Config{DeployWebhookURL: target}); err == nil {
			t.Fatalf("accepted invalid deployment origin %q", target)
		}
	}
}
