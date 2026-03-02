// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	defer rl.Stop()

	ip := "192.168.1.1"

	// First 3 requests should be allowed.
	for i := 1; i <= 3; i++ {
		if !rl.Allow(ip) {
			t.Fatalf("request %d should be allowed", i)
		}
	}

	// 4th request should be denied.
	if rl.Allow(ip) {
		t.Fatal("request 4 should be denied")
	}
}

func TestRateLimiter_WindowExpiry(t *testing.T) {
	window := 50 * time.Millisecond
	rl := NewRateLimiter(1, window)
	defer rl.Stop()

	ip := "10.0.0.1"

	if !rl.Allow(ip) {
		t.Fatal("first request should be allowed")
	}
	if rl.Allow(ip) {
		t.Fatal("second request should be denied within window")
	}

	// Wait for the window to expire.
	time.Sleep(window + 10*time.Millisecond)

	if !rl.Allow(ip) {
		t.Fatal("request after window expiry should be allowed")
	}
}

func TestRateLimiter_MultipleIPs(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	defer rl.Stop()

	if !rl.Allow("1.1.1.1") {
		t.Fatal("first IP first request should be allowed")
	}
	if rl.Allow("1.1.1.1") {
		t.Fatal("first IP second request should be denied")
	}

	// A different IP should have its own limit.
	if !rl.Allow("2.2.2.2") {
		t.Fatal("second IP first request should be allowed")
	}
}

func TestRateLimiter_Middleware(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	defer rl.Stop()

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	makeRequest := func() int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	// First 2 requests should succeed.
	for i := 1; i <= 2; i++ {
		if code := makeRequest(); code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, code)
		}
	}

	// 3rd request should be rate limited.
	if code := makeRequest(); code != http.StatusTooManyRequests {
		t.Fatalf("request 3: expected 429, got %d", code)
	}
}

func TestExtractIP_Spoofing(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		trustProxy bool
		wantIP     string
	}{
		{
			name:       "no proxy, uses RemoteAddr",
			remoteAddr: "1.2.3.4:9999",
			trustProxy: false,
			wantIP:     "1.2.3.4",
		},
		{
			name:       "trust proxy, single XFF",
			remoteAddr: "127.0.0.1:9999",
			xff:        "5.6.7.8",
			trustProxy: true,
			wantIP:     "5.6.7.8",
		},
		{
			name:       "trust proxy, spoofed XFF takes last IP",
			remoteAddr: "127.0.0.1:9999",
			xff:        "spoofed.ip.1.1, real.ip.2.2",
			trustProxy: true,
			wantIP:     "real.ip.2.2",
		},
		{
			name:       "trust proxy, multiple XFF entries takes last",
			remoteAddr: "127.0.0.1:9999",
			xff:        "client, proxy1, proxy2",
			trustProxy: true,
			wantIP:     "proxy2",
		},
		{
			name:       "trust proxy off, ignores XFF",
			remoteAddr: "9.8.7.6:1234",
			xff:        "attacker",
			trustProxy: false,
			wantIP:     "9.8.7.6",
		},
		{
			name:       "trust proxy, no XFF header falls back to RemoteAddr",
			remoteAddr: "4.3.2.1:5555",
			xff:        "",
			trustProxy: true,
			wantIP:     "4.3.2.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}

			got := extractIP(req, tc.trustProxy)
			if got != tc.wantIP {
				t.Errorf("extractIP() = %q, want %q", got, tc.wantIP)
			}
		})
	}
}
