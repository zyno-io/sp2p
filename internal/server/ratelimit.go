// SPDX-License-Identifier: MIT

package server

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// RateLimiter provides per-IP rate limiting.
type RateLimiter struct {
	mu             sync.Mutex
	visitors       map[string]*visitor
	rate           int           // max requests per window
	window         time.Duration // window duration
	TrustProxy     bool          // when true, use X-Forwarded-For to extract client IP
	TrustedProxies []netip.Prefix
	done           chan struct{}
	stopOnce       sync.Once
}

type visitor struct {
	count    int
	windowAt time.Time
}

// NewRateLimiter creates a rate limiter with the given rate per window.
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
		done:     make(chan struct{}),
	}
	// Cleanup goroutine.
	go func() {
		ticker := time.NewTicker(window)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rl.mu.Lock()
				now := time.Now()
				for ip, v := range rl.visitors {
					if now.Sub(v.windowAt) > window*2 {
						delete(rl.visitors, ip)
					}
				}
				rl.mu.Unlock()
			case <-rl.done:
				return
			}
		}
	}()
	return rl
}

// Stop stops the cleanup goroutine. Safe to call multiple times.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() { close(rl.done) })
}

// Allow checks if the IP is within the rate limit.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, ok := rl.visitors[ip]
	if !ok || now.Sub(v.windowAt) > rl.window {
		if !ok && len(rl.visitors) >= 65536 {
			return false
		}
		rl.visitors[ip] = &visitor{count: 1, windowAt: now}
		return true
	}

	v.count++
	return v.count <= rl.rate
}

// Middleware wraps an http.Handler with rate limiting.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r, rl.TrustProxy, rl.TrustedProxies...)
		if !rl.Allow(ip) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func extractIP(r *http.Request, trustProxy bool, proxies ...netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	direct, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	direct = direct.Unmap()
	trusted := func(ip netip.Addr) bool {
		for _, prefix := range proxies {
			if prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	if !trustProxy || !trusted(direct) {
		return direct.String()
	}
	current := direct
	chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	if len(chain) > 32 {
		return direct.String()
	}
	for i := len(chain) - 1; i >= 0 && trusted(current); i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(chain[i]))
		if err != nil {
			return direct.String()
		}
		current = ip.Unmap()
	}
	return current.String()
}
