// SPDX-License-Identifier: MIT

package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter provides per-IP rate limiting.
type RateLimiter struct {
	mu         sync.Mutex
	visitors   map[string]*visitor
	rate       int           // max requests per window
	window     time.Duration // window duration
	TrustProxy bool          // when true, use X-Forwarded-For to extract client IP
	done       chan struct{}
	stopOnce   sync.Once
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
		rl.visitors[ip] = &visitor{count: 1, windowAt: now}
		return true
	}

	v.count++
	return v.count <= rl.rate
}

// Middleware wraps an http.Handler with rate limiting.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r, rl.TrustProxy)
		if !rl.Allow(ip) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func extractIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the last IP — the one appended by the trusted reverse
			// proxy. Taking the first IP is unsafe because the client can
			// prepend arbitrary values to spoof their address.
			last := xff
			for i := len(xff) - 1; i >= 0; i-- {
				if xff[i] == ',' {
					last = xff[i+1:]
					break
				}
			}
			return strings.TrimSpace(last)
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
