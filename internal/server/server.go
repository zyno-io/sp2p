// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/zyno-io/sp2p/internal/signal"
)

// Config holds server configuration.
type Config struct {
	Addr      string
	BaseURL   string    // e.g., "https://sp2p.io"
	WebFS     *embed.FS // embedded web UI files (optional)
	Version   string    // server version (e.g., "1.0.0" or "dev")
	BuildTime string    // build timestamp (e.g., "2025-01-15T12:00:00Z")
	STUNServers []signal.ICEServer       // STUN servers to advertise to clients (optional)
	StaticTURN  []signal.ICEServer       // static TURN servers with fixed credentials (optional)
	TURNGen     *TURNCredentialGenerator // ephemeral TURN credential generator (optional, mutually exclusive with StaticTURN)
	MaxSessions      int  // global session cap (0 = default 1000)
	MaxSessionsPerIP int  // per-IP session cap (0 = default 10)
	TrustProxy bool               // trust X-Forwarded-For for rate limiting (set when behind a reverse proxy)
	TLSCert    string             // path to TLS certificate file (optional)
	TLSKey     string             // path to TLS private key file (optional)
	ACME       bool               // enable ACME auto-certificates (domain derived from BaseURL)
	ACMEEmail  string             // contact email for ACME (optional)
	ConfigDir  string             // directory for persistent data like ACME certs (optional)
}

// Server is the SP2P signaling server.
type Server struct {
	config       Config
	sessions     *SessionManager
	limiter      *RateLimiter
	stats        *StatsTracker
	releases     *ReleaseResolver
	http         *http.Server
	certReloader *CertReloader
	acme         *ACMEManager
}

// New creates a new signaling server.
func New(cfg Config) (*Server, error) {
	sessions := NewSessionManager(cfg.MaxSessions, cfg.MaxSessionsPerIP)

	// Build the WebSocket URL from BaseURL.
	wsURL := cfg.BaseURL
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	wsURL += "/ws"

	// Derive allowed WebSocket origins from BaseURL.
	// In dev mode (no BaseURL), allow all origins.
	var originPatterns []string
	if cfg.BaseURL != "" {
		if u, err := url.Parse(cfg.BaseURL); err == nil && u.Host != "" {
			originPatterns = []string{u.Host}
		}
	}
	if len(originPatterns) == 0 {
		originPatterns = []string{"*"}
	}

	// Create release resolver for production (non-dev) mode.
	// Start() is deferred until after all fallible constructor steps
	// to avoid leaking a polling goroutine on error.
	var resolver *ReleaseResolver
	if cfg.BaseURL != "" {
		if u, err := url.Parse(cfg.BaseURL); err == nil {
			host := u.Hostname()
			if host != "localhost" && host != "127.0.0.1" && host != "::1" {
				resolver = NewReleaseResolver()
			}
		}
	}

	stats := NewStatsTracker(cfg.ConfigDir)
	signalHandler := NewSignalHandler(sessions, cfg.Version, cfg.BaseURL, cfg.STUNServers, cfg.StaticTURN, cfg.TURNGen, resolver, originPatterns, cfg.TrustProxy, stats)
	fileInfoHandler := NewFileInfoHandler(sessions)

	bootstrapHandler, err := NewBootstrapHandler(cfg.BaseURL, wsURL, resolver)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	webHandler := NewWebHandler(cfg.WebFS, cfg.Version, cfg.BuildTime)

	// Rate limit: 30 WebSocket connections per IP per minute.
	wsLimiter := NewRateLimiter(30, time.Minute)
	wsLimiter.TrustProxy = cfg.TrustProxy

	mux := http.NewServeMux()

	// WebSocket endpoint with rate limiting.
	mux.Handle("/ws", wsLimiter.Middleware(signalHandler))

	// File-info API (encrypted metadata for receiver preview).
	mux.Handle("/api/file-info/", fileInfoHandler)

	// Health check.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Binary downloads.
	mux.HandleFunc("/dl/", bootstrapHandler.ServeBinary)

	// Root: curl gets send bootstrap script, browser gets send UI.
	// Non-root paths are served as static assets from the embedded web UI
	// (hashed filenames like main-abc123.js, style-abc123.css).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			// Try serving as a static asset from the web UI.
			if webHandler.fileServer != nil {
				setAssetCacheHeaders(w, r.URL.Path)
				webHandler.fileServer.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}
		if isScriptClient(r) {
			bootstrapHandler.ServeSendScript(w, r)
		} else {
			webHandler.ServeSendPage(w, r)
		}
	})

	// PowerShell bootstrap scripts.
	mux.HandleFunc("/ps", func(w http.ResponseWriter, r *http.Request) {
		bootstrapHandler.ServeSendPSScript(w, r)
	})
	mux.HandleFunc("/ps/r", func(w http.ResponseWriter, r *http.Request) {
		bootstrapHandler.ServeRecvPSScript(w, r)
	})

	// Receive: curl gets recv bootstrap script, browser gets receive UI.
	mux.HandleFunc("/r", func(w http.ResponseWriter, r *http.Request) {
		if isScriptClient(r) {
			bootstrapHandler.ServeRecvScript(w, r)
		} else {
			webHandler.ServeReceivePage(w, r)
		}
	})

	tlsActive := cfg.TLSCert != "" || cfg.ACME

	// Validate base URL scheme matches TLS mode.
	if tlsActive && !strings.HasPrefix(cfg.BaseURL, "https://") {
		return nil, fmt.Errorf("base URL must use https:// when TLS or ACME is enabled (got %s)", cfg.BaseURL)
	}

	s := &Server{
		config:   cfg,
		sessions: sessions,
		limiter:  wsLimiter,
		stats:    stats,
		releases: resolver,
		http: &http.Server{
			Addr:              cfg.Addr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		},
	}

	// Set up TLS or ACME if configured.
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cr, err := NewCertReloader(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
		s.certReloader = cr
	} else if cfg.ACME {
		u, err := url.Parse(cfg.BaseURL)
		if err != nil || u.Hostname() == "" {
			return nil, fmt.Errorf("acme: cannot derive domain from base URL: %s", cfg.BaseURL)
		}
		cacheDir := filepath.Join(cfg.ConfigDir, "acme")
		s.acme = NewACMEManager(u.Hostname(), cfg.ACMEEmail, cacheDir)
	}

	// Start background polling now that all fallible steps have passed.
	if resolver != nil {
		resolver.Start()
	}

	return s, nil
}

// Handler returns the server's HTTP handler for use with httptest.
func (s *Server) Handler() http.Handler {
	return s.http.Handler
}

// Start starts the server.
func (s *Server) Start() error {
	slog.Info("server listening", "addr", s.config.Addr)
	switch {
	case s.acme != nil:
		go s.acme.ListenHTTP()
		s.http.TLSConfig = s.acme.TLSConfig()
		return s.http.ListenAndServeTLS("", "")
	case s.certReloader != nil:
		s.http.TLSConfig = s.certReloader.TLSConfig()
		return s.http.ListenAndServeTLS("", "")
	default:
		return s.http.ListenAndServe()
	}
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.sessions.Stop()
	s.limiter.Stop()
	s.stats.Stop()
	if s.releases != nil {
		s.releases.Stop()
	}
	if s.certReloader != nil {
		s.certReloader.Stop()
	}
	if s.acme != nil {
		s.acme.Shutdown(ctx)
	}
	return s.http.Shutdown(ctx)
}
