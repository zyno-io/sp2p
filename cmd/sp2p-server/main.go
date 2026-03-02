// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sp2p "github.com/zyno-io/sp2p"
	"github.com/zyno-io/sp2p/internal/server"
	sigsignal "github.com/zyno-io/sp2p/internal/signal"
)

var version = "dev"
var buildTime string     // set via ldflags (e.g., "2025-01-15T12:00:00Z")
var defaultBaseURL string // set via ldflags for release builds

func main() {
	base := "http://localhost:8080"
	if defaultBaseURL != "" {
		base = defaultBaseURL
	}

	addr := flag.String("addr", envOr("SP2P_ADDR", ":8080"), "listen address (env: SP2P_ADDR)")
	baseURL := flag.String("base-url", envOr("SP2P_BASE_URL", base), "public base URL (env: SP2P_BASE_URL)")
	turnServers := flag.String("turn-servers", envOr("SP2P_TURN_SERVERS", ""), "comma-separated TURN server URLs (env: SP2P_TURN_SERVERS)")
	turnUsername := flag.String("turn-username", envOr("SP2P_TURN_USERNAME", ""), "TURN static username (env: SP2P_TURN_USERNAME)")
	turnPassword := flag.String("turn-password", envOr("SP2P_TURN_PASSWORD", ""), "TURN static password (env: SP2P_TURN_PASSWORD)")
	turnSecret := flag.String("turn-secret", envOr("SP2P_TURN_SECRET", ""), "shared secret for ephemeral TURN credentials (env: SP2P_TURN_SECRET)")
	turnTTL := flag.String("turn-ttl", envOr("SP2P_TURN_TTL", "5m"), "TTL for ephemeral TURN credentials (env: SP2P_TURN_TTL)")
	trustProxy := flag.Bool("trust-proxy", envOr("SP2P_TRUST_PROXY", "") != "", "trust X-Forwarded-For for rate limiting (env: SP2P_TRUST_PROXY)")
	tlsCert := flag.String("tls-cert", envOr("SP2P_TLS_CERT", ""), "TLS certificate file (env: SP2P_TLS_CERT)")
	tlsKey := flag.String("tls-key", envOr("SP2P_TLS_KEY", ""), "TLS private key file (env: SP2P_TLS_KEY)")
	acme := flag.Bool("acme", envBool("SP2P_ACME"), "enable ACME auto-certificates, domain derived from --base-url (env: SP2P_ACME)")
	acmeEmail := flag.String("acme-email", envOr("SP2P_ACME_EMAIL", ""), "contact email for ACME (env: SP2P_ACME_EMAIL)")
	configDir := flag.String("config-dir", envOr("SP2P_CONFIG_DIR", defaultConfigDir()), "directory for persistent data like ACME certs (env: SP2P_CONFIG_DIR)")
	flag.Parse()

	// Validate TURN credential modes are mutually exclusive.
	if *turnSecret != "" && (*turnUsername != "" || *turnPassword != "") {
		slog.Error("--turn-secret and --turn-username/--turn-password are mutually exclusive")
		os.Exit(1)
	}

	// Validate mutual exclusivity of TLS modes.
	if (*tlsCert != "" || *tlsKey != "") && *acme {
		slog.Error("--tls-cert/--tls-key and --acme are mutually exclusive")
		os.Exit(1)
	}
	if (*tlsCert != "") != (*tlsKey != "") {
		slog.Error("both --tls-cert and --tls-key must be provided together")
		os.Exit(1)
	}
	if *acme && *configDir == "" {
		slog.Error("--config-dir is required when --acme is enabled")
		os.Exit(1)
	}

	// Default to :443 when TLS is active and addr wasn't explicitly set.
	tlsActive := *tlsCert != "" || *acme
	if tlsActive && *addr == ":8080" && envOr("SP2P_ADDR", "") == "" {
		*addr = ":443"
	}

	slog.Info("starting", "version", version)

	// Split TURN server URLs and build STUN/TURN configuration.
	var turnURLs []string
	if *turnServers != "" {
		for _, u := range strings.Split(*turnServers, ",") {
			turnURLs = append(turnURLs, strings.TrimSpace(u))
		}
	}

	// Separate STUN and TURN URLs.
	var stunURLs, turnOnlyURLs []string
	for _, u := range turnURLs {
		if strings.HasPrefix(u, "turn:") || strings.HasPrefix(u, "turns:") {
			turnOnlyURLs = append(turnOnlyURLs, u)
		} else {
			stunURLs = append(stunURLs, u)
		}
	}

	var stunServers []sigsignal.ICEServer
	if len(stunURLs) > 0 {
		stunServers = append(stunServers, sigsignal.ICEServer{URLs: stunURLs})
	}

	var staticTURN []sigsignal.ICEServer
	var turnGen *server.TURNCredentialGenerator

	if *turnSecret != "" && len(turnOnlyURLs) > 0 {
		ttl, err := time.ParseDuration(*turnTTL)
		if err != nil {
			slog.Error("invalid --turn-ttl", "err", err)
			os.Exit(1)
		}
		if ttl <= 0 {
			slog.Error("--turn-ttl must be positive")
			os.Exit(1)
		}
		turnGen = &server.TURNCredentialGenerator{
			URLs:   turnOnlyURLs,
			Secret: *turnSecret,
			TTL:    ttl,
		}
		slog.Info("TURN servers configured (ephemeral credentials)", "urls", turnOnlyURLs, "ttl", ttl)
	} else if len(turnOnlyURLs) > 0 {
		staticTURN = append(staticTURN, sigsignal.ICEServer{
			URLs:       turnOnlyURLs,
			Username:   *turnUsername,
			Credential: *turnPassword,
		})
		slog.Info("TURN servers configured (static credentials)", "urls", turnOnlyURLs)
	}

	webFS := sp2p.WebFS
	srv, err := server.New(server.Config{
		Addr:        *addr,
		BaseURL:     *baseURL,
		WebFS:       &webFS,
		Version:     version,
		BuildTime:   buildTime,
		STUNServers: stunServers,
		StaticTURN:  staticTURN,
		TURNGen:     turnGen,
		TrustProxy:  *trustProxy,
		TLSCert:     *tlsCert,
		TLSKey:      *tlsKey,
		ACME:        *acme,
		ACMEEmail:   *acmeEmail,
		ConfigDir:   *configDir,
	})
	if err != nil {
		slog.Error("server init failed", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go func() {
		if err := srv.Start(); err != nil {
			slog.Error("server error", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
}

func defaultConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "sp2p")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string) bool {
	v, _ := strconv.ParseBool(os.Getenv(key))
	return v
}
