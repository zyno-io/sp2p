// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"

	"golang.org/x/crypto/acme/autocert"
)

// ACMEManager wraps autocert.Manager to provide automatic TLS certificates
// via the ACME protocol (HTTP-01 challenge).
type ACMEManager struct {
	mgr    *autocert.Manager
	httpSrv *http.Server
}

// NewACMEManager creates an ACMEManager for the given domain.
func NewACMEManager(domain, email, cacheDir string) *ACMEManager {
	mgr := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      autocert.DirCache(cacheDir),
		Email:      email,
	}
	return &ACMEManager{
		mgr: mgr,
		httpSrv: &http.Server{
			Addr:    ":80",
			Handler: mgr.HTTPHandler(nil), // HTTP-01 challenges + HTTP→HTTPS redirect
		},
	}
}

// TLSConfig returns a tls.Config that obtains certificates via ACME.
func (a *ACMEManager) TLSConfig() *tls.Config {
	return a.mgr.TLSConfig()
}

// ListenHTTP starts the HTTP server on :80 for ACME challenges and
// HTTP→HTTPS redirect. This blocks; call it in a goroutine.
func (a *ACMEManager) ListenHTTP() {
	slog.Info("ACME HTTP listener starting", "addr", a.httpSrv.Addr)
	if err := a.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("ACME HTTP listener error", "err", err)
	}
}

// Shutdown gracefully shuts down the HTTP-01 challenge server.
func (a *ACMEManager) Shutdown(ctx context.Context) {
	a.httpSrv.Shutdown(ctx)
}
