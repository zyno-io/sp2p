// SPDX-License-Identifier: MIT

package server

import (
	"crypto/tls"
	"log/slog"
	"os"
	"sync"
	"time"
)

// CertReloader loads a TLS certificate from disk and reloads it when the file changes.
// It polls the certificate and key file modification times every 30 seconds.
type CertReloader struct {
	certFile string
	keyFile  string

	mu          sync.RWMutex
	cert        *tls.Certificate
	certModTime time.Time
	keyModTime  time.Time

	once sync.Once
	done chan struct{}
}

// NewCertReloader creates a CertReloader that loads the given cert/key pair.
// It returns an error if the initial load fails.
func NewCertReloader(certFile, keyFile string) (*CertReloader, error) {
	cr := &CertReloader{
		certFile: certFile,
		keyFile:  keyFile,
		done:     make(chan struct{}),
	}
	if err := cr.load(); err != nil {
		return nil, err
	}
	go cr.poll()
	return cr, nil
}

// TLSConfig returns a tls.Config that uses GetCertificate to serve the latest cert.
func (cr *CertReloader) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: cr.GetCertificate,
	}
}

// GetCertificate returns the current certificate. It implements the
// tls.Config.GetCertificate callback.
func (cr *CertReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.cert, nil
}

// Stop stops the background polling goroutine. It is safe to call multiple times.
func (cr *CertReloader) Stop() {
	cr.once.Do(func() { close(cr.done) })
}

func (cr *CertReloader) load() error {
	cert, err := tls.LoadX509KeyPair(cr.certFile, cr.keyFile)
	if err != nil {
		return err
	}
	certInfo, err := os.Stat(cr.certFile)
	if err != nil {
		return err
	}
	keyInfo, err := os.Stat(cr.keyFile)
	if err != nil {
		return err
	}
	cr.mu.Lock()
	cr.cert = &cert
	cr.certModTime = certInfo.ModTime()
	cr.keyModTime = keyInfo.ModTime()
	cr.mu.Unlock()
	return nil
}

func (cr *CertReloader) poll() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-cr.done:
			return
		case <-ticker.C:
			certInfo, err := os.Stat(cr.certFile)
			if err != nil {
				slog.Warn("cert reload: stat cert failed", "err", err)
				continue
			}
			keyInfo, err := os.Stat(cr.keyFile)
			if err != nil {
				slog.Warn("cert reload: stat key failed", "err", err)
				continue
			}
			cr.mu.RLock()
			changed := certInfo.ModTime() != cr.certModTime || keyInfo.ModTime() != cr.keyModTime
			cr.mu.RUnlock()
			if changed {
				if err := cr.load(); err != nil {
					slog.Warn("cert reload: load failed", "err", err)
				} else {
					slog.Info("cert reloaded", "cert", cr.certFile, "key", cr.keyFile)
				}
			}
		}
	}
}
