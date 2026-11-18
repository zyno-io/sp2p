// SPDX-License-Identifier: MIT

// Command gate is the only deployment-hook listener the tunnel can reach.
// webhook buffers whole request bodies before checking signatures and has no
// size limit, so the gate rejects anything larger than a deployment request
// and bounds slow clients before forwarding to webhook on a private network.
package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

const (
	hookPath = "/hooks/sp2p-deploy"
	// A signed request is a version and a timestamp; 4 KiB leaves ample room.
	maxBodyBytes   = 4 << 10
	maxHeaderBytes = 16 << 10
)

func newHandler(upstream *url.URL) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != hookPath {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		// Forward a fully read, fixed-length body so webhook never streams
		// from the client.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.TransferEncoding = nil
		proxy.ServeHTTP(w, r)
	})
}

func main() {
	listen := flag.String("listen", ":9000", "address to listen on")
	upstreamURL := flag.String("upstream", "http://webhook:9000", "webhook base URL")
	flag.Parse()

	upstream, err := url.Parse(*upstreamURL)
	if err != nil || (upstream.Scheme != "http" && upstream.Scheme != "https") || upstream.Host == "" {
		log.Fatalf("invalid upstream URL %q", *upstreamURL)
	}
	server := &http.Server{
		Addr:              *listen,
		Handler:           newHandler(upstream),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	log.Printf("forwarding %s on %s to %s", hookPath, *listen, upstream.Redacted())
	log.Fatal(server.ListenAndServe())
}
