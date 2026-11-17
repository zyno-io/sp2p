// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// newDeployProxy forwards one fixed route to an operator-configured sidecar.
// The sidecar authenticates signed requests and exclusively owns Docker access.
func newDeployProxy(rawURL string) (http.Handler, error) {
	target, err := url.Parse(rawURL)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" ||
		target.User != nil || (target.Path != "" && target.Path != "/") || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" {
		return nil, fmt.Errorf("deploy-webhook-url must be an HTTP(S) origin without credentials, path, query, or fragment")
	}
	target.Path = ""
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(target)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "deployment sidecar unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "deployment request too large", http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, "invalid deployment request", http.StatusBadRequest)
			}
			return
		}
		// Preserve the exact signed bytes; do not parse or re-encode JSON here.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.TransferEncoding = nil
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		proxy.ServeHTTP(w, r.WithContext(ctx))
	}), nil
}
