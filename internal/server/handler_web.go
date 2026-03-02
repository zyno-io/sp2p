// SPDX-License-Identifier: MIT

package server

import (
	"embed"
	"html"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
)

// WebHandler serves the web UI from embedded files.
type WebHandler struct {
	distFS    fs.FS
	fileServer http.Handler
	version   string
	buildTime string
}

// NewWebHandler creates a web handler serving from an embed.FS.
// If webFS is nil or the dist directory is empty, it serves a placeholder.
func NewWebHandler(webFS *embed.FS, version, buildTime string) *WebHandler {
	h := &WebHandler{version: version, buildTime: buildTime}

	if webFS == nil {
		return h
	}

	sub, err := fs.Sub(*webFS, "web/dist")
	if err != nil {
		return h
	}

	// Verify the dist directory has content.
	entries, err := fs.ReadDir(sub, ".")
	if err != nil || len(entries) == 0 {
		return h
	}

	h.distFS = sub
	h.fileServer = http.FileServer(http.FS(sub))
	return h
}

// injectVersionPlaceholders replaces version/build-time placeholders in HTML.
func (h *WebHandler) injectVersionPlaceholders(data []byte) []byte {
	s := string(data)
	s = strings.ReplaceAll(s, "<!--SP2P_VERSION-->", html.EscapeString(h.version))
	s = strings.ReplaceAll(s, "<!--SP2P_BUILD_TIME-->", html.EscapeString(h.buildTime))
	return []byte(s)
}

// ServeSendPage serves the web send UI.
func (h *WebHandler) ServeSendPage(w http.ResponseWriter, r *http.Request) {
	if h.distFS == nil {
		servePlaceholder(w, "SP2P", "Web UI not built. Run <code>make build-web</code> first.")
		return
	}
	setSecurityHeaders(w)
	h.serveHTML(w, r, "index.html")
}

// ServeReceivePage serves the web receive UI.
func (h *WebHandler) ServeReceivePage(w http.ResponseWriter, r *http.Request) {
	if h.distFS == nil {
		servePlaceholder(w, "SP2P Receive", "Web UI not built.")
		return
	}
	setSecurityHeaders(w)
	h.serveHTML(w, r, "receive.html")
}

// ServeAsset serves static assets (CSS, JS, etc.).
func (h *WebHandler) ServeAsset(w http.ResponseWriter, r *http.Request) {
	if h.fileServer == nil {
		http.NotFound(w, r)
		return
	}
	// Strip /assets/ prefix — files are in the root of web/dist/.
	r.URL.Path = strings.TrimPrefix(r.URL.Path, "/assets")
	h.fileServer.ServeHTTP(w, r)
}

// serveHTML serves an HTML file with version placeholder injection.
func (h *WebHandler) serveHTML(w http.ResponseWriter, r *http.Request, name string) {
	data, err := fs.ReadFile(h.distFS, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(h.injectVersionPlaceholders(data))
}

func servePlaceholder(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Title is escaped; body is trusted static HTML from callers.
	w.Write([]byte(`<!DOCTYPE html><html><body><h1>` + html.EscapeString(title) + `</h1><p>` + body + `</p></body></html>`))
}

// hashedAssetPattern matches filenames with a content hash (e.g., main-IMLNX3OE.js).
var hashedAssetPattern = regexp.MustCompile(`-[A-Z0-9]{8}\.(js|css)(\.map)?$`)

// setAssetCacheHeaders sets cache headers for static assets.
// Hashed assets get long-lived immutable caching; unhashed assets get no-cache.
func setAssetCacheHeaders(w http.ResponseWriter, path string) {
	if hashedAssetPattern.MatchString(path) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' wss: ws:; style-src 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
}
