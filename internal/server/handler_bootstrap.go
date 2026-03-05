// SPDX-License-Identifier: MIT

package server

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const githubReleaseBaseURL = "https://github.com/zyno-io/sp2p/releases/latest/download"

// BootstrapHandler serves bootstrap shell scripts and CLI binary downloads.
type BootstrapHandler struct {
	baseURL  string
	wsURL    string
	resolver *ReleaseResolver
}

// NewBootstrapHandler creates a new bootstrap handler.
// It validates that baseURL and wsURL are well-formed URLs to prevent
// shell injection in generated bootstrap scripts.
// The resolver is optional — if nil, redirects fall back to GitHub's latest release URL.
func NewBootstrapHandler(baseURL, wsURL string, resolver *ReleaseResolver) (*BootstrapHandler, error) {
	// Validate URLs to prevent shell metacharacter injection.
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("invalid baseURL: %w", err)
	}
	if _, err := url.Parse(wsURL); err != nil {
		return nil, fmt.Errorf("invalid wsURL: %w", err)
	}
	// Reject URLs containing shell-dangerous characters.
	for _, u := range []string{baseURL, wsURL} {
		if strings.ContainsAny(u, "\"'`$\\!;|&(){}") {
			return nil, fmt.Errorf("URL contains unsafe characters: %s", u)
		}
	}
	return &BootstrapHandler{
		baseURL:  baseURL,
		wsURL:    wsURL,
		resolver: resolver,
	}, nil
}

// ServeSendScript serves the send bootstrap script.
func (h *BootstrapHandler) ServeSendScript(w http.ResponseWriter, r *http.Request) {
	script := generateScript("send", h.baseURL, h.wsURL)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
}

// ServeRecvScript serves the receive bootstrap script.
func (h *BootstrapHandler) ServeRecvScript(w http.ResponseWriter, r *http.Request) {
	script := generateScript("receive", h.baseURL, h.wsURL)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
}

// validAssetExtensions lists file extensions allowed for /dl/{filename} requests.
var validAssetExtensions = []string{".tar.gz", ".zip", ".deb", ".rpm", ".apk"}

// ServeBinary handles two URL patterns:
//   - /dl/{os}/{arch}   — redirects to the platform-specific archive
//   - /dl/{filename}    — redirects to a named asset (e.g. sp2p_amd64.deb)
//
// In dev mode (baseURL empty or localhost), /dl/{os}/{arch} serves the current
// binary directly for the matching platform.
func (h *BootstrapHandler) ServeBinary(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/dl/"), "/")

	switch len(parts) {
	case 2:
		h.serveBinaryByPlatform(w, r, parts[0], parts[1])
	case 1:
		h.serveBinaryByFilename(w, r, parts[0])
	default:
		http.Error(w, "expected /dl/{os}/{arch} or /dl/{filename}", http.StatusBadRequest)
	}
}

// serveBinaryByPlatform handles /dl/{os}/{arch} requests.
func (h *BootstrapHandler) serveBinaryByPlatform(w http.ResponseWriter, r *http.Request, reqOS, reqArch string) {
	validOS := map[string]bool{"linux": true, "darwin": true, "windows": true}
	validArch := map[string]bool{"amd64": true, "arm64": true}

	if !validOS[reqOS] || !validArch[reqArch] {
		http.Error(w, "unsupported platform", http.StatusNotFound)
		return
	}

	// Dev mode: serve the current binary as a tar.gz if the platform matches.
	if h.isDevMode() && reqOS == runtime.GOOS && reqArch == runtime.GOARCH {
		h.serveLocalBinary(w)
		return
	}

	ext := ".tar.gz"
	if reqOS == "windows" {
		ext = ".zip"
	}
	assetName := fmt.Sprintf("sp2p_%s_%s%s", reqOS, reqArch, ext)
	h.redirectToAsset(w, r, assetName)
}

// serveBinaryByFilename handles /dl/{filename} requests.
func (h *BootstrapHandler) serveBinaryByFilename(w http.ResponseWriter, r *http.Request, filename string) {
	if filename == "" {
		http.Error(w, "expected /dl/{os}/{arch} or /dl/{filename}", http.StatusBadRequest)
		return
	}

	// Validate filename: must start with "sp2p", have a known extension, no path traversal.
	if !strings.HasPrefix(filename, "sp2p") {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}
	if strings.Contains(filename, "..") || strings.ContainsAny(filename, "/\\") {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}
	validExt := false
	for _, ext := range validAssetExtensions {
		if strings.HasSuffix(filename, ext) {
			validExt = true
			break
		}
	}
	if !validExt {
		http.Error(w, "unsupported file type", http.StatusBadRequest)
		return
	}

	h.redirectToAsset(w, r, filename)
}

// redirectToAsset resolves the asset URL via the resolver (if available) and redirects.
func (h *BootstrapHandler) redirectToAsset(w http.ResponseWriter, r *http.Request, assetName string) {
	if h.resolver != nil {
		target, err := h.resolver.ResolveAssetURL(r.Context(), assetName)
		if err != nil {
			http.Error(w, "failed to resolve asset", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	// No resolver — fall back to latest release URL.
	target := fmt.Sprintf("%s/%s", githubReleaseBaseURL, assetName)
	http.Redirect(w, r, target, http.StatusFound)
}

// serveLocalBinary serves the current binary as a tar.gz for dev mode.
func (h *BootstrapHandler) serveLocalBinary(w http.ResponseWriter) {
	exe, err := os.Executable()
	if err != nil {
		http.Error(w, "cannot determine current binary", http.StatusInternalServerError)
		return
	}
	exe, _ = filepath.EvalSymlinks(exe)

	f, err := os.Open(exe)
	if err != nil {
		http.Error(w, "cannot open binary", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		http.Error(w, "cannot stat binary", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="sp2p.tar.gz"`)

	gw := gzip.NewWriter(w)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	tw.WriteHeader(&tar.Header{
		Name: "sp2p",
		Size: info.Size(),
		Mode: 0o755,
	})
	io.Copy(tw, f)
}

// isDevMode returns true when the server is running in development mode
// (baseURL is empty or points to localhost).
func (h *BootstrapHandler) isDevMode() bool {
	if h.baseURL == "" {
		return true
	}
	u, err := url.Parse(h.baseURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func generateScript(command, baseURL, wsURL string) string {
	return fmt.Sprintf(`#!/bin/sh
# SP2P bootstrap — downloads the CLI and runs %s.
main() {
    set -e

    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) ARCH=amd64 ;;
        aarch64|arm64) ARCH=arm64 ;;
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac

    case "$OS" in
        linux|darwin) ;;
        *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
    esac

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    echo "Downloading sp2p..." >&2
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "%s/dl/${OS}/${ARCH}" -o "$TMPDIR/sp2p.tar.gz"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$TMPDIR/sp2p.tar.gz" "%s/dl/${OS}/${ARCH}"
    else
        echo "Error: curl or wget is required" >&2; exit 1
    fi
    tar xz -C "$TMPDIR" -f "$TMPDIR/sp2p.tar.gz"
    chmod +x "$TMPDIR/sp2p"

    SP2P_SERVER="%s" SP2P_URL="%s" "$TMPDIR/sp2p" %s "$@"
}
main "$@"
`, command, baseURL, baseURL, wsURL, baseURL, command)
}

// ServeSendPSScript serves the send bootstrap script for PowerShell.
func (h *BootstrapHandler) ServeSendPSScript(w http.ResponseWriter, r *http.Request) {
	script := generatePSScript("send", h.baseURL, h.wsURL)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
}

// ServeRecvPSScript serves the receive bootstrap script for PowerShell.
func (h *BootstrapHandler) ServeRecvPSScript(w http.ResponseWriter, r *http.Request) {
	script := generatePSScript("receive", h.baseURL, h.wsURL)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
}

func generatePSScript(command, baseURL, wsURL string) string {
	return fmt.Sprintf(`# SP2P bootstrap — downloads the CLI and runs %s.
$ErrorActionPreference = 'Stop'

if ($IsWindows -or $env:OS -eq 'Windows_NT') { $os = 'windows' }
elseif ($IsMacOS) { $os = 'darwin' }
elseif ($IsLinux) { $os = 'linux' }
else { throw 'Unsupported OS' }

try { $arch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLower() }
catch { $arch = $env:PROCESSOR_ARCHITECTURE.ToLower() }
switch ($arch) {
    'x64'   { $arch = 'amd64' }
    'amd64' { $arch = 'amd64' }
    'arm64' { $arch = 'arm64' }
    default { throw "Unsupported architecture: $arch" }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) "sp2p-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $ext = if ($os -eq 'windows') { '.zip' } else { '.tar.gz' }
    $archive = Join-Path $tmp "sp2p$ext"
    Write-Host 'Downloading sp2p...' -ForegroundColor DarkGray
    Invoke-WebRequest -Uri "%s/dl/$os/$arch" -OutFile $archive
    if ($os -eq 'windows') {
        Expand-Archive -Path $archive -DestinationPath $tmp
    } else {
        tar xzf $archive -C $tmp
    }
    $binExt = if ($os -eq 'windows') { '.exe' } else { '' }
    $bin = Join-Path $tmp "sp2p$binExt"
    if ($os -ne 'windows') { chmod +x $bin }
    $env:SP2P_SERVER = '%s'
    $env:SP2P_URL = '%s'
    & $bin %s @args
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
`, command, baseURL, wsURL, baseURL, command)
}

// isScriptClient detects if the request is from a CLI tool (curl, wget, etc.) vs a browser.
func isScriptClient(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/html") {
		return false
	}
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	for _, prefix := range []string{"curl/", "wget/", "httpie/", "libcurl/"} {
		if strings.HasPrefix(ua, prefix) {
			return true
		}
	}
	return accept == "" || !strings.Contains(accept, "text/html")
}
