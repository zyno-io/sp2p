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
// Adding ?resolve=1 to a platform URL returns its pinned GitHub release URL as
// text, or 503 if unavailable; bootstrap uses this to pair archive and checksum.
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
	ext := ".tar.gz"
	if reqOS == "windows" {
		ext = ".zip"
	}
	assetName := fmt.Sprintf("sp2p_%s_%s%s", reqOS, reqArch, ext)
	if r.URL.Query().Get("resolve") == "1" {
		h.serveReleaseAssetURL(w, r, assetName)
		return
	}

	// Dev mode: serve the current binary as a tar.gz if the platform matches.
	if h.isDevMode() && reqOS == runtime.GOOS && reqArch == runtime.GOARCH {
		h.serveLocalBinary(w)
		return
	}

	h.redirectToAsset(w, r, assetName)
}

// serveReleaseAssetURL pins a platform archive to one release, so bootstrap can
// fetch its matching checksums even across scoped releases or cache refreshes.
// Never fall back to a moving latest URL or an unverifiable development archive.
func (h *BootstrapHandler) serveReleaseAssetURL(w http.ResponseWriter, r *http.Request, assetName string) {
	if h.resolver == nil {
		http.Error(w, "release resolution unavailable; use a locally built CLI", http.StatusServiceUnavailable)
		return
	}
	target, err := h.resolver.ResolveAssetURL(r.Context(), assetName)
	const prefix = "https://github.com/zyno-io/sp2p/releases/download/"
	if err != nil || !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "/"+assetName) {
		http.Error(w, "pinned release unavailable; retry later", http.StatusServiceUnavailable)
		return
	}
	tag := strings.TrimSuffix(strings.TrimPrefix(target, prefix), "/"+assetName)
	if tag == "" || tag == "." || tag == ".." || strings.ContainsFunc(tag, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-')
	}) {
		http.Error(w, "invalid release URL", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintln(w, target)
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

    SP2P_SKIP_CHECKSUM=0
    if [ "${1-}" = "--insecure-skip-checksum" ]; then
        SP2P_SKIP_CHECKSUM=1
        shift
        echo "WARNING: --insecure-skip-checksum disables archive integrity verification; downloaded code will run unchecked." >&2
    fi

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

    if [ "$SP2P_SKIP_CHECKSUM" = 0 ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            hash_file() { sha256sum "$1"; }
        elif command -v shasum >/dev/null 2>&1; then
            hash_file() { shasum -a 256 "$1"; }
        elif command -v openssl >/dev/null 2>&1; then
            hash_file() { openssl dgst -sha256 -r "$1"; }
        else
            echo "Error: sha256sum, shasum, or openssl is required (or explicitly opt out with --insecure-skip-checksum as the first bootstrap argument)" >&2; exit 1
        fi
    fi
    if command -v curl >/dev/null 2>&1; then
        download() { curl -fsSL --connect-timeout 10 --max-time 120 "$1" -o "$2"; }
    elif command -v wget >/dev/null 2>&1; then
        download() { wget -q --timeout=30 --tries=2 -O "$2" "$1"; }
    else
        echo "Error: curl or wget is required" >&2; exit 1
    fi

    SP2P_TMP=$(mktemp -d)
    trap 'rm -rf "$SP2P_TMP"' EXIT
    ASSET="sp2p_${OS}_${ARCH}.tar.gz"
    download "%s/dl/${OS}/${ARCH}?resolve=1" "$SP2P_TMP/release-url"
    DOWNLOAD_URL=$(cat "$SP2P_TMP/release-url")
    PREFIX=https://github.com/zyno-io/sp2p/releases/download/
    case "$DOWNLOAD_URL" in
        "$PREFIX"*/"$ASSET") ;;
        *) echo "Invalid SP2P release URL" >&2; exit 1 ;;
    esac
    RELEASE_URL=${DOWNLOAD_URL%%/*}
    TAG=${RELEASE_URL#"$PREFIX"}
    case "$TAG" in
        ''|.|..|*[!a-zA-Z0-9._-]*) echo "Invalid SP2P release tag" >&2; exit 1 ;;
    esac

    echo "Downloading sp2p..." >&2
    if [ "$SP2P_SKIP_CHECKSUM" = 0 ]; then
        download "$RELEASE_URL/checksums.txt" "$SP2P_TMP/checksums.txt"
        EXPECTED=$(awk -v asset="$ASSET" '
            { sub(/\r$/, "") }
            $2 == asset || $2 == "./" asset || $2 == "*" asset || $2 == "*./" asset {
                count++; digest = $1
                if (NF != 2 || length(digest) != 64 || digest ~ /[^0-9a-fA-F]/) bad = 1
            }
            END { if (count != 1 || bad) exit 1; print tolower(digest) }
        ' "$SP2P_TMP/checksums.txt") || { echo "Missing or invalid SP2P checksum" >&2; exit 1; }
    fi
    download "$DOWNLOAD_URL" "$SP2P_TMP/sp2p.tar.gz"
    if [ "$SP2P_SKIP_CHECKSUM" = 0 ]; then
        HASH_OUTPUT=$(hash_file "$SP2P_TMP/sp2p.tar.gz")
        ACTUAL=${HASH_OUTPUT%%%% *}
        if [ "$ACTUAL" != "$EXPECTED" ]; then
            echo "SP2P checksum verification failed; refusing to extract or execute" >&2; exit 1
        fi
    fi
    tar xz -C "$SP2P_TMP" -f "$SP2P_TMP/sp2p.tar.gz"
    chmod +x "$SP2P_TMP/sp2p"

    SP2P_SERVER="%s" SP2P_URL="%s" "$SP2P_TMP/sp2p" %s "$@"
}
main "$@"
`, command, baseURL, wsURL, baseURL, command)
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

$skipChecksum = $false
$sp2pArgs = @($args)
if ($sp2pArgs.Count -gt 0 -and $sp2pArgs[0] -ceq '--insecure-skip-checksum') {
    $skipChecksum = $true
    if ($sp2pArgs.Count -eq 1) { $sp2pArgs = @() }
    else { $sp2pArgs = @($sp2pArgs[1..($sp2pArgs.Count - 1)]) }
    [Console]::Error.WriteLine('WARNING: --insecure-skip-checksum disables archive integrity verification; downloaded code will run unchecked.')
}

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
    $asset = "sp2p_${os}_${arch}$ext"
    $archive = Join-Path $tmp "sp2p$ext"
    $releaseResponse = Invoke-WebRequest -UseBasicParsing -Uri "%s/dl/$os/${arch}?resolve=1" -TimeoutSec 120
    $downloadURL = ([string]$releaseResponse.Content).Trim()
    $pattern = '\Ahttps://github\.com/zyno-io/sp2p/releases/download/([a-zA-Z0-9._-]+)/' + [regex]::Escape($asset) + '\z'
    $releaseMatch = [regex]::Match($downloadURL, $pattern)
    if (-not $releaseMatch.Success -or $releaseMatch.Groups[1].Value -in @('.', '..')) { throw 'Invalid SP2P release URL' }
    $releaseURL = $downloadURL.Substring(0, $downloadURL.LastIndexOf('/'))
    $checksums = Join-Path $tmp 'checksums.txt'
    Write-Host 'Downloading sp2p...' -ForegroundColor DarkGray
    if (-not $skipChecksum) {
        Invoke-WebRequest -UseBasicParsing -Uri "$releaseURL/checksums.txt" -OutFile $checksums -TimeoutSec 120
        $entries = @(foreach ($line in Get-Content -LiteralPath $checksums) {
            $fields = $line.Trim() -split '\s+'
            if ($fields.Length -ge 2 -and $fields[1] -cin @($asset, "./$asset", "*$asset", "*./$asset")) {
                if ($fields.Length -ne 2 -or $fields[0] -notmatch '\A[0-9a-fA-F]{64}\z') { throw 'Invalid SP2P checksum' }
                $fields[0]
            }
        })
        if ($entries.Count -ne 1) { throw 'Missing or duplicate SP2P checksum' }
    }
    Invoke-WebRequest -UseBasicParsing -Uri $downloadURL -OutFile $archive -TimeoutSec 120
    if (-not $skipChecksum) {
        $actual = Get-FileHash -LiteralPath $archive -Algorithm SHA256
        if ($actual.Hash -ine $entries[0]) { throw 'SP2P checksum verification failed; refusing to extract or execute.' }
    }
    if ($os -eq 'windows') {
        Expand-Archive -Path $archive -DestinationPath $tmp
    } else {
        tar xzf $archive -C $tmp
        if ($LASTEXITCODE -ne 0) { throw 'SP2P archive extraction failed' }
    }
    $binExt = if ($os -eq 'windows') { '.exe' } else { '' }
    $bin = Join-Path $tmp "sp2p$binExt"
    if ($os -ne 'windows') {
        chmod +x $bin
        if ($LASTEXITCODE -ne 0) { throw 'Cannot make SP2P executable' }
    }
    $env:SP2P_SERVER = '%s'
    $env:SP2P_URL = '%s'
    & $bin %s @sp2pArgs
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
