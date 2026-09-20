// SPDX-License-Identifier: MIT

package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeBootstrapFixture(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0700); err != nil {
		t.Fatal(err)
	}
}

func bootstrapArchive(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("#!/bin/sh\nprintf 'CLI_EXECUTED:%s:%s:%s\\n' \"$1\" \"$2\" \"$SP2P_SERVER\"\nprintf 'CLI_ARG:<%s>\\n' \"$@\"\n")
	if err := tw.WriteHeader(&tar.Header{Name: "sp2p", Mode: 0700, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type bootstrapCase struct {
	skipChecksum        bool
	hashFailure         bool
	name, manifest, url string
	tamper, wantOK      bool
}

func bootstrapCases(asset, digest string) []bootstrapCase {
	url := "https://github.com/zyno-io/sp2p/releases/download/v0.4.0/" + asset
	valid := digest + "  " + asset + "\n"
	return []bootstrapCase{
		{name: "valid", manifest: valid, url: url, wantOK: true},
		{name: "explicit-bypass-no-manifest", url: url, skipChecksum: true, wantOK: true},
		{name: "explicit-bypass-hash-failure", manifest: valid, url: url, skipChecksum: true, hashFailure: true, wantOK: true},
		{name: "explicit-bypass-wrong-host", url: strings.Replace(url, "github.com", "example.invalid", 1), skipChecksum: true},
		{name: "explicit-bypass-wrong-platform", url: strings.Replace(url, asset, "sp2p_wrong_platform.zip", 1), skipChecksum: true},
		{name: "crlf", manifest: strings.ReplaceAll(valid, "\n", "\r\n"), url: url, wantOK: true},
		{name: "hash-command-failure", manifest: valid, url: url, hashFailure: true},
		{name: "dot-prefix", manifest: strings.ToUpper(digest) + "  ./" + asset + "\n", url: url, wantOK: true},
		{name: "binary-marker", manifest: digest + " *./" + asset + "\n", url: url, wantOK: true},
		{name: "tampered", manifest: valid, url: url, tamper: true},
		{name: "missing-entry", manifest: digest + "  sp2p_wrong_platform.zip\n", url: url},
		{name: "missing-manifest", url: url},
		{name: "duplicate-entry", manifest: valid + valid, url: url},
		{name: "duplicate-alias", manifest: valid + digest + "  ./" + asset + "\n", url: url},
		{name: "malformed-digest", manifest: strings.Repeat("g", 64) + "  " + asset + "\n", url: url},
		{name: "short-digest", manifest: "abcd  " + asset + "\n", url: url},
		{name: "extra-field", manifest: strings.TrimSpace(valid) + " extra\n", url: url},
		{name: "wrong-host", manifest: valid, url: strings.Replace(url, "github.com", "example.invalid", 1)},
		{name: "wrong-platform", manifest: valid, url: strings.Replace(url, asset, "sp2p_wrong_platform.zip", 1)},
		{name: "moving-latest", manifest: valid, url: githubReleaseBaseURL + "/" + asset},
		{name: "traversal", manifest: valid, url: strings.Replace(url, "v0.4.0", "../other", 1)},
		{name: "dot-tag", manifest: valid, url: strings.Replace(url, "v0.4.0", "..", 1)},
		{name: "encoded-tag", manifest: valid, url: strings.Replace(url, "v0.4.0", "%2e%2e", 1)},
	}
}

func TestShellBootstrapChecksums(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell integration")
	}
	archive := bootstrapArchive(t)
	digest := fmt.Sprintf("%x", sha256.Sum256(archive))
	asset := fmt.Sprintf("sp2p_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	for _, downloader := range []string{"curl", "wget"} {
		for _, hasher := range []string{"sha256sum", "shasum", "openssl"} {
			hashPath, err := exec.LookPath(hasher)
			if err != nil {
				continue
			}
			for _, tc := range bootstrapCases(asset, digest) {
				t.Run(downloader+"/"+hasher+"/"+tc.name, func(t *testing.T) {
					dir := t.TempDir()
					bin := filepath.Join(dir, "bin")
					if err := os.Mkdir(bin, 0700); err != nil {
						t.Fatal(err)
					}
					// Isolated PATH has no gh and selects each downloader/hash fallback.
					for _, name := range []string{"uname", "tr", "mktemp", "rm", "cat", "awk", "tar", "chmod", "cp"} {
						path, err := exec.LookPath(name)
						if err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(path, filepath.Join(bin, name)); err != nil {
							t.Fatal(err)
						}
					}
					if !tc.skipChecksum || tc.hashFailure {
						if err := os.Symlink(hashPath, filepath.Join(bin, hasher)); err != nil {
							t.Fatal(err)
						}
					}
					if tc.hashFailure {
						if err := os.Remove(filepath.Join(bin, hasher)); err != nil {
							t.Fatal(err)
						}
						writeBootstrapFixture(t, filepath.Join(bin, hasher), []byte("#!/bin/sh\necho '"+digest+"  archive'\nexit 1\n"))
					}
					writeBootstrapFixture(t, filepath.Join(bin, downloader), []byte(`#!/bin/sh
set -e
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o|-O) out=$2; shift 2 ;;
        https://*) url=$1; shift ;;
        *) shift ;;
    esac
done
case "$url" in
    *'?resolve=1') cp "$FIXTURE/release-url" "$out" ;;
    */checksums.txt)
        [ "$EXPECT_SKIP_CHECKSUM" != 1 ] || { echo UNEXPECTED_CHECKSUM_DOWNLOAD >&2; exit 44; }
        [ "$url" = 'https://github.com/zyno-io/sp2p/releases/download/v0.4.0/checksums.txt' ] || exit 43
        cp "$FIXTURE/checksums.txt" "$out" ;;
    *.tar.gz) cp "$FIXTURE/archive" "$out" ;;
    *) exit 42 ;;
esac
`))
					writeBootstrapFixture(t, filepath.Join(dir, "release-url"), []byte(tc.url+"\n"))
					if tc.manifest != "" {
						writeBootstrapFixture(t, filepath.Join(dir, "checksums.txt"), []byte(tc.manifest))
					}
					data := archive
					if tc.tamper {
						data = append(bytes.Clone(data), 'x')
					}
					writeBootstrapFixture(t, filepath.Join(dir, "archive"), data)
					if !tc.wantOK {
						if err := os.Remove(filepath.Join(bin, "tar")); err != nil {
							t.Fatal(err)
						}
						writeBootstrapFixture(t, filepath.Join(bin, "tar"), []byte("#!/bin/sh\necho EXTRACTED_UNVERIFIED\nexit 99\n"))
					}
					for _, command := range []string{"send", "receive"} {
						ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
						defer cancel()
						args := []string{"-s", "--"}
						skipExpected := "0"
						if tc.skipChecksum {
							args = append(args, "--insecure-skip-checksum")
							skipExpected = "1"
						}
						args = append(args, "argument with spaces", "-format", "json")
						cmd := exec.CommandContext(ctx, "/bin/sh", args...)
						cmd.Env = append(os.Environ(), "PATH="+bin, "FIXTURE="+dir, "EXPECT_SKIP_CHECKSUM="+skipExpected, "SP2P_SKIP_CHECKSUM=1")
						cmd.Stdin = strings.NewReader(generateScript(command, "https://example.invalid", "wss://example.invalid/ws"))
						var stderr bytes.Buffer
						cmd.Stderr = &stderr
						stdout, err := cmd.Output()
						output := string(stdout) + stderr.String()
						if strings.Contains(stderr.String(), "WARNING: --insecure-skip-checksum") != tc.skipChecksum || strings.Contains(string(stdout), "WARNING:") {
							t.Fatalf("incorrect bypass warning: %s", output)
						}
						if tc.wantOK {
							want := "CLI_EXECUTED:" + command + ":argument with spaces:wss://example.invalid/ws"
							wantArgs := "CLI_ARG:<" + command + ">\nCLI_ARG:<argument with spaces>\nCLI_ARG:<-format>\nCLI_ARG:<json>\n"
							if err != nil || !strings.Contains(output, want) || !strings.Contains(string(stdout), wantArgs) || strings.Contains(string(stdout), "--insecure-skip-checksum") {
								t.Fatalf("bootstrap failed: %v %s", err, output)
							}
						} else if err == nil || strings.Contains(string(output), "EXTRACTED_UNVERIFIED") || strings.Contains(string(output), "CLI_EXECUTED") {
							t.Fatalf("unsafe bootstrap: %v %s", err, output)
						}
					}
				})
			}
		}
	}
}

func TestPowerShellBootstrapChecksums(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell not installed")
	}
	archive := bootstrapArchive(t)
	digest := fmt.Sprintf("%x", sha256.Sum256(archive))
	platforms := []string{"windows"}
	if runtime.GOOS != "windows" {
		platforms = append(platforms, runtime.GOOS)
	}
	for _, platform := range platforms {
		ext := ".tar.gz"
		if platform == "windows" {
			ext = ".zip"
		}
		asset := fmt.Sprintf("sp2p_%s_%s%s", platform, runtime.GOARCH, ext)
		for _, tc := range bootstrapCases(asset, digest) {
			t.Run(platform+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				writeBootstrapFixture(t, filepath.Join(dir, "release-url"), []byte(tc.url+"\n"))
				if tc.manifest != "" {
					writeBootstrapFixture(t, filepath.Join(dir, "checksums.txt"), []byte(tc.manifest))
				}
				data := archive
				if tc.tamper {
					data = append(bytes.Clone(data), 'x')
				}
				writeBootstrapFixture(t, filepath.Join(dir, "archive"), data)
				prelude := `function Invoke-WebRequest {
    param($Uri, $OutFile, $TimeoutSec, [switch]$UseBasicParsing)
    if ($Uri.EndsWith('?resolve=1')) { return @{ Content = [IO.File]::ReadAllText((Join-Path $env:FIXTURE 'release-url')) } }
    $source = if ($Uri.EndsWith('/checksums.txt')) {
        if ($env:EXPECT_SKIP_CHECKSUM -eq '1') { throw 'UNEXPECTED_CHECKSUM_DOWNLOAD' }
        if ($Uri -cne 'https://github.com/zyno-io/sp2p/releases/download/v0.4.0/checksums.txt') { throw 'Checksum release drifted' }
        'checksums.txt'
    } else { 'archive' }
    Copy-Item -LiteralPath (Join-Path $env:FIXTURE $source) -Destination $OutFile
}
function gh { throw 'GH_MUST_NOT_BE_CALLED' }
function tar { throw 'VERIFIED_EXTRACTION' }
function Expand-Archive { throw 'VERIFIED_EXTRACTION' }
`
				if tc.hashFailure {
					prelude += "function Get-FileHash { throw 'hash-command-failure' }\n"
				}
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				script := generatePSScript("receive", "https://example.invalid", "wss://example.invalid/ws")
				skipExpected := "0"
				if tc.skipChecksum {
					script = "& {\n" + script + "\n} '--insecure-skip-checksum' 'argument with spaces' '-format' 'json'"
					skipExpected = "1"
				}
				cmd := exec.CommandContext(ctx, pwsh, "-NoProfile", "-NonInteractive", "-Command", prelude+script)
				osValue := ""
				if platform == "windows" {
					osValue = "Windows_NT"
				}
				cmd.Env = append(os.Environ(), "OS="+osValue, "FIXTURE="+dir, "EXPECT_SKIP_CHECKSUM="+skipExpected)
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				stdout, err := cmd.Output()
				output := string(stdout) + stderr.String()
				if strings.Contains(stderr.String(), "WARNING: --insecure-skip-checksum") != tc.skipChecksum || strings.Contains(string(stdout), "WARNING:") {
					t.Fatalf("incorrect bypass warning: %s", output)
				}
				// Positive cases stop at extraction; no platform executable runs.
				extracted := strings.Contains(string(output), "VERIFIED_EXTRACTION")
				if err == nil || extracted != tc.wantOK || strings.Contains(string(output), "GH_MUST_NOT_BE_CALLED") {
					t.Fatalf("unsafe or failed PowerShell bootstrap: %v %s", err, output)
				}
			})
		}
	}
}

func TestBootstrapPinnedReleaseResolution(t *testing.T) {
	asset := "sp2p_linux_amd64.tar.gz"
	const prefix = "https://github.com/zyno-io/sp2p/releases/download/"
	for _, target := range []string{
		prefix + "v0.4.0/" + asset, prefix + "v0.1.1-cli-windows/" + asset,
		githubReleaseBaseURL + "/" + asset, "https://example.invalid/" + asset,
		prefix + "../" + asset, prefix + "v1/other/" + asset, prefix + "%2e%2e/" + asset,
	} {
		t.Run(target, func(t *testing.T) {
			h := mustBootstrapHandler(t, "https://sp2p.io", "wss://sp2p.io/ws")
			h.resolver = NewReleaseResolver()
			h.resolver.cache = map[string]resolvedAsset{asset: {url: target}}
			h.resolver.fetchedAt = time.Now()
			rec := httptest.NewRecorder()
			h.ServeBinary(rec, httptest.NewRequest("GET", "/dl/linux/amd64?resolve=1", nil))
			wantOK := target == prefix+"v0.4.0/"+asset || target == prefix+"v0.1.1-cli-windows/"+asset
			if wantOK {
				if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != target || rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("bad pinned release response: %d %s", rec.Code, rec.Body.String())
				}
			} else if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("accepted unsafe URL: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
	h := mustBootstrapHandler(t, "", "")
	rec := httptest.NewRecorder()
	h.ServeBinary(rec, httptest.NewRequest("GET", "/dl/"+runtime.GOOS+"/"+runtime.GOARCH+"?resolve=1", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("development binary used without checksum: %d", rec.Code)
	}
}

func TestBootstrapTemplatesMatchGenerator(t *testing.T) {
	for _, command := range []string{"send", "receive"} {
		name := "bootstrap-send.sh"
		if command == "receive" {
			name = "bootstrap-recv.sh"
		}
		data, err := os.ReadFile(filepath.Join("..", "..", "scripts", name))
		if err != nil {
			t.Fatal(err)
		}
		template := strings.Replace(string(data), "# SPDX-License-Identifier: MIT\n", "", 1)
		template = strings.Replace(template, command+" -allow-relay", command, 1)
		if template != generateScript(command, "{{BASE_URL}}", "{{WS_URL}}") {
			t.Fatalf("%s differs from generated bootstrap", name)
		}
	}
}

func TestShellBootstrapMissingHashTool(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell integration")
	}
	dir := t.TempDir()
	for _, name := range []string{"uname", "tr"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{"send", "receive"} {
		for _, args := range [][]string{nil, {"file", "--insecure-skip-checksum"}, {"--insecure-skip-checksum=true"}} {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/bin/sh", append([]string{"-s", "--"}, args...)...)
			cmd.Env = append(os.Environ(), "PATH="+dir, "SP2P_SKIP_CHECKSUM=1")
			cmd.Stdin = strings.NewReader(generateScript(command, "https://example.invalid", "wss://example.invalid/ws"))
			output, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(output), "sha256sum, shasum, or openssl is required") || strings.Contains(string(output), "WARNING:") {
				t.Fatalf("did not fail closed without an explicit first-argument opt-out: %v %s", err, output)
			}
		}
	}
}

func TestPowerShellBootstrapBypassArguments(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell not installed")
	}
	platforms := []string{"windows"}
	if runtime.GOOS != "windows" {
		platforms = append(platforms, runtime.GOOS)
	}
	for _, platform := range platforms {
		for _, command := range []string{"send", "receive"} {
			for _, payload := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/payload=%t", platform, command, payload), func(t *testing.T) {
					ext := ".tar.gz"
					if platform == "windows" {
						ext = ".zip"
					}
					asset := fmt.Sprintf("sp2p_%s_%s%s", platform, runtime.GOARCH, ext)
					prelude := `function Invoke-WebRequest {
    param($Uri, $OutFile, $TimeoutSec, [switch]$UseBasicParsing)
    if ($Uri.EndsWith('?resolve=1')) { return @{ Content = $env:RELEASE_URL } }
    if ($Uri.EndsWith('/checksums.txt')) { throw 'UNEXPECTED_CHECKSUM_DOWNLOAD' }
    if ($Uri -cne $env:RELEASE_URL) { throw 'UNEXPECTED_ARCHIVE_URL' }
}
function Get-FileHash { throw 'UNEXPECTED_HASH_CALL' }
function tar { $global:LASTEXITCODE = 0 }
function Expand-Archive {}
function chmod { $global:LASTEXITCODE = 0 }
function Join-Path {
    param($Path, $ChildPath)
    if ($ChildPath -in @('sp2p', 'sp2p.exe')) { return 'Invoke-SP2PFixture' }
    Microsoft.PowerShell.Management\Join-Path $Path $ChildPath
}
function Invoke-SP2PFixture {
    foreach ($value in $args) { [Console]::Out.WriteLine("CLI_ARG:<$value>") }
}
`
					suffix := " '--insecure-skip-checksum'"
					want := "CLI_ARG:<" + command + ">\n"
					if payload {
						suffix += " 'argument with spaces' '-format' 'json' ''"
						want += "CLI_ARG:<argument with spaces>\nCLI_ARG:<-format>\nCLI_ARG:<json>\nCLI_ARG:<>\n"
					}
					script := prelude + "& {\n" + generatePSScript(command, "https://example.invalid", "wss://example.invalid/ws") + "\n}" + suffix
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, pwsh, "-NoProfile", "-NonInteractive", "-Command", script)
					osValue := ""
					if platform == "windows" {
						osValue = "Windows_NT"
					}
					cmd.Env = append(os.Environ(), "OS="+osValue, "RELEASE_URL=https://github.com/zyno-io/sp2p/releases/download/v0.4.0/"+asset)
					var stderr bytes.Buffer
					cmd.Stderr = &stderr
					output, err := cmd.Output()
					stdout := strings.ReplaceAll(string(output), "\r\n", "\n")
					if err != nil || !strings.Contains(stdout, want) || strings.Contains(stdout, "--insecure-skip-checksum") || !strings.Contains(stderr.String(), "WARNING: --insecure-skip-checksum") {
						t.Fatalf("incorrect bypass/argument handling: %v\n%s\n%s", err, stdout, stderr.String())
					}
				})
			}
		}
	}
}
