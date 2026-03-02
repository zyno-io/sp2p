# SP2P — Secure P2P File Transfer

## Quick Reference

```bash
make build          # Build web + CLI + server
make build-cli      # CLI only → bin/sp2p
make build-server   # Server only → bin/sp2p-server (requires web built first)
make build-web      # Web build via npm
make test           # go test ./...
make dev            # Dev server on :8080
```

## Project Structure

```
cmd/sp2p/           CLI client (send/receive)
cmd/sp2p-server/    Signaling server
internal/
  archive/          TAR archiving for multi-file sends
  cli/              Terminal UI, key listeners, progress bars
  config/           YAML config file loading (~/.config/sp2p/config.yaml)
  conn/             P2P connection (races WebRTC + TCP simultaneously)
  crypto/           X25519 key exchange, AES-256-GCM stream encryption, seed encoding
  flow/             High-level send/receive orchestration
  semver/           Version comparison
  server/           Signaling server, ACME, TURN, rate limiting, web handlers
  signal/           WebSocket signaling client
  transfer/         Frame-based transfer protocol (FrameReadWriter interface)
web/src/            TypeScript frontend (esbuild → web/dist/)
man/                Man pages
```

## Architecture

- **Transfer protocol**: Frame-based over `FrameReadWriter` interface — both `PlaintextFrameRW` and `EncryptedStream` implement it
- **Wire format**: `[4 len][1 type][8 seq][ciphertext]` — msg type in cleartext header + AAD
- **Directional keys**: sender uses k_s2r to write, k_r2s to read; receiver reverses
- **Key exchange**: X25519 ECDH → HKDF-SHA256 → directional AES-256-GCM keys
- **Connection**: WebRTC and TCP raced simultaneously; WebRTC used for browser peers
- **Signaling**: JSON-envelope WebSocket messages (Hello, Welcome, Offer, Answer, ICECandidate)

## Code Conventions

- All source files start with `// SPDX-License-Identifier: MIT`
- Go module: `github.com/zyno-io/sp2p`
- Error handling: wrap with `fmt.Errorf("context: %w", err)`
- Context passed explicitly through call chains
- Packages are flat within `internal/` — no deep nesting
- CGO_ENABLED=0 for fully static binaries

## Build Flags (ldflags)

- `-X main.version=$(VERSION)`
- `-X main.buildTime=$(BUILD_TIME)` (ISO 8601)
- `-X main.defaultBaseURL=$(RELEASE_URL)` (release builds embed `https://sp2p.io`)

## Key Dependencies

| Package | Role |
|---------|------|
| `github.com/pion/webrtc/v4` | WebRTC (DataChannel + SDP) |
| `github.com/coder/websocket` | WebSocket client/server |
| `golang.org/x/crypto` | X25519, HKDF, ChaCha20-Poly1305 |
| `golang.org/x/term` | Terminal raw mode |
| `github.com/huin/goupnp` | UPnP port mapping |
| `gopkg.in/yaml.v3` | Config file parsing |

## Config Precedence

CLI flags > Environment variables (`SP2P_SERVER`, `SP2P_URL`) > Config file (`~/.config/sp2p/config.yaml`) > Build-time defaults

## Testing

- `go test ./...` runs everything (unit, integration, e2e, adversarial crypto)
- Crypto package has adversarial tests and test vectors
- Transfer package has edge-case and error-handling test suites
- Web: Playwright tests available via npm

## Documentation Checklist

When changing CLI flags, server options, or user-facing behavior, update:

- `man/sp2p.1` — CLI man page (flags, environment, examples, FILES section)
- `man/sp2p-server.1` — Server man page (flags, environment)
- `README.md` — Usage tables, environment variables, configuration file section, examples
- `cmd/sp2p/main.go` — Flag help text, `printUsage()` output
- `cmd/sp2p-server/main.go` — Flag help text (server side)
- `internal/config/config.go` — Config struct fields and `Load()` if adding new config options
- `web/src/` — UI text if the change affects browser-based transfers
