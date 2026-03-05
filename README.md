# SP2P

Secure peer-to-peer data transfer. End-to-end encrypted. Send files, folders, and streams seamlessly - even between CLI and browser. Data flows directly between peers whenever possible; when both sides are behind restrictive NATs, an [encrypted relay](#turn-relay) is used as a last resort — the relay cannot decrypt the data.

## Table of Contents

- [Quick Start](#quick-start)
- [Install](#install)
- [Usage](#usage)
  - [Sending](#sending)
  - [Receiving](#receiving)
  - [Environment Variables](#environment-variables)
  - [Configuration File](#configuration-file)
- [Self-Hosting](#self-hosting)
  - [Docker Compose](#docker-compose)
  - [Server Configuration](#server-configuration)
- [Architecture Overview](#architecture-overview)
  - [Connection Flow](#connection-flow)
  - [P2P Connection Strategies](#p2p-connection-strategies)
  - [Transfer Protocol](#transfer-protocol)
- [Security Model](#security-model)
  - [Key Exchange](#key-exchange)
  - [Transfer Code](#transfer-code)
  - [Encrypted Metadata Preview](#encrypted-metadata-preview)
  - [Encryption](#encryption)
  - [Wire Format (Encrypted)](#wire-format-encrypted)
  - [Key Confirmation](#key-confirmation)
  - [TURN Relay](#turn-relay)
  - [Trust Model](#trust-model)
- [Development](#development)
- [License](#license)

## Quick Start

Send directly from the browser at [sp2p.io](https://sp2p.io), or use the CLI. No install required — pipe the bootstrap script to send a file:

```bash
curl -f https://sp2p.io | sh -s photo.jpg
```

The receiver can use the browser link, or receive via terminal:

```bash
curl -f https://sp2p.io/r | sh -s SESSION_ID-SEED
```

The bootstrap script downloads a temporary CLI binary, runs the transfer, and cleans up.

[sp2p.io](https://sp2p.io) is a public signaling and [relay server](#turn-relay) provided for public use by [Zyno Consulting](https://zyno.io). You can also [self-host](#self-hosting) your own server.

## Install

### macOS

```bash
brew install zyno-io/tap/sp2p
```

### Linux

The download links below (`sp2p.io/dl/...`) redirect to the latest GitHub release for each package.

**Debian / Ubuntu:**
```bash
curl -LO https://sp2p.io/dl/sp2p_amd64.deb
sudo dpkg -i sp2p_amd64.deb
```

**Fedora / RHEL:**
```bash
curl -LO https://sp2p.io/dl/sp2p_x86_64.rpm
sudo rpm -i sp2p_x86_64.rpm
```

**Alpine:**
```bash
curl -LO https://sp2p.io/dl/sp2p_x86_64.apk
wget -O /etc/apk/keys/oss@zyno.io-sp2p.rsa.pub https://cdn.zyno.io/apps/sp2p/sp2p.rsa.pub
apk add sp2p_x86_64.apk
```

**Arch (AUR):** *(pending)*
```bash
yay -S sp2p-bin
```

**Snap:** *(pending)*
```bash
sudo snap install sp2p --classic
```

### Windows

**Scoop:**
```powershell
scoop bucket add zyno-io https://github.com/zyno-io/scoop-bucket
scoop install sp2p
```

**Chocolatey:** *(pending)*
```powershell
choco install sp2p
```

**WinGet:** *(pending)*
```powershell
winget install zyno-io.sp2p
```

### From Source

See [Building from Source](#building-from-source).

## Usage

### Sending

```
sp2p send [flags] <file|folder|...|->
```

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | `wss://sp2p.io/ws` | Signaling server WebSocket URL |
| `-url` | `https://sp2p.io` | Public base URL for share links |
| `-name` | | Filename for stdin streams |
| `-compress` | `3` | zstd compression level (0=disabled, 1-9) |
| `-allow-relay` | `false` | Allow TURN relay without prompting (see [TURN Relay](#turn-relay)) |
| `-v` | `false` | Verbose diagnostic output |

Send a file, a folder, multiple files, or pipe from stdin:

```bash
sp2p send document.pdf
sp2p send ./my-folder
sp2p send *.jpg                        # multiple files sent as a tar archive
echo "hello world" | sp2p send -
tar czf - src/ | sp2p send -name src.tar.gz -
```

### Receiving

```
sp2p receive [flags] <CODE>
```

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | `wss://sp2p.io/ws` | Signaling server WebSocket URL |
| `-output` | `.` | Output directory |
| `-stdout` | `false` | Write to stdout instead of file |
| `-allow-relay` | `false` | Allow TURN relay without prompting (see [TURN Relay](#turn-relay)) |
| `-v` | `false` | Verbose diagnostic output |

```bash
sp2p receive abc123-xYz456
sp2p receive abc123-xYz456 -output ~/Downloads
sp2p receive abc123-xYz456 -stdout | tar xzf -
```

`receive` and `recv` are both accepted as the subcommand.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SP2P_SERVER` | Signaling server WebSocket URL | `wss://sp2p.io/ws` |
| `SP2P_URL` | Public base URL for share links | `https://sp2p.io` |

Environment variables are overridden by their corresponding flags.

When built from source, the CLI defaults to `localhost:8080` instead.

### Configuration File

SP2P reads defaults from `~/.config/sp2p/config.yaml` (or `$XDG_CONFIG_HOME/sp2p/config.yaml` if set).

```yaml
# Default signaling server
server: https://sp2p.example.com

# Public base URL for share links (optional, derived from server if omitted)
url: https://sp2p.example.com

# Default compression level (0=disabled, 1-9)
compress: 3

# Allow TURN relay without prompting
allow-relay: false

# Default output directory for received files
output: ~/Downloads

# Always show verbose output
verbose: false
```

**Precedence** (highest to lowest):
1. CLI flags (`-server`, `-compress`, etc.)
2. Environment variables (`SP2P_SERVER`, `SP2P_URL`)
3. Config file
4. Built-in defaults

If the config file does not exist, it is silently ignored. A malformed config file produces an error.

## Self-Hosting

### Docker Compose

Docker Compose is the easiest way to self-host SP2P. Clone this repo and run:

```bash
docker compose up -d
```

This starts the server on port 8080 with the default configuration. Customize by editing environment variables in `docker-compose.yml`.

#### With ACME (auto-TLS)

For production with automatic Let's Encrypt certificates, uncomment the ACME section in `docker-compose.yml` and set your domain:

```yaml
services:
  sp2p:
    ports:
      - "443:443"
      - "80:80"
    environment:
      - SP2P_ACME=true
      - SP2P_ACME_EMAIL=you@example.com
      - SP2P_BASE_URL=https://sp2p.example.com
      - SP2P_CONFIG_DIR=/data
    volumes:
      - sp2p-data:/data

volumes:
  sp2p-data:
```

#### With TURN Relay

To help peers behind restrictive NATs, uncomment the coturn service and TURN environment variables in `docker-compose.yml`.

**Ephemeral credentials (recommended):** Use a shared secret between sp2p and coturn. The server generates short-lived HMAC credentials per connection — no static passwords are exposed to clients:

```yaml
services:
  sp2p:
    environment:
      - SP2P_TURN_SERVERS=turn:localhost:3478
      - SP2P_TURN_SECRET=your-shared-secret-here
      # - SP2P_TURN_TTL=5m  # credential lifetime (default: 5m)

  coturn:
    image: coturn/coturn:latest
    network_mode: host
    volumes:
      - ./turnserver.conf:/etc/turnserver.conf:ro
```

Configure coturn with `use-auth-secret` and the same secret in `turnserver.conf`.

**Static credentials:** Alternatively, use a fixed username/password (simpler but less secure — credentials are delivered to clients):

```yaml
services:
  sp2p:
    environment:
      - SP2P_TURN_SERVERS=turn:localhost:3478
      - SP2P_TURN_USERNAME=sp2p
      - SP2P_TURN_PASSWORD=sp2p
```

TURN credentials are never included in the initial connection handshake. They are only delivered to clients after direct connection methods have failed and a minimum elapsed time has passed, making scripted credential extraction impractical.

### Server Configuration

The server supports three mutually exclusive TLS modes:
- **Plain HTTP** — default, suitable behind a reverse proxy
- **Manual TLS** — provide your own certificate and key via `-tls-cert` / `-tls-key`
- **ACME** — automatic Let's Encrypt certificates via `-acme` (requires `-config-dir` for cert storage)

When TLS is active (manual or ACME) and `-addr` is not explicitly set, the server defaults to `:443`.

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `-addr` | `SP2P_ADDR` | `:8080` | Listen address |
| `-base-url` | `SP2P_BASE_URL` | `http://localhost:8080` | Public base URL |
| `-trust-proxy` | `SP2P_TRUST_PROXY` | `false` | Trust X-Forwarded-For for rate limiting |
| `-tls-cert` | `SP2P_TLS_CERT` | | TLS certificate file |
| `-tls-key` | `SP2P_TLS_KEY` | | TLS private key file |
| `-acme` | `SP2P_ACME` | `false` | Enable ACME auto-certificates |
| `-acme-email` | `SP2P_ACME_EMAIL` | | ACME contact email |
| `-config-dir` | `SP2P_CONFIG_DIR` | | Persistent data directory (required for ACME) |
| `-turn-servers` | `SP2P_TURN_SERVERS` | | Comma-separated TURN server URLs |
| `-turn-secret` | `SP2P_TURN_SECRET` | | Shared secret for ephemeral TURN credentials |
| `-turn-ttl` | `SP2P_TURN_TTL` | `5m` | Lifetime of ephemeral TURN credentials |
| `-turn-username` | `SP2P_TURN_USERNAME` | | TURN static username (mutually exclusive with `-turn-secret`) |
| `-turn-password` | `SP2P_TURN_PASSWORD` | | TURN static password (mutually exclusive with `-turn-secret`) |

## Architecture Overview

SP2P has three components: the **CLI** (`sp2p`), the **signaling server** (`sp2p-server`), and a **web UI** served by the signaling server for browser-based receiving.

### Connection Flow

```
Sender                    Server                   Receiver
  |                         |                         |
  |------- hello ---------->|                         |
  |<------ welcome ---------|                         |
  |  (session ID + ICE)     |                         |
  |                         |                         |
  |--- file-info (enc) ---->|  [stored on session]    |
  |                         |                         |
  |   [share code/link]     |                         |
  |                         |                         |
  |                         |<------- join -----------|
  |                         |  GET /api/file-info/:id |
  |                         |-------> {encrypted} --->|
  |                         |  [receiver decrypts     |
  |                         |   and shows preview]    |
  |<---- peer-joined -------|-------> welcome ------->|
  |                         |                         |
  |------- crypto --------->|-------> crypto -------->|
  |<------ crypto ----------|<------- crypto ---------|
  |   [X25519 public key exchange via signaling]      |
  |                         |                         |
  |============ P2P connection (race) ================|
  |  WebRTC / Symmetric TCP — first wins               |
  |                         |                         |
  |====== key confirmation over raw P2P channel ======|
  |                         |                         |
  |========== encrypted transfer (AES-256-GCM) =======|
  |  metadata -> data chunks -> done -> complete      |
```

### P2P Connection Strategies

Two methods race in parallel — the first to succeed wins:

1. **WebRTC** — Uses ICE (STUN/TURN) to traverse NATs. Works in most network configurations.
2. **Symmetric TCP** — Both peers listen on a random TCP port and trickle LAN addresses via signaling. Each peer filters out loopback and link-local addresses, capped at 8 dial addresses. In background, each peer attempts a UPnP port mapping and sends the external address on success. First successfully handshaken TCP connection wins. Fast on local networks.

### Transfer Protocol

The transfer uses a framed binary protocol over the encrypted stream:

| Message | Type | Description |
|---------|------|-------------|
| Metadata | `0x01` | JSON with filename, size, MIME type, folder/stream flags |
| Data | `0x02` | File data chunk (up to 64 KiB) |
| Done | `0x04` | Sender signals transfer complete with totals + SHA-256 |
| Complete | `0x05` | Receiver confirms receipt with verified totals + SHA-256 |
| Error | `0x06` | Error message from either side |
| FinAck | `0x07` | Sender acknowledges Complete for safe shutdown |

## Security Model

### Key Exchange

1. Both peers generate ephemeral **X25519** key pairs
2. Public keys are exchanged over the signaling server
3. Each peer computes a shared secret via X25519 Diffie-Hellman
4. **HKDF** (SHA-256) derives four keys from the shared secret, using the encryption seed as salt:
   - `k_s2r` — sender-to-receiver data key
   - `k_r2s` — receiver-to-sender data key
   - `k_confirm` — key confirmation MAC key
   - `verify` — visual verification code (8 hex chars, displayed in the web UI)
5. The HKDF info string binds keys to the session: `"sp2p-v1" || session_id || sender_pub || receiver_pub`

### Transfer Code

The transfer code has the format `SESSION_ID-SEED` where:

- **Session ID** identifies the signaling session on the server
- **Seed** is a 128-bit random value (base62-encoded) used as the HKDF salt

Both components are required to derive encryption keys. The server only knows the session ID, not the seed — so even a compromised server cannot decrypt the transfer.

### Encrypted Metadata Preview

Before the P2P connection is established, the sender encrypts file metadata (name, size, type, file count) and sends it to the server via signaling. The server stores the opaque blob on the session. When the receiver opens the share link, the web UI fetches the encrypted metadata via `GET /api/file-info/{sessionId}`, decrypts it using the seed from the transfer code, and displays a confirmation card with the file name and size before proceeding.

The metadata is encrypted with **AES-256-GCM** using a key derived from the seed via HKDF (salt: `"sp2p-file-info"`, label: `"sp2p-v1-file-info-key"`). Since the server never knows the seed, it cannot read the metadata — it only stores and serves the encrypted blob. This is best-effort: if the metadata is unavailable or decryption fails, the transfer proceeds normally without a preview.

### Encryption

- **AES-256-GCM** with directional keys (each direction has its own key)
- Sequential nonces starting at 0 (counter-based, prevents reuse)
- Message type and sequence number are authenticated as AAD (Additional Authenticated Data)
- Nonce counter is capped at 2^32 to prevent nonce reuse

### Wire Format (Encrypted)

```
[4 bytes: total payload length, big-endian uint32]
[1 byte:  message type (cleartext, authenticated via AAD)]
[8 bytes: sequence number (big-endian uint64)]
[N bytes: AEAD ciphertext with AAD = type || seq || version]
```

### Key Confirmation

Before the encrypted stream starts, both peers perform **key confirmation** over the raw P2P connection:

1. Each peer computes `HMAC-SHA256(k_confirm, role || sender_pub || receiver_pub)`
2. Both send their HMAC and verify the peer's HMAC (constant-time comparison)
3. If confirmation fails, the connection is aborted — this detects wrong codes or MITM attacks

### TURN Relay

When both peers are behind restrictive NATs and direct P2P fails, WebRTC may fall back to a **TURN relay** server. In this case, encrypted data passes through the relay — but the relay **cannot decrypt it** (it only sees opaque ciphertext, the same AES-256-GCM stream used for direct connections).

TURN relay is only attempted as a **last resort** — after all direct connection methods (WebRTC via STUN, symmetric TCP with LAN/UPnP addresses) have failed. When this happens, the CLI **prompts for consent** before using the relay. Use the `-allow-relay` flag to skip the prompt (useful for scripting):

```bash
sp2p send -allow-relay photo.jpg
sp2p receive -allow-relay abc123-xYz456
```

If no TTY is available and `-allow-relay` is not set, TURN is skipped and the connection fails with a message suggesting the flag.

**Credential delivery:** TURN credentials are never included in the initial handshake. The server only delivers them after a client signals `relay-retry` (meaning all direct methods have failed) and a minimum time has elapsed since the session started. When `-turn-secret` is configured, each connection receives unique short-lived HMAC credentials that expire after the configured TTL.

### Trust Model

- The signaling server relays metadata only (public keys, ICE candidates, session management) and stores encrypted file-info blobs it cannot decrypt
- **File data flows directly between peers** when a direct connection succeeds
- If TURN relay is used, encrypted data routes through the relay but remains E2E encrypted and unreadable by the relay
- TURN relay requires explicit consent (`-allow-relay` or interactive prompt)
- The server cannot derive encryption keys (it never sees the seed portion of the transfer code)
- Ephemeral key pairs are generated per session and never reused

## Development

**Requirements:** Go 1.25+, Node.js (for web UI build)

### Make Targets

```bash
make dev        # Run the server locally on :8080
make test       # Run Go tests
make build      # Build everything (web + CLI + server)
make clean      # Remove build artifacts
```

### Web Development

```bash
cd web
npm run build   # Build web UI
npm run watch   # Watch mode for web development
npm test        # Run Playwright tests
```

### Building from Source

```bash
make build
```

This produces `bin/sp2p` (CLI) and `bin/sp2p-server` (signaling server). To build only the CLI:

```bash
make build-cli
```

### Project Structure

```
cmd/
  sp2p/             CLI entrypoint
  sp2p-server/      Server entrypoint
internal/
  archive/          Tar streaming for folder transfers
  cli/              CLI send/receive logic and progress display
  conn/             P2P connection strategies (WebRTC, Symmetric TCP/UPnP)
  crypto/           Key exchange, HKDF derivation, AES-GCM encrypted stream
  server/           HTTP/WebSocket server, signaling, and web UI serving
  signal/           Signaling protocol messages and WebSocket client
  transfer/         Framed transfer protocol (metadata, chunked data, ack/done)
web/
  src/              TypeScript source for browser-based receiving
  dist/             Built web UI (embedded into server binary)
```

## License

MIT
