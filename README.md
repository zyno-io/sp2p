# SP2P

Secure peer-to-peer data transfer. End-to-end encrypted. Send files, folders, and streams between any two machines, from the CLI or the browser. Data flows directly between peers whenever possible. When both sides are behind restrictive NATs, an [encrypted relay](#turn-relay) is used as a last resort, and the relay cannot read your data.

## Table of Contents

- [Quick Start](#quick-start)
- [Install](#install)
  - [One-shot bootstrap scripts](#one-shot-bootstrap-scripts)
- [Usage](#usage)
  - [Sending](#sending)
  - [Receiving](#receiving)
  - [Rsync Synchronization](#rsync-synchronization)
  - [TCP, Unix, and Stdio Tunnels](#tcp-unix-and-stdio-tunnels)
  - [AI Agents and Automation](#ai-agents-and-automation)
  - [Protocol compatibility and staged upgrades](#protocol-compatibility-and-staged-upgrades)
  - [Environment Variables](#environment-variables)
  - [Configuration File](#configuration-file)
- [Self-Hosting](#self-hosting)
  - [Docker Compose](#docker-compose)
  - [Server Configuration](#server-configuration)
  - [Proxy, container, and relay migration](#proxy-container-and-relay-migration)
- [Architecture Overview](#architecture-overview)
- [Security Model](#security-model)
- [Development](#development)
- [License](#license)

## Quick Start

**In the browser:** open [sp2p.io](https://sp2p.io), drop a file, and share the link.

**From a terminal, without installing anything:**

```bash
# Sender
curl -f https://sp2p.io | sh -s photo.jpg

# Receiver (or just open the link the sender got)
curl -f https://sp2p.io/r | sh -s SESSION_ID-SEED
```

**With the CLI installed:**

```bash
sp2p send photo.jpg          # prints a transfer code
sp2p receive SESSION_ID-SEED
```

The one-line commands download a temporary copy of the CLI, verify its checksum, run the transfer, and clean up. Details are in [One-shot bootstrap scripts](#one-shot-bootstrap-scripts).

[sp2p.io](https://sp2p.io) is a public signaling and [relay server](#turn-relay) provided by [Zyno Consulting](https://zyno.io). You can also [self-host](#self-hosting) your own.

## Install

### macOS

```bash
brew install zyno-io/tap/sp2p
```

### Linux

The `sp2p.io/dl/...` links redirect to the latest GitHub release. To verify a downloaded package before installing it, see [artifact verification](SECURITY.md#artifact-verification-and-endpoint-trust).

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

### One-shot bootstrap scripts

`sp2p.io` (shell) and `sp2p.io/ps` (PowerShell) serve small scripts that download a fixed release of the CLI into a temporary directory, run one transfer, and delete it. `/r` and `/ps/r` do the same for receiving.

```bash
curl -f https://sp2p.io | sh -s photo.jpg
wget -O- https://sp2p.io | sh -s photo.jpg
```

```powershell
& ([scriptblock]::Create((irm 'https://sp2p.io/ps'))) 'C:\path\to\report.pdf'
```

What the scripts need and what they check:

- **Shell** needs `curl` or `wget`, plus one of `sha256sum`, `shasum`, or `openssl` for hashing. **PowerShell** uses built-in commands.
- The downloaded archive is checked against the `checksums.txt` of the same release before it is extracted. A missing hash tool or a missing, duplicate, malformed, or mismatched checksum stops the script.
- This trusts GitHub's HTTPS release channel and the bootstrap host. It is not independent signer verification. For stronger provenance checks, see [artifact verification and endpoint trust](SECURITY.md#artifact-verification-and-endpoint-trust).
- Unreleased or locally built archives cannot bootstrap. Use a locally built CLI for development.

To skip the checksum step, put `--insecure-skip-checksum` **first** among the bootstrap arguments. The script prints a warning and runs the downloaded code without an integrity check, and no hash tool is needed. TLS certificate validation stays on. The flag belongs to the bootstrap script only and is stripped before the CLI runs. Use it only if you accept the risk of running unverified code.

```bash
curl -f https://sp2p.io | sh -s -- --insecure-skip-checksum ./report.pdf
```

```powershell
& ([scriptblock]::Create((irm 'https://sp2p.io/ps'))) '--insecure-skip-checksum' 'C:\path\to\report.pdf'
```

## Usage

### Sending

```text
sp2p send [flags] <file|folder|...|->
```

```bash
sp2p send document.pdf
sp2p send ./my-folder
sp2p send *.jpg                        # multiple paths are sent as one tar archive
echo "hello world" | sp2p send -
tar czf - src/ | sp2p send -name src.tar.gz -
```

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | `https://sp2p.io` | Signaling server: `https://host` (the `/ws` path is added for you) or a full `wss://host/ws` endpoint |
| `-url` | `https://sp2p.io` | Public base URL for share links |
| `-name` | | Filename for stdin streams |
| `-compress` | `3` | zstd compression level (0=disabled, 1-9) |
| `-allow-relay` | `false` | Allow TURN relay without prompting (see [TURN Relay](#turn-relay)) |
| `-transport` | `auto` | Transport mode: `auto`, `tcp`, or `webrtc` |
| `-parallel` | `0` | Parallel TCP connections: 0=auto, 1=single, 2-6=force count |
| `-v` | `false` | Verbose diagnostic output |
| `-format` | `human` | Output format: `human` or JSON Lines (`json`) |
| `-event-output` | `stdout` | JSON event stream: `stdout` or `stderr` |
| `-status-file` | | Atomically update a private JSON status snapshot (requires `-format json`) |

### Receiving

```text
sp2p receive [flags] <CODE>
```

```bash
sp2p receive abc123-xYz456
sp2p receive abc123-xYz456 -output ~/Downloads
sp2p receive abc123-xYz456 -stdout | tar xzf -
sp2p receive -format json -event-output stderr -stdout abc123-xYz456 > received.tar
```

`receive` and `recv` are both accepted.

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | `https://sp2p.io` | Signaling server: `https://host` (the `/ws` path is added for you) or a full `wss://host/ws` endpoint |
| `-output` | `.` | Output directory |
| `-stdout` | `false` | Write to stdout instead of a file |
| `-max-receive-bytes` | `0` | Decoded transfer byte limit; 0 means 1 TiB |
| `-max-extract-bytes` | `0` | Expanded archive byte limit; 0 means 1 TiB |
| `-allow-relay` | `false` | Allow TURN relay without prompting (see [TURN Relay](#turn-relay)) |
| `-transport` | `auto` | Transport mode: `auto`, `tcp`, or `webrtc` |
| `-parallel` | `0` | Parallel TCP connections: 0=auto, 1=single, 2-6=force count |
| `-v` | `false` | Verbose diagnostic output |
| `-format` | `human` | Output format: `human` or JSON Lines (`json`) |
| `-event-output` | `stdout` | JSON event stream: `stdout` or `stderr` |
| `-status-file` | | Atomically update a private JSON status snapshot (requires `-format json`) |

**What to expect on the receiving side:**

- **Nothing is overwritten.** A file whose name is already taken gets a numbered name instead. An archive is extracted into a new directory named after the transfer and fails if that directory already exists. A folder sent on its own keeps its name; several paths sent together get a wrapper directory.
- **Output is verified before it is acknowledged.** Every transfer is checked against the sender's byte count and SHA-256, then closed and published, before the sender is told it succeeded. This is not an fsync guarantee. If the final acknowledgement is lost, the receiver may hold a valid file while the sender reports a failure.
- **Limits default to 1 TiB** for both the received bytes and the expanded archive. Zero means the default, not unlimited. Raise them only for transfers you trust, for example `-max-receive-bytes 2199023255552` for 2 TiB.
- **Browser receives** stream to disk when the File System Access API is available (up to 1 TiB) or download into memory (up to 256 MiB). Pick the save location before connecting. Cancelling the picker cancels the transfer.
- **Piping to stdout** cannot roll back bytes that were already written if the transfer fails partway.

The full resource and output guarantees, including buffer bounds and timeouts, are listed in [SECURITY.md](SECURITY.md#resource-and-output-guarantees).

### Rsync Synchronization

`sp2p rsync` runs your installed rsync over an encrypted SP2P stream, so you get rsync's incremental deltas, partial files, and metadata handling between two machines that cannot reach each other directly. It works on macOS and Linux. Apple's built-in openrsync and the historical macOS rsync 2.6.9 both work without installing a replacement. On Windows, run both SP2P and rsync inside WSL.

The source machine always runs `send` and creates the code. The destination runs `recv` with that code. Either side can supply the rsync options; the other side just exposes a directory.

**Sender chooses the rsync options:**

```bash
# Source machine: prints CODE
sp2p rsync send -- -av --partial ./photos/ sp2p::share/

# Destination machine: exposes ./backup as a write-only target
mkdir -p ./backup
sp2p rsync recv CODE ./backup
```

**Receiver chooses the rsync options:**

```bash
# Source machine: exposes ./photos read-only and prints CODE
sp2p rsync send ./photos

# Destination machine: runs the rsync client
sp2p rsync recv CODE -- -av --partial sp2p::share/ ./photos/
```

Everything after `--` is passed to rsync unchanged. `sp2p::share/` is a placeholder for the remote side: `sp2p` is the host name and `share` is the module. Put SP2P flags such as `--server`, `--allow-relay`, and `--rsync-binary PATH` before `--`.

Good to know:

- **One code, one run.** Each pair of commands performs one rsync invocation. Running again reuses the existing files for rsync's delta comparison but needs a new code.
- **Deletion needs opt-in.** A destination that exposes a directory refuses sender-requested `--delete` options unless it passes `--allow-delete` before `CODE`. A destination that runs the rsync client controls deletion with its own rsync arguments.
- **Rsync owns the file semantics.** Selection, metadata, deltas, partials, compression, and symlink handling follow rsync's rules. SP2P's receive limits and no-overwrite behaviour do not apply here.
- **Symlinks are constrained.** The served directory is refused if it contains a symlink that resolves to a directory. File and dangling symlinks stay links under `-a` with munged targets, and peer requests for `copy-links`, `copy-unsafe-links`, `copy-dirlinks`, or `keep-dirlinks` are rejected. This is defense in depth, not a sandbox: control who can modify a served tree.
- **Write-only is not secret.** A write-only destination blocks downloads, but rsync's delta protocol still exchanges some information about existing files.
- **Transport is fixed.** SP2P configures rsync's transport itself (`RSYNC_CONNECT_PROG` for upstream rsync, a local `-e` helper for openrsync). No SSH is involved, and user-supplied `-e` or remote-shell options are rejected.
- **Done means both sides exited.** A connection or a partial file is not completion. Wait for both commands to exit successfully, or for a JSON `result` event with `outcome:"completed"`.

### TCP, Unix, and Stdio Tunnels

`sp2p tunnel` forwards one TCP port or Unix socket from one machine to another. The machine that can reach the service runs `serve` and creates the code. The other machine runs `connect`, which opens a local listener that forwards its first connection through the tunnel.

```bash
# Machine that can reach PostgreSQL: prints CODE
sp2p tunnel serve --to tcp://127.0.0.1:5432

# Other machine: wait for "Ready", then connect to localhost:15432
sp2p tunnel connect --listen tcp://127.0.0.1:15432 CODE
```

Unix sockets work the same way, and the two ends can be mixed:

```bash
# Unix to Unix
sp2p tunnel serve --to unix:///run/example/service.sock
sp2p tunnel connect --listen unix:///tmp/sp2p-example.sock CODE

# Unix target, TCP listener (the reverse also works)
sp2p tunnel serve --to unix:///run/example/service.sock
sp2p tunnel connect --listen tcp://127.0.0.1:15432 CODE
```

`--stdio` attaches the tunnel to stdin and stdout instead of a socket, giving you a raw full-duplex byte stream between two processes:

```bash
sp2p tunnel serve --stdio
sp2p tunnel connect --stdio CODE
```

Good to know:

- **One connection per code.** The listener accepts exactly one connection, then closes. To reconnect, create a new code.
- **The target is fixed by the serving side.** The connecting peer cannot pick a different host, port, or path, and SP2P dials the target only after the peer is authenticated and asks for the stream.
- **TCP listeners need at least a port.** An omitted host binds loopback, which is the recommended choice anyway. A `--to` Unix path must be an existing socket; a `--listen` Unix path must not exist yet. SP2P removes only the socket it created.
- **Half-close is preserved.** One side can finish sending and keep receiving where the local endpoint supports it. Cancelling closes the stream and the local endpoints.
- **Stdio is not `send -`.** `sp2p send -` transfers one finite, verified file in one direction. Tunnel stdio is bidirectional and unframed. In stdio mode stdout carries payload, so JSON events must go to stderr: `--format json --event-output stderr`.
- **CLI only.** The browser cannot run rsync or open local sockets, and these sessions have no browser link.

### AI Agents and Automation

Paste one of these prompts into an agent and replace the bracketed parts:

```text
Please send [file] using https://sp2p.io/llm
Please synchronize [source] to [destination] with rsync using https://sp2p.io/llm
Please forward [TCP or Unix target] to [local listener] using https://sp2p.io/llm
```

Every transfer command (`send`, `receive`, `rsync`, `tunnel`) accepts `-format json` and then emits JSON Lines: a `session` event with the transfer code on the creating side, lifecycle and `progress` events while running, and exactly one terminal `result` event with `outcome` set to `completed` or `failed`.

```bash
sp2p send -format json report.pdf
sp2p receive -format json SESSION-SEED
```

The essentials:

- **The code is a secret.** Share it only with the intended peer and keep it out of public logs. Only the creating side (`send`, `rsync send`, `tunnel serve`) emits it, and only file transfers include a browser `share_url`.
- **Wait for `result`.** An `error` event is diagnostic, not terminal. Keep reading until the single `result` event arrives.
- **Relay needs consent.** When a direct connection fails, JSON mode emits `relay_required` with the path of a temporary response file. Write `allow` or `deny` to that file. Pass `-allow-relay` to skip the prompt entirely.
- **`-status-file PATH`** atomically maintains a private JSON snapshot of the latest state for other processes to poll. The creator's snapshot contains the code.
- **Rsync and tunnel events** also carry `service` and `mode`, a `ready` event when the local listener or daemon is up, cumulative `bytes_sent` and `bytes_received`, and base64 `subprocess_output` events for rsync's own output.
- **Self-hosted servers:** pass the guide's origin to `-server` on both peers so they meet on the same signaling server.

The complete event contract, with examples for every mode, is in the [agent guide](https://sp2p.io/llm).

### Protocol compatibility and staged upgrades

Clients and servers upgrade independently, and no version flag or coordinated rollout is needed:

- Two updated peers use transfer protocol v3. A transfer that involves a 0.4.0 peer uses v2. Both work through a 0.4.0 or 0.5.0 signaling server.
- Capability markers are bound to the key-exchange transcript, so tampering with them fails authentication instead of quietly downgrading updated peers. Connection errors never trigger a retry at a lower version.
- A legacy (v2) transfer shows an informational warning (a `warning` event in JSON mode), disables parallel TCP, and lacks v3's candidate authentication and receive credits. Updated peers keep their local decoding, quota, and output protections but cannot fix an old peer. Upgrade the older side for the full guarantees.
- In JSON mode a `protocol` event reports the negotiated version once it is authenticated; later events and status snapshots include it.

The negotiation design is described in [docs/security-performance-implementation.md](docs/security-performance-implementation.md#transitional-protocol-compatibility).

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SP2P_SERVER` | Signaling server URL | `https://sp2p.io` |
| `SP2P_URL` | Public base URL for share links | `https://sp2p.io` |

Flags override environment variables. Builds from source default to `http://localhost:8080` instead.

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

# Transport mode (auto, tcp, webrtc)
transport: auto

# Parallel TCP connections (0=auto, 1=single, 2-6=force count)
parallel: 0

# Default output directory for received files
output: ~/Downloads

# Decoded transfer and expanded archive byte limits (0 = 1 TiB each)
max-receive-bytes: 0
max-extract-bytes: 0

# Always show verbose output
verbose: false
```

**Precedence** (highest to lowest):
1. CLI flags (`-server`, `-compress`, etc.)
2. Environment variables (`SP2P_SERVER`, `SP2P_URL`)
3. Config file
4. Built-in defaults

A missing config file is ignored. A malformed one is an error.

## Self-Hosting

### Docker Compose

Docker Compose is the easiest way to self-host SP2P. Clone this repo and run:

```bash
docker compose up -d
```

This starts the server on port 8080 with the default configuration. Customize it by editing the environment variables in `docker-compose.yml`.

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

**Ephemeral credentials (recommended):** share a secret between sp2p and coturn. The server then issues short-lived HMAC credentials per connection, and no static password is ever sent to clients:

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

Configure coturn with `use-auth-secret` and the same secret in `turnserver.conf`. Start from the [coturn policy example](deploy/turnserver.conf.example), but treat it as a template: add your own secrets, TLS and address settings, and an egress firewall.

**Static credentials:** a fixed username and password is simpler but weaker, because the credentials are delivered to clients and can be reused:

```yaml
services:
  sp2p:
    environment:
      - SP2P_TURN_SERVERS=turn:localhost:3478
      - SP2P_TURN_USERNAME=sp2p
      - SP2P_TURN_PASSWORD=sp2p
```

Either way, TURN credentials are never part of the initial handshake. They are handed out only after direct connection attempts have failed and a minimum time has passed, which makes scripted credential harvesting impractical.

### Server Configuration

The server supports three mutually exclusive TLS modes:
- **Plain HTTP**: the default, suitable behind a reverse proxy
- **Manual TLS**: provide your own certificate and key via `-tls-cert` / `-tls-key`
- **ACME**: automatic Let's Encrypt certificates via `-acme` (requires `-config-dir` for cert storage)

When TLS is active and `-addr` is not set, the server listens on `:443`.

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `-addr` | `SP2P_ADDR` | `:8080` | Listen address |
| `-base-url` | `SP2P_BASE_URL` | `http://localhost:8080` | Public base URL |
| `-trust-proxy` | `SP2P_TRUST_PROXY` | `false` | Honor forwarded IPs only through explicitly trusted proxies |
| `-trusted-proxies` | `SP2P_TRUSTED_PROXIES` | | Comma-separated immediate proxy IPs/CIDRs; required with `-trust-proxy` |
| `-tls-cert` | `SP2P_TLS_CERT` | | TLS certificate file |
| `-tls-key` | `SP2P_TLS_KEY` | | TLS private key file |
| `-acme` | `SP2P_ACME` | `false` | Enable ACME auto-certificates |
| `-acme-email` | `SP2P_ACME_EMAIL` | | ACME contact email |
| `-config-dir` | `SP2P_CONFIG_DIR` | | Persistent data directory (required for ACME) |
| `-turn-servers` | `SP2P_TURN_SERVERS` | | Comma-separated TURN server URLs |
| `-turn-secret` | `SP2P_TURN_SECRET` | | Shared secret for ephemeral TURN credentials |
| `-turn-ttl` | `SP2P_TURN_TTL` | `5m` | Lifetime of ephemeral TURN credentials, at most 1h |
| `-turn-username` | `SP2P_TURN_USERNAME` | | TURN static username (mutually exclusive with `-turn-secret`) |
| `-turn-password` | `SP2P_TURN_PASSWORD` | | TURN static password (mutually exclusive with `-turn-secret`) |

### Proxy, container, and relay migration

Things to check before rolling out 0.5.0 on an existing deployment:

- **Reverse proxies must be listed explicitly.** `-trust-proxy` now requires `-trusted-proxies` with the real proxy addresses, for example `-trust-proxy -trusted-proxies 127.0.0.1/32,::1/128` for a local proxy. Never use an all-address CIDR. Forwarded chains are read from the trusted side, so a direct client cannot spoof its address. `SP2P_TRUST_PROXY=false` or `0` disables trust.
- **Containers run as UID/GID 65532** and use `/config`. Make persistent mounts writable by that identity. Prefer a reverse proxy that terminates TLS on 443 and forwards to container port 8080. Binding low ports inside the container for native TLS or ACME needs an explicit low-port capability; do not switch the image back to root. Verify ACME renewal and volume permissions in staging.
- **Signaling admission is bounded.** The server admits at most `2 × max-sessions + 64` sockets globally and `2 × max-sessions-per-ip + 4` per IP, requires a first message within 10 seconds, and allows 600 messages and 4 MiB per minute per registered socket.
- **Public relays need their own policy.** The [coturn example](deploy/turnserver.conf.example) is a starting point. Add secrets, TLS and address settings, and an egress firewall that blocks private, loopback, link-local, translated IPv6, and any organisation-specific ranges. Confirm allocation, bandwidth, and expiry behaviour in staging. Expiring an application credential does not revoke a relay allocation that already exists.

## Architecture Overview

SP2P has three components: the **CLI** (`sp2p`), the **signaling server** (`sp2p-server`), and a **web UI** served by the signaling server for browser-based sending and receiving.

### Connection Flow

```text
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
  |   [X25519 key exchange; sender includes           |
  |    PreferTCP hint for large transfers]             |
  |                         |                         |
  |============ P2P connection (race) ================|
  |  WebRTC / Symmetric TCP — first wins              |
  |  (TCP preferred for large transfers; see below)   |
  |                         |                         |
  |====== key confirmation over raw P2P channel ======|
  |                         |                         |
  |========== encrypted transfer (AES-256-GCM) =======|
  |  metadata -> data chunks -> done -> complete      |
```

### P2P Connection Strategies

Two methods race in parallel, and the first to succeed wins:

1. **Symmetric TCP**: both peers listen on a random TCP port and trickle LAN addresses via signaling. Each peer filters out loopback and link-local addresses, capped at 8 dial addresses. In the background, each peer attempts a UPnP port mapping and sends the external address on success. The first successfully handshaken TCP connection wins. This uses the OS TCP stack (cubic or BBR congestion control) and reaches full link speed on most networks.
2. **WebRTC**: uses ICE (STUN/TURN) to traverse NATs. Works in most network configurations, including symmetric NATs where TCP cannot connect. Required when one peer is a browser. WebRTC data channels run over SCTP/DTLS with their own congestion control; see [Why TCP is preferred](#why-tcp-is-preferred) below.

#### Transport Selection

The `-transport` flag controls which methods are attempted:

| Mode | Behavior |
|------|----------|
| `auto` (default) | Race both TCP and WebRTC. For large transfers (≥64 MiB), prefer TCP (see below). |
| `tcp` | TCP only. Fails if no direct/UPnP path exists. |
| `webrtc` | WebRTC only. Useful when TCP is blocked or for debugging. |

Mismatched modes between sender and receiver work correctly. For example, a sender using `-transport tcp` will only attempt TCP, while a receiver on `auto` will race both but converge on TCP since the sender never produces a WebRTC offer.

#### TCP Preference for Large Transfers

In `auto` mode, when the file size is ≥64 MiB, SP2P prefers TCP over WebRTC. The sender signals this preference to the receiver during the key exchange, and both sides apply the same logic:

1. Both methods still race simultaneously.
2. If TCP wins first, it is used immediately (no change from normal behavior).
3. If WebRTC wins first, the connection is held for up to **6 seconds** to give TCP time to connect (for example, waiting for a UPnP port mapping to complete and for the remote peer to dial it).
4. If UPnP mapping succeeds during the wait, the timer **restarts**, giving the remote peer a fresh window to reach the newly mapped address.
5. If TCP connects within the window, it wins and the WebRTC connection is closed. If the window expires without TCP, WebRTC is used.

On a LAN, TCP almost always wins instantly, so the preference window never triggers. On a WAN without UPnP or behind a symmetric NAT, TCP fails and WebRTC is used after the window. That adds at most 6 seconds, which is negligible compared to the minutes a large transfer takes over WebRTC's slower transport.

#### Why TCP is Preferred

WebRTC data channels carry SCTP over DTLS/UDP. Browser-to-browser transfers use the browsers' WebRTC implementations; transfers involving a CLI use [Pion](https://github.com/pion/webrtc) on the CLI side. Throughput depends on the selected direct or TURN path, latency, loss, implementation, application flow control, and output speed. There is no universal WebRTC speed cap.

Direct TCP uses the OS networking stack, and SP2P can use parallel TCP connections for large CLI-to-CLI transfers. Browsers cannot use SP2P's direct TCP transport. For a fair comparison, force `-transport webrtc` on the CLI and use the same payload and compression settings.

Updated browser senders use 64 KiB chunks and offer a 4 MiB receive window to updated peers. Existing v3 receivers retain their 16-frame limit, giving those browser sends a 1 MiB window; v2 compatibility remains automatic. An authenticated receiver grant is required before the sender expands its window. The metadata offer, grant encoding, and bounds are described in [receive-window negotiation](docs/receive-window.md).

Browser console logs sample the selected direct/relay path, available RTT, queued bytes, and cumulative time spent waiting for credits, draining the DataChannel, encrypting/decrypting, reading, hashing, and writing. These counters help distinguish a network bottleneck from local processing. Missing browser statistics are reported as unavailable; timings include asynchronous scheduling and are not independent CPU utilization measurements.

### Transfer Protocol

The transfer uses a framed binary protocol over the encrypted stream:

| Message | Type | Description |
|---------|------|-------------|
| Metadata | `0x01` | JSON with filename, size, MIME type, folder/stream flags |
| Data | `0x02` | File data chunk (up to 256 KiB) |
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
   - `k_s2r`: sender-to-receiver data key
   - `k_r2s`: receiver-to-sender data key
   - `k_confirm`: key confirmation MAC key
   - `verify`: visual verification code (8 hex chars, displayed in the web UI)
5. The HKDF info string binds keys to the session: `"sp2p-v1" || session_id || sender_pub || receiver_pub`

### Transfer Code

The transfer code has the format `SESSION_ID-SEED` where:

- **Session ID** identifies the signaling session on the server
- **Seed** is a 128-bit random value (base62-encoded) used as the HKDF salt

Both components are required to derive encryption keys. The server only knows the session ID, not the seed, so a compromised signaling service alone cannot decrypt transfers between independently trusted clients. A compromised web or bootstrap host can instead deliver malicious client code; see the [trust model](#trust-model) below.

### Encrypted Metadata Preview

Before the P2P connection is established, the sender encrypts file metadata (name, size, type, file count) and sends it to the server via signaling. The server stores the opaque blob on the session. When the receiver opens the share link, the web UI fetches the encrypted metadata via `GET /api/file-info/{sessionId}`, decrypts it using the seed from the transfer code, and displays a confirmation card with the file name and size before proceeding.

The metadata is encrypted with **AES-256-GCM** using a key derived from the seed via HKDF (salt: `"sp2p-file-info"`, label: `"sp2p-v1-file-info-key"`). Since the server never knows the seed, it cannot read the metadata. It only stores and serves the encrypted blob. This is best-effort: if the metadata is unavailable or decryption fails, the transfer proceeds normally without a preview.

### Encryption

- **AES-256-GCM** with directional keys (each direction has its own key)
- Sequential nonces starting at 0 (counter-based, prevents reuse)
- Message type and sequence number are authenticated as AAD (Additional Authenticated Data)
- Nonce counter is capped at 2^32 to prevent nonce reuse

### Wire Format (Encrypted)

```text
[4 bytes: total payload length, big-endian uint32]
[1 byte:  message type (cleartext, authenticated via AAD)]
[8 bytes: sequence number (big-endian uint64)]
[N bytes: AEAD ciphertext with AAD = type || seq || version]
```

### Key Confirmation

Before the encrypted stream starts, both peers perform **key confirmation** over the raw P2P connection:

1. Each peer computes `HMAC-SHA256(k_confirm, role || sender_pub || receiver_pub)`
2. Both send their HMAC and verify the peer's HMAC (constant-time comparison)
3. If confirmation fails, the connection is aborted. This detects wrong codes and MITM attacks.

### TURN Relay

When both peers are behind restrictive NATs and direct P2P fails, WebRTC may fall back to a **TURN relay** server. Encrypted data then passes through the relay, but the relay **cannot decrypt it**: it only sees opaque ciphertext, the same AES-256-GCM stream used for direct connections.

TURN relay is only attempted as a **last resort**, after all direct connection methods (WebRTC via STUN, symmetric TCP with LAN/UPnP addresses) have failed. When this happens, the CLI **prompts for consent** before using the relay. Use the `-allow-relay` flag to skip the prompt (useful for scripting):

```bash
sp2p send -allow-relay photo.jpg
sp2p receive -allow-relay abc123-xYz456
```

In JSON mode, SP2P creates a temporary owner-only response file and emits its path in a `relay_required` event. An agent writes `allow` or `deny` to that file to answer the prompt, and SP2P removes the file after reading it. In human mode, if no TTY is available and `-allow-relay` is not set, TURN is skipped and the connection fails with a message suggesting the flag.

**Credential delivery:** TURN credentials are omitted from the initial handshake. After pairing and retry pacing, both participants share one cached issuance for that session; repeated requests never renew it. Ephemeral usernames bind expiry to an opaque session ID. The TTL defaults to 5 minutes and cannot exceed one hour. New issuances are limited to 120 per minute globally and 12 per minute per sender IP. These are abuse bounds, not user authentication: anonymous clients can create new sessions and reuse legitimately issued credentials elsewhere until expiry. Static credentials are reusable by design and need an external relay policy.

### Trust Model

- The signaling server relays metadata only (public keys, ICE candidates, session management) and stores encrypted file-info blobs it cannot decrypt
- **File data flows directly between peers** when a direct connection succeeds
- If a TURN relay is used, encrypted data routes through the relay but remains E2E encrypted and unreadable by the relay
- TURN relay requires explicit consent (`-allow-relay` or an interactive prompt)
- The server cannot derive encryption keys (it never sees the seed portion of the transfer code)
- Ephemeral key pairs are generated per session and never reused
- Browser JavaScript and bootstrap scripts must be trusted. Their host can replace them with code that exposes secrets or files, and a verifier fetched from that same compromised host cannot fix this. Independently verified CLI or package installations have a stronger endpoint trust boundary.

## Development

**Requirements:** Go 1.27.0 (or a newer supported, security-patched toolchain) and Node.js 25 (for the web UI build). CI and release builds follow `go.mod`; containers pin builder and runtime digests. Dependabot proposes weekly dependency, action, and image updates. Rebuild static binaries after toolchain security updates.

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

```text
cmd/
  sp2p/             CLI entrypoint
  sp2p-server/      Server entrypoint
internal/
  archive/          Tar streaming for folder transfers
  cli/              CLI send/receive logic and progress display
  config/           YAML config file loading
  conn/             P2P connection strategies (WebRTC, Symmetric TCP/UPnP)
  crypto/           Key exchange, HKDF derivation, AES-GCM encrypted stream
  flow/             High-level send/receive orchestration
  peer/             Authenticated v3 peer connections for stream services
  rsync/            Rsync transport and daemon configuration
  server/           HTTP/WebSocket server, signaling, and web UI serving
  signal/           Signaling protocol messages and WebSocket client
  stream/           Full-duplex encrypted streams for rsync and tunnels
  transfer/         Framed transfer protocol (metadata, chunked data, ack/done)
  tunnel/           TCP, Unix socket, and stdio tunnel endpoints
web/
  src/              TypeScript source for browser-based sending and receiving
  dist/             Built web UI (embedded into server binary)
```

## License

MIT
