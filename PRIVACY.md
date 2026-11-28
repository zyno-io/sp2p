# Privacy Policy

Effective: November 27, 2026

This policy covers the public SP2P service at [sp2p.io](https://sp2p.io): the website, the signaling server, the TURN relay, and the one-shot bootstrap scripts. It also covers the SP2P agent skill and Claude Code plugin. The service is operated by Signal24 LLC dba Zyno Consulting ("we").

If you run your own SP2P server, this policy doesn't apply to it. Whoever operates that server is responsible for its privacy practices.

## The short version

- Files, folders, streams, and file metadata are end-to-end encrypted between the two peers. The server never receives the keys needed to read them.
- There are no accounts, no analytics, no advertising, and no tracking cookies.
- The server keeps session state in memory only while a transfer is being set up, and its own log messages don't include IP addresses.

## What we can't see

**Your data.** Transfers are encrypted with keys that only the two peers derive, using X25519 and AES-256-GCM. The secret part of the transfer code never reaches the server. Share links keep it in the part of the URL that browsers don't send. When data goes through our TURN relay, the relay only carries ciphertext.

sp2p.io also serves the browser app and the one-shot bootstrap scripts, so this protection depends on that code being the published open-source code. See the [Trust Model](README.md#trust-model). For the strongest guarantee, install the CLI from a release you verify yourself.

**File details.** The sender encrypts the file name, size, type, and file count before giving them to the server, which only stores and serves the encrypted blob. See [Encrypted Metadata Preview](README.md#encrypted-metadata-preview).

## What the service handles

**While a session is active.** To pair two peers, the signaling server keeps the following in memory:

- a random session ID
- each peer's client type (CLI or browser) and protocol version
- for the CLI, its operating system and CPU architecture, used only to tell it about the latest release for that platform
- timestamps
- the encrypted file metadata described above
This state is removed when the session ends or goes idle.

The server also keeps the IP addresses of connected peers, and per-IP counters, to apply rate and abuse limits. These are kept only in memory, used for nothing else, and never written to disk or to its logs.

Peers exchange connection candidates through the server so they can connect directly. These include IP addresses and ports, and the server relays them without storing them.

**Server logs.** The SP2P server logs operational events, such as a peer connecting or disconnecting, or a session being removed. These events include the session ID, the peer's role, and its client type. Its log messages don't include IP addresses, transfer codes, file names, or file contents.

**Aggregate counters.** The server keeps service-wide totals of send attempts and connected sends. These are not linked to any person, session, or IP address.

**TURN relay.** Peers use the relay only if a direct connection fails and both of them agree to it. The relay sees both peers' IP addresses and ports, connection timing, and traffic volume, but only ciphertext. The relay server may log these connection details, along with the session ID that's part of the relay username. We use those logs only to operate the relay and prevent abuse.

**Your browser.** The website stores your light or dark theme choice in your browser's local storage. SP2P itself sets no cookies and loads no third-party scripts, fonts, or trackers. Cloudflare may set strictly necessary security cookies.

## Service providers

Some providers see standard network information, such as your IP address and request details, under their own privacy policies:

- **Cloudflare** serves sp2p.io and terminates its TLS connections. It sees requests to the website and the signaling messages that pass through it, including the session ID and the connection candidates (IP addresses and ports) peers exchange. It doesn't see transfer contents or readable file metadata. Cloudflare keeps any request logs for its standard retention periods, and we don't configure longer retention.
- **Our hosting provider** runs the server and the TURN relay, and sees the network traffic to them.
- **GitHub** hosts the CLI releases. The bootstrap scripts and most install instructions download binaries from GitHub. Package managers you choose to install with (such as Homebrew, Scoop, or WinGet), and npm for `npx skills add`, have their own policies.
- **Google** runs public STUN servers (`stun.l.google.com`). Unless sp2p.io provides its own STUN servers, the CLI and the browser use Google's to discover their public address for direct connections.

We don't sell personal information or logs, and we don't share them for advertising.

## The agent skill and plugin

The SP2P agent skill and Claude Code plugin contain only instructions. They collect nothing themselves. When an agent uses them to run a transfer, the transfer is covered by this policy as described above. Your AI agent's provider has its own privacy terms for the conversation and commands you run.

## Children

The service isn't directed at children under 13, and we don't knowingly collect their personal information.

## Changes

We'll update this page when our practices change and revise the effective date above. The history of this file is public in the [repository](https://github.com/zyno-io/sp2p/commits/main/PRIVACY.md).

## Contact

Questions or requests: **oss@zyno.io**
