# Privacy Policy

Effective: November 27, 2026

This policy covers the public SP2P service at [sp2p.io](https://sp2p.io): the website, the signaling server, the TURN relay, and the one-shot bootstrap scripts. It also covers the SP2P agent skill and Claude Code plugin. The service is operated by Signal24 LLC dba Zyno Consulting ("we").

If you run your own SP2P server, this policy doesn't apply to it. Whoever operates that server is responsible for its privacy practices.

## The short version

- We can't read what you transfer. Files, folders, streams, and file metadata are end-to-end encrypted between the two peers, and the server never has the key.
- There are no accounts, no analytics, no advertising, and no tracking cookies.
- The server keeps session state in memory only while a transfer is being set up, and it doesn't write IP addresses to its logs.

## What we can't see

**Your data.** Transfers are encrypted with keys that only the two peers derive, using X25519 and AES-256-GCM. The transfer code that carries the secret never reaches the server in a usable form. When data goes through our TURN relay, the relay only carries ciphertext.

**File details.** The sender encrypts the file name, size, type, and file count before giving them to the server, which only stores and serves the encrypted blob. See [Encrypted Metadata Preview](README.md#encrypted-metadata-preview).

## What the service handles

**While a session is active.** To pair two peers, the signaling server keeps the following in memory:

- a random session ID
- each peer's client type (CLI or browser) and protocol version
- timestamps
- the encrypted file metadata described above
- the sender's IP address, which is used only for rate limiting

This state is removed when the session ends or goes idle. The rate limiter also keeps short-lived per-IP request counters in memory, and clears them once the limit window passes. Peers exchange connection candidates through the server so they can connect directly. These include IP addresses and ports, and the server relays them without storing them.

**Server logs.** The SP2P server logs operational events, such as a peer connecting or disconnecting, or a session being removed. These events include the session ID, the peer's role, and its client type. The server does not log IP addresses, transfer codes, file names, or file contents.

**Aggregate counters.** The server keeps service-wide totals: send attempts, connected sends, completed sends, and bytes transferred. These are not linked to any person, session, or IP address.

**TURN relay.** Peers use the relay only if a direct connection fails and they agree to it. The relay sees both peers' IP addresses, connection timing, and traffic volume, but only ciphertext. Relay credentials are short-lived and tied to one session.

**Your browser.** The website stores your light or dark theme choice in your browser's local storage. It sets no cookies and loads no third-party scripts, fonts, or trackers.

## Service providers

Some infrastructure providers see standard network information, such as your IP address and request details, under their own privacy policies:

- **Cloudflare** serves sp2p.io and sees requests to the website and signaling server. Cloudflare keeps any request logs for its standard retention periods. We don't configure longer retention.
- **GitHub** hosts the CLI releases. The bootstrap scripts and install instructions download binaries from GitHub.
- **Google** runs the public STUN servers (`stun.l.google.com`). By default, the CLI and the browser use them to discover their public address for direct connections.

We don't sell personal information or logs, and we don't share them for advertising.

## The agent skill and plugin

The SP2P agent skill and Claude Code plugin contain only instructions. They collect nothing themselves. When an agent uses them to run a transfer, the transfer is covered by this policy as described above. Your AI agent's provider has its own privacy terms for the conversation and commands you run.

## Children

The service isn't directed at children under 13, and we don't knowingly collect their personal information.

## Changes

We'll update this page when our practices change and revise the effective date above. The history of this file is public in the [repository](https://github.com/zyno-io/sp2p/commits/main/PRIVACY.md).

## Contact

Questions or requests: **oss@zyno.io**
