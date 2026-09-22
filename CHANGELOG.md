# Changelog

All notable changes to SP2P are documented here.

This project uses [Semantic Versioning](https://semver.org/). During early development (0.x), minor versions may contain breaking changes.

## Unreleased

### Fixed

- Keep browser-to-browser receive progress responsive on slow transfers.
- Show one capability-appropriate browser receive action, restore its normal font weight, and timestamp browser diagnostic logs.

## [0.5.0] - 2026-09-21

### Upgrade notes

- Upgrade clients and servers independently. Transfer compatibility is automatic: updated peers use v3 together, and mixed 0.4.0/0.5.0 peers use v2, through either server version. No protocol flag or browser checkbox is required. Transcript-bound capabilities prevent signaling tampering from silently downgrading updated peers. Legacy compatibility warns without prompting, has fewer protections, and disables parallel TCP. See [protocol compatibility](README.md#protocol-compatibility-and-staged-upgrades).
- Configure explicit trusted proxy IPs/CIDRs when using `-trust-proxy`, and make container `/config` mounts writable by UID/GID 65532. Review [proxy, container, and relay migration](README.md#proxy-container-and-relay-migration) before rollout.
- Receive and archive-expansion limits default to 1 TiB each; zero selects the finite default. Browser memory downloads are capped at 256 MiB. Archive destinations must not already exist; extraction no longer merges into existing directories.
- Bootstrap verifies matching-release checksums by default without requiring `gh`. The bootstrap-only `--insecure-skip-checksum` flag is an explicit first-argument opt-out that warns before running unchecked downloaded code.
- Rsync uses the implementation installed on each macOS or Linux peer. Apple's built-in openrsync and historical macOS rsync 2.6.9 are supported without a Homebrew replacement. Options, metadata behavior, cross-version interoperability, and rsync security fixes depend on the installed implementations; this does not guarantee every historical patch level or option combination. On Windows, run both SP2P and rsync inside WSL because the native Windows adapter remains unsupported. Rsync and tunnel streams require updated authenticated-v3 CLI peers and do not fall back to legacy file-transfer mode.

### Added

- Add authenticated full-duplex streams with directional EOF, bounded flow control, and terminal acknowledgements over direct TCP, WebRTC, or an explicitly authorized encrypted relay.
- Add `sp2p rsync send|recv` for one-use incremental synchronization through an automatically configured installed rsync transport. The sender always creates the code; either peer can select exact rsync arguments, and `--rsync-binary` selects a specific executable. Upstream rsync uses `RSYNC_CONNECT_PROG`; Apple openrsync uses a fixed local `-e` helper without SSH or peer-selected remote commands.
- Add `sp2p tunnel serve|connect` for one fixed TCP or Unix target and one local TCP or Unix listener, including mixed endpoint types and duplex stdin/stdout. Each code accepts one connection.
- Add four homepage usage tabs for AI agents, rsync, tunnels, and installation, with current-server commands, accessible keyboard navigation, and copy controls.
- Extend JSON schema 1 stream events with service/mode context, endpoint readiness, bidirectional byte counters, base64-exact rsync subprocess output, and private status snapshots.
- Expand the agent guide, README, manual, and discovery index with files, archives, pipes, both rsync option-selection modes, TCP/Unix/mixed/stdio tunnels, relay consent, and terminal completion guidance.

### Changed

- Update Go, Node.js, Go modules, web dependencies, GitHub Actions, and GoReleaser to their latest mutually compatible releases, and group future Dependabot updates by ecosystem.

### Fixed

- Keep zero-install command text readable in the dark homepage theme.

### Security and correctness

- Negotiate transfer v3 between updated peers: authenticate transport candidates for CLI and browser peers, authenticate sender selection, bound confirmation, continuously drain controls, and enforce a 16-frame receive-credit window. Unauthenticated signaling client-type hints cannot bypass candidate authentication. Automatic v2 compatibility preserves updated peers' local decoding, queue, quota, and output protections, without claiming v3-only protections or repairs to old peers.
- Start receiver key confirmation immediately after authenticated sender selection, preventing large auto-mode transfers from timing out when WebRTC connects but TCP is unavailable.
- Drain parallel-transfer controls only into the remaining pending-queue capacity, so valid credit bursts followed by Heartbeat and Complete do not fail the connection.
- Bound decompression, browser queues, signaling admission/traffic, reassembly, decoded receive bytes, and archive expansion. Receive/extraction default to 1 TiB each; browser memory downloads are limited to 256 MiB.
- Finalize verified output before acknowledging; abort failed browser writes, publish archive wrappers atomically without replacement, and retain committed output after acknowledgement loss.
- Coalesce tiny browser receive chunks into bounded owned blocks, keep healthy idle stdin/finalization alive without stale socket deadlines, and bound final FinAck waits to five seconds. Cancel blocked browser buffer drains immediately on peer failure.
- Require trusted proxy IPs/CIDRs, cache/rate-limit TURN issuance, bound TTL, and provide an operator relay-policy example.
- Preserve long or Unicode TAR paths with PAX headers and calculate exact archive sizes. CLI and browser receivers accept inaccurate legacy v2 archive size estimates while retaining local quotas and final byte-count, chunk-count, and SHA-256 verification; v3 archives and v2 regular files still require exact declared sizes.
- Escape terminal control characters and apply HTML security headers consistently.
- Update Go to 1.26.8 and `golang.org/x/crypto` to 0.56.0, pin container images, GitHub Actions, and release-tool downloads, run containers without root, and configure final release-artifact attestations for optional independent verification.
- Check bootstrap archives against the matching release's SHA-256 manifest before extraction using standard OS tools, without requiring GitHub CLI (`gh`). Bootstrap trusts GitHub's HTTPS release channel; it does not independently verify signer identity.
- Fall back to OpenSSL for shell bootstrap SHA-256 checks when neither `sha256sum` nor `shasum` is installed; by default, refuse execution if no verifier is available or hashing fails.
- Add the explicit bootstrap-only `--insecure-skip-checksum` flag to shell and PowerShell. As the first bootstrap argument it skips manifest/hash checks, warns on stderr, and is not forwarded to the CLI; normal invocations still verify checksums.
- Correct the documented web/bootstrap endpoint trust model and add security regressions, fuzz coverage, race/static checks, and full browser CI.

### Performance

- Stream single browser files with incremental hashing; coalesce archive reads while retaining interactive stdin latency.
- Bound parallel compression to four workers, give each parallel stream its own write worker, and decrypt owned frame payloads in place.
- Close/join partial secondary connections and bound UPnP cleanup, including mappings discovered after transfer teardown.

## [0.4.0] - 2026-09-05

### Added

- JSON Lines CLI output for automation and AI agents with `-format json`, selectable event output via `-event-output`, and private atomic status snapshots via `-status-file`.
- Structured session, progress, relay-consent, and terminal result events; agents can approve or deny relay use through a temporary private response file.
- Agent guides at `/llm` and `/agents.md`, discovery documents at `/llms.txt` and `/llms-full.txt`, and copyable send/receive handoff prompts with self-hosted server guidance.

### Fixed

- Skip sockets, symlinks, and devices before constructing TAR headers so unsupported entries do not abort folder sends.
- Stop the Unix terminal key-reading loop before restoring terminal state and closing its descriptor.
- Cancel pending machine-mode relay prompts when the peer declines, disconnects, or signaling ends, and report relay-wait disconnects promptly.
- Omit secret transfer codes from verbose receive logs.

### Changed

- Decouple package publication from the release workflow; publish packages through a manual workflow that validates the release tag and derives its version.

## [0.3.0] - 2026-08-24

### Fixed

- Reliable large browser transfers by fragmenting encrypted WebRTC frames to the negotiated SCTP message size.
- Ordered completion for parallel TCP transfers, preventing a completion signal from overtaking delayed data.

### Changed

- Updated Go and web dependencies, including Pion WebRTC, Playwright, esbuild, and TypeScript.
- Updated the web build container to Node.js 24.

## [0.2.0] - 2026-03-10

### Added

- Multi-stream parallel transfers
- Protocol v2: heartbeat/cancel frames, signaling closes after P2P established
- Transport selection with TCP preference for large transfers, pipelined sender
- Streaming folder extraction on receive, eliminating 2x disk usage
- Configurable session limits via env vars and flags
- Platform-aware update notifications in CLI

### Fixed

- Chocolatey package metadata (author, title, icon, release notes URL)

## [0.1.1-server] - 2026-03-05

Server-only patch release.

### Added

- Platform-aware release resolution for `/dl/` endpoint

### Fixed

- `SP2P_VERSION` not set in CI snapshot builds
- Server footer now links to repo root instead of release tag

## [0.1.1-cli-windows] - 2026-03-05

Windows CLI patch release.

### Fixed

- Windows `KeyListener.Stop()` deadlock that blocked signaling shutdown

## [0.1.0] - 2026-03-05

Initial public release.

### Added

- End-to-end encrypted peer-to-peer file and folder transfer
- X25519 key exchange with AES-256-GCM stream encryption
- WebRTC and TCP transport with automatic selection
- Browser-to-CLI transfers via web UI
- Signaling server with built-in TURN relay
- CLI with progress bars, seed phrases, and interactive prompts
- Homebrew, Scoop, AUR, Chocolatey, and WinGet packaging
- Man pages for `sp2p` and `sp2p-server`

[0.5.0]: https://github.com/zyno-io/sp2p/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/zyno-io/sp2p/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/zyno-io/sp2p/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/zyno-io/sp2p/compare/v0.1.1-server...v0.2.0
[0.1.1-server]: https://github.com/zyno-io/sp2p/compare/v0.1.1-cli-windows...v0.1.1-server
[0.1.1-cli-windows]: https://github.com/zyno-io/sp2p/compare/v0.1.0...v0.1.1-cli-windows
[0.1.0]: https://github.com/zyno-io/sp2p/releases/tag/v0.1.0
