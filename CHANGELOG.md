# Changelog

All notable changes to SP2P are documented here.

This project uses [Semantic Versioning](https://semver.org/). During early development (0.x), minor versions may contain breaking changes.

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

[0.1.1-server]: https://github.com/zyno-io/sp2p/compare/v0.1.1-cli-windows...v0.1.1-server
[0.1.1-cli-windows]: https://github.com/zyno-io/sp2p/compare/v0.1.0...v0.1.1-cli-windows
[0.1.0]: https://github.com/zyno-io/sp2p/releases/tag/v0.1.0
