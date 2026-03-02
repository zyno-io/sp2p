# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SP2P, please report it responsibly:

1. **Do not** open a public GitHub issue.
2. Email **oss@zyno.io** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact
3. You should receive a response within 48 hours.

## Scope

SP2P's security model is described in the [README](README.md#security-model). Key areas:

- **Cryptography**: X25519 key exchange, AES-256-GCM encryption, HKDF key derivation
- **Signaling server**: Session management, WebSocket handling, rate limiting
- **Transfer protocol**: Wire format integrity, path traversal prevention
- **Web UI**: CSP headers, origin validation, input sanitization

## Supported Versions

Security fixes are applied to the latest release only.
