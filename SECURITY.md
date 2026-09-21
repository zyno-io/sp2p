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

## Artifact verification and endpoint trust

The signaling server cannot derive session encryption keys between trusted clients. This does not protect a browser or bootstrap client from a compromised host that serves its executable code. Downloading a checksum or verifier from that same host is not an independent trust anchor. Prefer a trusted package installation or a CLI verified independently of the signaling host.

Shell and PowerShell bootstraps do **not** require GitHub CLI (`gh`). By default, they resolve a fixed GitHub release URL for the exact platform, download its archive and `checksums.txt`, and verify SHA-256 **before extraction or execution**. Shell chooses `sha256sum`, then `shasum`, then `openssl dgst -sha256 -r`; PowerShell uses `Get-FileHash`. An unavailable verifier or a failed hash command stops execution. Missing, duplicate, malformed, or mismatched checksum entries fail closed by default. The release URL must belong to this repository and must name the expected platform archive; a moving `latest` URL is not accepted. Development archives and unavailable pinned releases need a locally built/installed CLI.

The explicit bootstrap-only flag `--insecure-skip-checksum`, supplied as the **first bootstrap argument**, bypasses verifier detection, checksum-manifest download, and digest comparison. It prints an unconditional stderr warning and permits extraction/execution without an archive integrity check. It does not disable TLS certificate verification, change allowed release URLs/platforms, permit development archives, or disable SP2P transfer encryption/verification. No environment variable or automatic retry enables the bypass. Only use it when you explicitly accept this risk; examples are in the [README](README.md#quick-start).

This is integrity verification through GitHub's HTTPS release channel, **not independent signer verification**. Someone who controls the release assets can replace both archive and checksum. A compromised bootstrap host can replace the checks entirely. Checksums do not prevent rollback, and old releases with matching manifests do not require attestations to bootstrap. Choose an independently trusted installation when these trust assumptions are unsuitable.

For optional, stronger provenance verification of new attested releases, install GitHub CLI through a trusted channel, download the exact platform artifact from GitHub, and verify **before extraction or installation**:

```bash
# Replace the filename and tag with the exact approved artifact/release.
gh attestation verify sp2p_linux_amd64.tar.gz \
  --repo zyno-io/sp2p \
  --signer-workflow zyno-io/sp2p/.github/workflows/release.yml \
  --source-ref refs/tags/vAPPROVED_VERSION \
  --deny-self-hosted-runners
```

Use the same command in PowerShell (one line), and stop on a nonzero exit code. Check the platform filename and the verified subject digest. The workflow attests final archives/packages and `checksums.txt` after platform signing/notarization, using GitHub's identity-backed attestation service; existing macOS, Windows, and package signatures remain in place. See the official [GitHub CLI verifier documentation](https://cli.github.com/manual/gh_attestation_verify) and [provenance action](https://github.com/actions/attest-build-provenance).

For rollback resistance, independently select and pin an approved tag with `--source-ref`, retain your minimum approved version, and reject older artifacts. There is no online freshness guarantee. Older unattested releases cannot pass this optional provenance check; build from independently approved source or use a trusted package channel instead.

The first new attested release still needs an independent verification canary before claiming that provenance workflow works end to end. Attestations are not a bootstrap prerequisite. No signing identity, release, or deployment was provisioned by the local remediation changes.

## Resource and output guarantees

All v3 peers, including browsers, authenticate fresh connection challenges and the sender's selection before key confirmation. Signaling client-type hints may affect transport compatibility but never disable authentication. Browser handshake input is capped at 8 MiB/256 queued messages; candidate proof and key confirmation each have a five-second deadline, and a receiver waits at most 30 seconds for candidate selection. Failure closes the channel without transferring files or retrying at v2.

Protocol v3 fixes the cooperative receive window at 16 unconsumed data frames. Chunks decode to at most 256 KiB, frames are capped at 512 KiB, controls at 4 KiB, browser queued input/application payloads at 8 MiB and 256 frames, and parallel payload reassembly at 32 MiB/128 sequence slots. These are application budgets, not total RSS guarantees: transport buffers, decoder state, sender workers, and browser downloads add overhead. Hostile over-credit/invalid frames terminate the session. Paused input and slow sinks keep controls flowing; loss of authenticated inbound activity expires after 15 seconds.

Receive and archive-expansion defaults are each 1 TiB. Browser memory downloads are capped at 256 MiB and browser disk receives at 1 TiB. CLI flags can raise finite local limits; peer metadata cannot. Libraries must provide interruptible readers/writers or a close/cancellation contract for blocking caller-owned I/O. SP2P-owned sockets, pipes, and stdin are closed on cancellation.

Browser memory staging coalesces arbitrary input into at most 1,024 owned 256 KiB blocks, with capacity capped at 256 MiB. Decoder results do not retain oversized scratch buffers; short unknown-size results are copied into exact-size buffers. Blob creation can temporarily duplicate payload storage, so this is not a 256 MiB process/RSS guarantee. Go sessions apply two-minute timeouts to physical writes rather than leaving socket deadlines armed during healthy input/finalization pauses. Browser buffer-drain waits are also time-bounded and reject immediately on terminal failure. Both production receivers bound the final FinAck wait to five seconds without deleting verified output.

Success follows checksum/count/size verification and destination finalization. Failed browser writes abort instead of committing; CLI files and archive wrappers use no-replace publication on Linux, macOS, and Windows, failing closed on unsupported filesystems/platforms. Stdout cannot roll back bytes. Browser Blob creation cannot attest that a user completed the download. Close/rename is not a power-loss durability guarantee. A valid published destination is retained if an acknowledgement is lost; the sender may remain unconfirmed.

## Deployment requirements

Clients and servers can be upgraded independently. Signaling remains compatible with 0.4.0, and peers automatically select transfer v3 when both are updated or v2 when one is old. Two updated peers retain v3 even through an old server. No version flag, checkbox, or additional confirmation is needed. Transfer capability markers are bound to the existing raw-key HKDF/confirmation transcript; altering either or both fails authentication before file transfer. Connection errors never trigger a lower-version retry. See the [negotiation design and threat assumptions](docs/security-performance-implementation.md#transitional-protocol-compatibility).

V2 compatibility is **not security-equivalent to v3**. It omits connection-candidate authentication and receiver credits, disables parallel TCP even if requested, and retains legacy idle/backpressure limitations. Updated peers still enforce local decoder, queue, quota, and output-publication protections. An old peer remains vulnerable to its old defects; a slow browser may reject a fast v2 sender when its bounded queue fills. Legacy warnings are unconditional and informational, including machine-readable `warning` events in JSON mode; they require no user response. Upgrade the older peer for the full v3 protections described above.

Use a supported patched Go toolchain for every static binary/container rebuild. The remediation selects Go 1.27.0; security fixes still apply only to the latest SP2P release.

Forwarded client identities require explicit trusted proxy IPs/CIDRs. TURN issuance is cached and rate-limited, but public anonymous relay use still needs coturn quotas, an egress firewall, monitoring, and staging checks of allocation expiry and refresh. Review [the example relay policy](deploy/turnserver.conf.example) and [migration guidance](README.md#proxy-container-and-relay-migration). Do not expose it unchanged.
