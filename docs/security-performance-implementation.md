# Security and performance implementation results

Implementation record: local remediation was implemented on 5 September 2026 against reviewed revision `7a616cd`, with follow-up fixes and repeated verification on 8 September 2026. The verification results below describe those runs, not the current CI status. This document retains the protocol design, implementation evidence, and outstanding acceptance/release checks; local verification does not establish production acceptance.

Release preparation: the changes are assigned to [0.5.0](../CHANGELOG.md#050---unreleased), which is not yet released; set its release date when publication occurs. The intended tag is `v0.5.0`, not a component-scoped tag. Clients and servers can be upgraded independently; mixed peers negotiate compatibility automatically as described below. Build versions are injected from the tag; development defaults remain `dev`. Pushing the tag triggers artifact/image publication and server deployment in the existing release workflow, so release preparation does not push or create it. The outstanding validation gates below remain open.

## Coverage

| Finding | Implementation |
| --- | --- |
| F01: vulnerable build inputs | Go 1.26.8 across builds; x/crypto 0.56.0; pinned container/action/tool inputs and automated update proposals |
| F02: decompression allocation | Go window/output caps and capacity-limited decoding; browser envelope validation before fzstd allocation, fixed output storage; 256 KiB decoded chunks |
| F03: signaling resource abuse | Pre-upgrade global/per-IP admission, 10-second Hello deadline, traffic budgets, failed-ping closure, bounded IP maps |
| F04: candidate authentication | Fresh per-candidate challenges, role/transcript-bound HMACs, authenticated sender selection and receiver acknowledgement, bounded deadlines/concurrency |
| F05: browser queues | Byte/count/partial-frame bounds, one decoder/read owner, terminal cleanup, and receiver credits |
| F06: metadata ordering | Receiver-only metadata phase, ordered data/Done barrier, prioritized bounded controls |
| F07: failed browser output | Abort on failure, close only after verification, finalization before Complete |
| F08: proxy identity | Correct boolean parsing, explicit IP/CIDR trust, trusted-side chain resolution shared by limits |
| F09: parallel reassembly | Stale/duplicate rejection, byte/entry bounds, reserved next-frame capacity; malformed parallel negotiation is terminal |
| F10: large browser sends | File slicing and incremental SHA-256 |
| F11: picker lifecycle | User activation before connection, saved handle retained, writable opened only after authenticated metadata; explicit RAM option |
| F12: acknowledgement timing | Verified pipe EOF, sink-close/publication result, then Complete; committed output survives acknowledgement loss |
| F13: TURN abuse | One cached session outcome, opaque identity, positive TTL capped at 1h, 120/min global and 12/min sender-IP issuance budgets; coturn policy example |
| F14: liveness/cancellation | Continuous reverse read owner, serialized controls, independent expiry watcher, context causes and closeable-input cancellation |
| F15: TAR paths | USTAR splitting/PAX Unicode and size extensions, duplicate/path rejection, exact serialized size accounting |
| F16: web headers | Security headers on canonical/direct HTML and asset paths, CSP frame protection |
| F17: terminal injection | Shared Unicode-aware display sanitizer; JSON event schema preserved |
| F18: publication | Atomic no-replace operations on Linux/macOS/Windows, one archive wrapper, no unsafe rename fallback; cleanup errors identify recovery paths |
| O01: serial multistream writes | Bounded per-stream workers and a Done barrier, preserving nonce order |
| O02: compression serialization | Up to four compression workers with ordered futures and bounded queues/encoder concurrency |
| O03: tiny TAR reads | Fill normal chunks across short reads; interactive stdin remains latency-preserving |
| O04: extra copies | In-place Go decryption of owned payloads; browser incremental sends and validated non-shared DOM buffer types |
| O05: disk quotas | Independent decoded/expanded byte limits, known-zero versus stream distinction, overflow-safe accounting |
| O06: receiver slots | Version check before atomic receiver attachment |
| O07: UPnP teardown | Independent five-second context-aware deletion; cleanup owns mappings that arrive after transfer completion |
| O08: secondary indices | Complete indexed set or agreed single-stream fallback; cancel/join producers before draining partial connections |
| O09: build/runtime hardening | Non-root images, writable config, limited workflow permissions, immutable references/hashes, full browser and race/static CI |
| O10: distribution trust | Final artifact/manifest attestations after platform signing and optional manual provenance verification; dependency-light bootstrap checks matching-release SHA-256, trusting GitHub HTTPS rather than an independent signer |

The protocol-v3 specification in code uses credit type `0x0c` with an eight-byte big-endian cumulative consumed-chunk count and a fixed 16-frame window. Credits must strictly increase and cannot exceed sent chunks. No new file-encryption nonce is consumed during candidate selection; secondary keys remain separated by the original stream index.

### Transitional protocol compatibility

Signaling remains at version 2, compatible with the 0.4.0 server. Transfer versions are independent: two updated peers select v3, and a transfer involving a 0.4.0 peer selects v2, automatically. There is no protocol flag, browser checkbox, extra confirmation, or special share command. Even two updated peers using an old signaling server retain v3. Signaling errors fail normally; there is no lower-version retry.

SP2P advertises transfer-v3 support in bit 255 of each X25519 public-key encoding. Canonical public keys generated by 0.4.0 leave this bit clear, and X25519 decoders mask it as required by [RFC 7748 §5](https://www.rfc-editor.org/rfc/rfc7748#section-5), so the marker does not change the shared-secret computation. This capability encoding is an SP2P design, not a negotiation mechanism specified by the RFC. Both markers must be set to select v3.

The existing SP2P HKDF and confirmation HMAC—including in 0.4.0—bind the **original advertised public-key bytes**, not normalized curve encodings. Each endpoint retains its own exact advertisement in that transcript. Stripping or adding either or both markers therefore produces different transcripts and authentication fails. Never normalize these bytes in key derivation or confirmation, and never transfer file contents or report the negotiated version before confirmation succeeds. As with the existing encryption, this protection assumes the out-of-band transfer seed remains secret; it does not prevent denial of service by a malicious signaling server.

Every v3 peer, including browsers, performs the same fresh-challenge candidate proof and authenticated sender-selection exchange. The server's unauthenticated client-type hint never gates authentication. Browser candidate authentication and key confirmation share one bounded byte-stream reader, so fragmented/coalesced handshake records and early encrypted frames survive the transition without a listener gap. Input is capped at 8 MiB/256 queued messages. Proof and confirmation each have five-second deadlines; receivers wait at most 30 seconds for selection. Invalid proofs/selections, channel failures, overflow, and timeouts close the channel and release handshake state without a lower-version retry.

V2 does not use candidate authentication or credit frames. Updated peers advertise parallel TCP only via a new `parallelTCPv3` capability, so an old peer never starts the incompatible secondary negotiation. V2 disables parallel TCP even if a larger count was requested. Updated peers retain bounded decoding/queues, receive/extraction limits, and transactional publication, but not v3 liveness/backpressure guarantees. Slow browsers can reject legacy senders when input queues fill; old peers retain old vulnerabilities. Legacy warnings are informational and unconditional. JSON mode emits a `protocol` event only after confirmation, then includes the version in later records/status snapshots; it also emits a `warning` event for v2, without requiring a response. Pre-confirmation records omit `protocol`.

Compatibility regressions cover automatic v3/v2 selection, unchanged signaling, mismatch-without-slot-consumption, no downgrade retry, raw-key marker tampering in Go/WebCrypto, end-to-end rejection of a stripping relay before file transfer, legacy queue limits, and optional real v0.4.0 binaries. Set `SP2P_TEST_LEGACY_BINARY` for Go/Playwright cross-release tests, `SP2P_TEST_LEGACY_SERVER_BINARY` for the Go old-server matrix, and `SP2P_TEST_LEGACY_WEB_DIR` for browser assets built from the old tag. Normal local runs do not download or execute older release artifacts. The dedicated CI compatibility job builds fixtures from immutable v0.4.0 commit `7a616cd5ac1b51f7ad8d1b1de85a91780fff1ccb` and gates snapshot package builds.

The automatic cross-release CLI matrix passed **56 cases** across both server versions, all four old/new peer directions, TCP/WebRTC/automatic transport selection, and uncompressed/zstd levels 3 and 9. Payloads exceed the v3 16-frame window to catch accidental credit waits in legacy mode. New-peer JSON events assert the authenticated selected version, including v3 through an old server. TCP level-9 cases also request six streams on updated peers to check automatic mixed-peer single-stream behavior. Browser regressions cover 0.4.0 CLI and cached 0.4.0 browser interoperability in both directions on the first attempt; cached HTML fixtures need a test-context-only localhost permission in Chromium, and native dialogs are excluded in favor of the legacy memory-download path.

## Verified locally

- Full `go test ./...`, including CLI end-to-end transfers.
- Race suites for crypto, transfer, flow, connection, server, archive, and file publication.
- `go vet ./...`, TypeScript `tsc --noEmit`, workflow `actionlint`, and `git diff --check`.
- All **71 Playwright tests**, including current and cross-release browser/CLI transfers, cached v0.4.0 browser assets, automatic first-attempt negotiation, authenticated capability markers, Go/TypeScript crypto vectors, writer fault injection, long Unicode TAR output, picker activation/cancellation, hostile initial queues, tiny-chunk memory ownership, FinAck expiry with ongoing heartbeats, timed-reader cleanup, and cancellation of blocked buffer drains. The 19 candidate-handshake tests use an independent HMAC oracle to check both roles, v2/v3 wire sequences, malformed proofs/selections/confirmation, bounded deadlines/input, and fragmented/coalesced startup with early encrypted data. Some security tests use Node/mocked transports. Picker tests stub or omit the native dialog; they do not certify real OS picker behavior.
- Bounded zstd fuzzing: **452,461 executions in 10 seconds**, two workers, no failure. This was a local bounded-input run, not a memory-limited production soak.
- Go regressions for finalizer failure before Complete, metadata ahead of buffered data, duplicate/stale sequences, over-credit input, empty-file metadata, cancelled stdin, peer-error cancellation, parallel compressed transfers, a stalled secondary writer, socket admission/expiry, proxy spoofing, version-slot rejection, cached TURN credentials, archive quotas/wrappers, and no-replace file/directory publication.
- Shell and PowerShell failure-injection tests prove checksum rejection prevents extraction. Shell checks run without `gh` on PATH and cover curl/wget plus sha256sum/shasum/openssl fallbacks; PowerShell covers both archive branches with mocked downloads/extraction and real hashing. Real signed-release wrong-identity/tamper verification remains a gate for the optional manual provenance workflow.
- Linux and Windows amd64 cross-builds; native macOS arm64 builds; Linux arm64 server build. Binary metadata reports Go 1.26.8 and `CGO_ENABLED=0`.
- Both Dockerfiles built locally. Both ran as UID/GID 65532 and served health checks; the Alpine variant's `/config` write permission was checked. No image was pushed.
- `npm audit`: zero vulnerabilities. `govulncheck`: zero called-symbol or imported-package vulnerabilities. The remaining module-only warning is **GO-2026-5932**, unmaintained `x/crypto/openpgp`, which is not imported. No advisory suppression was added. Recheck at release, after dependency/import changes, or by 5 October 2026.

## Follow-up review loops

The compatibility review found that unauthenticated signaling client-type hints could skip candidate authentication while still reporting v3. V3 now requires the handshake for every peer, with browser support added. End-to-end regressions forge the sender type, receiver type, and both types as browsers and require successful v3 transfers with both CLI candidate-authentication paths exercised. Marker-stripping rejection remains covered separately.

The first double-check found three missed cases: tiny decompressed views retained 256 KiB scratch buffers, legacy socket deadlines expired during healthy stdin pauses, and the browser waited indefinitely for FinAck from a peer that continued heartbeats. All three now have fixes and regressions. Subsequent passes fixed two more lifecycle gaps: terminal failure now directly rejects a blocked browser buffer-drain wait instead of waiting for a graceful DataChannel close event, and UPnP cleanup owns mappings that arrive after a successful transfer has already completed.

- Memory fallback copies input into owned blocks, bounding both allocation capacity and object count. Known-size zstd output allocates only its validated size; unknown-size short output returns an exact-size copy.
- Session-owned physical write timeouts replace application-level socket deadlines in the production Go flows. Per-stream async writers use the same timeout owner, and completed writes stop/join timeout callbacks before reuse.
- Production Go and browser receivers wait at most five seconds for FinAck. Timed reads leave no outstanding application waiter and do not discard committed output.
- Fake-clock Go regressions cover three-minute stdin/finalization pauses, blocked writes despite live heartbeats, stalled secondary writes with a healthy primary, and bounded FinAck waits. Focused lifecycle tests passed ten repetitions; all Session tests passed twenty race-instrumented repetitions. Full Go and targeted race suites passed again.
- A network-disabled, non-root Node container with a hard **256 MiB** memory limit processed **200,000** one-byte zstd chunks and tested quota overflow/Blob finalization. Tiny-chunk staging retained one **256 KiB** block. Sampled peak process RSS was **90,861,568 bytes** (approximately 87 MiB), with a separate 16 MiB full-quota case. This checks bounded retention, not every browser's RSS behavior or the broader WAN/slow-disk soak matrix.
- Coverage-guided Go decoder fuzzing passed **331,023 cases in 20 seconds**, two workers, inside a network-disabled **512 MiB** container with `GOMEMLIMIT=64MiB` per process. The first 256 MiB run without that Go memory policy was OOM-killed and is not counted as a pass. The fuzz harness reserves 100 MiB of shared address space per worker; harness/process budgets are separate from the decoder's per-chunk bounds. This does not establish a 256 MiB RSS guarantee for the Go fuzz harness or production CLI.
- Archive extraction and native no-replace file/directory tests passed on Linux arm64 in a non-root container, in addition to the native macOS suite. Windows was cross-built, not runtime-tested.
- UPnP registration/cleanup tests exercise both an already-closed owner and concurrent registration/cleanup. Cleanup uses a fresh bounded context and deletes each owned mapping once; router I/O is outside the ownership lock. The connection suite passed ten race-instrumented repetitions after this fix; the full Go and Playwright suites passed again.

The memory check is reproducible from the `web` directory (Docker required):

```bash
CHECK_DIR=$(mktemp -d)
npx esbuild tests/memory-soak.ts --bundle --platform=node --format=cjs --outfile="$CHECK_DIR/memory-soak.cjs"
docker run --rm -i --network=none --memory=256m --memory-swap=256m --cpus=1 --read-only --cap-drop=ALL --security-opt=no-new-privileges --user=65532:65532 node:24-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e node --max-old-space-size=128 < "$CHECK_DIR/memory-soak.cjs"
```

## Bootstrap dependency follow-up

At the user's request, bootstrap no longer depends on GitHub CLI. It resolves an exact platform release once via `/dl/OS/ARCH?resolve=1`, accepts only a pinned archive URL in this GitHub repository, and normally fetches the archive and checksum manifest from that same release. By default, standard SHA-256 tools verify before extraction; missing, duplicate, malformed, wrong-platform, or mismatched entries fail closed. CRLF manifests and the GoReleaser/sha256sum filename forms are supported. A failed hash command cannot be hidden by a successful output-parsing pipeline.

Shell verifier selection is `sha256sum`, then `shasum`, then `openssl dgst -sha256 -r`. OpenSSL's coreutils-style output uses the same digest parser, and its exit status is checked before parsing. Normally, if no verifier exists or the selected verifier fails, bootstrap stops. PowerShell continues to use `Get-FileHash`.

The subsequent user-requested manual bypass is `--insecure-skip-checksum`, accepted only as the first shell/PowerShell bootstrap argument. It skips verifier detection, manifest download, and digest comparison; warns on stderr; and removes only that first flag before forwarding CLI arguments. Default invocations still verify, and an environment variable or a later argument cannot silently opt out. The bypass does not relax TLS certificate checking, release/platform URL validation, or SP2P transfer verification.

This deliberately changes the trust boundary: bootstrap trusts GitHub's HTTPS release channel and its own script host, not an independent signer. The explicit bypass additionally accepts archive execution without a checksum check. Release attestations remain available for optional manual verification, and a matching older release no longer needs an attestation to bootstrap. Development archives remain unavailable even with the bypass. The 0.4.0 changelog was also backfilled from the local `v0.3.0..v0.4.0` history; protocol-v3 remediation is prepared for 0.5.0, with publication still pending.

Verification after removing `gh`: full `go test ./...`, race-instrumented bootstrap tests, `go vet ./...`, shell syntax checks, web build, all 16 UI/static-document Playwright tests, and `git diff --check` passed. The subsequent OpenSSL fallback passed the shell bootstrap/template/no-verifier regressions with LibreSSL 3.3.6 and a separate OpenSSL-only matrix with OpenSSL 3.6.3; `go vet ./internal/server`, shell syntax checks, web build, and `git diff --check` also passed. Downloads are fixture-backed in the bootstrap regressions; no live release was executed or published.

The manual-bypass follow-up passed the full bootstrap regression set, including default checksum enforcement, opt-out without hash tools/manifests, skipped hash calls, stderr-only warnings, unchanged URL validation, flag removal, and argument preservation in shell and both PowerShell archive branches. A missing or non-leading flag does not enable the shell bypass, even with `SP2P_SKIP_CHECKSUM=1` in the environment. `go vet ./...`, shell syntax checks, the web build, and `git diff --check` also passed; these changes remain local and undeployed.

## Performance evidence

Environment: Apple M1 Max, macOS arm64, Go 1.26.8, 256 KiB chunks; two 500 ms runs per case. These are component microbenchmarks, not end-to-end WAN throughput guarantees.

| Case | Before / serial | After / parallel |
| --- | --- | --- |
| Owned-payload decrypt | 81.6–88.5 µs, approximately 532 kB/op, 2 allocations | 62.8–63.7 µs, approximately 270 kB/op, 1 allocation |
| Compressible zstd chunk | 38.4–38.7 µs | 11.9–12.4 µs |
| Random zstd chunk | 61.2–63.4 µs | 19.9–20.3 µs |

Decryption eliminates one plaintext allocation: approximately 49% fewer allocated bytes and 22–29% less elapsed time in this benchmark. Compression shows approximately 3× aggregate chunk throughput with encoder concurrency capped at four. Ordered futures preserve file/hash/nonce order. A deterministic blocked-secondary test confirms another stream continues until the shared bounded window fills.

Commands:

```bash
go test ./internal/crypto ./internal/transfer -run '^$' -bench 'BenchmarkDecryptOwnedPayload|BenchmarkCompressionChunks' -benchmem -benchtime=500ms -count=2
GOMAXPROCS=2 go test ./internal/transfer -run '^$' -fuzz FuzzBoundedZstd -fuzztime=10s
```

Resource limits are not RSS claims: sender read/compression futures, codec state, transport buffering, in-flight decoding, and Blob construction add separately bounded or runtime-owned memory. Broad before/after RSS, CPU profiles, queue high-water telemetry, constrained-WAN throughput, and long slow-disk/browser soaks remain acceptance work. Do not use the microbenchmarks as proof that every optimization improves every network workload.

## Migration and release gates

Defaults: 1 TiB decoded receive, 1 TiB expanded archive; zero selects those finite defaults. Positive CLI/config byte values can raise limits for trusted transfers. Browser RAM fallback is 256 MiB; browser disk policy is 1 TiB. Existing archive destinations fail instead of merging. Output close/publication is not fsync durability; stdout cannot roll back, and a ready Blob is not a saved download.

Read [README migration guidance](../README.md#proxy-container-and-relay-migration), [security and verification policy](../SECURITY.md), and the updated man pages before upgrading.

- [ ] Publish a transition-release candidate with final artifact attestations, canary the updated server and automatic cross-version transfers before widening rollout, then independently test valid, tampered, absent, wrong-signer/platform, and approved-tag verification for manual provenance checks. Exercise bootstrap against real matching-release checksum manifests; attestations are not a bootstrap prerequisite.
- [ ] Verify additional release filesystems and native Windows no-replace/failure behavior, and real native picker behavior on supported browser/OS combinations. Linux arm64 container and native macOS publication tests passed locally.
- [ ] Validate coturn authentication, private/link-local/loopback destination restrictions, allocation/bandwidth/total-capacity quotas, credential expiry/refresh, and non-root ACME renewal/config persistence in isolated staging. Account for anonymous clients creating new sessions and reusing issued credentials elsewhere. The example is not production provisioning.
- [ ] Exercise relay transfers across CLI/browser roles and rsync/tunnel adapters, including saturation, stalled consumers, disconnects, and cancellation. Verify TURN allocation refresh and credential expiry during long sessions before promising long-lived relay tunnels. Closing signaling after connection establishment does not itself limit stream duration; any credential-renewal policy needs a separate bounded design.
- [ ] Complete the broad performance/soak matrix and remaining hostile-input variants before making production capacity or performance guarantees. Compare the original revision, secure baseline, and optimizations across file sizes, compressibility, tiny archive entries, asymmetric TCP streams, slow sinks, and constrained networks. Record throughput, first-byte and cancellation latency, CPU, allocations, peak RSS/browser memory, queue high-water marks, and repeated-run variance; verify fixed-window buffering stays bounded as payloads grow. The targeted memory-limited checks above are not a complete capacity study.
- [ ] Obtain separate approval for release/tag publication or deployed proxy/TURN changes. Maintain an independently approved secure rollback version; bootstrap checksums do not enforce signer identity or freshness.

## Deferred stream work

Reusable port forwarding remains a future feature. A negotiated `stream/2` could
multiplex connections under one authenticated peer session, with connection IDs,
independent open/ready/FIN/reset and credits, aggregate limits, fair scheduling,
and a bounded connection count. Each connection would use the provider's fixed
target, and a failed target connection would not close unrelated streams. This
is distinct from parallel TCP file-transfer striping. UDP, SOCKS, arbitrary remote
execution, automatic reconnect, and replay remain outside the current scope.

Migrating existing file-transfer flows to `internal/peer` is also deferred; the
current rsync/tunnel implementation preserves their v2 and parallel TCP behavior.
