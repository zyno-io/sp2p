# Browser transfer throughput and v0.5.0 re-release

Baseline: `d303e1a947ca8ef6bb000dfe8660e7a05c7738cd`, the previous v0.5.0. Compatibility fixtures pin this commit because the release tag is being replaced. The protocol and benchmark details are in [receive-window negotiation](receive-window.md).

## Findings

The reported Miami–LA baseline is approximately 1.1 MB/s for both browser-to-browser and browser-to-CLI P2P WebRTC. This does not identify the bottleneck. Browser-to-browser transfers use browser WebRTC implementations, so Pion-specific behavior cannot explain both paths by itself.

Previously, 64 KiB browser chunks and 16 outstanding frames gave browser sends a 1 MiB application window. CLI chunks can fill 4 MiB. Network congestion, disk writes, hashing, encryption, and scheduling may impose lower limits than either window.

## Implemented changes

- [x] Add an authenticated metadata offer and fixed-size encrypted grant for 64 outstanding 64 KiB frames: a bounded 4 MiB payload window.
- [x] Start under the original 16-frame limit without waiting for negotiation. Preserve cumulative credit counters, and wake blocked senders when a grant arrives.
- [x] Grant only explicit, supported, uncompressed v3 offers. Existing v2/v3 peers remain compatible; malformed or repeated grants fail closed.
- [x] Enforce the same limits in Go and TypeScript, retain separate queue bounds, and return credits only after consumption.
- [x] Sample direct/relay path, available RTT, DataChannel counters, queues, credit/buffer waits, encryption/decryption, single-file reads, hashing, and disk writes. Stop sampling on termination; omit raw addresses, codes, keys, and payloads.
- [x] Replace timer-based cooperative yielding with message tasks, keeping receive work responsive without depending on animation callbacks or background timer schedules.
- [x] Remove receive commands when accepting a transfer and sender share commands when sending starts.
- [x] Show sending and final verification status, detailed offer/answer/ICE/authentication stages, and the selected direct or relay path.
- [x] Replace unsupported universal speed claims with measured, qualified results.

An adaptive or 8 MiB window is not part of this iteration: it would require different queue budgeting and evidence that 4 MiB is insufficient.

## Validation

- [x] Go tests, transfer race checks, vet, TypeScript checking, production build, workflow lint, and release-note script checks.
- [x] Chromium security, interop, memory/disk, archive, and responsiveness tests, including a slow sink spanning the negotiated window.
- [x] Test both directions with pinned original v0.5.0 browser/CLI fixtures. CI also runs existing v0.4.0 and old/new signaling compatibility.
- [x] Reject oversized chunks, excess frames, malformed/unsolicited/repeated grants, and unsupported v2 grants; verify transitions preserve cumulative credits.
- [x] Use real encryption and final file verification in a three-repeat simulated credit-latency benchmark: approximately 3.2× at 100 ms and 3.3× at 200 ms.
- [x] WebKit passes all four transfer/active-UI scenarios. Local Firefox ICE setup fails before transfer on both this change and the unmodified baseline; Firefox end-to-end validation remains unavailable in this environment.

The benchmark is an application-credit test, not an Internet/WebRTC speed forecast. Real Miami–LA measurements remain a follow-up requiring access to those endpoints.

## Release procedure

- [x] Include changes in the v0.5.0 changelog.
- [x] Generate curated release notes from the changelog instead of GitHub author/contributor announcements.
- [x] Update the workflow to build, sign, and attest before replacing downloads; publish the new checksum manifest last.
- [ ] Merge after CI passes and save the previous release body, asset manifest, downloads, and tag target.
- [ ] Move `v0.5.0` to the verified commit; refresh all 19 assets, both server container tags, and the deployment.
- [ ] Verify downloaded checksums, the tag target, live bundle/health, and the published notes. Remove every requested author mention and the entire New Contributors section from release prose; preserve Git authorship.

## Follow-up measurement plan

Use identical incompressible files with CLI compression disabled. Compare browser/browser, browser/CLI, CLI/browser, and forced-WebRTC CLI/CLI; record direct TCP separately. Record browser versions, direct/relay path, RTT, output mode, tab visibility, elapsed time through verification, and diagnostic counters.

Take at least three runs per case on the real Miami–LA route, plus low-latency and controlled 50/100/200 ms paths. Network shaping must affect UDP, not just HTTP requests. Compare memory and disk output and foreground/background receivers. Investigate repeatable regressions above 10%.

If credit waits dominate, confirm that the 64-frame grant is active on both updated endpoints. If sink writes or crypto/hash work dominate, use those measurements to scope write coalescing or worker offloading separately. Do not claim that the window change alone fixes the reported 1.1 MB/s path.
