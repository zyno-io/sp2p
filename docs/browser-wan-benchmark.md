# Browser WAN investigation

## Outcome

The sender's share controls now disappear when a receiver joins, before key
exchange or WebRTC connectivity. Joining claims the one-use session; another
receiver cannot reuse that code. A regression test holds offer creation open
and checks that both the commands and any open QR modal have disappeared.

The WAN tests reproduced delivery stalls while the browser remained responsive.
Controls point to Chrome UDP buffer pressure and SCTP recovery as substantial
bottlenecks on these endpoints. The fixed small-message/queue experiments did
not demonstrate improvement in both directions and are not enabled.

The follow-up implements authenticated parallel WebRTC in both the browser and
CLI, with compatible fallback and aggregate flow-control/memory bounds. It is
unreleased. Three-repeat real 500 MB SP2P tests have browser/browser medians of
8.24 MB/s local→Ubuntu and 8.99 MB/s Ubuntu→local, compared with released-browser
medians of 4.72 and 1.84 MB/s. Browser→CLI and CLI→browser also improve. The
controlled-RTT validation is tracked below.
These measurements are not a universal speed promise.

## Setup

The September 21–22, 2026 investigation uses a local macOS headless Chromium and a
disposable Ubuntu headless Chromium, both version 153.0.8010.12. The remote host
was supplied by the operator. These are real direct WebRTC transfers over the
Internet, not simulated DataChannel acknowledgements or HTTP throttling.

Each run offers the same 500,000,000-byte file. The receiver uses the production
disk-writing path with a real OPFS `FileSystemWritableFileStream`. Successful
runs additionally read the persisted file and independently verify its size and
SHA-256. The file contains repeated random blocks; browser sends do not compress
it, and the wire data is encrypted. Results below use decimal MB/s; the current
browser UI labels binary MiB as MB.

The baseline is the deployed browser from commit `1e36613`. Experimental bundles
are substituted in the two disposable browsers without deploying to the site.
The parallel implementation preserves aggregate application credits and
completion checks, adds encrypted lane setup, and uses independent per-lane
keys and authenticated ordering. Earlier fixed-queue experiments leave the
protocol unchanged.
Five-second polling bounds completion measurements; reported elapsed times
include up to one polling interval after completion, and SP2P timings also
include connection setup. Raw timings start after connection setup. Compare
raw variants with raw controls, not directly with full file-transfer timings.

## Reproduction

Use an isolated remote browser with CDP bound to loopback, forwarded over SSH.
Never expose an unauthenticated CDP endpoint publicly. Install the repository's
Playwright dependencies and browser locally. Use Node.js 24.

```bash
cd web
SP2P_WAN_DIR=/absolute/path/to/a/dedicated/test-directory \
REMOTE_CDP=http://127.0.0.1:39127 \
SP2P_WAN_VARIANT=baseline \
node tests/wan-transfer.mjs
```

The dedicated directory must already exist. The harness creates `wan-test.bin`
there if absent and appends numeric diagnostics to a variant-specific JSONL file.
Use a new variant name for each run. It dismisses relay-consent prompts rather
than silently accepting a relay, keeps transfer codes out of artifacts, and closes
its browser contexts after success, timeout, or interruption. The remote browser
process and SSH tunnel remain the operator's responsibility.

For the opposite direction, place the identical file on the remote browser's
filesystem and add `SP2P_WAN_REVERSE=1` and
`SP2P_WAN_REMOTE_FILE=/absolute/remote/path/wan-test.bin`. Final verification still
compares the receiver's file against the local source hash. An optional
`SP2P_WAN_ASSETS` directory substitutes an experimental `main-*.js` bundle on both
pages. `SP2P_WAN_TIMEOUT_MS` bounds an observation; a timeout is not a successful
500 MB transfer.

Run cases sequentially so they do not compete for bandwidth. Record both peers'
credit/buffer waits, crypto/hash/read/write time, timer lag, paint gaps,
DataChannel counters, and nominated candidate-pair statistics. Socket discard
counters are not the same as measured end-to-end packet loss. Host-wide UDP
counters can corroborate a hypothesis but cannot attribute every drop to a
particular transfer.

Any UDP delay/rate experiments must be confined to a disposable container's
network namespace, not the remote host's production interfaces. HTTP/CDP latency
emulation does not model WebRTC's UDP path.

## Initial controls

| Direction / configuration | Result |
| --- | --- |
| Local Chrome to Ubuntu Chrome, released browser | 500 MB verified in 80.866 s: 6.18 MB/s |
| Same released browser and direction, repeat | 500 MB verified in 126.843 s: 3.94 MB/s; approximately 30 s of near-stalled delivery after initial sender socket discards |
| Same direction, split sends into 16 KiB messages without pacing | 500 MB verified in 85.834 s: 5.83 MB/s |
| Ubuntu to local, split sends into 16 KiB messages without pacing | Approximately 248 MB received in a 187.3 s observation: 1.32 MB/s; deliberately interrupted, not a completed transfer |
| Ubuntu Chrome to local Chrome, released browser | 278 MB received in a 181.6 s observation; approximately 1.5 MB/s, with an early dip near 330 KiB/s |
| Same slow direction, 256 KiB native send threshold | 344 MB received in a 181.6 s observation; approximately 1.9 MB/s |
| Same slow direction, 16 KiB messages and 16 KiB send threshold | 500 MB verified in 161.470 s: 3.10 MB/s |
| Local to Ubuntu, 16 KiB messages and 16 KiB send threshold | 500 MB verified in 95.928 s: 5.21 MB/s |
| Local to Ubuntu, 16 KiB messages and 64 KiB send threshold | 500 MB verified in 95.902 s: 5.21 MB/s |
| Local to Ubuntu, 32 KiB messages and 16 KiB send threshold | 500 MB verified in 242.920 s: 2.06 MB/s; rejected after forward-direction regression |
| Ubuntu to local, SSH/TCP capacity control | 500 MB in 10.246 s: 48.80 MB/s |
| Ubuntu to local, raw WebRTC without SP2P processing | 225 MB of synthetic bytes in a 120.1 s observation: 1.87 MB/s |
| Ubuntu to local, released SP2P with a test-only 1 MiB receiver UDP buffer | 500 MB verified in 85.879 s: 5.82 MB/s including an initial recovery stall; later sustained intervals approximately 10–12 MB/s |
| Ubuntu to local, raw WebRTC over four independent connections | 500 MB of synthetic bytes delivered in 125.123 s: 4.00 MB/s |
| Local to Ubuntu, raw WebRTC over four independent connections | 500 MB of synthetic bytes delivered in 50.654 s: 9.87 MB/s |
| Local to Ubuntu, raw WebRTC over one connection | 500 MB of synthetic bytes delivered in 70.876 s: 7.05 MB/s |

The initial slow Chrome baseline did not block either page's main thread: maximum timer lag
was under 10 ms and no long tasks were observed. Disk writes and cryptographic
work accounted for a small part of elapsed time. Around 4 MiB remained in the
sender's native DataChannel queue while the receiver waited for delivery.
Reducing that queue alone removed application-credit waiting but did not remove
the transport bottleneck. Merely splitting messages without changing queueing
also did not improve the forward direction.

The raw control (`tests/wan-raw.mjs`) removes SP2P framing, credits, file reads,
disk writes, hashing, and application encryption. Its similarly slow delivery
isolates a substantial bottleneck below those layers. It does not independently
verify a file and must not be reported as a successful file-transfer test.

Read-only socket inspection showed 65,536-byte send and receive buffers for the
local Chromium WebRTC socket. Host UDP receive-buffer drops increased during
transfers. Chromium's [UDP socket implementation](https://chromium.googlesource.com/chromium/src/+/988ef7646e298b923c329e1d56da216912544494/services/network/p2p/socket_udp.cc)
also specifies 64 KiB defaults. A test-only native interposer changed the local
disposable browser's 64 KiB UDP receive-buffer request to 1 MiB; socket inspection
confirmed the change. It changed neither system-wide settings nor the deployed
browser code. The large improvement supports UDP buffer pressure and SCTP loss
recovery as major causes on this path, rather than expensive application work.
The remaining initial stall coincided with sender socket discards.

The native interposer is a diagnostic control, not a web-app fix or a recommended
browser-launch configuration. Small-message/queue experiments must still be
measured in both directions: the 16 KiB experiment improved the slow direction
but regressed the faster direction in its first run.
Splitting into 16 KiB messages while leaving the original queue unchanged did
not improve the reverse path, either. The queue and message-size changes must
not be treated as interchangeable.
Repeating the unchanged release also produced a long initial stall and a much
lower average. Single-run averages therefore do not establish a universal
throughput improvement or regression. Both rate and delivery-stall duration
matter, and a production change must be checked in both directions.

An initial egress-delay experiment was excluded from latency conclusions after
sender socket discards appeared: delaying egress can retain sender-owned UDP
packets in the kernel queue. Subsequent RTT experiments use an ingress IFB inside
the disposable container to delay acknowledgement arrival without holding
outgoing datagrams in that queue.

With 70 ms added only at ingress in that isolated namespace, the released
reverse path delivered approximately 64 MB in a 92.5 s observation (about
0.70 MB/s), with measured RTT around 100–116 ms and no reported sender socket
discards. The 16 KiB variant delivered approximately 62 MB in 46.4 s before its
SSH/CDP tunnel disconnected. Neither observation completed 500 MB; neither is
a full-transfer result or a repeated benchmark. The disconnect is a harness
failure, not evidence of a WebRTC failure.

## Parallel transport prototype

`SP2P_WAN_LANES=4` enables four separate `RTCPeerConnection` instances in the raw
control, not four DataChannels on one SCTP association. Each has a 1 MiB send
threshold, keeping the aggregate threshold equal to the single-connection 4 MiB
control. These tests still omit file processing and application encryption.
Fixed per-lane byte assignments expose a slow-lane tail; their full completion
average is lower than the aggregate rate before the faster lanes finish.

The raw prototype is separate from the implemented SP2P extension described in
[authenticated parallel WebRTC](parallel-webrtc.md). It does not implement
SP2P's lane authentication, per-lane keys, replay guarantees, aggregate credits,
bounded reassembly, or file completion checks, and is not deployment evidence.

To reproduce the raw control, use the same SSH-forwarded disposable browser:

```bash
cd web
REMOTE_CDP=http://127.0.0.1:39127 \
SP2P_WAN_REVERSE=0 \
SP2P_WAN_LANES=4 \
SP2P_WAN_BUFFER_BYTES=1048576 \
SP2P_WAN_TIMEOUT_MS=300000 \
node tests/wan-raw.mjs
```

Use `SP2P_WAN_REVERSE=1` for Ubuntu-to-local. For the single-connection control,
use `SP2P_WAN_LANES=1` and `SP2P_WAN_BUFFER_BYTES=4194304` to keep the same total
native send threshold. Only run one WAN case at a time.

## Authenticated implementation and acceptance gates

The implementation covers browser-to-browser **and** browser/CLI in both
directions. The natural-WAN matrix completed three sequential, hash-verified
500 MB transfers per case. Rates are decimal MB/s including setup and up to
five seconds of completion-polling overhead.

| Local / Ubuntu direction | Single median | Parallel median | Single runs | Parallel runs |
| --- | ---: | ---: | --- | --- |
| Browser → browser | 4.72 | 8.24 | 4.72, 4.72, 5.82 | 8.24, 8.25, 7.06 |
| Browser ← browser | 1.84 | 8.99 | 1.84, 1.42, 1.94 | 8.97, 8.99, 10.91 |
| Browser → CLI | 14.27 | 19.98 | 16.65, 14.27, 12.49 | 19.98, 19.92, 19.98 |
| Browser ← CLI | 1.84 | 18.41 | 1.84, 1.60, 1.91 | 15.57, 18.48, 18.41 |

Single-connection controls use the released browser. CLI controls use the test
CLI with `-parallel 1`, not a released CLI binary. Compression is disabled.
One CLI→browser control was interrupted during an operator-requested pause;
the table uses its completed retry and excludes the partial observation.
Median sampled RTTs range from 30–58 ms for browser/browser and 30–100 ms for
browser/CLI. These are measured RTTs under load, not a fixed latency setting.

All parallel runs used unmodified Chromium, real SP2P encryption, and
persisted-output SHA-256 verification. No socket shim or raw-byte shortcut was
used. The latest benchmark build is `main-WWE34XGV.js` (SHA-256
`3c15f2789362165408f12aae56e94300217bdaf013a24538c0e70bcdf2b2f414`).
The first runs preceded cleanup/encoded-frame-bound refinements; the final
repeat round uses this build. The refinements do not change scheduling policy.

In the natural-WAN parallel runs, maximum sampled browser timer lag was
44.4 ms. No post-start delivery stall spanning a full five-second sampling
interval was detected in this repeat matrix; this does not exclude shorter
stalls or supersede the earlier approximately 30-second baseline stall.
Foreground visibility is explicitly asserted in the final repeat round.

### Controlled RTT fixture

The repeat matrix adds 70 ms to inbound IPv4 UDP inside a disposable bridged
container, using an ingress IFB and `netem`. It does not delay the SSH/CDP or
signaling TCP connections and does not change the host interface queue.
Natural-WAN tests use a separate host-networked container.

The first bridged fixture connected in the forward direction, but the released
browser repeatedly failed reverse ICE setup, even with the delay removed.
A replacement fixture publishes UDP ports 39140–39203 and confines ephemeral
port allocation to that range **inside its own network namespace**. This
restored direct reverse connectivity; it changes neither Chromium code nor
socket-buffer sizes. The final controlled comparisons all use that same
replacement fixture. Earlier unmatched fixture results and pre-transfer ICE
failures are excluded from its throughput medians, not counted as completed
transfers.

Each remote browser container is limited to two CPUs and 3 GiB memory, with
1 GiB shared memory. Container resource samples include native browser buffers,
filesystem cache, and the independent whole-file verification probe; they are
not measurements of the application receive-queue budget alone. Temporary
Docker port mappings, namespaces, and browser processes are removed after testing.

The controlled repeat matrix is still running. Its first pass completed and
verified all eight 500 MB transfers; these are single-run results, not medians:

| Local / Ubuntu direction | Single connection, MB/s | Parallel, MB/s |
| --- | ---: | ---: |
| Browser → browser | 2.83 | 5.49 |
| Browser ← browser | 0.95 | 8.17 |
| Browser → CLI | 9.08 | 14.27 |
| Browser ← CLI | 0.78 | 9.63 |

Acceptance checklist:

- [x] Negotiate optional parallel WebRTC support through authenticated v3 messages.
   Old v2/v3 peers must retain the existing single-connection framing, without
   receiving unknown controls or waiting for a grant they cannot send.
- [x] Establish at most four independent connections. Bind each lane's identity,
   role, fresh authentication challenge, and directional keys to the primary
   authenticated session. Keep signaling bounded; never authorize lanes from
   unauthenticated client-type hints. Reuse the Go parallel-transport primitives
   where their invariants fit, without changing existing parallel TCP behavior.
- [x] Preserve per-lane nonce/replay validation and authenticated global data
   ordering. Keep one aggregate receiver-credit and memory budget rather than
   multiplying the current limits by the lane count. Route terminal controls
   through barriers so completion cannot overtake data on a slower lane.
- [x] Schedule against lane availability rather than fixed file quarters. Bound
   setup time and fall back to one lane if extras cannot connect before data
   starts. A lane failure after payload starts must fail closed unless explicit
   replay-safe recovery has been designed and tested. Close all lanes on cancel,
   error, or completion. Preserve explicit relay consent.
- [x] Test forged/replayed lane proofs, cross-session joins, duplicate sequence
   numbers, excess buffering, slow lanes, setup timeout, cancellation, disk
   failure, and completion acknowledgement loss. Verify old/new browser and CLI
   combinations before enabling the extension by default.
- [ ] Repeat hash-verified 500 MB transfers at least three times per direction and
   peer combination, sequentially, with unmodified browsers. Measure median
   throughput, delivery-stall duration, main-thread responsiveness, and resource
   use at natural and controlled RTT. Require improvement in the slow cases
   without a repeatable greater-than-10% regression in the fast cases. A native
   socket shim, raw-byte prototype, or application-credit simulation cannot
   satisfy this gate.

These endpoints do not reproduce the user's exact Miami–LA route. Successful
transfers or improvements here are not a guarantee of the same rate elsewhere.

### Browser/CLI reproduction

`tests/wan-cli.mjs` runs a local headless browser against a remote CLI inside an
operator-owned disposable Docker container reached over SSH. Place the built
Linux CLI at `/work/sp2p` and the identical fixture at `/work/wan-test.bin` inside
that container. It must already have networking suitable for direct WebRTC.

```bash
cd web
SP2P_WAN_DIR=/absolute/path/to/a/dedicated/test-directory \
SP2P_WAN_SSH=ubuntu@your-test-host \
SP2P_WAN_CONTAINER=your-disposable-container \
SP2P_WAN_VARIANT=parallel-browser-cli-1 \
SP2P_WAN_ASSETS=/absolute/path/to/sp2p/web/dist \
node tests/wan-cli.mjs
```

Add `SP2P_WAN_REVERSE=1` for CLI→browser. `SP2P_WAN_PARALLEL=1` disables extra
connections in the current CLI; omit `SP2P_WAN_ASSETS` to use the released
browser for the single-connection control. CLI compression is disabled. Remote
received files remain under `/work/receive-VARIANT` for independent size/hash
verification and subsequent operator cleanup. A remote timeout bounds a lost
SSH session. Neither raw CLI output nor private transfer-code arguments are
included in artifacts.

## Local regression validation

TypeScript checking, production builds, Go tests, vet, and targeted Go race
checks pass. The full Chromium suite passed 148 tests with real v0.4.0 and
original v0.5.0 browser/CLI fixtures; only the optional simulated-credit benchmark
was skipped. A subsequent 35-test parallel run verified the encoded-frame bound
with incompressible data, partial three-lane agreement, one-lane fallback,
compressed CLI sending, slow sinks, disk errors, lost FinAck, malformed setup,
setup deadlines, and cleanup when native DataChannel construction fails.

The pinned v0.4.0 source fixture matches all 140 tracked blobs at `7a616cd`;
the original v0.5.0 fixture is pinned to `d303e1a`. Forced four-lane CLI/CLI and
mixed old/new CLI tests also pass through old and new signaling servers.
The new large-transfer browser group uses its own test signaling server to
avoid consuming the existing suite's per-IP quota; production admission limits
are unchanged. Production services and host-wide transport tuning are unchanged;
temporary Docker port mappings and traffic shaping are scoped to the test
containers. Disposable WAN resources are removed when testing finishes.
