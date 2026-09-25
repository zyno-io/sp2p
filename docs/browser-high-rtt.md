# Browser transfers at higher RTT

## Status

This September 24, 2026 investigation follows a report of approximately
1.1 MiB/s between two foreground Chrome browsers using four direct connections.
It reproduces substantial degradation with the released scheduling policy at
higher RTT.

**Fix (September 25):** two changes.

1. **Socket-buffer hint.** Every WebRTC offer now includes a video transceiver
   that never carries media. Chrome then uses 1 MiB receive / 256 KiB send UDP
   socket buffers for the connection instead of 64 KiB. This also applies to
   released receivers, because the sender's offer decides it. The CLI adds the
   same hint when it offers to a browser.
2. **Eight connections.** Updated peers negotiate up to eight authenticated
   WebRTC connections instead of four, using a backward-compatible `max` field
   in the encrypted `hello` setup control (see
   [parallel WebRTC negotiation](parallel-webrtc.md)).

At 150 ms added delay, whole-file rates rose from 4.30 MB/s (Ubuntu → local) and
about 5 MB/s (local → Ubuntu) to about 9 MB/s in both directions with a
two-CPU remote browser. With six CPUs, they rose to 11–12 MB/s, with 14–15.5 MB/s
steady-state intervals. The fixed 4 MiB application receive window is now the
main limit at this RTT. See [Socket-buffer hint](#socket-buffer-hint) and
[Eight-connection follow-up](#eight-connection-follow-up).

## Reported evidence

The sender's 64-frame window was full in all three supplied samples. Between
the first and last, credit waiting increased by 3,659 ms, while file reads,
hashing, and encryption added approximately 503 ms combined. Native send queues
held 1.3–3.4 MB. There were 4,055 cumulative local socket discards (4.9 MB), but
that counter did not increase across the samples. These are not measurements of
an end-to-end packet-loss percentage.

Receiver samples showed 34, seven, and 27 complete encoded chunks' worth of
queued bytes while no data chunks were awaiting application consumption.
Writing, hashing, and decryption were inexpensive. Candidate-pair RTTs rose
from approximately 130–300 ms on the sender to 524–779 ms in its final sample.
These are ICE connectivity/consent measurements, not a direct SCTP congestion
window measurement. See the [WebRTC statistics definitions](https://www.w3.org/TR/webrtc-stats/#rtcicecandidatepairstats-dictionary).

The two peers' pasted samples do not include synchronized timestamps. They
support a transport/ordering investigation but cannot establish an exact
cross-peer packet timeline or identify which layer first lost a packet.

## Isolated reproduction

- Local macOS and disposable Ubuntu Chromium 153.0.8010.12, foreground pages.
- Real encrypted SP2P transfers of the same 500,000,000-byte source used in the
  [earlier WAN investigation](browser-wan-benchmark.md), with an OPFS disk sink
  and independent persisted-file SHA-256 verification.
- Expected source hash:
  `d0b82ddbfbb35448898607b4870b1f1e62b79dd5003ae56d2c8f6f35a0c43581`.
- One bridged disposable container, two CPUs, 3 GiB memory, 1 GiB shared memory.
  Only its network namespace has a 150 ms ingress IPv4 UDP delay. SSH/CDP and
  signaling TCP are not shaped; host interfaces and production services are
  unchanged. The ingress queue reported no packet drops during the controls.
- Container-local ephemeral ports and matching Docker UDP mappings use
  39140–39203, as in the prior verified bridged fixture. CDP is exposed only
  through a loopback-bound SSH tunnel.
- The unmodified-browser controls and JavaScript experiments use no native
  socket-buffer shim, custom Chromium transport flags, or artificial packet-loss
  setting. The original control's median sampled RTT is approximately
  196–236 ms, with excursions above 500 ms under load.

The control bundle uses product source from `ee291a0` with additional numeric
observability only. `tests/wan-parallel-build.mjs` adds bounded sender sequence
assignments, per-lane queued bytes, receive reassembly counts, and wait timings.
`tests/wan-transfer.mjs` associates numeric native statistics with a local lane
index. Numeric artifacts contain no addresses, SDP, transfer codes, keys, or
file contents.
The observation bundle is `main-4DSTBTTN.js`, SHA-256
`086f8a614017b10a4fd2bbfcbbee9ea43b836852ab5135b2b6ee1af951291c6a`.

Ordering-wait time alone is not proof of a throughput problem: healthy striped
transfers also reorder data. A sustained unchanged missing sequence, queued
later chunks, and a delivery-rate collapse are stronger evidence. In the
forward control, one connection stopped delivering while the other three had
delivered their queued data; the receiver held more than 50 later chunks.

## Results so far

Rates are decimal MB/s and include connection setup and up to five seconds of
completion polling. These are individual trials, not repeated medians.

| Configuration | Local → Ubuntu | Ubuntu → local | Verification |
| --- | ---: | ---: | --- |
| Released scheduling, observation counters only | 2.06 MB/s, 242.534 s | 1.46 MB/s, 343.497 s; return-to-normal repeat 1.48 MB/s, 338.431 s | All three 500 MB hashes verified |
| 16 KiB native messages, 64 KiB per-lane queue threshold | 2.60 MB/s, 192.010 s | Approximately 1 MiB/s during screening; interrupted | Forward 500 MB hash verified; reverse incomplete |
| 16 KiB native messages, 1 ms submission delay | 3.53 MB/s, 141.445 s | 1.65 MB/s, 303.135 s | Both 500 MB hashes verified |
| 16 KiB native messages, no submission delay | 4.30 MB/s, 116.198 s | 1.55 MB/s, 323.276 s | Both 500 MB hashes verified |
| Gradual startup, one extra outstanding frame per 16 consumption acknowledgements | Not run | Approximately 1.3 MiB/s at 111 s; interrupted | Incomplete screening run |

The forward control recorded 3,777 sender socket discards and a 65.6-second
near-stall; one missing sequence remained unchanged across 10.1 seconds of
samples. The reverse control had no sender socket discards but still had a
15.2-second near-stall. A near-stall uses the earlier report's criterion of
consecutive sample intervals below 256 KiB/s, excluding setup and the final
completion tail. It does not mean literally zero bytes arrived.

These controls reproduce both the aggregate slowdown and cross-connection
blocking at higher RTT. They do not imply that every slow transfer has the
same loss source, nor that eliminating startup send discards alone is enough.

The smaller-queue forward trial reduced its longest near-stall to 30.3 seconds,
but still recorded 1,934 sender socket discards. In the reverse screening run,
reassembly stayed small while queue waiting dominated and throughput decreased.
That run was deliberately stopped after 101 seconds; it is not a
completed or hash-verified 500 MB result. A smaller queue is therefore not a
demonstrated bidirectional improvement.

The paced forward trial had a 5.0-second longest near-stall but still recorded
4,351 sender socket discards. This experiment changes message size as well as
submission timing; it cannot attribute a speed difference to pacing alone.
Fixed timer delays can also cap fast transfers, so this is a diagnostic control,
not a proposed production default.

The reverse transfer started above 3 MiB/s but settled much lower over the full
file; early progress snapshots would have overstated the improvement.
Smaller messages without pacing also preserved the large directional gap. Its
forward run had no sampled near-stall despite 11,121 sender socket discards;
its reverse run had no sender socket discards but remained slow. The discard
counter is not a standalone measure of user-visible throughput or loss recovery.

Gradual startup also reached the full negotiated window without removing the
reverse bottleneck. Its 111-second screening run was deliberately interrupted;
it does not establish a whole-file rate or a forward-direction outcome.

### Native receive-buffer diagnostic

A separate control used the observation-only product bundle and the earlier
test-only macOS interposer. Only in the disposable local receiver process tree, UDP
receive-buffer requests for 64 KiB were changed to 1 MiB. Read-only socket
inspection confirmed eight 64 KiB receive/send UDP sockets in an ordinary test
browser, then eight 1 MiB receive / 64 KiB send sockets with the interposer.
No system-wide setting, normal user browser, remote browser, or product source
was changed.

With the same 150 ms ingress delay, the reverse 500 MB transfer verified in
91.037 seconds: **5.49 MB/s**, compared with the original 1.46 MB/s control.
There was no sampled near-stall. A fresh browser was then confirmed back on
normal 64 KiB buffers. That return-to-normal transfer verified in 338.431
seconds: **1.48 MB/s**, with a 35.4-second near-stall. This reversal strengthens
the evidence for browser UDP receive-buffer pressure on this route, consistent
with the earlier native-buffer investigation. It does not identify every lost
packet's location or reproduce the user's exact route and operating systems.
The native control is diagnostic evidence, not a web-app fix or a recommended
browser configuration.

Across this round, nine complete 500 MB transfers passed independent persisted
SHA-256 verification. Two screening runs were deliberately interrupted and
excluded from whole-file results. No tested JavaScript variant establishes a
sustained bidirectional solution. Further transport work must account for burst
handling and cross-lane recovery while preserving ordering, authentication,
receiver credits, and bounded memory.

The disposable remote container, its latency namespace, test-file copy, browser
profile, and CDP tunnel were removed after testing. Local JSONL evidence and the
source fixture remain available; no host-wide networking setting was changed.

## Socket-buffer hint

Chrome requests 64 KiB UDP socket buffers for DataChannel-only connections. If
the connection has a video transceiver, it requests 1 MiB receive / 256 KiB
send, even when that transceiver is `inactive` or rejected. Local
`netstat -anv` checks on macOS Chromium 153 showed:

| Connection contents | Receive / send buffer |
| --- | --- |
| DataChannel only | 64 KiB / 64 KiB |
| + audio transceiver | 64 KiB / 64 KiB |
| + video transceiver (`inactive`, `recvonly` or `sendonly`) | 1 MiB / 256 KiB |
| Answering an offer with an `inactive` or `recvonly` video section | 1 MiB / 256 KiB |

On Linux, `ss -m` showed 2 MiB (1 MiB doubled by the kernel; this host allows
up to 4 MiB) instead of 128 KiB. Hosts with a default `net.core.rmem_max` of
about 208 KiB receive less. The section adds about 4 KB of SDP, sends no RTP,
and causes no permission prompts. DataChannels with it opened in Chromium,
Firefox and WebKit.

The browser uses `max-bundle` with the hint. Otherwise, the two sections gather
ICE candidates separately until the answer arrives, which doubles TURN
allocations on a relay retry. Firefox does not use the hint: it kept extra
allocations for the whole connection, and its `max-bundle` offers mark the data
section `bundle-only`, which pion before 4.2.18 cannot answer. CLI connections
to a browser register only VP8, which keeps CLI answers to hinted lane offers
at about 2 KB. Pion allows track-less transceivers only as `recvonly`, so
CLI offers use that direction; Chrome answers `inactive`.

All rows below used eight connections, a 150 ms ingress delay, and hash-verified
500 MB transfers. Rates are whole-file decimal MB/s.

| Remote CPUs | Configuration | Ubuntu → local | Local → Ubuntu |
| --- | --- | ---: | ---: |
| 2 | No hint | 5.81, 8.19 | 5.49, 5.82 |
| 2 | Hint (experimental bundle with an opt-in build flag) | 8.90, 8.93 | 8.94, 9.82 |
| 2 | Hint (implemented source) | 8.91 | 8.94 |
| 2 | Hint (final source, `max-bundle`) | 8.17 | 9.82 |
| 2 | Implemented sender → released receiver (four connections) | 8.94 | 9.85 |
| 6 | Hint (implemented source) | 12.33 | 10.95 |

The macOS count of drops due to full socket buffers fell from 403–1,774 per
transfer without the hint to 214–686 with it. Remote receive-buffer errors fell
from 1,189–1,928 to zero.

The run with the implemented sender and the released receiver shows that the
hint alone provides most of the gain: that pair negotiated four connections.

The two-CPU remote browser also limited throughput. With six CPUs, it used
about three cores. Steady-state intervals then reached 14–15.5 MB/s. The sender
kept the full 64-chunk window outstanding while its native queues were nearly
empty. At about 200 ms RTT, that makes the 4 MiB application receive window the
next limit.

## Eight-connection follow-up

### Mechanism

The September 25 fixture rebuilt the same topology: a disposable bridged
Ubuntu container (two CPUs, Chromium 153.0.8010.12), a 150 ms delay on UDP
entering only that container, and local macOS headless Chromium. Numeric
per-lane samples showed:

- Sender DataChannel queues held roughly 500–900 KB per lane while each lane
  delivered only about 1.5 MB/s. SCTP, not the 4 MiB application window, was
  limiting throughput: data was waiting to be sent, not waiting for credits.
- The macOS receiver's UDP counter for drops due to full socket buffers rose by
  roughly 1,400–1,650 per 500 MB transfer. This matches the earlier native
  receive-buffer diagnostic.
- After an early loss, affected lanes spent tens of seconds below 1 MB/s before
  recovering to about 6 MB/s. Each SCTP association halves its congestion window
  on loss and then grows it by about one packet per round trip, so recovery
  time increases with RTT.

This is the usual single-flow loss sensitivity at high RTT. More independent
associations make each loss affect a smaller share of the aggregate rate and
multiply total window growth during recovery. Chrome does not let web pages
change UDP buffers or SCTP congestion control, but they can change the
connection count.

Neither a 20 Mbit/s bottleneck with a deep queue nor a 50 Mbit/s bottleneck
with a shallow queue caused a collapse. With the deep queue, four connections
saturated the link at 2.25 MB/s while ICE RTT rose to about 1.7 s. This matches
the report's growing RTT under load: part of a user's low rate can be the real
uplink capacity, which more connections cannot exceed.

### Results

All runs transferred the same 500,000,000-byte file and passed independent
SHA-256 verification of the persisted OPFS output. Rates are decimal MB/s,
including setup and up to five seconds of completion polling.

| Configuration | Ubuntu → local (+150 ms) | Local → Ubuntu (+150 ms) | Natural RTT, both directions |
| --- | ---: | ---: | --- |
| Four connections (released, observation counters) | 2.60, 4.30, 4.49 | 5.20, 4.94 | 9.81 reverse, 6.59 forward |
| Eight connections (experimental bundle) | 8.20, 7.57 | 5.81, 5.81, 6.59 | 9.80 reverse, 7.58 forward |
| Sixteen connections (experimental bundle) | 8.18, 8.17 | Not run | Not run |
| Eight connections (implemented source) | 7.01, 7.56 | 5.48 | Not run |

With eight connections, Ubuntu → local steady-state intervals reached
8.6–9.6 MB/s, close to the earlier natural-RTT ceiling. Sixteen connections
added no measurable throughput and would add setup cost, so the limit is eight.
The forward direction gained less. Its two-CPU container receiver recorded its
own socket-buffer drops, and the 4 MiB application window sometimes limited
throughput.

Mixed-version runs completed and were hash-verified with the implemented
source on only one page and the deployed release on the other. Both negotiated
four connections: implemented sender → released receiver at 3.95 MB/s, and
released sender → implemented receiver at 3.66 MB/s.

These are individual trials on one route, not a universal speed guarantee.
At the report's 500–780 ms RTT, the unchanged 4 MiB application window bounds
throughput to roughly 5–8 MB/s even without loss.

## Experiments and reproduction

Build a separate observation-only bundle from `web/`:

```bash
SP2P_WAN_ASSETS=/absolute/test-directory/observed \
node tests/wan-parallel-build.mjs
```

Use that directory with the existing WAN harness's `SP2P_WAN_ASSETS` option.
The following optional controls change only the generated experimental bundle:

| Variable | Experiment |
| --- | --- |
| `SP2P_WAN_WIRE_BYTES` | Cap individual native DataChannel messages; application chunks and authentication remain unchanged. |
| `SP2P_WAN_LANE_HIGH_WATER` | Reduce each lane's native queue threshold without expanding receiver credits or budgets. |
| `SP2P_WAN_RAMP_ACKS` | Start with four outstanding data frames and grow by one per specified number of consumed-frame acknowledgements, up to the negotiated limit. |
| `SP2P_WAN_PACE_MS` | Delay between data-message submissions to test burst sensitivity; this deliberately imposes a diagnostic rate limit and is not a production recommendation. |

Set `SP2P_WAN_ASSETS_ROLE=sender` or `receiver` to substitute the bundle on only
that page, leaving the deployed release on the other; this checks mixed-version
negotiation.

The remote Chromium must be the full `chrome` binary with `--headless=new`.
Headless shell ignored both the WebRTC UDP port-range policy and
`--remote-debugging-address`. Playwright's Chromium build reads managed policies
from `/etc/opt/chrome_for_testing/policies/managed/`, not `/etc/chromium/` or
`/etc/opt/chrome/`. Without the port
range, ICE failed across the container's NAT.

Run cases sequentially and use a fresh variant name for every trial. Summarize
a JSONL artifact without printing private URLs:

```bash
node tests/wan-summary.mjs /absolute/test-directory/case.jsonl
```

Any candidate production change still needs repeated, hash-verified comparisons
in both directions, natural-RTT fast-case regression checks, and browser/CLI
compatibility validation. Preserve authenticated framing and bounded memory.
