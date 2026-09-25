# Authenticated parallel WebRTC

This optional v3 file-transfer extension uses at most eight independent
`RTCPeerConnection` instances, each with one ordered, reliable `sp2p`
DataChannel. Multiple channels on one connection would still share SCTP
congestion control and are not equivalent. The extension does not apply to
rsync/tunnel streams, v2 transfers, or existing parallel TCP negotiation.

## Compatibility and authorization

Both peers advertise the optional `parallelWebRTC` boolean in `crypto-exchange`.
It is a compatibility hint, **not authentication**. Only v3 peers that both
advertise it attempt the encrypted setup below, after candidate authentication
and key confirmation on the selected primary WebRTC connection. Old peers see
no new encrypted controls and keep their original single-connection framing.

A signaling attacker can strip or falsify this hint and affect availability or
performance, but cannot authenticate an extra lane or decrypt its traffic.
Asymmetric hints can fail setup closed. The existing transcript-bound v3
selection remains unchanged; the extension does not claim to make the optional
performance hint downgrade-resistant.

Browser senders request eight connections for advertised sizes of at least
64 MiB and one otherwise. CLI automatic mode follows the same threshold;
`-parallel 1` disables the extension, and explicit higher counts are capped at
eight (the `-parallel` flag itself still tops out at 6). The receiver can
reduce the requested count. Unknown-size input keeps one connection in
automatic mode.

## Encrypted setup

Control type `0x0e` carries JSON only during opted-in setup, before metadata or
the transfer session starts. The maximum control size is 16 KiB; each SDP is
limited to 12 KiB and is never logged. Setup has a 25-second overall deadline.

| Step | Direction | Required content |
| --- | --- | --- |
| `hello` | Sender → receiver | `version: 1`, `count: 1..4`, optional `max: 5..8` (only with `count: 4`), fresh 32-byte base64 `nonce` |
| `accept` | Receiver → sender | Accepted `count`, no greater than the request |
| `offer` | Sender → receiver | One per extra lane, increasing original `id` from 1, bounded `sdp` |
| `answer` | Receiver → sender | One per offered lane, same `id`, bounded `sdp` |
| `ready` | Both, sender first | `mask` of successfully authenticated extras |
| `commit` | Sender → receiver | Exact intersection of both ready masks |
| `committed` | Receiver → sender | Exact echo of the committed mask |

An accepted count of one ends setup immediately. Otherwise, each extra lane
gathers candidates concurrently for up to three seconds. An empty/omitted SDP
marks an unavailable lane. Extra connection/authentication waits are bounded
to eight seconds. Mask bit `id` identifies its original lane; bit zero and bits
outside the accepted count are invalid. Missing `mask` means zero.

### Requesting more than four lanes

`count` alone only ever carries 1..4, so an already-released peer that has
never heard of `max` always sees a value it already validates. A sender
wanting more than four lanes keeps `count` at 4 and carries the real request
in `max` (5..8) instead. A receiver that understands `max` treats it — when
present — as the actual request in place of `count`, still bounded by its own
limit; the accepted count returned in `accept` may then be 5..8. A receiver
that does not understand `max` silently ignores the unknown field and accepts
based on `count` alone, i.e. at most 4. An old sender never sends `max`, so a
new receiver talking to it simply sees `count` with no `max` and negotiates
at most 4 lanes, exactly as before. Wire version stays `1` throughout.

Only the mutually committed lanes may carry file data. If the intersection is
empty, both peers retain the primary without changing its framing. An invalid
control, mismatched commit, or primary setup failure aborts the transfer;
fallback never guesses what the other peer selected. Unselected connections
are closed. No post-start migration or replay-based lane recovery is attempted.

Extra connections reuse only the primary's ICE configuration and already
authorized TURN credentials. They neither request new relay consent on behalf
of the user nor bypass an existing consent decision.

## Socket-buffer hint

Offers from Chromium and WebKit, and CLI offers to a browser, also include one
video section that never carries media, on the primary connection and each
extra lane. Browsers use `inactive` with `max-bundle`; the CLI uses `recvonly`.
Firefox senders and CLI-to-CLI offers omit it. Chrome then requests 1 MiB
receive / 256 KiB send UDP socket buffers for the connection instead of 64 KiB,
which avoids burst drops at high RTT. The section does not change
authentication, lane selection, or framing. It adds about 4 KB to each SDP,
within the 12 KiB lane limit. Peers that ignore or reject the section are
unaffected. See the [high-RTT investigation](browser-high-rtt.md#socket-buffer-hint).

## Keys and lane authentication

For each original extra-lane ID (1..7 — up to seven extra lanes alongside the
primary), HKDF-SHA-256 derives three separate 32-byte values:

```text
IKM  = primary v3 confirmation key
salt = fresh encrypted setup nonce (32 bytes)
info = sp2p/v3/webrtc/lane/{id}/{label}
label = sender-to-receiver | receiver-to-sender | key-confirm
```

The primary confirmation key already binds the session and both original
public keys. The labels, lane ID, and setup nonce separate direction, lane,
setup, and TCP key domains. Each extra connection then runs the existing fresh
v3 candidate challenge/proof/selection exchange and key confirmation using its
own derived keys and the original sender/receiver public keys. SDP possession
alone does not authenticate it.

AES-GCM nonce sequences are independent per direction and lane, with existing
strict monotonic replay checks. The primary keeps its original keys and nonce
counters across setup and transfer; counters are never reset or keys reused
between lanes. Go and TypeScript tests share independently calculated HKDF
vectors.

## Ordering, flow control, and cleanup

With two or more committed connections, every encrypted Data payload starts
with an eight-byte big-endian global sequence number. This prefix is inside
AES-GCM authentication. All control frames remain on the primary. Metadata is
delivered before data; Done's `chunkCount` is a barrier across every lane.
Error/cancel controls bypass a pending Done barrier. Final size, chunk count,
SHA-256, sink finalization, Complete, and bounded FinAck rules remain unchanged.

Scheduling selects the least queued connection, rotating ties. It does not
assign fixed file quarters. Browser sends use native buffered bytes; Go adds
pending serialized-writer bytes. Each active parallel send threshold is 1 MiB,
for at most 8 MiB total. Single-connection queue settings are unchanged.

Receiver credits remain **one aggregate window**, not one window per lane:
16 ordinary frames, or the separately negotiated 64 × 64 KiB browser profile.
Credits return only after sink consumption. Cross-lane reassembly rejects
duplicate/stale sequences, offsets of 64 or more, empty/oversized chunks, and
encoded payload buffering above 8 MiB. Encoded zstd may be larger than its
256 KiB decoded chunk; decoded output retains its separate size/quota checks.
Browser raw, reassembly, and application queues
share an 8 MiB/256-frame budget. Go raw DataChannel input shares an 8 MiB/
256-message budget across connections; its decoded reassembly and Session
queues have their own aggregate bounds. Native SCTP buffers are additional,
per-connection memory; Pion extra-lane receive buffers are capped at 2 MiB each.

A lane failure after commit fails the transfer closed and closes every lane.
Cancellation wakes pending reads/writes, closes all connections, and aborts
uncommitted browser output. A verified, finalized output is not discarded just
because its final acknowledgement is lost. Diagnostics aggregate all active
connections, preserve unavailable counters, and omit addresses, SDP, keys,
transfer codes, and payloads.

See the [WAN investigation](browser-wan-benchmark.md) for reproducible
benchmarks and the limits of the current performance evidence.
