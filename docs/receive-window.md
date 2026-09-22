# Receive-window negotiation

Transfer v3 normally allows 16 unconsumed data frames. The optional receive-window profile extends that allowance for browser-originated uncompressed file and TAR transfers. It is negotiated within the authenticated encrypted transfer and requires no signaling-server changes.

An updated browser sends `"receiveWindow": 1` in its metadata. Existing receivers ignore this extra JSON field and continue returning ordinary credits. Until a grant arrives, the sender remains limited to 16 outstanding frames. There is no negotiation timeout or startup wait.

A supporting receiver installs the profile's limits before sending encrypted message type `0x0d` (`MsgReceiveWindow`). Its 12-byte payload contains three big-endian unsigned 32-bit integers:

| Offset | Value | Meaning |
| --- | --- | --- |
| 0 | 1 | Profile version |
| 4 | 64 | Maximum outstanding data frames |
| 8 | 65,536 | Maximum plaintext data bytes per frame |

Profile 1 permits at most 4 MiB of unconsumed plaintext. Both frame count and per-frame size are enforced, including for tiny and final partial chunks. Browser encrypted/application queues remain bounded at 8 MiB with independent frame/reassembly limits. The Go session queue accommodates 64 data frames plus bounded control headroom. Credits are returned only after the sink consumes data.

The sender validates the entire grant against its offer, permits it only once, and wakes any credit wait. The existing `0x0c` credit payload remains an eight-byte cumulative frame count: counters never reset during negotiation. Unsolicited grants, duplicate grants, invalid parameters, excess credits, and oversize data fail the transfer. Metadata cannot be renegotiated mid-transfer.

Older senders receive no new control. Unknown profiles and compressed offers retain ordinary v3 limits. Compression may expand a decoded chunk beyond its encoded size, so profile 1 does not apply to compressed transfers. CLI senders retain their existing chunk sizes and credits; updated CLI receivers understand browser offers. Protocol v2 neither offers nor grants the extension.

## Diagnostics and measurements

Browser diagnostics sample every two seconds and stop at transfer termination. They report the selected direct/relay path, available candidate-pair RTT, DataChannel counters, outstanding frames, queued bytes, and cumulative processing/wait timings. These are elapsed timings, including asynchronous scheduling; they are not independent CPU measurements. Missing browser statistics do not prevent transfers. The diagnostic payload contains no transfer codes, keys, raw SDP, or candidate addresses.

The reported Miami–LA baseline was approximately 1.1 MB/s for both browser-to-browser and browser-to-CLI WebRTC. That measurement does not isolate the limiting component. In particular, Pion-specific behavior cannot explain browser-to-browser performance by itself.

The opt-in application-credit benchmark uses two encrypted transports with simulated acknowledgement latency, 32 MiB files, and three repetitions per case. It includes hashing and output verification, but has no real SCTP congestion control or network bandwidth limit. The initial measurements were:

| Simulated RTT | 16-frame median | 64-frame median | Improvement |
| --- | --- | --- | --- |
| 100 ms | 8.70 MiB/s | 27.95 MiB/s | 3.21× |
| 200 ms | 4.70 MiB/s | 15.51 MiB/s | 3.30× |

Run it from `web/` with:

```sh
SP2P_BENCHMARK=1 npx playwright test tests/throughput.spec.ts
```

These results verify the application-window benefit under credit pressure, not an expected Miami–LA speed. Compare the live path and wait counters when retesting that route.
