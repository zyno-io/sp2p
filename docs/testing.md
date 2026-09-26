# Testing

## Test layers

- **Go unit tests** — alongside the code they test (`*_test.go` in each
  `internal/*` package). Includes adversarial crypto tests and vectors
  (`internal/crypto`), and transfer protocol edge cases (`internal/transfer`).
- **Go end-to-end tests** — `internal/e2e_test.go` builds the CLI and drives
  real send/receive pairs against an in-process signaling server.
- **Playwright (browser) tests** — `web/tests/*.spec.ts`. Cover the browser
  UI, crypto vectors, handshake/session security, parallel WebRTC lanes
  (`parallel.spec.ts`, `parallel-interop.spec.ts`), the WebRTC buffer-hint
  policy (`webrtc-policy.spec.ts`), and CLI↔browser interop
  (`interop.spec.ts`). `web/tests/helpers.ts` holds fixtures/helpers shared
  across more than one spec file (an isolated signaling server, a CLI JSON
  event watcher, the WebRTC lane observer, and the OPFS-backed save-file
  sink) — reuse it before duplicating a helper into a new spec.
- **Protocol compatibility** — `internal/compatibility_test.go`
  (`TestE2E_ProtocolCompatibility`) and `web/tests/compatibility.spec.ts`
  build real fixtures from past releases and run them against the current
  build, in both directions, on both the current and (for the Go test) an
  old signaling server. See below.
- **Opt-in WAN harnesses** — `web/tests/wan-*.mjs`, not run in CI. Drive real
  browsers (optionally over a remote CDP connection) across a real network
  path to measure throughput and reproduce RTT-sensitive regressions. See
  [browser-wan-benchmark.md](browser-wan-benchmark.md) for setup and
  reproduction steps.
- **Realistic-WAN (netem) suite** — `web/tests/netem.spec.ts`, run in CI (the
  `netem` job) inside a real, shaped Linux network namespace instead of an
  opt-in harness against a real remote host. See
  [Realistic-WAN (netem) suite](#realistic-wan-netem-suite) below.

## Running locally

```bash
go test ./...                          # everything, Go side
go vet ./...
cd web && npx tsc --noEmit              # type-check web/src (not web/tests)
cd web && npm test                      # Playwright, all specs
cd web && npx playwright test tests/webrtc-policy.spec.ts   # one spec
```

Focused runs: `go test ./internal/transfer -run TestName`, or
`go test ./internal -run '^TestE2E_ProtocolCompatibility$'` for just the
compatibility matrix.

## Protocol compatibility and previous-release resolution

`TestE2E_ProtocolCompatibility` always runs a `new<->new` matrix against the
current build. Three more fixture pairs are opt-in, each unlocked by setting
the CLI/server binary env vars below (unset ones are skipped, matching the
existing legacy-fixture handling):

| Fixture | Env vars | What it adds |
|---|---|---|
| v0.4.0 (protocol 2, pinned) | `SP2P_TEST_LEGACY_BINARY`, `SP2P_TEST_LEGACY_SERVER_BINARY` | `old-new`/`new-old`/`old-old` pairs, against both signaling servers |
| Previous release (protocol 3) | `SP2P_TEST_PREVIOUS_BINARY`, `SP2P_TEST_PREVIOUS_SERVER_BINARY`, `SP2P_TEST_PREVIOUS_VERSION` | `new-prev`/`prev-new` pairs (against the new and previous servers, never the v0.4.0 one), plus the >4-lane WebRTC cases below |

The "previous release" is resolved automatically, not hand-pinned: CI runs
[`scripts/ci/previous-release.sh`](../scripts/ci/previous-release.sh), which
lists tags from `origin` (works in a shallow checkout), keeps plain
`vMAJOR.MINOR.PATCH` tags, and picks the highest one below the current ref
(skipping any tag that happens to point at `HEAD`). It prints `tag=`, `sha=`,
and `version=` lines for `$GITHUB_OUTPUT`. Test its resolution logic against
a throwaway local repo with:

```bash
bash scripts/ci/previous-release_test.sh
```

To exercise the previous-release compat cases locally, build a real fixture
at the resolved commit and pass it to the Go test:

```bash
sha=$(bash scripts/ci/previous-release.sh | grep ^sha= | cut -d= -f2)
version=$(bash scripts/ci/previous-release.sh | grep ^version= | cut -d= -f2)
git worktree add /tmp/sp2p-prev "$sha"
(cd /tmp/sp2p-prev && npm --prefix web ci --ignore-scripts && npm --prefix web run build \
  && go build -ldflags "-X main.version=$version" -o bin/sp2p ./cmd/sp2p \
  && go build -ldflags "-X main.version=$version" -o bin/sp2p-server ./cmd/sp2p-server)

SP2P_TEST_PREVIOUS_BINARY=/tmp/sp2p-prev/bin/sp2p \
SP2P_TEST_PREVIOUS_SERVER_BINARY=/tmp/sp2p-prev/bin/sp2p-server \
SP2P_TEST_PREVIOUS_VERSION="$version" \
  go test ./internal -run '^TestE2E_ProtocolCompatibility$' -count=1 -timeout=15m

git worktree remove /tmp/sp2p-prev
```

A `previous-binary-identity` subtest checks the binary's own `version`
output against `SP2P_TEST_PREVIOUS_VERSION` first, so a stale cache or wrong
binary fails fast instead of silently testing the wrong release.

### The capabilities table

[`testdata/release-capabilities.json`](../testdata/release-capabilities.json)
records each release's protocol version and maximum WebRTC lane count
(`webrtcLanes`), keyed by version without the `v` prefix. The compat test's
lane-count assertions (`min(6, cap(prev))`, `cap(prev)` at 64 MiB auto) read
this table for `SP2P_TEST_PREVIOUS_VERSION` and **fail closed** — an unlisted
version fails the test rather than assuming a default.

**Release checklist:** every plain `vX.Y.Z` release needs an entry in
`testdata/release-capabilities.json`, added before the tag is pushed. Once
tagged it becomes "the previous release" for CI, and the lookup fails closed
for unlisted versions.

## Opt-in WAN harnesses

`web/tests/wan-*.mjs` are standalone scripts, not Playwright specs — they are
never picked up by `npm test` or CI. They need `SP2P_WAN_DIR` and either a
local Chromium or a `REMOTE_CDP` endpoint (never expose CDP unauthenticated).
See [browser-wan-benchmark.md](browser-wan-benchmark.md) and
[browser-high-rtt.md](browser-high-rtt.md) for concrete invocations and past
results.

## Realistic-WAN (netem) suite

`web/tests/netem.spec.ts` runs all five transfer pairings (browser↔browser,
browser→CLI, CLI→browser, CLI↔CLI auto, CLI↔CLI WebRTC) over a real, shaped
Linux network namespace instead of a remote host, and proves: hash integrity,
the 8-lane WebRTC policy, Chrome's enlarged UDP socket buffer (the "buffer
hint" — see [browser-high-rtt.md](browser-high-rtt.md#socket-buffer-hint) and
[parallel-webrtc.md](parallel-webrtc.md#socket-buffer-hint)), that WebRTC
traffic is actually shaped while signaling is not, and no throughput
collapse. It's skipped unless `SP2P_NETEM_PROFILE` is set, which only the
`netem` CI job (`.github/workflows/ci.yml`) and the nightly job
(`.github/workflows/nightly.yml`) set — running it unshaped would silently
prove nothing, so it refuses to guess.

**Status: shadow period.** The `netem` job runs on every PR and push to
`main`, but is intentionally not in `build`'s `needs:` and not a required
status check yet, until its floors are calibrated against enough real runs
(see below).

### Network setup

- `scripts/ci/netns.sh {up|down|exec -- cmd...}` creates a `sp2p` Linux
  network namespace containing only `lo` and a `dummy0` at `10.99.0.1/24`
  (IPv6 disabled on `dummy0` only, so `::1` on `lo` still works) — no route to
  the internet, so WebRTC ICE inside it only ever gathers host candidates.
  `dummy0` exists so pion/Chromium have a non-loopback local address for host
  candidates; because the peer's candidate is also a local address of this
  same host, the kernel actually delivers that traffic over `lo` regardless
  (a locally-owned destination is always routed via `lo`), which is why
  shaping targets `lo`, not `dummy0`. `exec` runs a command as the *calling*
  (non-root) user — it escalates internally only for the `ip netns
  exec`/`setpriv` step, then drops back to that uid/gpid before running the
  command, forwarding `PATH`, `HOME`, and a small allowlist of other
  variables (`GOCACHE`, `GOMODCACHE`, `PLAYWRIGHT_BROWSERS_PATH`,
  `SP2P_NETEM_PROFILE`, the `SP2P_PW_*` overrides below, and the GitHub
  Actions step variables) captured from the calling shell, since `sudo`
  otherwise resets almost the whole environment.
- `scripts/ci/netem.sh {apply <profile>|verify|stats}` lays down a `prio`
  qdisc with two bands on `lo` inside the namespace: everything defaults to
  band `1:2`, which carries a `netem` child qdisc with the profile's
  delay/loss; signaling TCP traffic on the fixed test-server port (18090),
  both directions and both address families, is filtered to band `1:1`
  instead, which has no netem — that's the bypass the suite's `/health`
  latency check proves. Profiles: `wan150` (75ms delay + 0.1% loss each way →
  ~150ms RTT; used by the PR/push `netem` job), `wan150-cap` (`wan150` +
  `rate 100mbit`; nightly), `wan500` (250ms delay, no loss → ~500ms RTT;
  nightly). No profile adds jitter — reordering on a delay qdisc causes
  spurious SCTP retransmits unrelated to the WAN conditions being simulated.
  `verify` pings the namespace's own `dummy0` address from inside the
  namespace (which round-trips over `lo`, picking up the delay in both
  directions) and **hard-fails** unless the average is 140–200ms, so a broken
  or missing qdisc never lets the suite run unshaped.
- The CI job also disables `lo`'s GSO/TSO/GRO (large segments distort
  netem's per-packet loss/delay) and raises `net.core.rmem_max` /
  `net.core.wmem_max` to 4 MiB **on the host**, before the namespace exists,
  so Chrome's 1 MiB buffer-hint request isn't silently capped.
- The test signaling server is never given a `-turn-servers` value containing
  a bare (non-`turn:`/`turns:`) URL, so it advertises no STUN servers in
  `Welcome` (`cmd/sp2p-server/main.go`, `internal/server/handler_signal.go`).
  Clients that get no ICE servers from signaling fall back to public Google
  STUN (`internal/flow/helpers.go`, `web/src/webrtc.ts`) — that fallback is
  unchanged production behavior, not something this suite turns off — but
  inside the namespace those lookups simply can't reach anything, so ICE
  still only ever completes with host candidates. `--disable-features=
  WebRtcHideLocalIpsWithMdns` keeps Chromium from hiding those host
  candidates behind unresolvable `.local` names.
- The netem project in `web/playwright.config.ts` uses `channel: "chromium"`
  (the full, non-headless-shell Chromium build) because the buffer-hint and
  ICE port-range behavior this suite checks isn't guaranteed to match the
  headless-shell build.

### Running locally (Linux only)

```bash
sudo modprobe sch_netem   # or: sudo apt-get install -y linux-modules-extra-$(uname -r)
sudo sysctl -w net.core.rmem_max=4194304 net.core.wmem_max=4194304
make build-cli build-server
cd web && npm ci && npm run build && npx playwright install --with-deps chromium && cd ..
sudo scripts/ci/netns.sh up
sudo scripts/ci/netem.sh apply wan150
sudo scripts/ci/netem.sh verify
cd web
SP2P_NETEM_PROFILE=wan150 SP2P_PW_SKIP_WEB_BUILD=1 \
  SP2P_PW_CLI_BIN="$PWD/../bin/sp2p" SP2P_PW_SERVER_BIN="$PWD/../bin/sp2p-server" \
  ../scripts/ci/netns.sh exec -- npx playwright test --project=netem
cd ..
sudo scripts/ci/netem.sh stats   # optional: drops/packets while it's still up
sudo scripts/ci/netns.sh down
```

`SP2P_PW_SKIP_WEB_BUILD`/`SP2P_PW_CLI_BIN`/`SP2P_PW_SERVER_BIN` tell
`web/tests/global-setup.ts` to use the binaries/`web/dist` built above instead
of rebuilding — the namespace has no route to the internet, so anything that
could reach for the network has to happen before `netns.sh exec`, not inside
it. Every other spec/project is unaffected (those env vars are unset).

### Per-pairing results and floors

Each pairing writes one numeric-only JSON file to `test-results/perf/` (MB/s,
lane counts, max UDP receive-buffer size, candidate-pair RTT, netem
drops/packets, signaling `/health` median latency) — never transfer codes,
addresses, or SDP. `web/tests/perf-summary.mjs` turns those into a markdown
table on `$GITHUB_STEP_SUMMARY` and, with `--gate`, fails if any pairing is
below its floor in `web/tests/perf-floors.json` (used by the nightly job on
the median of `--repeat-each=3`; the PR/push job runs it without `--gate` and
relies on the per-test `expect` inside `netem.spec.ts` instead, which asserts
the same floors as it goes).

**Performance floor calibration:** the floors committed alongside this suite
are deliberately low placeholders (1.0 MB/s), not calibrated numbers — there
was no Linux box available to establish a real baseline before merging.
Calibrate them once the `netem` job has a run of real numbers: set each
floor to roughly 35% of the observed MB/s for that pairing, push, and confirm
the job stays green. Re-calibrate if a legitimate protocol change shifts
throughput meaningfully; don't let floors silently drift stale in the other
direction either.

`cli-cli-auto` intentionally has no floor: transport racing may legitimately
pick either TCP or WebRTC depending on timing, and the two have different
achievable throughput on this path, so gating it before there's data on both
outcomes risks flakiness rather than catching a regression. Its record is
still written (bytes, duration, MB/s, whichever transport/lane count the CLI
reported) for visibility.

### Known rough edges

- `packetsDiscardedOnSend` (from `RTCPeerConnection.getStats()`) is recorded
  per pairing but not gated. If a `wan500` (no-loss) nightly run shows it
  climbing, that's the "netem on `lo` holds the sender's `SO_SNDBUF`" failure
  mode: move the delay to an IFB ingress qdisc on `lo` instead of the egress
  `prio`/`netem` chain used today, and update this section.
- `web/tests/helpers.ts`'s `udpSockets()` and `netem.spec.ts`'s `tc -s qdisc
  show` both assume an unprivileged read of `ss -uanmp` / `tc -s qdisc show`
  works from inside the namespace as the non-root test-runner user (true on
  current Ubuntu kernels for read-only queries); if a future runner image
  restricts this, those reads will need to move to a small root-run helper
  instead.
- The `ss -m` "drops" (`d<N>`) skmem field is parsed best-effort and recorded
  but not asserted on, since its exact availability/format across
  kernel/iproute2 versions wasn't verified ahead of time.
