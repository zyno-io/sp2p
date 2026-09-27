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
  policy (`webrtc-policy.spec.ts`), CLI↔browser interop (`interop.spec.ts`),
  and the cross-engine sender/receiver matrix (`engine-matrix.spec.ts` — see
  [Engines](#engines-firefox-and-webkit) below). `web/tests/helpers.ts` holds
  fixtures/helpers shared across more than one spec file (an isolated
  signaling server, a CLI JSON event watcher, the WebRTC lane observer, an
  OPFS-backed save-file sink, and an OPFS-free incremental-hashing save-file
  sink for cross-engine use) — reuse it before duplicating a helper into a
  new spec.
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
cd web && npm test                      # Playwright, Chromium only (pins --project=chromium)
cd web && npx playwright test tests/webrtc-policy.spec.ts   # one spec, but see below
```

Focused runs: `go test ./internal/transfer -run TestName`, or
`go test ./internal -run '^TestE2E_ProtocolCompatibility$'` for just the
compatibility matrix.

**`npm test` is Chromium-only** (`package.json`'s `test` script pins
`playwright test --project=chromium`); this keeps the existing single-engine
default. Running `npx playwright test` directly, with no `--project` flag —
as in the one-spec example above — is **not** Chromium-only: it runs every
project whose `testMatch` includes that spec, so a spec named on the command
line without `--project` also runs under `firefox` and `webkit` if it's one
of the three cross-engine specs (needs `npx playwright install firefox
webkit` first — see [Engines](#engines-firefox-and-webkit) below for which
specs those are and why). A bare `npx playwright test` with no arguments at
all runs the full suite across every project, including the 15-cell,
64&nbsp;MiB `engines` project — expect it to take several minutes.

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

### Browser previous-release matrix

`web/tests/compatibility.spec.ts`'s `"previous release"` describe block is
the browser-side counterpart to `TestE2E_ProtocolCompatibility`'s
`webrtc-lanes` cases above, and is driven by the same
`testdata/release-capabilities.json` table plus three env vars — unset any
one and every test in the block skips cleanly:

| Env var | What it points at |
|---|---|
| `SP2P_TEST_PREVIOUS_BINARY` | The previous release's `sp2p` CLI binary |
| `SP2P_TEST_PREVIOUS_WEB_DIR` | The previous release's built `web/dist` |
| `SP2P_TEST_PREVIOUS_VERSION` | Its plain `X.Y.Z` version (no `v` prefix; a `release-capabilities.json` lookup key) |

It runs all four sender/receiver pairings of a new peer against a
previous-release peer, plus a browser-to-browser test that covers both
directions on one pair of pages, all at 64&nbsp;MiB — the `PARALLEL_MIN_BYTES`
(`web/src/webrtc-parallel.ts`) / `parallelMinFileSize`
(`internal/flow/send.go`, `receive.go`) auto threshold, so a browser sender
and a previous-release CLI sender in auto mode both actually request more
than one WebRTC lane. Each case asserts the received file's SHA-256, that
both sides reach `.complete`/exit 0, and that both sides negotiated
`min(8, cap(prev))` lanes (`0` lanes — no parallel WebRTC at all — for a
protocol-2 previous release; see `expectedLaneCounts` in the spec, which
reads this off the capabilities table rather than checking the version
string). A cheap 5&nbsp;MiB variant covers one CLI/browser pairing without the
cost of another 64&nbsp;MiB buffer, since the 64&nbsp;MiB cases already cover lane
negotiation.

**Fixture identity checks:** a previous/legacy browser page is served by
intercepting routes (`serveLegacyBrowser` in the spec) rather than a real
second `webServer`; if that interception ever misses (e.g. a route regex that
stops matching a renamed asset), Playwright silently falls through to the
live app and the test would pass while comparing new-vs-new instead of
old/previous-vs-new. `assertBundleIdentity` guards against this: it reads the
page's loaded `script[src*="main-"]` basename and asserts it equals the
`main-*.js` file actually present in the fixture's web dir. This runs for
every legacy/previous browser page, including the pre-existing pinned
v0.4.0/v0.5.0 cases. The CLI side has an equivalent check: `sp2p version`'s
output must contain `SP2P_TEST_PREVIOUS_VERSION`.

**CI wiring:** `.github/actions/build-release-fixture` is a composite action
that checks out a commit SHA (never a moving tag), builds its web assets, CLI,
and server, and caches the result keyed on both the SHA and the version
(`compat-<sha>-<version>-<os>-v1` — the version is included because a commit
can end up tagged with more than one version, e.g. a no-op re-release, and
the version string is baked into the binaries via `-ldflags`, so the SHA
alone isn't a safe cache key). `ci.yml`'s `protocol-compatibility` job uses
it to build `.compat-prev` (resolved via `previous-release.sh`'s default
`--nth 1`, i.e. N-1) and feeds both the Go test and this Playwright spec from
it. `nightly.yml`'s `compat-n2` job builds a second fixture the same way at
`--nth 2` (N-2), so a peer two releases back also keeps getting exercised,
not just whichever release happens to be "the previous one" at any given
moment.

**Protocol-2 previous releases aren't reachable from CI today.** The
`expectedLaneCounts` branch above that expects no lane negotiation exists so
the spec stays correct *if* `SP2P_TEST_PREVIOUS_VERSION` is ever pointed at a
protocol-2 release (verified locally against a real v0.4.0 fixture — 7/7
pass), but neither `ci.yml` nor `nightly.yml` can currently produce that:
`previous-release.sh`'s `--nth 1`/`--nth 2` both resolve to protocol-3
releases today, and `TestE2E_ProtocolCompatibility` (which runs before this
spec in both jobs) isn't protocol-2-aware for the `SP2P_TEST_PREVIOUS_*` env
vars — it would fail first. Revisit both if a future release ever makes N-2
protocol-2 again.

### Pinned fixtures and the tag-move policy

The v0.4.0 and (original) v0.5.0 fixtures in `ci.yml` are checked out by
commit SHA, not by tag, specifically so a moved or re-pushed tag can never
change what they test. **Policy: if a release tag ever has to move** (as
v0.5.0's did, from `d303e1a947ca8ef6bb000dfe8660e7a05c7738cd` to its current
commit), pin the tag's pre-move SHA as a new historical fixture before
moving it, the same way v0.5.0's pre-move SHA is pinned today — never let a
historical-compatibility fixture depend on a tag that can move out from
under it. The resolved-at-runtime "previous release"/"N-2" fixtures above
are the deliberate exception: they always track a real, current tag by
design, since they exist to test whatever the previous release(s) actually
are right now.

## Engines (Firefox and WebKit)

Playwright projects (`web/playwright.config.ts`): `chromium` (default, full
spec set minus the two below), `firefox` and `webkit` (the cross-engine
interop specs only), and `engines` (`engine-matrix.spec.ts` only). `npm test`
and `ci.yml`'s `browser-interop` job pin `--project=chromium` explicitly, so
existing behavior is unchanged; `web/playwright.cross-browser.config.ts` (an
older, narrower two-project config) has been folded in and removed.

**Why only three specs run cross-engine.** `firefox`/`webkit` `testMatch`
only `interop.spec.ts`, `parallel-interop.spec.ts`, and `webrtc-policy.spec.ts`
— the specs that exercise a real `browser`/`page` fixture and generalize
across engines. Everything else (crypto vectors, session security,
Node-only `parallel.spec.ts`, the env-gated `netem`/`compatibility` specs)
stays Chromium-only; running them again per engine would test the same
Node-side logic three times for no added coverage.

**The buffer-hint policy is asymmetric by design** (`web/src/webrtc.ts`'s
`BUFFER_HINT`): Firefox's own offers never carry the video section and never
set `bundlePolicy: "max-bundle"` (older pion's `bundle-only` incompatibility —
see `docs/browser-high-rtt.md`), but Firefox answers a Chromium/WebKit/CLI
offer that has the hint completely normally. `webrtc-policy.spec.ts`'s
`assertOfferingPolicy` branches on `browserName` for exactly this: the
Firefox branch asserts no video section and non-`max-bundle`; every other
engine (including WebKit, which gets identical assertions to Chromium) keeps
the original assertions. The CLI→browser direction has no branch at all,
because a Firefox *answerer* behaves like every other engine.

**The OPFS-free hashing sink.** `web/tests/helpers.ts`'s `receiveToDisk`
fakes `showSaveFilePicker` with a real OPFS file handle; a local spike
(`navigator.storage.getDirectory()` → `getFileHandle` → `createWritable()`
→ `write()`/`close()` → read back) found this reliable on Firefox but
throwing `NotReadableError`-class failures ("operation failed for an
unknown transient reason") on Playwright's bundled WebKit build. Rather than
skip most of `webrtc-policy.spec.ts`/`parallel-interop.spec.ts` on WebKit,
both specs now use the new `hashingPicker`/`verifyHashingSink` instead: the
fake `showSaveFilePicker` returns a handle whose `createWritable()` streams
every written chunk into the incremental SHA-256 from `web/src/sha256.ts`
(loaded on the page via the existing `crypto-test.js` bundle — see
`crypto-vectors.spec.ts` for the same load pattern) and records
`{size, hash}` on `window.__hashingSink` at `close()`. No OPFS, no
`arrayBuffer()` read-back of the whole file — it works identically on every
engine. `engine-matrix.spec.ts` uses the same sink for its receivers.
`receiveToDisk`/`verifyDisk` are unchanged and still used by
`compatibility.spec.ts` and `netem.spec.ts`, which only ever run on
Chromium-family engines.

**The shared config's `baseURL` fix.** `playwright.config.ts`'s top-level
`use.baseURL` was `http://localhost:18090`. On a machine where `localhost`
resolves IPv6 (`::1`) first, Firefox's ICE agent gathered *zero* local
candidates and failed instantly ("ICE failed, add a TURN server") whenever
the page's origin was the IPv6 loopback address; Chromium and WebKit were
unaffected on the same machine. Changed to the literal `http://127.0.0.1:18090`
— a real fix, confirmed by toggling it back and forth against the same
Firefox failure. No spec asserts the literal string `"localhost"` in
rendered UI (`ui.spec.ts`'s origin test reads `page.url()` dynamically), and
the two places that do (`ui.spec.ts`'s agent-doc check, `interop.spec.ts`'s
`SP2P_URL` CLI env var) refer to the *server's own* `--base-url`, set
separately in `global-setup.ts` and unrelated to Playwright's navigation
`baseURL`.

**`engine-matrix.spec.ts`** covers the full sender×receiver matrix
(chromium/firefox/webkit, 3×3 = 9 cells) plus the CLI against each engine in
both directions (6 more cells) — 15 total — at 64 MiB of random content,
asserting the received SHA-256 and that both sides negotiate the full
8-lane parallel-WebRTC policy. Every engine is launched explicitly through
the `playwright` fixture (e.g. `playwright.firefox.launch()`) and closed in
a `finally`, never through the project's own `browser`/`page` fixtures, so
the `engines` project declares no `browserName` — it exists only to scope
enumeration. Chromium↔Firefox and CLI↔Firefox (both directions each, 4
cells) are tagged `@pr`; the rest — anything touching WebKit, plus
CLI↔Chromium — is nightly-only.

**CI wiring.** `ci.yml`'s new `browser-firefox` job (`ubuntu-latest`, not
yet a required check) runs `--project=firefox` plus
`--project=engines --grep @pr`. `nightly.yml`'s new `engines` job
(`macos-15` — closer to Safari's WebKit than a Linux runner) runs
`--project=webkit` plus the full, untagged `--project=engines` (all 15
cells); it was added to `report-failure`'s `needs` and failure-summary
logic alongside `netem-nightly` and `compat-n2`. Browsers in the matrix
expose plain host candidates (Chromium's `WebRtcHideLocalIpsWithMdns`
disabled, Firefox's `media.peerconnection.ice.obfuscate_host_addresses`
off): hosted macOS runners don't reliably resolve the `.local` names, which
broke browser↔browser cells while CLI cells passed.

**Fixed: CLI sender → browser receiver stall.** On hosted runners, CLI →
browser transfers occasionally hung for 15 s: the CLI logged `webrtc trying`
and then `Receiver disconnected`, while the browser sat at `Waiting for
sender's offer`. The CLI sends its offer as soon as its own key derivation and
ICE gathering finish, which can be before the browser has derived its session
keys and registered an `offer` handler, and `SignalClient` dropped messages
with no handler. It now holds `offer`/`answer`/`candidate` messages until a
handler registers, and drops held messages before sending `relay-retry` (the
peer only starts its next attempt after receiving it). `interop.spec.ts` has a
regression test that slows the receiver's key derivation to force the
ordering; it fails without the fix with the same signature seen on CI.

**Known rough edge: multi-homed-host lane sockets (WebKit and browser↔browser
alike).** On the Mac this was developed on — two active interfaces on the
same /24 (Wi-Fi `en0` and Ethernet `en9`) — WebKit occasionally lands on 6-7
of the requested 8 parallel-WebRTC lanes instead of 8, and the same
symptom (lanes stuck at a fixed, well-below-8 count) has also been observed
locally on an `engine-matrix.spec.ts` browser↔browser cell where Chromium is
answering Firefox's lane offers, so this isn't exclusively a WebKit
behavior — it's whichever side's lane socket happens to bind wrong on this
particular multi-homed host. This is **not** the
8-second per-lane authentication timeout in `web/src/webrtc-parallel.ts`'s
`Lane.wait()` running out (a timing margin that a retry could reasonably
absorb): the affected lane's ICE connectivity check makes *zero* progress
for the entire 8 seconds. WebKit's lane sockets bind `INADDR_ANY`, and on a
multi-homed host they can answer a STUN connectivity check from a different
local address than the one the check was sent to; pion (the CLI/server's
WebRTC stack) discards that reply outright — "Discard message: transaction
source and destination does not match expected" (RFC 8445 §7.2.5.2.1) — so
the lane never has a chance to connect at all, regardless of how long it
waits. This is specific to a multi-homed, same-subnet host, not expected on
CI's single-NIC runners (`ubuntu-latest`, `macos-15`), so no retry was added
for it — a retry would only be masking noise if the failure were timing-
sensitive, and this one isn't. If the macos-15 nightly `engines` job shows
the same lane shortfall for real, that's the point to investigate further:
it would mean either that runner is multi-homed too, or that this is a
genuine Safari/WebKit-multi-lane interoperability issue independent of
network topology (the transfer itself still completes over however many
lanes did connect — this reduces parallelism, it doesn't break transfers).

**New finding, not yet root-caused: `engine-matrix.spec.ts`'s browser↔browser
cells mostly fail on the macos-15 nightly runner.** Dispatching `nightly.yml`
on this branch (`gh workflow run nightly.yml --ref <branch>`) to validate
its `engines` job before merge (it cannot be triggered by a PR) surfaced
this: `--project=webkit` was clean, 15/15, but `--project=engines` had
**8 of its 9 browser↔browser cells** time out waiting for `.complete` —
every pairing except webkit→webkit, including **chromium→chromium**, the
simplest possible cell and the first one that runs. All 6 CLI↔browser
cells in the same run passed. This is a different failure shape from both
rough edges above (a 100s hard timeout with zero transfer progress, not a
partial lane count), and it does **not** reproduce in many local runs of
the same `--project=engines` on this Mac (chromium→chromium has never
failed here). The dump-on-failure diagnostics added for item 1 above fired
but weren't useful for this one: `runBrowserToBrowser`'s own `finally`
closes both browsers before the test throws, so `flushDiagnostics` found
every receiver page already closed by the time `afterEach` ran — and
`flushDiagnostics` had a real bug (now fixed) that skipped the
still-available buffered console/pageerror lines too, not just the live
DOM snapshot that actually needs an open page. That fix landed here, but
a nightly dispatch takes the better
part of an hour end to end and this branch's cost/time budget didn't
stretch to a second one — so the *fix* was validated (diagnostics correctly
dump buffered console lines for a closed page, confirmed by inspection),
but the *actual root cause of the browser↔browser failures* was not
re-captured with the fix in place. Given webkit→webkit (both sides
launched the same way, via the `playwright` fixture rather than a project's
own `browser` fixture) is the one cell that passed, and the *project-level*
`webkit`/`firefox`/`chromium` suites (which never launch via the raw
`playwright` fixture — see `webrtc-policy.spec.ts`/`parallel-interop.spec.ts`
running fine under all three engines) don't show this, the most likely
culprit is something about `launchEnginePage`'s `pw[engine].launch(...)` +
`browser.newPage({ baseURL })` pattern specifically on `macos-15` GitHub
Actions runners — not a specific engine's WebRTC implementation. This is
reported here for follow-up rather than guessed at further; it does not
block this PR's Firefox/`ubuntu-latest` rollout (`browser-firefox`, the
required-eventually job), only the WebKit/`engines` nightly rollout, which
was already explicitly staged as "nightly-only, promote later" for exactly
this kind of reason.

**Local validation results** (this Mac, one run each unless noted):

| Command | Result |
| --- | --- |
| `npx tsc --noEmit` | passes (test files aren't type-checked) |
| `npx playwright test --project=firefox` (15 tests) | 15 passed, ~2.1m |
| `npx playwright test --project=webkit` (15 tests) | 13 passed, 2 failed (the lane-count rough edge above); a later isolated rerun of just those two passed once and failed once more — consistent with transient flakiness, not a hard failure |
| `npx playwright test --project=engines` (15 cells) | 14 passed, 1 failed (the same rough edge, on a browser↔browser cell); reran the failing cell in isolation twice more and it passed both times |
| Mutation: `BUFFER_HINT = true` unconditionally | Firefox policy tests fail as expected (`bundlePolicy`/video assertions); reverted exactly (`git diff` clean) |
| Mutation: remove `bundlePolicy` from the peer connection config | WebKit policy tests fail as expected; reverted exactly (`git diff` clean) |

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
  shaping targets `lo`, not `dummy0`. **`up` also adds a default route via
  `dummy0`** (`ip route add default dev dummy0`): Chromium's network
  enumeration skips interfaces it considers unroutable, and without a default
  route it gathered zero usable host candidates at all (every browser pairing
  failed with "no TURN relay available" until this was added) — the route
  only changes what Chromium considers viable, not where traffic actually
  goes (still `lo`, per above). `exec` runs a command as the *calling*
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
  directions) and **hard-fails** unless the average is in the profile's band
  (140–200 ms for `wan150`/`wan150-cap`, 480–560 ms for `wan500`), so a broken
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
sudo scripts/ci/netem.sh verify wan150
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

Each pairing writes one numeric-only JSON file per repeat and attempt to
`test-results/perf/` (MB/s,
lane counts, max UDP receive-buffer size, candidate-pair RTT, netem
drops/packets, signaling `/health` median latency) — never transfer codes,
addresses, or SDP. `web/tests/perf-summary.mjs` turns those into a markdown
table on `$GITHUB_STEP_SUMMARY` and, with `--gate`, fails if any pairing is
missing or its median is below the floor for the current profile in
`web/tests/perf-floors.json`. The PR/push job also asserts the floor inside
each test. The nightly job sets `SP2P_NETEM_GATE_PER_TEST=0` so one slow
repeat of `--repeat-each=3` doesn't fail the run, and gates on the medians
instead. Traces, screenshots and the Playwright report are not collected for
this suite, because they would capture transfer codes; only the numeric
records are uploaded.

**Performance floor calibration:** floors are set to roughly 35% of a real
`wan150` `netem` job run's observed MB/s per pairing (rounded down slightly),
per this table from the run that first went green end-to-end:

| Pairing | Observed MB/s | Floor (35%) |
| --- | ---: | ---: |
| browser-browser | 2.09 | 0.7 |
| browser-cli | 2.24 | 0.75 |
| cli-browser | 2.24 | 0.75 |
| cli-cli-webrtc | 2.12 | 0.7 |

That run also confirmed the mechanics this suite exists to prove: all three
browser-involving pairings negotiated 8 lanes and reported a UDP receive
buffer of exactly 2097152 bytes (the doubled 1 MiB hint); `cli-cli-auto`
picked TCP with 6 parallel connections (not WebRTC — recorded, not gated,
see below); netem's drop ratio stayed near the configured 0.1% loss on every
pairing (e.g. 212/194263 ≈ 0.11%); and the signaling `/health` median stayed
under 3ms on every pairing versus the profile's ~150ms shaped RTT. Re-run
this calibration if a legitimate protocol change shifts throughput
meaningfully; don't let floors silently drift stale in the other direction
either.

`cli-cli-auto` intentionally has no floor: transport racing may legitimately
pick either TCP or WebRTC depending on timing, and the two have different
achievable throughput on this path, so gating it before there's data on both
outcomes risks flakiness rather than catching a regression. Its record is
still written (bytes, duration, MB/s, whichever transport/lane count the CLI
reported) for visibility.

### Known rough edges

- **RTT and socket-buffer sampling happens *during* the transfer, not
  after.** The app closes every WebRTC connection immediately once a
  transfer completes (right after showing `.complete`), and a closed
  `RTCPeerConnection`'s `getStats()` can come back with no candidate-pair
  report at all. `startSampling()` in `netem.spec.ts` instead polls
  `getStats()` and `udpSockets()` roughly once a second for the whole
  transfer and keeps the maximum/accumulated readings, closing over that
  race entirely.
- **The buffer-hint check is a threshold, not an exact match.** A plain
  headless Chromium opens its own background UDP sockets unrelated to
  WebRTC — one was observed with a coincidental ~1 MiB receive buffer, on a
  freshly launched browser that never even loaded the app. That ruled out
  both "it's stale state from an earlier test" and "filter by `ss` state
  (ESTAB vs UNCONN)" as fixes (the real, correctly-hinted WebRTC socket did
  not reliably show as `ESTAB` either). `udpSockets()` therefore returns
  every UDP socket for the browser's process tree, and callers compare the
  *maximum* rb against the hinted threshold (2 MiB) rather than asserting
  an exact byte count — true for both the positive checks (`>=` 2 MiB) and
  the negative control (`<` 2 MiB, not "equals exactly 131072").
- `web/tests/helpers.ts`'s `udpSockets()` and `netem.spec.ts`'s `tc -s qdisc
  show` both assume an unprivileged read of `ss -uanmp` / `tc -s qdisc show`
  works from inside the namespace as the non-root test-runner user — confirmed
  on the `ubuntu-latest` runner image as of this writing; if a future image
  restricts this, those reads will need to move to a small root-run helper
  instead.
- The `ss -m` "drops" (`d<N>`) skmem field is parsed best-effort and recorded
  but not asserted on, since its exact availability/format across
  kernel/iproute2 versions wasn't verified ahead of time.
- `packetsDiscardedOnSend` (from `RTCPeerConnection.getStats()`) is recorded
  per pairing but not gated. If a `wan500` (no-loss) nightly run shows it
  climbing, that's the "netem on `lo` holds the sender's `SO_SNDBUF`" failure
  mode: move the delay to an IFB ingress qdisc on `lo` instead of the egress
  `prio`/`netem` chain used today, and update this section.
