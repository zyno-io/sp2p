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
- **TURN relay (relay-only) suite** — `web/tests/relay.spec.ts`, run in CI
  (the `relay`/`relay-full` jobs) inside the same kind of Linux network
  namespace as the netem suite, but firewalled instead of shaped: direct
  UDP is blocked so every WebRTC pairing is forced through a real (CI-only)
  TURN server, with exact allocation accounting and no leaked allocations.
  See [TURN relay (relay-only) suite](#turn-relay-relay-only-suite) below.

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

## TURN relay (relay-only) suite

`web/tests/relay.spec.ts` proves that a real relay-only WebRTC transfer
works — 8 parallel lanes, both peers behind a firewall that blocks direct
UDP — with exact TURN allocation accounting (no leaked allocations) and
graceful degradation under a per-session TURN quota. It reuses the `sp2p`
network namespace from [Realistic-WAN (netem) suite](#realistic-wan-netem-suite)
above, but firewalls it instead of shaping it: `scripts/ci/relay-firewall.sh`
blocks every direct UDP path so ICE inside the namespace can only ever
succeed by relaying through a real (CI-only) TURN server,
`internal/testturn`'s `testturnd`. Skipped unless `SP2P_RELAY_TEST` is set,
which only `ci.yml`'s `relay` job and `nightly.yml`'s `relay-full` job set —
same rationale as the netem suite's `SP2P_NETEM_PROFILE` gate: running this
unfirewalled would silently prove nothing.

**Status: shadow period**, same as `netem`: `ci.yml`'s `relay` job runs on
every PR and push to `main` (the `@pr`-tagged Chromium-only subset — 4
tests) but is not in `build`'s `needs:` and not a required status check
yet. `nightly.yml`'s `relay-full` job runs the complete suite (12 tests,
including Firefox pairings, the quota case, and the consent negative
controls) and is wired into `report-failure` alongside `netem-nightly`,
`compat-n2`, and `engines`.

### Topology and the relay-only firewall

`scripts/ci/relay-firewall.sh apply` installs a stateless iptables/ip6tables
chain (`SP2P_RELAY`) hooked into `INPUT -i lo` inside the `sp2p` namespace —
stateless because there is deliberately no conntrack `ESTABLISHED` accept
rule: two peers running ICE connectivity checks against each other must
never be treated as "replies" to one another, or the direct path this
firewall exists to block would work again.

| Traffic | Match | Verdict |
| --- | --- | --- |
| Signaling TCP | ports `18090,18091` (either side — `-m multiport --ports`) | ACCEPT |
| Our own REJECT resets | any TCP with the RST flag set | ACCEPT |
| TURN/STUN control | UDP port `3478` (either side) | ACCEPT |
| Relayed data | UDP, **both** source and destination in `31000-31127` | ACCEPT |
| DNS | UDP dport `53` | REJECT (fast, not a hang) |
| Everything else UDP | any | DROP |
| Everything else TCP | any | REJECT `tcp-reset` (fails fast, e.g. a CLI's direct-TCP attempt) |

Why signaling and TURN-control use `--ports`/`-m multiport` (either source
*or* destination) but relayed data does not: with no conntrack, a rule has
to recognize both legs of a real exchange from the port number alone. The
signaling server's reply to a client connected on port 18091 has *source*
port 18091 but an ephemeral *destination* port; the same shape applies to a
client's own control-channel traffic to the TURN server's fixed port 3478.
A dport-only rule would reject/drop the legitimate return leg in both
cases, so both need the permissive "either side" match.

Relayed data is different, and **this was a real correctness bug caught in
review, not a deliberate asymmetry**: a client's own local UDP socket never
talks to a relay-range port directly — it only ever talks to the server's
control port (3478), which relays the payload internally. The relay range
is used exclusively for genuine relay-socket-to-relay-socket traffic (e.g.
two TURN allocations on the same `testturnd` process, one per peer,
exchanging relayed payload with each other directly). An earlier version of
this rule matched "either side" here too, which meant a packet from one
peer's own *host* candidate (ephemeral source port) straight to the *other*
peer's relay candidate address (destination port in `31000-31127`) was also
accepted — a mixed host↔relay ICE pair that let one side skip relaying
entirely, silently defeating the suite's central claim. The relayed-data
rule now requires **both** the source and destination port to be in
`31000-31127` (`--sport X:Y --dport X:Y`, not `multiport --ports`), which
only ever matches genuine relay↔relay traffic; a mixed host↔relay pair
correctly falls through to the UDP DROP catch-all instead. This makes "the
transfer completed" and "both peers actually relayed" the same fact by
construction — no separate `getStats()`-based candidate-type assertion is
needed in `relay.spec.ts`.

Why the relay range (`31000-31127`) sits below the kernel's ephemeral range
(`32768-60999`, `/proc/sys/net/ipv4/ip_local_port_range`): so no
host-candidate (kernel-assigned) UDP socket that a peer opens for a direct
WebRTC path can ever land inside the relay range and be mistaken for one.
`relay-firewall.sh verify` checks this invariant against the namespace's
actual `ip_local_port_range` rather than assuming it.

The `netem` and `relay` suites never share a running namespace instance:
each runs in its own CI job on its own runner, `netns.sh up` refuses to
create a namespace that already exists, and both suites pin fixed ports
with `workers: 1`, ruling out an accidental concurrent local run too. Don't
run `netem.spec.ts` in a namespace that has the relay firewall applied (or
vice versa) — the netem suite expects direct UDP to work.

### `testturnd`

`internal/testturn` wraps `github.com/pion/turn/v5` directly instead of
running a real coturn instance, so CI needs no extra service to install or
configure. Its binary, `internal/testturn/testturnd`, is a deliberate
exception to the repo's flat `internal/` package layout (see AGENTS.md,
CLAUDE.md): it lives nested under the one library it wraps instead of under
`cmd/`, because it's CI test tooling built directly by CI
(`go build ./internal/testturn/testturnd`) and never by the `Makefile` or
`.goreleaser.yaml`.

- **Credentials.** `testturnd -secret` (env `SP2P_TESTTURN_SECRET`) must
  match the signaling server's `-turn-secret`/`SP2P_TURN_SECRET`.
  `turn.LongTermTURNRESTAuthHandler` implements exactly the same TURN-REST
  scheme as `internal/server/turn.go`'s `TURNCredentialGenerator`: username
  `<unix-expiry>:<sp2p-session-id>`, password
  `base64(HMAC-SHA1(secret, username))`. Both peers of one sp2p session
  share a single TURN username, so `testturnd`'s per-session accounting is
  naturally per-username too.
- **No egress denylist.** Unlike `deploy/turnserver.conf.example` (which
  denies loopback/private/multicast peer IPs for a real public deployment),
  `testturnd` allows same-host peers — the whole point here is two peers on
  the *same* CI runner relaying through it.
- **Exact accounting, no reservation needed.** `testturnd`'s quota check
  (`tracker.allow` in `internal/testturn/stats.go`) is a plain
  check-then-increment with no reservation step, and it's still race-free:
  pion runs exactly one read-loop goroutine per `turn.PacketConnConfig`
  entry, and `testturnd` registers exactly one entry and zero
  `ListenerConfigs`, so `QuotaHandler`, `CreateAllocation`, and the
  resulting `OnAllocationCreated`/`OnAllocationDeleted` events are all
  handled synchronously within that one goroutine — even under concurrent
  client `Allocate` requests for the same session (verified by
  `TestServer_QuotaConcurrency` in `internal/testturn/turn_test.go`, which
  fires 12 concurrent allocation attempts at a quota of 4 and asserts
  exactly 4 succeed). Adding a TCP/TLS listener would break this invariant
  and require a reservation-with-timeout scheme instead.
- **`stats.json`** is written atomically (temp file + rename, mirroring
  `internal/cli/machine.go`'s status-snapshot pattern) on every allocation
  event. Schema (all fields present, `users` keyed by a 16-hex-char
  `sha256(userID)` prefix — TURN usernames, which embed the sp2p session
  ID, are never written to disk in the clear):

  ```jsonc
  {
    "version": 1, "seq": 42, "ready": true, "closed": false, "userQuota": 0,
    "created": 16, "deleted": 16, "live": 0, "peakLive": 16,
    "quotaRejected": 0, "authFailures": 0, "relayAllocFailures": 0, "anomalies": 0,
    "pionLive": 0, // turn.Server.AllocationCount() at write time — cross-check
    "relayedBytesFromPeers": 67145728, "relayedBytesToPeers": 67145728,
    "users": { "<16-hex-char key>": { "created": 16, "deleted": 16, "live": 0, "peakLive": 16, "quotaRejected": 0, "relayedBytesFromPeers": 67108864, "relayedBytesToPeers": 67108864 } }
  }
  ```

  `relay.spec.ts` polls this file directly (never over the network) to
  assert exact per-session allocation counts and to detect a "no new TURN
  session key appeared" leak-free release.
- **Logging.** `-log-level` defaults to `disabled`. `pion/turn`'s
  long-term-credential auth handler logs the full TURN username — which
  embeds the sp2p session ID — at Trace/Error level, so `testturnd` always
  uses a disabled logger for auth regardless of `-log-level`; anything above
  `disabled` is for local debugging only, never CI (AGENTS.md: never log
  transfer codes or TURN secrets).
- **Orphan protection.** `-exit-with-parent` polls its parent PID and exits
  cleanly within 500ms of being reparented, so a killed Playwright worker
  can't leave a `testturnd` holding UDP port 3478 across later runs.

### Allocation formula

**Every lane (the primary connection plus each authenticated extra
parallel-WebRTC lane) on every peer that actually relays makes its own TURN
allocation.** Each lane is its own `RTCPeerConnection`/ICE agent that reuses
the primary's already-negotiated ICE server configuration (browser:
`web/src/webrtc-parallel.ts`'s `Lane` constructor calls
`new RTCPeerConnection(pc.getConfiguration())`; CLI: pion's own ICE agent,
one per lane) — TURN credentials are never re-requested per lane, but each
lane still gathers its own candidates and therefore makes its own
allocation. So for the full 8-lane policy relayed on both sides:

```text
created = PEERS × LANES = 2 × 8 = 16
```

Chromium's `bundlePolicy: "max-bundle"` (`web/src/webrtc.ts`'s
`BUFFER_HINT`/`addBufferHint`, set for every non-Firefox connection) is why
this holds at exactly one allocation per *connection*: max-bundle keeps a
connection's data channel and its buffer-hint video section on one ICE
transport instead of two. Removing it (mutation (a); see
[Mutation checks](#mutation-checks) below) is expected to
double the per-connection count for Chromium-*offering* connections
specifically — a Chromium *answerer* isn't affected, since it only starts
gathering once it accepts the offer's BUNDLE group. The exact figure above
was derived from source, not measured; **a real CI run's `relay-turn-stats`
artifact / `test-results/relay/*.json` (surfaced by
`web/tests/relay-summary.mjs`'s job-summary table) is the empirical
confirmation** — if a real run disagrees with 16, treat that as a genuine
finding, not something to paper over with a range: a uniform multiple
across every cell points at the test harness (e.g. IPv6 or a second
network path inside the namespace); a mismatch confined to
Chromium-*offering* cells points at `bundlePolicy` not actually being
honored — a real regression against the identical assumption
`deploy/turnserver.conf.example`'s quota sizing already depends on.

> **Confirmed value from CI:** `created == 16` on the first green `relay` job
> run on this branch (all four `@pr` pairings — chromium-chromium,
> chromium-cli, cli-chromium, cli-cli — each showed `lanes=8 created=16
> peakLive=16 quotaRejected=0`, run
> [36351066353](https://github.com/zyno-io/sp2p/actions/runs/36351066353)).
> The firewall's own packet counters from that run corroborate the fix
> above: the genuine relay↔relay rule (`--sport 31000:31127 --dport
> 31000:31127`) carried ~299 MB of real traffic across the run, while the
> catch-all UDP DROP rule still caught 4,583 packets — proof that ICE did
> attempt direct/mixed host↔relay pairs and they were correctly rejected,
> forcing every connection through a genuine relay↔relay path rather than
> silently succeeding some other way.
>
> Also confirmed across the full `@pr` + Firefox + CLI set: a clean
> `relay-full` dispatch
> ([36354141441](https://github.com/zyno-io/sp2p/actions/runs/36354141441))
> passed all 12 tests, with `created == 16` identically on all eight
> relay-carrying pairings — `chromium-chromium`, `chromium-cli`,
> `cli-chromium`, `cli-cli`, `chromium-firefox`, `cli-firefox`,
> `firefox-chromium`, `firefox-cli` — confirming the formula holds for
> Firefox too (Firefox's balanced `bundlePolicy` was already expected to
> hold at one allocation per connection just like a Chromium *answerer*
> does, per the derivation above; this run confirms it empirically for
> both Firefox roles).

### Quota and graceful degradation

Both peers of one sp2p session share a single TURN username (issued once
by the signaling server on `relay-retry` — `internal/server/handler_signal.go`),
so `testturnd -user-quota` caps live allocations *per session*, combined
across both peers, not per peer. The nightly-only quota case
(`-user-quota 8`, mirroring `deploy/turnserver.conf.example`'s production
`user-quota=32` sizing logic) transfers 64 MiB Chromium-to-Chromium and
asserts, structurally rather than against a hardcoded number (the exact
reduced count is recorded in `test-results/relay/quota8-chromium-chromium.*.json`
for a human/CI-log reader, not asserted in the test):

- the transfer still completes with a matching SHA-256 and size;
- both sides independently negotiate the **same** reduced lane count
  (mutual agreement — `1 <= count < 8`);
- exactly 8 allocations were created (capped precisely at the quota) and at
  least one was quota-rejected;
- live allocations still return to 0 within the leak window once the
  transfer completes.

No protocol change is needed for "both sides agree on a reduced lane
count": `web/src/webrtc-parallel.ts`'s `negotiateParallelWebRTC` already
commits the *intersection* of both sides' successfully-authenticated lane
masks (`selected = ours & peerMask`, then a `commit`/`committed`
round-trip) — a lane whose TURN allocation was rejected by quota simply
never authenticates, drops out of `ours`/`peerMask` on its own side, and
the mutual intersection naturally shrinks to whatever both sides actually
managed to connect. This is the same mechanism that already handles an
ordinary lane connectivity failure; quota-induced ICE failure on some lanes
is indistinguishable from that to the protocol.

**Confirmed on real CI:** at quota 8, this degrades all the way to
`lanes == 1` (the primary only), not a partial count like 6 or 7 — and the
mechanism is fully explained by the negotiation's own strict ordering, not
a bug. The *sender* builds and gathers **all** of its own extra lanes
(consuming its share of the quota) before sending any offer at all
(`Promise.all(gathering)` before the write loop); the *receiver* only
starts allocating its own matching lane once it has read that lane's offer
— strictly after the sender. With a quota of 8 shared across the whole
session and 2 already spent on both primaries, only 6 slots remain for up
to 14 possible extra-lane allocation attempts (7 sender + 7 receiver) — and
because the sender always goes first, it can (and on this run, did) consume
every remaining slot for its own lanes before the receiver gets a chance to
allocate any of its own. Since a genuine relay↔relay pair needs a working
relay candidate on **both** sides of the same lane id (see the firewall fix
above), zero of the receiver's extra lanes ever get a matching partner, and
negotiation converges on the primary alone. This is why the assertion above
is deliberately structural (`1 <= count < 8`) rather than a specific
midpoint number: the real outcome is a hard floor, not a graceful linear
taper, given this specific (single sender, strictly-ordered) negotiation
order.

**This hard floor is specific to this CI setup, not a general production
claim.** It depends on `relay-firewall.sh` allowing only genuine
relay↔relay pairs (see the firewall fix above) — that is what makes a
receiver lane with no relay candidate of its own completely unable to
connect, rather than just less likely to. In a real deployment (no such
firewall), a receiver lane that lost the quota race can still reach the
sender's successfully-allocated relay candidate directly, via its own
host or server-reflexive candidate — a genuinely viable ICE pair without
a firewall forcing both ends through TURN. So production degradation
under a shared quota would likely be *partial* (some reduced count above
1), not this hard floor; this suite doesn't attempt to reproduce that
distinction, since doing so would need a topology where relay↔relay
isn't the only viable path, which defeats the rest of this suite's
central guarantee. The test's own assertions (`1 <= lanes < 8`,
`created == 8`, `quotaRejected > 0`) don't depend on which of these two
shapes actually occurs and are correct either way.

### Consent controls

The relay path requires explicit user consent on both peers independently:
browsers via the `confirm()` dialog in `web/src/main.ts`'s
`establishP2PWithRetry` callers (`RELAY_CONFIRM` in `relay.spec.ts`); the
CLI via the `relay_required` JSON event answered through the response-file
mechanism (`internal/cli/machine.go`'s `promptRelay`) — never
`-allow-relay`, since that would remove the very prompt whose appearance
proves the direct path failed first. `relay.spec.ts`'s positive-path tests
therefore register a real dialog handler on every browser page *before*
navigation (Playwright auto-dismisses an unhandled dialog, which would
look exactly like a genuine decline) and answer every CLI's relay prompt
explicitly via `answerRelayPrompt`.

The nightly-only negative controls dismiss/deny consent instead:

- **Both browsers decline** — each independently throws
  `"P2P connection failed and relay was declined"` (own-side decline is
  checked before this side even learns the peer's answer — see
  `establishP2PWithRetry`) and zero TURN allocations are ever created.
- **A CLI receiver denies, and the browser sender independently declines**
  — the CLI's terminal result is exactly
  `{outcome: "failed", error: {code: "relay_denied", message: "Could not establish direct connection. Use -allow-relay to route encrypted data through a TURN relay."}}`
  with exit code 1; the browser shows the same
  `"...relay was declined"` message.

**Known asymmetric-consent-messaging gap, found while writing this suite:**
each side's own `confirm()`/prompt decision is checked *before* that side
learns whether its peer already agreed or declined — `relay-retry` is sent
to the peer before showing the local prompt specifically so both prompts
can appear in parallel, but the side that already sent `relay-retry` and
then declines "wins" the peer's `agree-vs-deny` race as "agreed" from the
*other* peer's perspective. So if peer A declines while peer B is still
about to accept, B never sees "peer denied" — it proceeds to attempt 2,
allocates a TURN relay, and then fails on a plain timeout/disconnect
instead of a clear "peer declined the relay" message. Consent itself is
still correctly enforced (the declining side never allocates), but the
*other* side's error message is misleading. This is a product-behavior
finding, not a test bug; it isn't fixed here.

### Leak check

Every positive-path test polls `testturnd`'s `stats.json` for up to 10s
after the transfer completes (`LEAK_WINDOW_MS` in `relay.spec.ts`) and
requires the session's `live` count (and pion's own independent
`pionLive` cross-check) to reach exactly 0 — proving every lane's
`RTCPeerConnection`, including every one that was ever created during
setup, actually released its TURN allocation, not just the ones selected
for the final transfer.

A completed transfer alone can't prove this: `web/src/webrtc-parallel.ts`'s
`negotiateParallelWebRTC` already closes every unselected/failed lane in
its own `finally` block once setup succeeds, so a completed transfer's
"lanes that were never selected" case is exercised by every ordinary
pairing test already. What it *can't* exercise is a peer that abandons
setup entirely partway through — the nightly-only "receiver abandons lane
setup" test does: an injected `RTCPeerConnection` subclass on the receiver
closes every connection on the page (primary and every extra lane) the
instant the first extra-lane offer is applied, before that lane ever starts
its own ICE gathering. This reaches the primary `negotiateParallelWebRTC`'s
`!success` cleanup path (not the ordinary success path's per-lane
cleanup), which is the one place mutation (c) (see
[Mutation checks](#mutation-checks) below, skipping
`lanes[id]?.close()`) can be observed to matter — every other test in this
suite fully commits every lane it creates, so removing that line wouldn't
change their outcome at all.

### Mutation checks

Confirms the suite's assertions actually depend on what they claim to,
not just on the transfer completing. (a) and (b) were run for real on
this branch and reverted immediately afterward (`git revert`, confirmed
clean via `git diff` against the pre-mutation commit); (c) was not run —
say so rather than claiming an unverified result.

| # | Change | File | Result |
| --- | --- | --- | --- |
| (a) | Delete `bundlePolicy: "max-bundle" as const` from the peer connection config | `web/src/webrtc.ts`'s `establishWebRTC` | `chromium-chromium` and `chromium-cli` (Chromium *offering*) failed with `created: 24` (double the expected 16, matching the derived doubled-transport count); `cli-chromium` and `cli-cli` passed unchanged — confirms the formula's offer/answer asymmetry. Run [36351594540](https://github.com/zyno-io/sp2p/actions/runs/36351594540). |
| (b) | Strip TURN servers from `pc.getConfiguration()` before constructing each extra lane's `RTCPeerConnection` | `web/src/webrtc-parallel.ts`'s `Lane` constructor | `chromium-chromium`, `cli-chromium`, and `chromium-cli` all collapsed to 1 connection (`.step-p2p` shows no lane count) and failed; `cli-cli` (no browser) passed unchanged. Run [36351869449](https://github.com/zyno-io/sp2p/actions/runs/36351869449). |
| (c) | Delete `lanes[id]?.close()` from `negotiateParallelWebRTC`'s `finally` block | `web/src/webrtc-parallel.ts` | **Not run.** Every test that completes normally already closes every lane via the ordinary success path (see the Leak check section above), so only the nightly-only "receiver abandons lane setup" test's `!success` cleanup path can observe this mutation. Left undone rather than claimed without evidence — a real validation run is future work if this section is revisited. |

### Running locally (Linux only)

```bash
sudo apt-get install -y ethtool iptables
make build-cli build-server
go build -o bin/testturnd ./internal/testturn/testturnd
cd web && npm ci && npm run build && npx playwright install --with-deps chromium firefox && cd ..
sudo scripts/ci/netns.sh up
sudo scripts/ci/relay-firewall.sh apply
sudo scripts/ci/relay-firewall.sh verify
cd web
SP2P_RELAY_TEST=1 SP2P_PW_SKIP_WEB_BUILD=1 \
  SP2P_PW_CLI_BIN="$PWD/../bin/sp2p" SP2P_PW_SERVER_BIN="$PWD/../bin/sp2p-server" \
  SP2P_PW_TESTTURND_BIN="$PWD/../bin/testturnd" \
  ../scripts/ci/netns.sh exec -- npx playwright test --project=relay   # add --grep @pr for the PR subset
cd ..
sudo scripts/ci/relay-firewall.sh stats   # optional: packet/byte counters while it's still up
sudo scripts/ci/relay-firewall.sh clear   # optional: only needed to re-apply/iterate without tearing the namespace down
sudo scripts/ci/netns.sh down
node web/tests/relay-summary.mjs --expect full   # markdown table from test-results/relay/*.json
```

`SP2P_PW_SKIP_WEB_BUILD`/`SP2P_PW_CLI_BIN`/`SP2P_PW_SERVER_BIN` behave
exactly as in the netem suite (see above); `SP2P_PW_TESTTURND_BIN` is the
same idea for the TURN test binary — set it to reuse a prebuilt binary
instead of letting the suite's worker fixture `go build` a fresh one (which
would otherwise need network access for module resolution, unavailable
inside the namespace).

### Known rough edges (found while validating this branch)

Four real `relay-full` dispatches on this branch
([36351500512](https://github.com/zyno-io/sp2p/actions/runs/36351500512),
[36352419122](https://github.com/zyno-io/sp2p/actions/runs/36352419122),
[36353067890](https://github.com/zyno-io/sp2p/actions/runs/36353067890),
[36354141441](https://github.com/zyno-io/sp2p/actions/runs/36354141441))
landed 8-12/12, with the two most novel cases — the abandon-setup leak
check (`created == 9`, exactly the derived count) and the quota case
(structurally passed, `lanes == 1`) — passing cleanly and precisely every
single time. The fourth dispatch (after the fixes and the revert below)
was fully clean, 12/12. Four real findings surfaced across the first
three dispatches, all confined to nightly-only tests: two are fixed and
confirmed (including by the clean fourth run); one fix was tried, caused
a worse regression, and was reverted; one remains open, intermittent, and
did not recur in the clean fourth run — consistent with it being a real
but rare timing race rather than a hard, always-reproducing failure.
`ci.yml`'s `@pr` subset was green on every dispatch except one, where it
independently hit the same open `cli-cli` finding below (expected, since
the underlying race isn't specific to the larger `relay-full` job).

- **"Both browsers decline consent" hung until its 60s timeout, both
  runs, identically.** Root-caused: `web/src/main.ts` calls
  `showSaveFilePicker()` synchronously inside the confirm button's click
  handler, *before* the receiver even connects to signaling ("Invoke the
  picker in the click handler itself, before transient activation expires
  during ICE/key exchange"). This test was the only one in the suite that
  navigated a browser receiver page without calling
  `installReceiverSink()` first to shim that API — so the real, unshimmed
  browser call hung forever in headless Chromium (no display exists for a
  native picker to resolve against), which blocked everything downstream
  on both pages (the sender waits for the receiver to join, which never
  happened). Fixed by calling `installReceiverSink(receiverPage,
  "chromium")` before navigating, exactly like every other test's browser
  receiver — even though the transfer is declined before any file
  actually moves, the shim just needs to exist so the confirm click's
  awaited promise resolves immediately instead of hanging on a real,
  unresolvable native API call.
- **The CLI-denial race (fixed and confirmed):** `"CLI receiver denies,
  browser sender declines"` failed once with `cli.results[0].error` =
  `{code: "operation_failed", message: "Peer denied relay connection"}`
  instead of the hardcoded `{code: "relay_denied", message: CLI_DENIED}`
  — a genuine, unavoidable race (not a bug): this CLI's own
  `answerRelayPrompt("deny")` (written to a file the CLI polls every
  100ms) and the browser sender's independent decline (which notifies the
  peer immediately, without waiting to learn the peer's own answer first
  — see the asymmetric-consent-messaging note above) can arrive in either
  order. `internal/cli/machine.go`'s `finish()` reports `relay_denied`
  only if `promptRelay`'s own file-read set `r.relayResponse` first; if
  the peer's `relay-denied` signal is observed first instead
  (`internal/flow/helpers.go`'s `<-deniedCh` case), the error is
  `operation_failed` / `"Peer denied relay connection"` instead. Both are
  a correct "consent was denied, nothing relayed" outcome. The test now
  asserts that shared shape (outcome, exit code, zero allocations, one of
  the two known error shapes) instead of one hardcoded race winner, and
  has passed cleanly on every run since.
- **A `testturnd -allocation-lifetime 8s` fix for the CLI↔CLI allocation
  leak (below) was tried, worked for its target, and was reverted after
  it broke every Firefox pairing.** With the short lifetime wired into
  `startTurn()`, `cli to cli`'s leak-window miss disappeared — but all
  four Firefox pairings (`firefox-chromium`, `chromium-firefox`,
  `cli-firefox`, `firefox-cli`) started failing with Firefox's own
  `"WebRTC: ICE failed, your TURN server appears to be broken"`. The
  `lifetime/2` proportional-refresh behavior confirmed for pion/turn's
  client (used by the CLI) does not extend to Firefox's own, separate
  (non-pion) WebRTC/ICE stack — whatever Firefox's real refresh timing
  actually is, 8s wasn't enough for it. Reverted; `testturnd` keeps the
  `-allocation-lifetime` flag (harmless, unused by default, and now known
  to need real per-engine verification before ever being turned on for
  this suite) but `relay.spec.ts` no longer passes it.
- **Fixed: CLI TURN allocations held for up to 10 minutes after a
  transfer.** `cli to cli` intermittently found one allocation still live
  after the 10 s poll (about one run in six), and it stayed live for the
  full default allocation lifetime. Instrumented CI runs showed the cause:
  the leaked lane's pion/turn client never sent its `Refresh(lifetime=0)`
  deallocation, and the TURN server never received one. pion's
  `PeerConnection.Close` returns immediately to any second caller while
  the first close, which closes the relay candidates and sends the
  deallocations, is still running. That includes pion's own close when the
  peer shuts down first. The CLI exits right after closing its lanes, so
  the last lane's deallocation could be lost. `WebRTCConn.Close`
  (`internal/conn/webrtc.go`) now runs one `GracefulClose`, which waits for
  a close already in progress, and makes every concurrent caller wait for
  it; setup-error paths close through it too. Callers inside pion callbacks
  already close from their own goroutine, as `GracefulClose` requires.
  After the fix, two consecutive CI runs of `cli to cli` repeated 12 times
  each passed 24/24.

### Known gaps

- **WebKit isn't covered.** The netns-based approach needs a real Linux
  network namespace; WebKit only gets meaningful coverage on `macos-15`
  runners (see `nightly.yml`'s `engines` job), which has no netns support.
- **TURN over TCP/TLS isn't covered** — `testturnd` registers only a UDP
  `PacketConnConfig`, matching the one transport sp2p's signaling server
  ever configures (`-turn-servers` only ever carries `turn:...?transport=udp`
  URLs in this codebase today).
- **Single-host topology.** Every peer, the signaling server, and
  `testturnd` all run on the same CI runner, so one relay allocation per
  lane is always sufficient — this suite doesn't (and can't, on a single
  host) exercise a topology where a lane might need two relay hops.
