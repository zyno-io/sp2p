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
  signaling server, a CLI JSON event watcher, the WebRTC lane observer, a
  real-OPFS save-file sink for Chromium-family engines (`receiveToDisk`/
  `verifyDisk`), and a picker-free in-memory hashing sink for every other
  engine (`installReceiverSink`/`verifyReceiverSink` — see
  [Engines](#engines-firefox-and-webkit) below)) — reuse it before
  duplicating a helper into a new spec.
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
- **Large-transfer suite** — `web/tests/large.spec.ts`, run in CI (the
  `large` job) at 1 GiB across all four transfer pairings, on both an
  unshaped and a `wan150`-shaped namespace. Catches stalls, integrity bugs,
  and memory that scales with file size. See
  [Large transfers](#large-transfers) below.
- **Packaging validation** — `.github/workflows/packaging-validate.yml`
  renders every package-manager manifest with the exact script
  `publish-packages.yml` uses (`scripts/packaging/render.sh`) and installs
  each one on its native platform, without ever publishing. See
  [Packaging validation](#packaging-validation) below.
- **Production smoke test** — `web/tests/smoke-prod.mjs`, run automatically
  by `release.yml`'s `smoke` job right after each full release deploys: a
  real CLI→browser and browser→browser transfer through production
  sp2p.io, using the release's own checksum-verified CLI, with relay denied.
  See [Production smoke test](#production-smoke-test) below.

## Extended checks

`.github/workflows/extended.yml` ("Extended checks") runs the slower suites
that don't gate every PR: the `netem-extended` performance matrix (`wan150-cap`
and `wan500`), `engines` (WebKit plus the full, untagged `--project=engines`
matrix, on `macos-15`), `compat-n2` (N-2 previous-release compatibility),
`relay-full` (the complete TURN relay suite, including Firefox pairings, the
quota case, and the consent negative controls), and `large` (1 GiB transfers
across all four pairings, on `clean` and `wan150` profiles). It runs:

- on every push to `main`, so a failure points at the single merge that
  caused it;
- weekly (Mondays 07:00 UTC), to catch browser and runner drift between
  merges;
- on manual dispatch (`gh workflow run extended.yml --ref <branch>`), useful
  for validating a branch before merge, or `--ref <tag>` to produce a run on
  a tagged commit after `main` has moved on.

`report-failure` opens or updates a GitHub issue (label `extended-checks`,
title "Extended checks failed") when any job fails or is cancelled, except on
a manual dispatch, which only reports in the run itself.

**Release gate:** `release.yml`'s `extended-checks` job refuses to publish a
release unless Extended checks passed on the tagged commit. If a run is
already in progress on that commit, it waits (up to ~2 hours) instead of
failing immediately.

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
specs those are and why), and additionally under `msedge` on win32 (see
[Windows](#windows-native-cli-and-edge) below) — `msedge`'s project is
omitted from `web/playwright.config.ts`'s `projects` array entirely on every
other platform, so this only changes behavior on a Windows dev machine. A
bare `npx playwright test` with no arguments at all runs the full suite
across every project, including the 15-cell, 64&nbsp;MiB `engines` project —
expect it to take several minutes.

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

### Release checklist

Every plain `vX.Y.Z` release needs an entry in
`testdata/release-capabilities.json`, added before the tag is pushed. Once
tagged it becomes "the previous release" for CI, and the lookup fails closed
for unlisted versions. Releases also require a green Extended checks run on
the tagged commit: `release.yml`'s `extended-checks` job waits for one already
in progress (up to ~2 hours) or refuses to publish without it — see
[Extended checks](#extended-checks) above. After the tag is pushed,
`release.yml`'s `smoke` job runs automatically against production once the
deploy lands (see [Production smoke test](#production-smoke-test)); package
manifests (Homebrew, Scoop, AUR, Chocolatey, WinGet) are always published
separately by the maintainer running `publish-packages.yml` by hand — never
by an agent — and its rendering is continuously checked, pre- and
post-release, by [Packaging validation](#packaging-validation).

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
it. `extended.yml`'s `compat-n2` job builds a second fixture the same way at
`--nth 2` (N-2), so a peer two releases back also keeps getting exercised,
not just whichever release happens to be "the previous one" at any given
moment.

**Protocol-2 previous releases aren't reachable from CI today.** The
`expectedLaneCounts` branch above that expects no lane negotiation exists so
the spec stays correct *if* `SP2P_TEST_PREVIOUS_VERSION` is ever pointed at a
protocol-2 release (verified locally against a real v0.4.0 fixture — 7/7
pass), but neither `ci.yml` nor `extended.yml` can currently produce that:
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
older, narrower two-project config) has been folded in and removed. A fourth
cross-engine project, `msedge`, exists only on win32 — see
[Windows](#windows-native-cli-and-edge) below.

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

**The cross-engine receive sink.** `web/tests/helpers.ts`'s `receiveToDisk`
fakes `showSaveFilePicker` with a real OPFS file handle; a local spike
(`navigator.storage.getDirectory()` → `getFileHandle` → `createWritable()`
→ `write()`/`close()` → read back) found this reliable on Firefox but
throwing `NotReadableError`-class failures ("operation failed for an
unknown transient reason") on Playwright's bundled WebKit build. Rather than
skip most of `webrtc-policy.spec.ts`/`parallel-interop.spec.ts` on WebKit —
and rather than force Firefox/WebKit down the disk-streaming path a real
user on those engines never takes (neither implements `showSaveFilePicker`
for real: Firefox 155, WebKit 26.6, as tested here) —
`installReceiverSink`/`verifyReceiverSink` install no picker at all for
Firefox/WebKit, letting `"showSaveFilePicker" in window` read its real
(`false`) value. Instead they hook `URL.createObjectURL` — which `main.ts`'s
`downloadBlob` (the real in-memory-sink path those engines actually take)
calls on the Blob it already built in memory — and hash that same buffer
with a one-shot `crypto.subtle.digest("SHA-256", ...)`, rather than reading
anything back a second time or depending on Playwright's download handling.
Chromium-family engines (including `msedge` — see
[Windows](#windows-native-cli-and-edge) below, since `browserName` stays
`"chromium"` for Edge) still take the real-OPFS `receiveToDisk`/`verifyDisk`
path. `engine-matrix.spec.ts` uses the same `installReceiverSink`/
`verifyReceiverSink` pair for every one of its receivers.
`compatibility.spec.ts` and `netem.spec.ts` call `receiveToDisk`/
`verifyDisk` directly (unchanged), since both only ever run on
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
CLI↔Chromium — is extended-checks only (after merge / weekly / pre-release).

**CI wiring.** `ci.yml`'s new `browser-firefox` job (`ubuntu-latest`, not
yet a required check) runs `--project=firefox` plus
`--project=engines --grep @pr`. `extended.yml`'s `engines` job
(`macos-15` — closer to Safari's WebKit than a Linux runner) runs
`--project=webkit` plus the full, untagged `--project=engines` (all 15
cells); it was added to `report-failure`'s `needs` and failure-summary
logic alongside `netem-extended` and `compat-n2`. Browsers in the matrix
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
sensitive, and this one isn't. If the macos-15 `engines` job in Extended
checks shows the same lane shortfall for real, that's the point to investigate further:
it would mean either that runner is multi-homed too, or that this is a
genuine Safari/WebKit-multi-lane interoperability issue independent of
network topology (the transfer itself still completes over however many
lanes did connect — this reduces parallelism, it doesn't break transfers).

**New finding, not yet root-caused: `engine-matrix.spec.ts`'s browser↔browser
cells mostly fail on the macos-15 `engines`-job runner.** Dispatching what
was then `nightly.yml` (now `extended.yml`) on this branch (`gh workflow run
nightly.yml --ref <branch>` at the time) to validate its `engines` job
before merge (it cannot be triggered by a PR) surfaced this:
`--project=webkit` was clean, 15/15, but `--project=engines` had
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
an Extended checks (then nightly) dispatch takes the better
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
required-eventually job), only the WebKit/`engines` rollout under Extended
checks, which was already explicitly staged as "extended-checks only,
promote later" for exactly this kind of reason.

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
`netem` CI job (`.github/workflows/ci.yml`) and the Extended checks
workflow's `netem-extended` job (`.github/workflows/extended.yml`) set —
running it unshaped would silently prove nothing, so it refuses to guess.

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
  `rate 100mbit`; Extended checks), `wan500` (250ms delay, no loss → ~500ms RTT;
  Extended checks). No profile adds jitter — reordering on a delay qdisc causes
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
each test. The Extended checks `netem-extended` job sets
`SP2P_NETEM_GATE_PER_TEST=0` so one slow repeat of `--repeat-each=3` doesn't
fail the run, and gates on the medians instead. Traces, screenshots and the
Playwright report are not collected for
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
  per pairing but not gated. If a `wan500` (no-loss) Extended checks run shows it
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
which only `ci.yml`'s `relay` job and `extended.yml`'s `relay-full` job set —
same rationale as the netem suite's `SP2P_NETEM_PROFILE` gate: running this
unfirewalled would silently prove nothing.

**Status: shadow period**, same as `netem`: `ci.yml`'s `relay` job runs on
every PR and push to `main` (the `@pr`-tagged Chromium-only subset — 4
tests) but is not in `build`'s `needs:` and not a required status check
yet. `extended.yml`'s `relay-full` job runs the complete suite (12 tests,
including Firefox pairings, the quota case, and the consent negative
controls) and is wired into `report-failure` alongside `netem-extended`,
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
across both peers, not per peer. The quota case (extended-checks only —
after merge / weekly / pre-release; `-user-quota 8`, mirroring
`deploy/turnserver.conf.example`'s production
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

The negative controls (extended-checks only) dismiss/deny consent instead:

- **Both browsers decline** — each independently throws
  `"P2P connection failed and relay was declined"` (own-side decline is
  checked before this side even learns the peer's answer — see
  `establishP2PWithRetry`) and zero TURN allocations are ever created.
  Both dialogs are held open (`registerHeldDialog`) until both have
  appeared, then dismissed together, so the test is deterministic instead
  of racing the two independent per-side assertions against each other.
- **A CLI receiver denies, and the browser sender independently declines**
  — the CLI's terminal result is exactly
  `{outcome: "failed", error: {code: "relay_denied", message: "Could not establish direct connection. Use -allow-relay to route encrypted data through a TURN relay."}}`
  with exit code 1; the browser shows the same
  `"...relay was declined"` message. The browser's dialog is held open
  until the CLI's own decline is confirmed sent (`answerRelayPrompt` then
  `cli.relayResponded`), which is *why* this is deterministic: with the
  peer-already-declined fast path below, an unheld dialog could let the
  browser decline first and skip the CLI's prompt entirely, making
  `answerRelayPrompt` hang waiting for a `relay_required` event that never
  comes.

**Two-phase consent, and the split tests that prove it.** Consent is split
into two stages carried as additive payload fields on the existing
`relay-retry`/`relay-denied` messages (`internal/conn/relay.go`'s
`RelayWatch`/`RetryWithRelay`; `web/src/relay-consent.ts`'s
`RelayConsentWatch` is the same state machine in TypeScript): a side sends
`relay-retry{consent:"pending"}` the instant its own direct attempt fails
(so the peer learns immediately and can prompt in parallel), then either
`relay-retry{consent:"granted"}` after its own prompt says yes, or
`relay-denied{reason}` if it says no. Critically, **a side never starts (or
even requests) TURN credentials for attempt 2 until it has learned the
peer's decision is `granted`** — this replaces the old "whoever sent
`relay-retry` first is assumed to have agreed" behavior, which made a fast
accepter allocate a real TURN relay and then fail on a bare timeout instead
of a clear "peer declined" message whenever the peer actually declined.
Old (≤0.6.2) peers are unaffected: their bare `relay-retry {}` /
`relay-denied {}` payloads are always treated as `granted`/`declined`
respectively, matching their original go-immediately behavior.
`relay.spec.ts`'s 8 **consent split** tests (`consent split: <pairing>,
<sender|receiver> declines`) prove this directly, for all 4 pairings x
both declining sides: the accepting side allows immediately, the decliner
holds its own prompt open until the accepter has visibly committed to
waiting for it (a browser's `.step-p2p` text, or a CLI's `relay_response`
event — see `runConsentSplit`), then declines. Each test asserts the
accepting side reports the peer's decline within 10s (well under the old
15s/30s misleading-timeout paths), with **zero TURN allocations** on
either side — proving the accepting side genuinely waited rather than
having already allocated by the time it learned of the decline. Two of the
eight (one with Go, one with web as the accepting side) are tagged `@pr`
and run on every PR; all eight run in extended checks.

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
setup entirely partway through — the extended-checks-only "receiver abandons lane
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
| (c) | Delete `lanes[id]?.close()` from `negotiateParallelWebRTC`'s `finally` block | `web/src/webrtc-parallel.ts` | **Not run.** Every test that completes normally already closes every lane via the ordinary success path (see the Leak check section above), so only the extended-checks-only "receiver abandons lane setup" test's `!success` cleanup path can observe this mutation. Left undone rather than claimed without evidence — a real validation run is future work if this section is revisited. |

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
three dispatches, all confined to extended-checks-only tests: two are fixed and
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
- **The CLI-denial race (since eliminated by the relay-consent redesign,
  not just papered over):** at the time, `"CLI receiver denies, browser
  sender declines"` failed once with `cli.results[0].error` =
  `{code: "operation_failed", message: "Peer denied relay connection"}`
  instead of the hardcoded `{code: "relay_denied", message: CLI_DENIED}`
  — a genuine, unavoidable race under the *old* single-phase consent
  design (not a test bug): this CLI's own `answerRelayPrompt("deny")`
  (written to a file the CLI polls every 100ms) and the browser sender's
  independent decline could arrive in either order, because a side's
  `relay-retry` doubled as both "I'm asking" and "I agree", sent *before*
  its own local prompt — so a fast peer could already look "agreed" to
  the other side by the time either prompt resolved. The test was patched
  at the time to assert a shared shape across both known outcomes instead
  of one hardcoded race winner.

  The relay-consent redesign (`internal/conn/relay.go`'s
  `RelayWatch`/`RetryWithRelay`; `web/src/relay-consent.ts`'s
  `RelayConsentWatch`) removed the race at its root by splitting consent
  into `relay-retry{consent:"pending"}` (asking) and a separate, later
  `relay-retry{consent:"granted"}` or `relay-denied{reason}` (deciding) —
  a side never looks "agreed" until it actually has agreed. Both this test
  and the 8 new **consent split** tests (see "Two-phase consent" above)
  now assert one exact, deterministic outcome instead of a shared shape
  across possible races, and hold the browser's dialog open
  (`registerHeldDialog`) until the CLI's own denial is confirmed sent —
  removing the race from the test's own sequencing too, not just from the
  product.
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
  runners (see `extended.yml`'s `engines` job), which has no netns support.
- **TURN over TCP/TLS isn't covered** — `testturnd` registers only a UDP
  `PacketConnConfig`, matching the one transport sp2p's signaling server
  ever configures (`-turn-servers` only ever carries `turn:...?transport=udp`
  URLs in this codebase today).
- **Single-host topology.** Every peer, the signaling server, and
  `testturnd` all run on the same CI runner, so one relay allocation per
  lane is always sufficient — this suite doesn't (and can't, on a single
  host) exercise a topology where a lane might need two relay hops.

## Large transfers

`web/tests/large.spec.ts` runs a 1 GiB transfer across all four pairings
(browser-browser, browser-CLI, CLI-browser, CLI-CLI with `-transport auto`)
and asserts completion, exact size, SHA-256 integrity, the 8-lane WebRTC
policy where it applies, and — the reason this suite exists — that peak
process memory for the 1 GiB run doesn't scale with file size beyond a
small constant relative to a 64 MiB control run of the same pairing. It's
skipped unless `SP2P_LARGE_TEST=1`, which only the Extended checks `large`
job (`.github/workflows/extended.yml`) sets — same rationale as the
netem/relay suites' env gates. It is deliberately not part of the PR-gated
suite: a 1 GiB transfer takes minutes even unshaped, and this class of bug
(a stall or a memory leak that only shows up at scale) is exactly what
Extended checks (runs after each merge to `main`, weekly, and gates
releases — see [Extended checks](#extended-checks) above) exists for.

Every browser page and CLI process this suite drives is registered for
dump-on-failure diagnostics (`trackForDiagnostics`/`trackCLIForDiagnostics`,
`flushDiagnostics` from `test.afterEach` — the same pattern `relay.spec.ts`
and `interop.spec.ts` use), so a stall or an unexpected failure logs each
page's buffered console output (plus its live step/status/error DOM
snapshot, but only if the page is still open at flush time — every `run*`
helper in this file closes its browser/context in a `finally` block right
after returning, so in practice that snapshot is rarely available here; see
`helpers.ts`'s `flushDiagnostics`) and the CLI's sanitized JSON event
log/stderr, instead of just the bare assertion message. The CLI side of
this actively redacts a resolved transfer code from its own printed output
(`flushCLIDiagnostics` in `helpers.ts`); page console output is not
redacted by the harness — the app itself only ever logs a transfer code's
session-id component (`web/src/main.ts`), never the encryption-seed
component that makes a code sensitive, so this hasn't been a real
disclosure so far, but it's not a guarantee the way the CLI-side redaction
is. Each CLI process's exit is also bounded by a timer (`waitForCLIExit`,
racing `cli.exited` against `CLI_EXIT_TIMEOUT_MS`, or the full
`TRANSFER_TIMEOUT_MS` for the one wait that's itself a pairing's actual
completion gate — see `large.spec.ts`) rather than relying solely on the
`large` project's 30-minute Playwright test timeout to
eventually catch a hung CLI process.

### Source data and hashing

The 1 GiB source file (and a 64 MiB control file, generated alongside it)
are written once per run with `generateRandomFile` in `large.spec.ts`:
`crypto.randomBytes()` in 4 MiB chunks, streamed to disk with backpressure
(`stream.write()`/`"drain"`), hashing each chunk into a running SHA-256 as
it's written — the content is never held in memory all at once on the
generation side. `SP2P_LARGE_TEST_SIZE_BYTES` overrides the 1 GiB default
for local iteration on a smaller file; the control size scales down with it
(`min(64 MiB, max(4 MiB, large/4))`) so it stays smaller than the large run
and (at the 1 GiB default) still meets the 64 MiB parallel-WebRTC/parallel-TCP
threshold (`PARALLEL_MIN_BYTES` in `web/src/webrtc-parallel.ts`;
`tcpPreferThreshold`/`parallelMinFileSize` in `internal/flow`) — see
[Realistic-WAN (netem) suite](#realistic-wan-netem-suite) above for the same
threshold's role there.

Verifying the received copy never loads the whole file into memory either:

- **CLI receivers** are hashed from Node with a streaming `createReadStream`
  piped through `crypto.createHash("sha256")` (`hashFileStreaming`).
- **Browser (Chromium) receivers** use the real OPFS sink
  (`receiveToDisk`/`helpers.ts`, the same one `netem.spec.ts` and
  `compatibility.spec.ts` use — this is a real user's actual receive path,
  not a test-only shortcut), but are verified with a new streaming
  counterpart, `verifyDiskStreaming` (`helpers.ts`), instead of the existing
  `verifyDisk`: it hashes the received `File` in 8 MiB chunks via
  `File.slice(...).arrayBuffer()`, feeding each chunk into the incremental
  SHA-256 implementation in `web/src/sha256.ts` — exposed on the page as
  `window.__cryptoTest.SHA256` by `dist/crypto-test.js`, the same bundle
  `crypto-vectors.spec.ts` uses (built by `global-setup.ts`, or, when
  `SP2P_PW_SKIP_WEB_BUILD=1` inside the netns like the `wan150` `large` job
  leg, by an explicit `npx esbuild src/crypto-test-entry.ts ...` CI step —
  see below). `verifyDisk`'s one-shot `file.arrayBuffer()` would work
  functionally, but defeats the point of this suite by loading the entire
  received file into page memory just to check it.
- **Browser senders** already stream from disk in `SEND_CHUNK_SIZE` (64 KiB)
  slices (`web/src/transfer.ts`'s `sendFile`, via `File.slice(...)`), so
  `chooseFileAtPath` (`helpers.ts` — a `chooseFile` split that takes an
  already-on-disk path instead of a `Buffer`, so a caller with a 1 GiB file
  already generated on disk never needs to hold it in memory to select it)
  is all that's needed on that side.

The two source files (and the shared temp directory holding them) are
allocated with a plain `mkdtempSync`, not `helpers.ts`'s `temporaryDirectory`
— that helper tracks every directory it returns in one shared, module-level
list that `cleanupTemporaryDirectories()` (run from every spec's
`test.afterEach`, including this one, to clean up each pairing's
destination files) empties completely on every test. Using it for the
shared source files too deleted them right after the first test in early
development of this suite, breaking every pairing after the first — caught
by running the full file locally rather than one test in isolation.
`test.afterAll` removes the `mkdtempSync` directory explicitly once, after
every test has run.

### Memory sampling and the scaling assertion

Each pairing test runs the 64 MiB control transfer, then the 1 GiB large
transfer, and compares peak memory between them:

```
peak(large) <= 1.5 * peak(control) + 32 MiB          (relative — the real regression check)
peak(large) <= peak(control) + 256 MiB               (additive — browser tree only, see below)
peak(large) <= 512 MiB (CLI) / 2 GiB (browser tree)  (absolute backstop)
```

The relative check is what actually catches "memory that scales with file
size": the product's real per-chunk buffering (256 KiB chunks,
8-deep pipeline — see `internal/transfer/sender.go`/`receiver.go` — and
64 KiB browser chunks) means peak memory should stay roughly flat between a
64 MiB and a 1 GiB transfer of the same pairing; the constant (32 MiB) and
multiplier (1.5x) allow for real per-run variance (GC timing, OS page
cache, a second Chromium renderer/GPU/utility process spinning up) without
being loose enough to miss an actual per-byte leak. The absolute backstop
is a second, independent floor that would catch a bug on the very first run
(no control needed) if the relative comparison were ever somehow gamed.
**Calibrate/confirm both numbers against real Extended checks runs and
record the observed figures here** (see [Observed figures](#observed-figures)
below) rather than trusting them from source alone, the same way the netem
suite's throughput floors and the relay suite's allocation formula were
both confirmed against a real CI run before being trusted (see
[Realistic-WAN (netem) suite](#realistic-wan-netem-suite) and
[TURN relay (relay-only) suite](#turn-relay-relay-only-suite) above).

The additive check (`assertMemoryScaling`'s optional `additiveCeilingBytes`
argument, `web/tests/large.spec.ts`) applies only to the browser-tree
assertions, not the CLI ones. It exists because the 1.5x relative ceiling
scales with the control run's own peak: Chromium's fixed per-process
overhead (tens to hundreds of MiB per process, before any payload bytes)
gets multiplied by 1.5x right along with the real per-byte signal the check
is meant to catch, so a pairing whose control run happens to have a higher
baseline (browser-to-browser's two full Chromium instances, for example)
gets a looser large-run ceiling for a reason that has nothing to do with
file size. The additive bound catches that: regardless of how large the
control peak is, the large run's peak may not exceed it by more than a
fixed number of bytes. `BROWSER_TREE_ADDITIVE_CEILING_BYTES` in
`large.spec.ts` is calibrated from real Extended checks runs — see
[Observed figures](#observed-figures) below for whether/how it's been
recalibrated for the current per-process-VmHWM sampling method (its initial
value was calibrated from the older, now-replaced VmRSS-snapshot method's
numbers, with headroom added on top for the newer method's tendency to read
at or above what the old one reported for the same run — see the
per-process-VmHWM sampling comment above).

- **CLI process peak.** On Linux (every CI runner; this suite always runs on
  `ubuntu-latest`), `readCLIPeakRSSBytes` polls `/proc/<pid>/status`'s
  `VmHWM` — the kernel's own lifetime high-water mark for the process, so a
  single read at any point during its life already reflects the true peak
  up to that point; polling (every 50ms) just needs to catch one reading
  shortly before the process exits, since `/proc/<pid>` is gone by the time
  Node's `"exit"` event fires (the child has already been reaped). The
  50ms interval matters more than it looks: a control-run CLI receiver can
  exit in well under 500ms (92ms observed locally on a tiny control file),
  and under-sampling the fast control run — not the slow large run — is
  what would silently make the relative ceiling too tight, not too loose.
  Non-Linux (local macOS iteration only) falls back to `ps -o rss=`, an
  instantaneous sample rather than a true high-water mark, so local numbers
  can under-count between polls — expect CI's numbers to be the accurate
  ones.
- **Browser process tree peak.** Chromium exposes no single tree-wide
  high-water-mark API, but each individual process in the tree *does* still
  expose its own `VmHWM` — the same lifetime high-water mark
  `readCLIPeakRSSBytes` above reads for the CLI process, reused here.
  `startBrowserRSSSampling` polls every ~500ms (fast enough to promptly
  discover new pids as Chromium spawns renderer/GPU/utility processes
  through the run, not because the interval itself needs to catch a spike
  anymore): each tick re-lists every pid across every given browser's
  process tree (`browserProcessPids`, the same `SystemInfo.getProcessInfo`
  CDP call `netem.spec.ts` uses for its UDP socket check; more than one
  `Browser` for browser-to-browser, whose sender and receiver are two
  separate browser processes — see below), reads each pid's current
  `VmHWM`, and keeps the maximum seen so far *per pid* in a map. On
  `stop()`, it sums that map's values. Because each pairing test launches
  fresh browser(s) per control/large run (rather than reusing the project's
  shared `browser`/`page` fixtures), every *currently-live* pid's `VmHWM` at
  `stop()` is that one process's true peak for its entire lifetime so far.
  The sum across pids is still only an **upper bound** on the tree's actual
  simultaneous peak, not a literal instant-in-time measurement — it adds
  together maxima different processes reached at different points in time,
  which need not have coincided — but for a ceiling check that's the safe
  direction to be imprecise in: it can only overstate the tree's memory use,
  never understate it. That's exactly the failure mode it replaces: the
  earlier version summed each pid's *current* `VmRSS` (a live snapshot, not
  a high-water mark) every ~2s, so a short-lived process — and the clean
  64 MiB control run's *entire* transfer lasts only ~1-3s — could spawn,
  peak, and exit within one 2s window and contribute nothing to any sample,
  understating the control run's real peak and artificially tightening the
  relative ceiling for that pairing's large run. The 500ms tick still
  matters for two things VmHWM alone doesn't cover: discovering a new pid
  (a renderer/GPU/utility process spawning mid-run) promptly enough to track
  it at all, and catching growth that happens after this loop's last read of
  a pid but before that process exits (a pid that's already gone by the next
  tick can't be read again). Each pairing test launching its own fresh
  browser(s) also means one run's sample is never polluted by another
  test's residual pages/processes. Sampling stops right after `.complete`
  is asserted, before the streaming-hash verification above runs in the
  same page — so the in-page SHA-256 pass isn't itself counted as part of
  the transfer's memory footprint.
- **A browser receiver page always runs inside `launchPersistentContext`,
  never a plain `launch()` + `newPage()`.** Chromium's default context (no
  explicit user-data directory) behaves like an incognito profile, and
  backs origin storage — including OPFS, the real receive path
  `receiveToDisk`/`verifyDiskStreaming` exercise — in memory rather than on
  disk. That's invisible functionally (the write/read-back still round-trips
  correctly) but fatal to this suite's actual purpose: writing a 1 GiB file
  to an in-memory OPFS store inflates the browser process's RSS by roughly
  the file's own size, which would fail the memory-scaling assertion on
  every correct build — a false positive manufactured by the test harness,
  not a real product regression, and not representative of a real user's
  browser (a real, non-incognito Chrome profile backs OPFS with real disk
  I/O, same as `launchPersistentContext`). Confirmed locally: writing
  512 MiB to OPFS raised RSS by roughly 530 MiB under a plain
  `launch()`+`newPage()`, versus roughly 43 MiB under
  `launchPersistentContext` (backed by a real, `temporaryDirectory`-managed
  profile directory) for the identical write. Only pages that *receive* use
  this — `runBrowserToCLI`'s browser only sends (reads from disk via
  `File.slice()`, never touches OPFS), so it stays on a plain `launch()`.
  `browser-to-browser` therefore launches two separate browser processes
  (a plain-launched sender, a persistent-context receiver) rather than two
  pages sharing one browser, which is why its process-tree sampling sums
  more than one `Browser`'s pids (see above) and why its reported browser-tree
  peak runs meaningfully higher than the single-browser pairings' — two
  Chromium instances' baseline overhead, not a bug.
- **A zero peak fails loudly instead of passing vacuously.**
  `assertMemoryScaling` asserts both the control and large peaks are
  `> 0` before comparing them — a sampler that never got a single
  successful reading would otherwise report `0`, which passes both the
  relative and absolute checks trivially (`0 <= anything`).

### Observed figures

Duration, throughput, and CLI peak-RSS numbers below are from
[run 36514431412](https://github.com/zyno-io/sp2p/actions/runs/36514431412)
(a `workflow_dispatch` of this branch) — those are unaffected by the
browser-tree sampling-method change above (CLI sampling didn't change; wall
time and bytes/sec don't depend on how memory is measured), so they stand
as-is. The "browser tree peak" columns from that run used the old,
now-replaced VmRSS-snapshot-every-2s method — see the per-process-VmHWM
sampling comment above for why those numbers aren't directly reusable as a
calibration target for the current method, and whichever of the
placeholder note below or a later revision of this section has the current
method's own real numbers and the resulting
`BROWSER_TREE_ADDITIVE_CEILING_BYTES` value.

**`clean` profile (no network namespace):**

| pairing | size | duration | throughput | CLI peak (bytes) | browser tree peak, old method (bytes) |
|---|---|---:|---:|---:|---:|
| browser-browser | control | 12.0s | 5.6 MB/s | — | 938,909,696 (895.5 MiB) |
| browser-browser | large | 51.7s | 20.7 MB/s | — | 1,107,849,216 (1056.6 MiB) |
| browser-cli | control | 8.9s | 7.5 MB/s | receiver 36,139,008 (34.5 MiB) | 416,206,848 (396.9 MiB) |
| browser-cli | large | 47.3s | 22.7 MB/s | receiver 35,454,976 (33.8 MiB) | 515,694,592 (491.7 MiB) |
| cli-browser | control | 8.6s | 7.8 MB/s | sender 51,142,656 (48.8 MiB) | 527,785,984 (503.4 MiB) |
| cli-browser | large | 30.1s | 35.6 MB/s | sender 53,334,016 (50.9 MiB) | 547,254,272 (521.9 MiB) |
| cli-cli-auto | control | 0.14s | 472.6 MB/s | sender 30,871,552 / receiver 33,165,312 | — |
| cli-cli-auto | large | 1.4s | 783.8 MB/s | sender 33,280,000 / receiver 33,652,736 | — |

**`wan150` profile (75ms delay + 0.1% loss, inside the netns):**

| pairing | size | duration | throughput | CLI peak (bytes) | browser tree peak, old method (bytes) |
|---|---|---:|---:|---:|---:|
| browser-browser | control | 31.8s | 2.1 MB/s | — | 1,000,255,488 (953.9 MiB) |
| browser-browser | large | 7m34s | 2.4 MB/s | — | 1,048,547,328 (1000.0 MiB) |
| browser-cli | control | 30.8s | 2.2 MB/s | receiver 41,877,504 (39.9 MiB) | 452,915,200 (431.9 MiB) |
| browser-cli | large | 7m32s | 2.4 MB/s | receiver 43,819,008 (41.8 MiB) | 513,220,608 (489.4 MiB) |
| cli-browser | control | 38.8s | 1.7 MB/s | sender 46,510,080 (44.4 MiB) | 541,536,256 (516.5 MiB) |
| cli-browser | large | 8m02s | 2.2 MB/s | sender 52,436,992 (50.0 MiB) | 552,292,352 (526.7 MiB) |
| cli-cli-auto | control | 16.3s | 4.1 MB/s | sender 36,630,528 / receiver 29,306,880 | — |
| cli-cli-auto | large | 5m13s | 3.4 MB/s | sender 34,971,648 / receiver 27,865,088 | — |

(The three browser-involving pairings — browser-browser, browser-cli,
cli-browser — show `8`/`8` WebRTC lanes in both profiles, per the
`size >= PARALLEL_THRESHOLD` assertions in `large.spec.ts`. `cli-cli-auto`
picked `transport: tcp` on both legs, as expected racing on a single host
(`runCLIToCLI`'s comment in `large.spec.ts`); its `lanes` field is
`counts[0] ?? 1` from `watchCLI` — a `parallel_streams` JSON event only
where the CLI actually negotiated one, else the `1` fallback. `clean` shows
`1`/`1` (no parallel TCP negotiated at effectively zero local RTT);
`wan150` shows `6`/`6` (parallel TCP negotiated under the profile's shaped
RTT). Neither is asserted in the test — see [Known
limitations](#known-limitations) below.)

With the old method, the largest observed browser-tree control→large delta
across every pairing/profile pair above was browser-browser/`clean`:
`1,107,849,216 - 938,909,696 = 168,939,520` bytes (~161 MiB, ~169 MB) — the
real-run number `BROWSER_TREE_ADDITIVE_CEILING_BYTES` (256 MiB) was
initially sized against, before recalibrating it against the new
per-process-VmHWM method below.

<!-- Filled in after a real validation run of the per-process-VmHWM
browser-tree sampling change: new browser-tree peak bytes per
pairing/profile, the resulting control→large deltas, and the
BROWSER_TREE_ADDITIVE_CEILING_BYTES value/headroom chosen from them. -->

### CI wiring

`extended.yml`'s `large` job runs on `ubuntu-latest` with a
`profile: [clean, wan150]` matrix (`fail-fast: false`, `SP2P_LARGE_TEST: "1"`):

- **`clean`** runs `npx playwright test --project=large` directly on the
  runner — no network namespace.
- **`wan150`** reuses `netem-extended`'s namespace/shaping setup steps
  verbatim (load `sch_netem`, widen `net.core.rmem_max`/`wmem_max`,
  `netns.sh up`, `netem.sh apply wan150`, `netem.sh verify wan150`) and then
  runs the same Playwright command through `netns.sh exec --`, matching how
  the `netem`/`netem-extended` jobs run `netem.spec.ts`. This is the plain
  `wan150` profile (75ms delay + 0.1% loss, uncapped rate), the same one
  the PR/push `netem` job uses — not `netem-extended`'s rate-capped
  `wan150-cap`. Two things this leg needs that weren't automatic: `netns.sh
  exec`'s allowlist of environment variables it forwards into the namespace
  (see [Network setup](#network-setup) above — `sudo` resets almost
  everything else) didn't include `SP2P_LARGE_TEST`/`SP2P_LARGE_TEST_SIZE_BYTES`
  until this suite added them, and without it every test silently skips
  inside the namespace (Playwright still exits 0) — caught by
  `large-summary.mjs --gate` failing with all eight records MISSING on the
  first real dispatch. And the `large` Playwright project's `launchOptions`
  sets `--disable-features=WebRtcHideLocalIpsWithMdns` unconditionally (see
  the `netem`/`relay`/`engine-matrix` projects for the same flag), since
  `wan150`'s namespace has no mDNS resolution for the `.local` host
  candidate names Chromium would otherwise gather on `dummy0` — harmless on
  the `clean` leg, which isn't namespaced.
  **Its durations are not directly comparable to `netem.spec.ts`'s own
  `wan150` numbers, because its signaling traffic is shaped too, unlike
  `netem.spec.ts`'s.** `netem.sh apply` only bypasses netem shaping for TCP
  traffic on the *fixed* port `18090` (`SIGNAL_PORT` in
  `scripts/ci/netem.sh` — see [Network setup](#network-setup) above);
  `netem.spec.ts` runs against that exact port, via the shared server
  `global-setup.ts` always starts there.
  This suite's tests use `isolatedServerTest` (`helpers.ts`) instead — its
  own real signaling server, bound to a random OS-assigned port
  (`listener.listen(0, ...)`), deliberately isolated from the shared server
  so this suite doesn't compete with unrelated tests for the production rate
  limiter. That port is never `18090` and is never added to netem's bypass,
  so on the `wan150` leg this suite's signaling handshake and every page
  load over it are shaped along with the transfer itself — `netem.spec.ts`'s
  signaling is not. A reported `wan150` duration here is therefore slower,
  by more than shaping the transfer bytes alone would account for, than the
  same profile in `netem.spec.ts`; don't compare the two directly, and don't
  read a duration delta between them as a throughput regression. (Making
  this suite's isolated server share the bypassed port instead isn't simple:
  `global-setup.ts`'s shared server already binds `18090` unconditionally,
  even for the `large` Playwright project, so this suite's server can't
  reuse that same port without either colliding with it or giving up the
  isolation `isolatedServerTest` exists for — see `helpers.ts`'s comment on
  it. Documenting the limitation was the simpler, lower-risk fix.)

Both matrix legs build web assets, the CLI/server binaries, and — unlike
the `netem`/`relay` jobs, which don't need it — `dist/crypto-test.js`
(`npx esbuild src/crypto-test-entry.ts --bundle --outfile=dist/crypto-test.js
--target=es2020`, the same command `global-setup.ts` runs when it isn't
skipped) as an explicit step *before* the `wan150` leg enters the
namespace, since `SP2P_PW_SKIP_WEB_BUILD=1` (needed there for the same
no-network-inside-the-namespace reason as `netem`/`relay` — see
[Realistic-WAN (netem) suite](#realistic-wan-netem-suite) above) would
otherwise skip building it, and `verifyDiskStreaming` above needs it on
both legs. A `df -h` step logs disk headroom for the job log; the suite's
own `large.spec.ts` module-level `df -k` check skips the whole suite
outright (rather than failing opaquely with `ENOSPC` partway through) if
the runner has less than 10 GB free — a browser receiver's real on-disk
profile (`launchPersistentContext` above) means the concurrent footprint
within one pairing test is now roughly source file + destination copy +
that same copy again inside the browser profile, all at the same size, not
just source + destination. `test.afterEach(cleanupTemporaryDirectories)`
removes each pairing's on-disk source/destination copies and browser
profile directories between tests, so the 1 GiB source and control files
(generated once, in `test.beforeAll` into a directory outside that
tracking — see above) are the only files that persist across the whole
run, cleaned up in `test.afterAll`.

Numeric-only perf JSON — one record per pairing per size, `bytes`,
`durationMs`, `mbps`, peak memory in bytes, lane counts, transport — is
written to `test-results/perf-large/` (`large.spec.ts`'s `writeRecord`,
the same pattern as `netem.spec.ts`'s `writePerfRecord` and
`relay.spec.ts`'s equivalent) *before* that pairing's memory-scaling
`expect()` calls, so a failing assertion still leaves both runs' numbers in
the uploaded artifact instead of only in the failure message. Rendered as a
markdown table on `$GITHUB_STEP_SUMMARY` by `web/tests/large-summary.mjs
--gate` (fails if any of the four pairings is missing a control or large
record — the actual memory-scaling pass/fail comes from `expect()` inside
`large.spec.ts` itself, not from this summary script). `global-setup.ts`
clears `test-results/perf-large/` up front when `SP2P_LARGE_TEST` is set,
the same way it already does for the netem/relay suites' perf
directories, so a stale local record can't hide a real MISSING pairing (CI
always starts from a fresh checkout, so this only matters locally). Only
that `test-results/perf-large/**` directory is uploaded as an artifact
(`large-perf-<profile>`); like `netem`/`relay`, this suite's Playwright
project (`web/playwright.config.ts`) disables traces, screenshots, and
video, since they'd capture transfer codes in a public artifact.

The four pairing tests use a plain `test.describe`, not `.describe.serial`:
`playwright.config.ts`'s global `workers: 1`/`fullyParallel: false` already
run every test in the file in order, so `.serial`'s only actual effect
would be skipping the rest of the file after one failure — which would
hide the CLI-involving pairings (the ones that actually catch the
`os.ReadFile`-style mutation this suite exists to catch; see
[Mutation check](#mutation-check) below) behind an unrelated
browser-pairing failure.

### Mutation check

Confirms the memory-scaling assertion actually depends on the product
streaming the file, not just on the transfer completing:
`internal/flow/helpers.go`'s `PrepareInput`, for a single regular file,
normally opens the file and returns it directly as the `io.Reader`
(`os.Open`, streamed through `internal/transfer/sender.go`'s bounded
256 KiB/8-deep-pipeline chunking). The mutation reads the whole file into
memory first instead (`os.ReadFile` + `bytes.NewReader`), touching only the
CLI *sender* path for a regular file — folders, stdin, and the receive path
are untouched. Expected: the CLI-sender memory assertion fails on the
1 GiB run for both CLI-involving pairings (`cli-browser`, `cli-cli-auto`);
`browser-cli` (CLI is the *receiver* there) is unaffected, which is itself
part of confirming the mutation is caught for the right reason.

Confirmed against a real throwaway-commit run on Extended checks:
[run 36584881023](https://github.com/zyno-io/sp2p/actions/runs/36584881023)
(mutation commit 597fb60, "THROWAWAY MUTATION: CLI sender reads the whole
file into memory"; reverted in 38e5304) failed the `large (clean)` job's
`large.spec.ts` exactly as expected, on both CLI-sender-involving
pairings, and only those:

- `cli-browser: CLI sender`: peak RSS `2,222,731,264` bytes (~2.07 GiB)
  vs. relative ceiling `304,873,472` bytes (~290.7 MiB; 1.5x control
  `180,879,360` bytes + 32 MiB).
- `cli-cli-auto: sender`: peak RSS `2,169,237,504` bytes (~2.02 GiB) vs.
  relative ceiling `242,505,728` bytes (~231.3 MiB; 1.5x control
  `139,300,864` bytes + 32 MiB).

Both failures show the mutated run's peak rising well past its own control
peak: `2,041,851,904` bytes (~1.90 GiB) for `cli-browser`, `2,029,936,640`
bytes (~1.89 GiB) for `cli-cli-auto` — roughly *1.9x* the mutated 1 GiB
payload's own size, not the ~1x a naive "the sender now holds one extra
copy of the file" read of the mutation would predict. This suite doesn't
have enough visibility into the sender's actual allocation behavior under
the mutation to say why the multiple lands near 2x rather than 1x (whether
that's the normal per-chunk pipeline's own buffering stacking on top of the
mutation's single big buffer, GC not yet having reclaimed the `os.ReadFile`
buffer, or something else) — what the mutation run does confirm is the
thing it's for: the assertion fails on exactly the CLI-sender-involving
pairings and no others, which is the actual test of whether the
memory-scaling check depends on the product streaming the file. The
`browser-cli` pairing (CLI is the *receiver* there,
untouched by the mutation) was unaffected, confirming the assertion fails
for the mutated code path specifically and not from some unrelated
side-effect of the throwaway commit. The rest of that run's jobs
(`netem-extended`, `engines`, `relay-full`, `large (wan150)`) were cancelled
once `large (clean)`'s failure had confirmed the mutation was caught — they
don't exercise the CLI sender's memory path this mutation targets, so
letting them run to completion wasn't needed to confirm the result.

### Known limitations

- **No throughput floor is gated** for this suite (unlike `netem.spec.ts`'s
  `perf-floors.json`) — `mbps` is recorded for visibility only. A floor
  calibrated for a 1 GiB transfer would need its own real-run baseline
  separate from the 128 MiB netem floors, and throughput regressions at
  this scale are already covered by the netem suite's existing floors; this
  suite's job is stalls/integrity/memory, not throughput.
- **The CLI absolute backstop is platform-accurate on Linux only** (CI); a
  local macOS run's `ps`-sampled numbers are a lower bound, not a true peak
  (see above).
- **`SP2P_LARGE_TEST_SIZE_BYTES` is for local iteration only** — CI always
  runs the 1 GiB default; a smaller override may fall under the 64 MiB
  parallel-WebRTC/parallel-TCP threshold, in which case the lane-count
  assertions are skipped rather than adjusted (`large.spec.ts` checks
  `size >= PARALLEL_THRESHOLD` before asserting `[8]`).
- **`cli-cli-auto`'s lane count isn't asserted**, unlike the three
  browser-involving pairings' `[8]` checks — see
  [Observed figures](#observed-figures) above for why its `1`/`1` (clean)
  vs. `6`/`6` (wan150) numbers differ and aren't a regression signal by
  themselves.
- **Dump-on-failure page diagnostics are console-only in practice.** Every
  `run*` helper in `large.spec.ts` closes its browser/context before
  returning, so by the time `test.afterEach`'s `flushDiagnostics` runs, the
  page is already closed and only its buffered console output prints — the
  live DOM step/status/error snapshot `helpers.ts` can also capture is
  reachable only if the page is still open at flush time, which doesn't
  happen here. Page console output also isn't redacted the way CLI
  diagnostics are (see [Large transfers](#large-transfers) above) — that's
  safe today only because the app itself never logs a transfer code's
  seed component, just its session-id component, but that's a product-code
  invariant this suite doesn't itself enforce.

## Windows (native CLI and Edge)

`ci.yml`'s `windows` job runs the Go test suite natively on `windows-latest`
and drives CLI↔Edge browser interop there, so a real Windows bug (path
handling, process/file semantics, terminal I/O) surfaces in CI instead of
only ever being found by a user. **No throughput/performance floor is
gated on Windows.** Per-packet CPU cost inside a VM is environmental, not a
product signal — see [browser-high-rtt.md](browser-high-rtt.md) — and this
job's netem/relay-style siblings already own throughput calibration on
Linux; Windows only ever needed correctness coverage.

**Status: shadow period**, same as netem/relay/`browser-firefox` above:
`ci.yml`'s `windows` job runs on every PR and push to `main` but is not in
`build`'s `needs:` and not a required status check yet.

### What runs

- `go vet ./...` and `go test ./... -count=1` (no `-race`: the race
  detector needs cgo, and this repo builds `CGO_ENABLED=0`). This is the
  only CI job that compiles and vets `*_windows.go` files at all — every
  other job runs on Linux or macOS.
- `npx playwright test --project=msedge`: the same three cross-engine
  specs Firefox/WebKit run (`interop.spec.ts`, `parallel-interop.spec.ts`,
  `webrtc-policy.spec.ts`) against Microsoft Edge, channel `msedge`. Edge is
  Chromium under the hood, so `browserName` stays `"chromium"` for it —
  every existing Chromium-vs-Firefox branch (`assertOfferingPolicy` in
  `webrtc-policy.spec.ts`, `installReceiverSink`'s OPFS path — see
  [Engines](#engines-firefox-and-webkit) above) already applies to Edge with
  no new branches. The `msedge` project (`web/playwright.config.ts`) exists
  only when `process.platform === "win32"`, so it's invisible to every other
  platform and to a bare `npx playwright test` on a non-Windows dev machine.

### `.exe` handling

Windows needs an explicit `.exe` suffix on a binary path before `exec`/
`spawn` can find it: `go build -o sp2p` on Windows still writes a file named
literally `sp2p` (Go's own `-o` handling only appends `.exe` when `-o` is
omitted or a directory), and neither Go's `os/exec` nor Node's `child_process`
tries appending `PATHEXT` extensions to a path that already has an extension
— an extension-less one gets `ErrNotFound`/`ENOENT`.

- `internal/e2e_test.go`'s `buildBinary` — the single `go build -o` helper
  every Go test that execs a built `sp2p` binary shares (`e2e_test.go`,
  `stream_cli_test.go`, `compatibility_test.go`, `downgrade_test.go`,
  `receive_selection_test.go`, `legacy_archive_test.go`) — appends `.exe`
  when `runtime.GOOS == "windows"`.
- `web/tests/global-setup.ts` does the same for both the CLI and server
  binaries it builds (via `execFileSync`, not a shell, so Windows `cmd.exe`
  quoting never comes up), and always writes the resulting (already
  correctly suffixed) paths into `state.json`/`.pw-state.json` as
  `cliBin`/`serverBin`. `fixtures.ts`'s `cliBin` fixture and
  `helpers.ts`'s isolated-server fixture now read those stored paths
  directly rather than reconstructing one — `helpers.ts` used to fall back
  to a hand-built `join(state.tmpDir, "sp2p-server")` path when
  `state.serverBin` was unset, which would have silently targeted the
  wrong (unsuffixed) binary name on Windows; that fallback is gone there,
  and `serverBin` is now a required field on `fixtures.ts`'s `ServerState`
  type. `web/tests/relay.spec.ts` still has the equivalent fallback
  (`state.serverBin ?? join(state.tmpDir, "sp2p-server")`) — left as-is,
  since that spec only ever runs inside `ci.yml`'s Linux network-namespace
  `relay` job, never on Windows.

### CRLF

`ci.yml`'s `windows` job runs `git config --global core.autocrlf false`
**before** `actions/checkout`. The repository's Go source and shell script
files are all committed as LF; `TestBootstrapTemplatesMatchGenerator`
(`internal/bootstrap_checksum_test.go`) compares a generated copy of
`scripts/bootstrap-*.sh` byte-for-byte against the checked-out one, so a
CRLF-converting checkout would fail it for a reason that has nothing to do
with the behavior the test actually exists to check.

### What's skipped on Windows, and why

| Test(s) | Reason |
| --- | --- |
| `internal/rsync`: `TestOpenRsyncUsesFixedRSHHelper`, every `testBridgeHelper`-based rsync-bridge case, `TestDaemonConfigIsFixedAndPrivate`, `TestDaemonConfigRejectsControlPath`, `TestValidateDirectoryCanonicalizesRootAndPermitsFileLinks` | rsync integration is explicitly Windows-unsupported (`rsync.InspectBinary` refuses up front, `"use WSL on Windows"`); the config/directory-validation cases exercise `validateConfigPath`, which rejects any path containing `\` — every Windows absolute path — and `TestDaemonConfigRejectsControlPath` needs to create a directory whose name contains `\n`, which NTFS itself rejects before the intended assertion is ever reached. |
| `internal` (`stream_cli_test.go`) `TestStreamCLI/tunnel-tcp-to-unix`, `/tunnel-unix-to-tcp`, `/tunnel-unix-to-unix` | `unix://` endpoints are rejected outright by `tunnel.ParseEndpoint` on native Windows — see below. |
| `internal/cli`'s response/status-file permission assertions, `internal/testturn`'s stats-file permission assertion | Only the specific `info.Mode().Perm() != 0o600` assertion is skipped (not the surrounding test): Windows has no POSIX permission bits, so `os.Stat` reports a fixed 0666/0444 there regardless of what the code requested: real protection on Windows comes from the file's inherited ACL, not a mode bit. |
| `internal/stream_cli_unix_test.go`, `internal/tunnel/listen_unix_test.go`, `internal/cli/stdio_unix_test.go`, `internal/rsync`'s `_unix.go`/`_unix_test.go` files | Pre-existing POSIX-only build-tag files (signals, Unix domain sockets, POSIX file modes) — Windows never compiles or runs them; nothing new needed for this phase. |
| `netem`, `relay`, `browser-firefox`'s `engines`/webkit-only cells, `macos-rsync` | Linux-network-namespace or macOS-only by design (see their own sections above); orthogonal to this job. |

**Two real product gaps this phase found and fixed, not just guarded:**

- **`internal/archive/tar.go`'s `validateTarPath` accepted an absolute path
  on Windows.** `filepath.IsAbs` requires a Windows volume name to consider
  a path absolute, so a POSIX-style rooted entry name like `/etc/passwd`
  inside a received tar archive reported `false` there and slipped past the
  check un-rejected (the destination-prefix check afterward still prevented
  an actual escape, so this was not an exploitable traversal — but a
  Windows receiver silently accepted archive entries every other platform's
  receiver correctly rejects). Fixed to also reject any path carrying a
  Windows volume name (`filepath.VolumeName`, a no-op on POSIX) or any
  slash-normalized form starting with `/` — which also catches a leading
  `\` and a UNC `\\server\share\...` path.
- **Unix tunnel endpoints (`unix://...`) mostly failed with the wrong
  error on native Windows, and the rare form that didn't still had no real
  protection there.** `tunnel.ParseEndpoint`'s `filepath.IsAbs` check meant
  most `unix:///path` URLs already failed to parse on Windows (no volume
  name), but only with a confusing "must be an absolute unix:///path"
  error and no indication the real problem is platform support — and a UNC
  form (`unix:////server/share/path`) *did* parse successfully, with no
  Windows equivalent of the `chmod 0600` socket-protection guarantee
  `tunnel.Listen` otherwise provides. `ParseEndpoint` now rejects every
  `unix://` endpoint explicitly on Windows with `"Unix socket endpoints are
  unsupported on native Windows; use TCP or WSL"`. Documented in the
  README, `man/sp2p.1`, and `web/llm.md`.

### CI wiring

`ci.yml`'s `windows` job (`windows-latest`, `timeout-minutes: 45`): disables
git's CRLF conversion before checkout, best-effort disables Windows Defender
real-time scanning (`Set-MpPreference -DisableRealtimeMonitoring $true`,
wrapped so a failure there — e.g. a runner image that already has it off,
or lacks permission — doesn't fail the job), checks out, sets up Go
(`go-version-file: go.mod`) and Node 25, `npm --prefix web ci`, builds web
assets (`npm --prefix web run build` — needed before any Go step, since
`web.go`'s `//go:embed web/dist/*` won't compile without it; not `make
build-web`, since `make` isn't guaranteed on this runner image), `go vet
./...`, `go test ./... -count=1 -timeout=20m`, confirms `msedge.exe` exists
at its default install location (Edge is preinstalled on `windows-latest`;
running `npx playwright install msedge` must **not** happen — under `CI=true`
it skips Playwright's own already-installed guard and reinstalls Edge via
MSI over the image's copy) and prints its version, then
`npx playwright test --project=msedge` from `web/`. On failure, a final step
dumps `netsh interface ipv4 show excludedportrange protocol=tcp` and
`Get-NetFirewallProfile` for diagnosis (no artifact upload). The
Edge-locate and Playwright steps run even if the Go test step failed
(`if: ${{ !cancelled() && steps.web.outcome == 'success' }}`), so a Go-side
failure doesn't hide Edge-side results from the same run — both halves are
independent evidence.

No `SP2P_TEST_TIME_SCALE` knob exists in this repo (nothing to reuse), and
this phase doesn't introduce one: every wait in the suite already carries at
least 10x headroom over real observed durations (the whole `internal`
package runs in well under a minute on Linux; per-transfer limits are
45–120s; Playwright allows 60s per 64&nbsp;MiB), so a slow-but-passing
Windows run is not expected to need one. If a Windows run instead *hangs*,
that's a real bug to fix (or, failing that, to skip with a specific,
evidenced reason) — a time-scale knob would only mask it.

### Running locally (PowerShell)

```powershell
git config --global core.autocrlf false   # only matters if you haven't already
go vet ./...
go test ./... -count=1
cd web
npm ci
npm run build
npx playwright test --project=msedge
```

### First CI runs

The `windows` job's first real run
([36392203084](https://github.com/zyno-io/sp2p/actions/runs/36392203084))
found a real Windows product bug:
`TestWriteFileAtomic_ConcurrentReadersNeverSeePartialWrites` hung for the
entire 20-minute `go test` timeout (25m06s job). Defender was not the
cause (the log's `True` is `DisableRealtimeMonitoring`, so scanning was
already off). Windows refuses to replace a file that another process has
open without delete sharing, which is how Go opens files, so the
create-temp-then-rename write failed while the test's reader had the file
open. The writer exited on that error without stopping the reader, which
then spun until the timeout. The CLI's `--status-file` uses the same
pattern for other processes to poll, so a poller could leave it stale.
`fileutil.ReplaceFile` now retries the rename briefly on Windows while a
reader holds the file, both writers use it, and the test stops its reader
on every exit so a write error fails fast. The msedge/CLI interop half of the same run, wholly
unaffected by the Go-side hang (its `if:` condition only depends on the web
build succeeding), passed all 16 tests in 2.9 minutes on the first attempt,
with no engine-specific findings.

CRLF handling was also confirmed correct on this run:
`TestBootstrapTemplatesMatchGenerator`, which compares a generated copy of
`scripts/bootstrap-*.sh` byte-for-byte against the checked-out one, passed
as part of the `internal` package (`ok  ...  47.313s`) — `core.autocrlf
false` before checkout is doing its job.

After skipping that one test, the second run
([36394934897](https://github.com/zyno-io/sp2p/actions/runs/36394934897))
confirmed the fix — `go test ./...` completed in about a minute instead of
20+ minutes — and surfaced a genuine, unrelated Windows finding:
`internal/conn`'s `TestNetConnAdapterImplementsP2PConn` failed with
`wsarecv: An established connection was aborted by the software in your
host machine`. This was a real test bug, not a product bug or a
Windows-only guard: the test's fake TCP server wrote `"pong"` and closed
the connection without ever reading the `"ping"` the client had already
written, leaving unread data in the server's receive buffer at close
time — the standard trigger for an abortive close (RST instead of FIN).
Linux and macOS tolerated it (the existing `test`/`macos-rsync` jobs never
caught this), but Windows' stack surfaces the resulting error to the
client's `Read` even after the `"pong"` payload was already delivered.
Fixed by having the fake server actually drain the client's write
(`io.ReadFull`) before responding and closing — a correctness fix that
helps every platform's test hygiene, not a Windows-specific branch.

### Known gaps

- **No `-race`.** The race detector needs cgo; this repo's Windows binaries
  (like all its binaries) build `CGO_ENABLED=0`.
- **rsync and Unix tunnel endpoints are unsupported on native Windows** —
  by explicit product decision (`rsync.InspectBinary`,
  `tunnel.ParseEndpoint`), not merely untested. WSL is the documented
  workaround.
- **Firefox, WebKit, the `netem`/`relay` network-namespace suites, and the
  full `engines` matrix don't run on Windows** — Firefox/WebKit have no
  Windows-specific job of their own (see [Engines](#engines-firefox-and-webkit)
  above), and netem/relay need a real Linux network namespace.
- **No Windows ARM64 coverage** — `windows-latest` is x86-64 only.
- **Symlink-dependent tests** (`internal/rsync`'s
  `TestServeDoesNotTraverseSelectedSymlink` and
  `TestValidateDirectoryRejectsUnsafeCanonicalAlias`) create symlinks
  successfully on `windows-latest`, but they don't exercise the property
  they test there: `ValidateDirectory` rejects every path containing `\`,
  and rsync is unsupported on native Windows anyway.

## Packaging validation

`.github/workflows/packaging-validate.yml` exercises the exact rendering
`publish-packages.yml` performs for Homebrew, Scoop, AUR, and Chocolatey
(WinGet is checked separately, below) and then actually installs each
package on its native platform — without ever publishing. It has no
`environment:` and no publishing secrets (`permissions: contents: read`
only), so it's safe to run on every PR and to re-run freely.

Both workflows call the same script, `scripts/packaging/render.sh
<channel> <version> <baseURL> <checksums-file> <outdir>`, so a publish run
and a validation run render byte-identical bytes from the same inputs. It's
hermetic (no network, git, `gh`, or `makepkg`) — including the AUR channel's
`.SRCINFO`, which is generated by a small format-pinned function rather than
shelling out to `makepkg --printsrcinfo` (which also refuses to run as
root). The `sha()` lookup inside it is the same strict, fail-closed check
that was already in `publish-packages.yml`: exactly one `checksums.txt`
line for the asset, a well-formed 64-hex sha256, accepting both a real
release's `./`-prefixed lines and a bare goreleaser snapshot's unprefixed
ones. `scripts/packaging/render_test.sh` is a hermetic self-test of this
logic (synthetic checksums, no network) — run it directly with `bash
scripts/packaging/render_test.sh`.

### Triggers and sources

| Trigger | `render.sh`'s `<version>`/`<baseURL>` come from | When it runs |
|---|---|---|
| `pull_request` (paths: `.github/workflows/publish-packages.yml`, `packaging-validate.yml`, `scripts/packaging/**`, `.goreleaser.yaml`, `scripts/filter-goreleaser.sh`) | A goreleaser **snapshot** build (version `0.0.0`, mirroring `release.yml`'s real invocation and `ci.yml`'s `build` job), served locally over plain HTTP (`scripts/packaging/serve.sh`) | Any PR touching packaging files — including the PR that introduced this workflow, since it touches exactly those paths |
| `workflow_run` (`Release`, `completed`) | The real, tagged release's actual assets and `checksums.txt` | After every real release deploys |
| `workflow_dispatch` (`tag` input) | Same as `workflow_run`, for a tag chosen by hand | Anytime — e.g. right after this workflow file merges, since `workflow_run` can't fire retroactively for tags already released |

The `resolve` job skips cleanly (job succeeds, does nothing further) when:
the triggering Release run's conclusion wasn't `success`; the resolved tag
isn't a plain `vX.Y.Z` (the same rule `publish-packages.yml`'s
`validate-release` job enforces); or the tag predates
`scripts/packaging/render.sh` existing. It also hard-fails if a
`workflow_run`-triggered validation finds the tag now pointing at a
different commit than the Release run built — tags must never move (see the
[pinned-fixtures policy](#pinned-fixtures-and-the-tag-move-policy) above).

### Per-channel checks

Every channel job: downloads the `inputs` job's assets/checksums, renders
with `render.sh` on its own platform, downloads the `render` job's
ubuntu-rendered output and `diff -r`s the two (proving `render.sh` is
platform-independent, since `publish-packages.yml` renders Homebrew and
Scoop on ubuntu but AUR and Chocolatey on their own platforms), then
`scripts/packaging/verify-urls.sh <channel> <dir> <checksums-file>` — which
cross-checks every URL/sha256 the manifest references against
`checksums.txt`, a live `HEAD` request, and the sha256 of the actually
downloaded bytes.

| Channel | Runner | Installs via |
|---|---|---|
| Homebrew | `macos-15` | `brew tap-new` a throwaway local tap, `brew install`, `brew test`, `brew audit --strict` |
| Scoop | `windows-latest` | A pinned copy of the Scoop installer, `scoop install <manifest>`, run, `scoop uninstall` |
| Chocolatey | `windows-latest` | `choco pack`, `choco install -s <dir>`, run, `choco uninstall` |
| AUR | `archlinux:base` container | `makepkg --printsrcinfo` diffed against the hermetic `.SRCINFO`, `namcap`, `makepkg -s`, `pacman -U`, run, `pacman -Rns` |

### Homebrew audit

`brew audit --strict --os=all --arch=all --except=version` — confirmed
locally (Homebrew 7.0.6) against the real, currently-published formula:
without `--except=version`, `brew audit --strict` always fails with
`` `version 0.6.2` is redundant with version scanned from URL `` for any
`on_macos`/`on_linux` formula whose URL embeds the version (which every
`.../download/vX.Y.Z/...` URL here does) — `--except=version` skips only
that one audit, not the rest of `--strict`. Homebrew ≥7 also refuses to load
formulae from a tap it doesn't trust; `brew trust --tap local/sp2p` handles
that for the throwaway local tap. `--os=all --arch=all` audits every
`on_macos`/`on_linux`/`on_arm`/`on_intel` branch offline, even though the
`macos-15` runner itself is only one of the four.

### WinGet

The real `winget` job in `publish-packages.yml` (`vedantmgoyal9/winget-releaser`,
which wraps `komac`) needs a `WINGET_TOKEN` PAT to fork, push a branch, and
open a pull request against `microsoft/winget-pkgs` — none of which this
workflow can or should do. What it validates instead, with no token beyond
the default read-only `github.token`: it resolves the same installer URLs
the action would (from the real release's assets, or the snapshot's), runs
a pinned `komac update --dry-run --output` (no submission), and checks the
rendered manifest's version, installer count, `NestedInstallerType:
portable`, and `NestedInstallerFiles` against a real, currently-published
`zyno-io.sp2p` manifest's shape — then runs it through the same
`verify-urls.sh` as every other channel. Not validated: the fork/branch/PR
steps themselves, and `winget validate` (the winget CLI isn't a dependable
tool on a Linux/macOS runner image; komac writes schema-versioned manifests
itself, which is what's checked instead).

### Running locally

```bash
bash scripts/packaging/render_test.sh          # hermetic self-test, no network

gh release download v0.6.2 -R zyno-io/sp2p -p checksums.txt -D /tmp/dl
B=https://github.com/zyno-io/sp2p/releases/download/v0.6.2
bash scripts/packaging/render.sh homebrew 0.6.2 "$B" /tmp/dl/checksums.txt /tmp/out/homebrew
bash scripts/packaging/verify-urls.sh homebrew /tmp/out/homebrew /tmp/dl/checksums.txt
```

### Mutation checks

Confirmed on this branch's own draft PR with two throwaway commits (each
edits the `inputs` job in `packaging-validate.yml` to mutate the snapshot's
`dist/` before it's uploaded, re-triggering the `pull_request` run), then
reverted with `git revert --no-edit`:

- **Rename the Windows amd64 archive.** Expected and observed: `render`
  fails (`scoop`/`chocolatey` can't resolve `sp2p_windows_amd64.zip`'s
  checksum, so every downstream channel job that `needs: render` is
  skipped rather than passing on stale rendered output), and `winget` fails
  to resolve 2 installer URLs.
- **Corrupt one `checksums.txt` line with a well-formed but wrong sha256.**
  Expected and observed: `render` still passes (the value is well-formed),
  but `homebrew`'s and `aur`'s `verify-urls.sh` step fails with a sha256
  mismatch against the actually-downloaded bytes — proving the check isn't
  just comparing two copies of the same (wrong) value.

## Production smoke test

`web/tests/smoke-prod.mjs` is a standalone Node + Playwright script, in the
same style as `web/tests/wan-*.mjs` (not picked up by `npm test` or any
other CI job) — but unlike those, it's the one such script CI *does* run:
`.github/workflows/smoke-production.yml`'s `smoke` job, called automatically
by `release.yml` right after a full release's SSH deploy step
(`needs: [release, publish-release]`), and dispatchable by hand for any
already-published tag. It has no `environment:` and needs no secrets —
everything it touches (sp2p.io, public GitHub Release assets) is public.

### What it checks

1. **Waits (up to `--deploy-timeout`, default 600s) for the deploy to
   actually land.** Fetches `https://sp2p.io/` with `Accept: text/html` (a
   plain `curl`-shaped request gets the `curl | sh` bootstrap script
   instead — `internal/server/handler_bootstrap.go`'s content negotiation),
   and requires **two consecutive** polls, 15s apart, where the served
   `index.html` names the expected `main-XXXXXXXX.js` bundle, its
   `footer-version` element's `data-version` attribute equals the tag's
   version, and a `HEAD` on the bundle URL succeeds. The version check
   matters on its own: the bundle filename is a content hash
   (`web/build.js`), so a release that doesn't touch `web/src` ships the
   *same* bundle name as the release before it — a bundle-only check could
   pass before the new deploy actually lands.
2. **Downloads and verifies the tag's Linux CLI** against that release's
   `checksums.txt` (the same strict, fail-closed lookup as
   `scripts/packaging/render.sh`'s `sha()`), then confirms `sp2p version`
   reports the expected version before using it for anything.
3. **CLI (sender) → Chromium (receiver), 64 MiB**: asserts both sides
   negotiate all 8 WebRTC lanes (`PARALLEL_MIN_BYTES` /
   `parallelMinFileSize`'s auto threshold), the CLI reports `connection`
   method `webrtc`, and the received file's streamed SHA-256 matches.
4. **Chromium → Chromium, 8 MiB**: asserts the received file's streamed
   SHA-256 matches. (Below the lane threshold, so lane count isn't
   asserted here — scenario 3 already covers 8-lane negotiation.)
5. Either scenario failing retries once, after a 60s backoff, with a fresh
   CLI process, fresh browser(s), and a fresh session; the job fails only
   on a second failure.

The received file is hashed by streaming 4 MiB slices back from the page
(base64-encoded in the page, decoded and fed to a streaming SHA-256 in
Node) rather than reusing `web/tests/helpers.ts`'s `verifyDiskStreaming`,
which loads a `/crypto-test.js` helper production doesn't serve.

### Relay is denied

Both scenarios dismiss the browser's relay-consent dialog
(`page.on("dialog", ...)`, matching `wan-transfer.mjs`'s existing pattern)
and run the CLI with `-allow-relay=false` and a clean, `SP2P_*`-stripped
environment (`XDG_CONFIG_HOME` pointed at an empty directory, so no stray
`~/.config/sp2p/config.yaml` can flip this) — so only a genuine direct P2P
path can succeed. This is a hard requirement, not just "the dialog gets
dismissed and ignored": tracing `web/src/main.ts` and
`internal/flow/helpers.go` confirms the *first* connection attempt on both
CLI and browser never includes TURN servers at all (they're only added
*after* consent), and denying consent throws a real, explicit error on both
sides rather than silently falling back — `internal/cli/machine.go`'s
`relay_required` event blocks on a response-file write, which the script
answers `deny` the instant it sees the event, so a relay-only path fails
fast and loud instead of hanging. The probe injected into every page also
tracks whether any `RTCPeerConnection` was ever configured with a
`turn:`/`turns:` ICE server and whether any `typ relay` candidate appeared
in an offer/answer/trickled candidate, asserting all of it is zero — not
just inferring "no relay" from the absence of a dialog.

### Privacy

- Transfer codes and share URLs are masked (`::add-mask::`, GitHub Actions
  log redaction) the instant they're known — before being used to build a
  URL, navigate a page, or log anything — and only when
  `GITHUB_ACTIONS=true` (emitting the mask line itself on a local terminal
  would print the value it's supposed to hide).
- All output is passed through a redactor that also strips the transfer
  code shape (`internal/server/session.go`'s 8-char session-ID alphabet
  plus `internal/crypto/seed.go`'s base62 seed) and any URL `#` fragment,
  as a second layer beyond the exact-value masking above.
- Playwright traces, screenshots, video, and HAR are never enabled; no
  artifacts are uploaded (a page's DOM briefly holds the live share URL).
- The script refuses to run at all if `DEBUG`/`PWDEBUG` is set (Playwright
  debug logging prints full navigated URLs outside the script's control).

### CI wiring

`smoke-production.yml` is a reusable workflow (`workflow_call` +
`workflow_dispatch`, both taking `tag`, an optional `expected_bundle`, and
an optional `cli_tag`). It always runs `web/tests/smoke-prod.mjs` as it
exists on the ref the workflow itself runs from — not a tag-pinned copy —
since this checks current production behavior, not a specific tag's copy of
the script; a fix to the script benefits re-validating an old tag too.
`release.yml`'s `release` job adds a `web_bundle` output (parsed from
`web/dist/index.html`, not just listed from the build directory, so it's
exactly what the server serves) and a `smoke` job
(`needs: [release, publish-release]`, `if: needs.release.outputs.scope ==
'all'` — a `-server`-scoped release has no CLI asset to drive one side, and
a CLI-only release deploys nothing) that calls it. `workflow_dispatch` only
becomes invokable once this workflow file is on the default branch — to
validate an already-released tag, dispatch with `--ref main`.

### Running locally

```bash
npm --prefix web ci
npx --prefix web playwright install chromium
node web/tests/smoke-prod.mjs --tag v0.6.2
```

No `--cli-asset` needed on a Mac: it defaults to the host's actual
platform/arch (`darwin-arm64`, etc.); CI always passes `--cli-asset
linux-amd64` explicitly. Confirmed passing against real production
(`v0.6.2`, this Mac): resolved bundle `main-ZTSKTWN6.js` from the release's
server archive (matching what sp2p.io actually served), CLI installed and
identity-checked, deploy confirmed in 2 polls, `cli-to-chromium` passed on
a retried attempt (attempt 1 hit the pre-existing "6-7/8 lanes on a
multi-homed host" rough edge from the [Engines](#engines-firefox-and-webkit)
section above — the retry-once design working as intended, not a bug in
this script), `chromium-to-chromium` passed on the first attempt, overall
`PASS`. A full run's output, redaction-scanned afterward for the transfer-code
and URL-fragment patterns above, contained zero matches; under
`GITHUB_ACTIONS=true` it emitted exactly the expected `::add-mask::` lines
(session code, session ID, seed, and full share URL — once per scenario)
and nothing else changed in the output.

### Known gaps

- **Not a WAN test.** In CI both peers run on the same runner, so "direct
  path" here means host-local connectivity through sp2p.io's real
  signaling/TURN-credential/deploy path — a production smoke test, not a
  reproduction of real-world NAT traversal (that's
  [Opt-in WAN harnesses](#opt-in-wan-harnesses) above).
- Chromium launches with `--disable-features=WebRtcHideLocalIpsWithMdns`
  (see [Engines](#engines-firefox-and-webkit) above) — real users don't set
  this flag, though it only affects whether host candidates resolve on a
  hosted runner, not the transfer's correctness.
- Only the Linux amd64 CLI asset is checked in CI (a local run can check
  any platform's asset via `--cli-asset`).
- A re-released *identical* version (a re-tag with no source changes) can't
  be distinguished from "the previous deploy never updated" by the
  version/bundle check alone — both would show the same values before and
  after.
- A failing smoke job does not roll anything back; production is already
  deployed by the time it runs. Re-running it (or dispatching
  `smoke-production.yml` directly) re-checks the same live deploy.
