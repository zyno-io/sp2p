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
