import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false, // tests share a server
  retries: 0,
  workers: 1, // serial — share a single server process
  use: {
    baseURL: "http://127.0.0.1:18090",
    headless: true,
  },
  projects: [
    {
      name: "chromium",
      use: { browserName: "chromium" },
      // netem.spec.ts is skipped without SP2P_NETEM_PROFILE anyway, but keep
      // it out of the default project's enumeration too — it needs the
      // "netem" project below (full-Chromium channel, mDNS flag, longer
      // timeout) to run for real, inside the CI netem job's namespace.
      // engine-matrix.spec.ts likewise has its own "engines" project below
      // (it launches every engine itself via the `playwright` fixture, so it
      // does not belong to any single-browserName project's enumeration).
      testIgnore: [/netem\.spec\.ts/, /engine-matrix\.spec\.ts/],
    },
    // Firefox and WebKit only run the browser-facing interop specs that
    // generalize across engines — not Node-only specs (parallel.spec.ts,
    // crypto-vectors.spec.ts, etc.) that never touch a `browser`/`page`
    // fixture, and not env-gated/Chromium-specific suites (netem, compat).
    // See docs/testing.md's "Engines" section for per-engine skips and why.
    {
      name: "firefox",
      use: { browserName: "firefox" },
      testMatch: [/interop\.spec\.ts/, /parallel-interop\.spec\.ts/, /webrtc-policy\.spec\.ts/],
    },
    {
      name: "webkit",
      use: { browserName: "webkit" },
      testMatch: [/interop\.spec\.ts/, /parallel-interop\.spec\.ts/, /webrtc-policy\.spec\.ts/],
      // Real-timing WebRTC lane negotiation (web/src/webrtc-parallel.ts's
      // per-lane 8s auth timeout) occasionally lands one lane short of the
      // full count under CPU contention — see docs/testing.md's Engines
      // section. One retry absorbs that noise without loosening any
      // assertion; a lane count that's consistently short is still a
      // failure after the retry.
      retries: process.env.CI ? 1 : 0,
    },
    // engine-matrix.spec.ts's tests never request the `browser`/`page`
    // fixtures — every engine involved is launched explicitly through the
    // `playwright` fixture — so this project's own browserName is unused;
    // it exists only to scope the project's test enumeration.
    {
      name: "engines",
      testMatch: /engine-matrix\.spec\.ts/,
      // See the retries comment on the "webkit" project above — the same
      // per-lane timing margin applies here, including on the @pr-tagged
      // cells that gate PRs.
      retries: process.env.CI ? 1 : 0,
    },
    {
      name: "netem",
      testMatch: /netem\.spec\.ts/,
      timeout: process.env.SP2P_NETEM_PROFILE === "wan500" ? 900_000 : 240_000,
      retries: process.env.CI ? 1 : 0,
      use: {
        browserName: "chromium",
        // Full new-headless Chromium, not the headless-shell build: the
        // buffer-hint/UDP-socket and ICE port-range behavior this suite
        // checks isn't guaranteed to match the shell (see
        // docs/browser-high-rtt.md).
        channel: "chromium",
        launchOptions: {
          // mDNS on a dummy interface inside the netem namespace isn't
          // guaranteed to resolve, so host candidates would otherwise be
          // unusable .local names.
          args: ["--disable-features=WebRtcHideLocalIpsWithMdns"],
        },
        // Traces, screenshots and DOM snapshots would capture transfer codes
        // (share URLs and signaling frames) in a public artifact.
        trace: "off",
        screenshot: "off",
      },
    },
  ],
  globalSetup: "./tests/global-setup.ts",
  globalTeardown: "./tests/global-teardown.ts",
});
