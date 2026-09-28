import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false, // tests share a server
  retries: 0,
  // A test that only passes after a retry is still telling us something is
  // wrong (see docs/testing.md's Engines section) — fail the run instead of
  // letting a retry quietly launder it. This is a global option (Playwright
  // has no per-project equivalent), so no project retries in CI.
  failOnFlakyTests: !!process.env.CI,
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
      // relay.spec.ts likewise has its own "relay" project below (env-gated
      // on SP2P_RELAY_TEST, needs the firewalled netns, and also launches
      // every engine itself via the `playwright` fixture).
      testIgnore: [/netem\.spec\.ts/, /engine-matrix\.spec\.ts/, /relay\.spec\.ts/],
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
      // No retries: retries hid a real CLI→browser offer race (now fixed;
      // see docs/testing.md's Engines section). Failures should surface.
    },
    {
      name: "webkit",
      use: { browserName: "webkit" },
      testMatch: [/interop\.spec\.ts/, /parallel-interop\.spec\.ts/, /webrtc-policy\.spec\.ts/],
      // No retries: the occasional lane shortfall below is environment-
      // specific (this multi-homed dev machine), not expected on CI's
      // single-NIC runners — see docs/testing.md's Engines section. If it
      // shows up for real on the macos-15 nightly job, handle it there
      // instead of absorbing it here.
    },
    // engine-matrix.spec.ts's tests never request the `browser`/`page`
    // fixtures — every engine involved is launched explicitly through the
    // `playwright` fixture — so this project's own browserName is unused;
    // it exists only to scope the project's test enumeration.
    {
      name: "engines",
      testMatch: /engine-matrix\.spec\.ts/,
      // No retries — see the "webkit" project's comment above.
    },
    {
      name: "netem",
      testMatch: /netem\.spec\.ts/,
      // The spec must not override this: wan500 transfers need the longer limit.
      timeout: process.env.SP2P_NETEM_PROFILE === "wan500" ? 900_000 : 240_000,
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
    // relay.spec.ts's tests never request the `browser`/`page` fixtures —
    // every engine involved is launched explicitly through the `playwright`
    // fixture — so this project's own browserName is unused; it exists only
    // to scope the project's test enumeration and timeout/trace settings.
    {
      name: "relay",
      testMatch: /relay\.spec\.ts/,
      timeout: 240_000,
      use: {
        // Traces/screenshots/video would capture transfer codes and TURN
        // credentials in a public artifact — never collect them for this suite.
        trace: "off",
        screenshot: "off",
        video: "off",
      },
    },
  ],
  globalSetup: "./tests/global-setup.ts",
  globalTeardown: "./tests/global-teardown.ts",
});
