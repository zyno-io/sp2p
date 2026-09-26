import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false, // tests share a server
  retries: 0,
  workers: 1, // serial — share a single server process
  use: {
    baseURL: "http://localhost:18090",
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
      testIgnore: /netem\.spec\.ts/,
    },
    {
      name: "netem",
      testMatch: /netem\.spec\.ts/,
      timeout: 240_000,
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
        trace: "retain-on-failure",
        screenshot: "only-on-failure",
      },
    },
  ],
  globalSetup: "./tests/global-setup.ts",
  globalTeardown: "./tests/global-teardown.ts",
});
