// SPDX-License-Identifier: MIT

// Cross-engine transfer matrix: every sender/receiver pairing of
// chromium/firefox/webkit (3x3 = 9 cells) plus the CLI against each engine
// in both directions (6 cells) — 15 cells total, all at 64 MiB of random
// (incompressible) content, asserting the received SHA-256 and that both
// sides negotiate the full 8-lane parallel WebRTC policy (internal/flow,
// web/src/webrtc-parallel.ts). See webrtc-policy.spec.ts for the structural
// SDP (buffer-hint/bundle-policy) assertions this file does not repeat.
//
// Every engine involved is launched explicitly through the `playwright`
// fixture (playwright.firefox.launch(), etc.) rather than through the
// project's own `browser`/`page` fixtures, so this spec's "engines" project
// (playwright.config.ts) declares no browserName of its own — it exists
// only to scope which tests run.
//
// Each receiver uses installReceiverSink (web/tests/helpers.ts), which picks
// each engine's own real receive path: real OPFS on Chromium, the in-memory
// blob + downloadBlob path on Firefox/WebKit (neither implements
// showSaveFilePicker for real) — see docs/testing.md's Engines section.
//
// Chromium↔Firefox (both directions) and CLI↔Firefox (both directions) are
// tagged @pr and gate PRs cheaply (ci.yml's browser-firefox job, `--project
// engines --grep @pr`). Every other cell — anything touching WebKit, plus
// CLI↔Chromium — is nightly-only (nightly.yml's engines job, macos-15)
// until WebKit is promoted to gate PRs too.

import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import type { Page, PlaywrightWorkerArgs } from "@playwright/test";
import { expect } from "./fixtures";
import {
  chooseFile, cleanupTemporaryDirectories, flushDiagnostics, installReceiverSink, isolatedServerTest as test,
  observeConnections, temporaryDirectory, trackCLIForDiagnostics, trackForDiagnostics, verifyReceiverSink, watchCLI,
} from "./helpers";

test.setTimeout(120_000);
test.afterEach(async ({}, testInfo) => {
  cleanupTemporaryDirectories();
  await flushDiagnostics(testInfo);
});

// Matches PARALLEL_MIN_BYTES (web/src/webrtc-parallel.ts) / parallelMinFileSize
// (internal/flow) — the auto threshold at which both sides request the full
// lane count, same as parallel.spec.ts/parallel-interop.spec.ts.
const contents = randomBytes(64 * 1024 * 1024);
const expectedHash = createHash("sha256").update(contents).digest("hex");
const LANE_COUNT = 8;
const COMPLETE_TIMEOUT = 100_000;

type EngineName = "chromium" | "firefox" | "webkit";
type Playwright = PlaywrightWorkerArgs["playwright"];

// Hosted CI runners don't reliably resolve the mDNS (.local) names Chromium and
// Firefox use to hide host candidates, which breaks browser-to-browser ICE
// while CLI peers (plain addresses) still connect. Expose plain local
// addresses; WebKit doesn't obfuscate them.
const LAUNCH_OPTIONS: Record<EngineName, Parameters<Playwright["chromium"]["launch"]>[0]> = {
  chromium: { headless: true, args: ["--disable-features=WebRtcHideLocalIpsWithMdns"] },
  firefox: { headless: true, firefoxUserPrefs: { "media.peerconnection.ice.obfuscate_host_addresses": false } },
  webkit: { headless: true },
};

async function launchEnginePage(pw: Playwright, engine: EngineName, baseURL: string): Promise<{ browser: import("@playwright/test").Browser; page: Page }> {
  const browser = await pw[engine].launch(LAUNCH_OPTIONS[engine]);
  const page = await browser.newPage({ baseURL });
  return { browser, page };
}

async function runBrowserToBrowser(pw: Playwright, baseURL: string, senderEngine: EngineName, receiverEngine: EngineName): Promise<void> {
  const { browser: senderBrowser, page: sender } = await launchEnginePage(pw, senderEngine, baseURL);
  const { browser: receiverBrowser, page: receiver } = await launchEnginePage(pw, receiverEngine, baseURL);
  await installReceiverSink(receiver, receiverEngine);
  trackForDiagnostics(receiver, "receiver");
  try {
    const senderCounts = observeConnections(sender);
    const receiverCounts = observeConnections(receiver);
    const code = await chooseFile(sender, contents, "engine-matrix.bin");
    await receiver.goto(`/r#${code}`);
    await receiver.locator(".confirm-btn").click();
    await expect(sender.locator(".complete")).toBeVisible({ timeout: COMPLETE_TIMEOUT });
    await expect(receiver.locator(".complete")).toBeVisible({ timeout: COMPLETE_TIMEOUT });
    expect(senderCounts).toEqual([LANE_COUNT]);
    expect(receiverCounts).toEqual([LANE_COUNT]);
    await verifyReceiverSink(receiver, receiverEngine, contents.length, expectedHash);
  } finally {
    await senderBrowser.close();
    await receiverBrowser.close();
  }
}

async function runCLIToBrowser(pw: Playwright, baseURL: string, wsUrl: string, cliBin: string, receiverEngine: EngineName): Promise<void> {
  const { browser, page } = await launchEnginePage(pw, receiverEngine, baseURL);
  await installReceiverSink(page, receiverEngine);
  trackForDiagnostics(page, "receiver");
  try {
    const src = join(temporaryDirectory("sp2p-engine-matrix-send-"), "engine-matrix.bin");
    writeFileSync(src, contents);
    const child = spawn(cliBin, ["send", "-format", "json", "-server", wsUrl, "-transport", "webrtc", src]);
    const cli = watchCLI(child);
    trackCLIForDiagnostics(cli, "sender");
    try {
      const code = await cli.code;
      await page.goto(`/r#${code}`);
      await page.locator(".confirm-btn").click();
      await expect(page.locator(".complete")).toBeVisible({ timeout: COMPLETE_TIMEOUT });
      const status = await cli.exited;
      expect(status).toBe(0);
      expect(cli.counts).toEqual([LANE_COUNT]);
      await verifyReceiverSink(page, receiverEngine, contents.length, expectedHash);
    } finally {
      child.kill();
    }
  } finally {
    await browser.close();
  }
}

async function runBrowserToCLI(pw: Playwright, baseURL: string, wsUrl: string, cliBin: string, senderEngine: EngineName): Promise<void> {
  const { browser, page } = await launchEnginePage(pw, senderEngine, baseURL);
  try {
    const dest = temporaryDirectory("sp2p-engine-matrix-recv-");
    const code = await chooseFile(page, contents, "engine-matrix.bin");
    const child = spawn(cliBin, ["receive", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-output", dest, code]);
    const cli = watchCLI(child);
    trackCLIForDiagnostics(cli, "receiver");
    try {
      await expect(page.locator(".complete")).toBeVisible({ timeout: COMPLETE_TIMEOUT });
      const status = await cli.exited;
      expect(status).toBe(0);
      expect(cli.counts).toEqual([LANE_COUNT]);
      const received = readFileSync(join(dest, "engine-matrix.bin"));
      expect(createHash("sha256").update(received).digest("hex")).toBe(expectedHash);
    } finally {
      child.kill();
    }
  } finally {
    await browser.close();
  }
}

const ENGINES: EngineName[] = ["chromium", "firefox", "webkit"];

function isChromiumFirefoxPair(a: EngineName, b: EngineName): boolean {
  return (a === "chromium" && b === "firefox") || (a === "firefox" && b === "chromium");
}

test.describe("browser ↔ browser", () => {
  for (const senderEngine of ENGINES) {
    for (const receiverEngine of ENGINES) {
      const details = isChromiumFirefoxPair(senderEngine, receiverEngine) ? { tag: "@pr" } : {};
      test(`${senderEngine} sender → ${receiverEngine} receiver, 64 MiB, ${LANE_COUNT} lanes`, details, async ({ playwright, isolatedServer }) => {
        await runBrowserToBrowser(playwright, isolatedServer, senderEngine, receiverEngine);
      });
    }
  }
});

test.describe("CLI ↔ browser", () => {
  for (const engine of ENGINES) {
    const details = engine === "firefox" ? { tag: "@pr" } : {};
    test(`CLI sender → ${engine} receiver, 64 MiB, ${LANE_COUNT} lanes`, details, async ({ playwright, isolatedServer, wsUrl, cliBin }) => {
      await runCLIToBrowser(playwright, isolatedServer, wsUrl, cliBin, engine);
    });
    test(`${engine} sender → CLI receiver, 64 MiB, ${LANE_COUNT} lanes`, details, async ({ playwright, isolatedServer, wsUrl, cliBin }) => {
      await runBrowserToCLI(playwright, isolatedServer, wsUrl, cliBin, engine);
    });
  }
});
