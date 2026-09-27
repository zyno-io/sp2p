// SPDX-License-Identifier: MIT

// Uses the OPFS-free hashingPicker sink (not receiveToDisk) so this spec's
// browser-receiver tests run for real on every engine: a spike found
// Playwright's bundled WebKit's OPFS createWritable() unreliable (see
// docs/testing.md's Engines section).

import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import type { Page } from "@playwright/test";
import { expect } from "./fixtures";
import {
  chooseFile, cleanupTemporaryDirectories, hashingPicker, isolatedServerTest as test,
  observeConnections, temporaryDirectory, verifyHashingSink, watchCLI,
} from "./helpers";

test.setTimeout(90000);
// Incompressible content catches encoded zstd frames slightly larger than
// their 256 KiB decoded chunks, including compression with parallel lanes.
const contents = randomBytes(64 * 1024 * 1024);
const expectedHash = createHash("sha256").update(contents).digest("hex");
test.afterEach(() => { cleanupTemporaryDirectories(); });

function choose(page: Page): Promise<string> {
  return chooseFile(page, contents, "parallel.bin");
}

function verifyReceived(page: Page): Promise<void> {
  return verifyHashingSink(page, contents.length, expectedHash);
}

for (const blockedExtras of [0, 1, 3, 7]) {
  test(`browser parallel WebRTC verifies ${8 - blockedExtras} agreed lanes`, async ({ browser, baseURL }) => {
    const sender = await browser.newPage({ baseURL }), receiver = await browser.newPage({ baseURL });
    const senderCounts = observeConnections(sender), receiverCounts = observeConnections(receiver);
    await hashingPicker(receiver);
    if (blockedExtras) await sender.addInitScript(blockedExtras => {
      const Native = RTCPeerConnection;
      let count = 0;
      (window as any).RTCPeerConnection = class extends Native {
        private extra: boolean;
        constructor(config?: RTCConfiguration) { super(config); const index = count++; this.extra = index > 0 && index <= blockedExtras; }
        createOffer(options?: RTCOfferOptions): Promise<RTCSessionDescriptionInit> {
          return this.extra ? Promise.reject(new Error("test: secondary path unavailable")) : super.createOffer(options);
        }
      };
    }, blockedExtras);
    try {
      const code = await choose(sender);
      await receiver.goto(`/r#${code}`);
      await receiver.addScriptTag({ url: "/crypto-test.js" });
      await receiver.locator(".confirm-btn").click();
      await expect(sender.locator(".complete")).toBeVisible({ timeout: 60000 });
      await expect(receiver.locator(".complete")).toBeVisible({ timeout: 60000 });
      expect(senderCounts).toEqual([8 - blockedExtras]);
      expect(receiverCounts).toEqual(senderCounts);
      await verifyReceived(receiver);
    } finally { await sender.close(); await receiver.close(); }
  });
}

test("browser parallel WebRTC sender interoperates with CLI receiver", async ({ page, cliBin, wsUrl }) => {
  const dest = temporaryDirectory("sp2p-parallel-recv-");
  const counts = observeConnections(page);
  const code = await choose(page);
  const child = spawn(cliBin, ["receive", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-output", dest, code]);
  const cli = watchCLI(child);
  try {
    await expect(page.locator(".complete")).toBeVisible({ timeout: 60000 });
    const status = await cli.exited;
    expect(status).toBe(0);
    expect(counts).toEqual([8]); expect(cli.counts).toEqual([8]);
    const received = readFileSync(join(dest, "parallel.bin"));
    expect(createHash("sha256").update(received).digest("hex")).toBe(expectedHash);
  } finally { child.kill(); }
});

for (const compression of [0, 3]) {
  test(`CLI parallel WebRTC sender interoperates with disk browser, compression ${compression}`, async ({ page, cliBin, wsUrl }) => {
    const src = join(temporaryDirectory("sp2p-parallel-send-"), "parallel.bin");
    writeFileSync(src, contents);
    const counts = observeConnections(page);
    await hashingPicker(page);
    const child = spawn(cliBin, ["send", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-compress", String(compression), src]);
    const cli = watchCLI(child);
    try {
      const code = await cli.code;
      await page.goto(`/r#${code}`);
      await page.addScriptTag({ url: "/crypto-test.js" });
      await page.locator(".confirm-btn").click();
      await expect(page.locator(".complete")).toBeVisible({ timeout: 60000 });
      const status = await cli.exited;
      expect(status).toBe(0);
      expect(counts).toEqual([8]); expect(cli.counts).toEqual([8]);
      await verifyReceived(page);
    } finally { child.kill(); }
  });
}
