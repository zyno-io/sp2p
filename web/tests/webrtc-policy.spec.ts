// SPDX-License-Identifier: MIT

// Deterministic assertions on the WebRTC "buffer hint" policy (see
// web/src/webrtc.ts addBufferHint and internal/conn/webrtc.go
// newOfferPeerConnection): every offering side of a browser-involved
// connection must request max-bundle and carry a media-less video section,
// and a browser answering a CLI's VP8-only recvonly offer must come back
// inactive. An init script wraps RTCPeerConnection to record only structural
// SDP properties (bundle policy, m-line kinds, video direction/codecs, byte
// length) — never ICE candidates or addresses.

import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Page } from "@playwright/test";
import { expect } from "./fixtures";
import { chooseFile, cleanupTemporaryDirectories, isolatedServerTest as test, receiveToDisk, temporaryDirectory, verifyDisk, watchCLI } from "./helpers";

test.afterEach(() => { cleanupTemporaryDirectories(); });

test.setTimeout(60_000);

const SDP_LANE_LIMIT = 12 * 1024; // internal/conn/webrtc_lane.go / webrtc-parallel.ts SetDescription limit
const CLI_ANSWER_LIMIT = 4 * 1024; // a VP8-only, no-track CLI answer stays far smaller than the general lane limit
const LANE_COUNT = 8; // PARALLEL_MAX_LANES / webRTCParallelLimit at a file this size

// A file at the parallel threshold reaches the full lane count on both ends
// without inflating this suite's runtime.
const contents = randomBytes(64 * 1024 * 1024);
const expectedHash = createHash("sha256").update(contents).digest("hex");

interface SdpSummary {
  mLines: string[];
  video: { direction: string | null; codecs: string[] } | null;
  byteLength: number;
}

interface PolicyRecord {
  bundlePolicy: string | null;
  localDescriptions: SdpSummary[];
  remoteDescriptions: SdpSummary[];
}

// installPolicyRecorder wraps window.RTCPeerConnection before any app code
// runs, so every connection the page creates — primary and every parallel
// lane — is captured. Only structural SDP fields are kept; candidate lines
// and addresses are never read.
async function installPolicyRecorder(page: Page): Promise<void> {
  await page.addInitScript(() => {
    function summarize(sdp: string | undefined): any {
      if (!sdp) return null;
      const mLines: string[] = [];
      let video: { direction: string | null; codecs: string[] } | null = null;
      let current: { direction: string | null; codecs: string[] } | null = null;
      for (const line of sdp.split(/\r\n|\n/)) {
        if (line.startsWith("m=")) {
          const kind = line.slice(2).split(" ")[0];
          mLines.push(kind);
          current = kind === "video" ? { direction: null, codecs: [] } : null;
          if (current) video = current;
          continue;
        }
        if (!current) continue;
        if (line === "a=recvonly" || line === "a=sendonly" || line === "a=sendrecv" || line === "a=inactive") {
          current.direction = line.slice(2);
        } else if (line.startsWith("a=rtpmap:")) {
          const name = line.split(" ")[1]?.split("/")[0];
          if (name) current.codecs.push(name);
        }
      }
      return { mLines, video, byteLength: sdp.length };
    }

    const records: any[] = [];
    (window as any).__policyRecords = records;
    const Native: any = window.RTCPeerConnection;
    class RecordingPeerConnection extends Native {
      __record: any;
      constructor(config?: RTCConfiguration) {
        super(config);
        this.__record = {
          bundlePolicy: this.getConfiguration().bundlePolicy ?? null,
          localDescriptions: [],
          remoteDescriptions: [],
        };
        records.push(this.__record);
      }
      async createOffer(...args: any[]): Promise<any> {
        const offer = await super.createOffer(...args);
        this.__record.localDescriptions.push(summarize(offer.sdp));
        return offer;
      }
      async createAnswer(...args: any[]): Promise<any> {
        const answer = await super.createAnswer(...args);
        this.__record.localDescriptions.push(summarize(answer.sdp));
        return answer;
      }
      async setRemoteDescription(description: any): Promise<any> {
        this.__record.remoteDescriptions.push(summarize(description.sdp));
        return super.setRemoteDescription(description);
      }
    }
    (window as any).RTCPeerConnection = RecordingPeerConnection;
  });
}

async function policyRecords(page: Page): Promise<PolicyRecord[]> {
  return page.evaluate(() => (window as any).__policyRecords ?? []);
}

function allDescriptions(record: PolicyRecord): SdpSummary[] {
  return [...record.localDescriptions, ...record.remoteDescriptions];
}

function assertLaneSizeLimits(records: PolicyRecord[], limit = SDP_LANE_LIMIT): void {
  for (const record of records) {
    for (const desc of allDescriptions(record)) {
      expect(desc.byteLength).toBeLessThanOrEqual(limit);
    }
  }
}

// A browser-side offering connection (primary or lane) must bundle
// everything onto one candidate pair and carry a media-less, inactive video
// section — the "buffer hint" that widens Chrome's UDP socket buffers.
function assertOfferingPolicy(records: PolicyRecord[]): void {
  expect(records).toHaveLength(LANE_COUNT);
  for (const record of records) {
    expect(record.bundlePolicy).toBe("max-bundle");
    const offers = record.localDescriptions;
    expect(offers.length).toBeGreaterThan(0);
    for (const offer of offers) {
      expect(offer.mLines).toContain("video");
      expect(offer.video?.direction).toBe("inactive");
    }
  }
}

test.describe("browser ↔ browser", () => {
  test("every offer is max-bundle with an inactive video section on both sides", async ({ browser, baseURL }) => {
    const sender = await browser.newPage({ baseURL });
    const receiver = await browser.newPage({ baseURL });
    await installPolicyRecorder(sender);
    await installPolicyRecorder(receiver);
    await receiveToDisk(receiver);
    try {
      const code = await chooseFile(sender, contents, "policy-b2b.bin");
      await receiver.goto(`/r#${code}`);
      await receiver.locator(".confirm-btn").click();
      await expect(sender.locator(".complete")).toBeVisible({ timeout: 60_000 });
      await expect(receiver.locator(".complete")).toBeVisible({ timeout: 60_000 });

      const senderRecords = await policyRecords(sender);
      const receiverRecords = await policyRecords(receiver);
      assertOfferingPolicy(senderRecords);
      expect(receiverRecords).toHaveLength(LANE_COUNT);
      for (const record of receiverRecords) expect(record.bundlePolicy).toBe("max-bundle");
      assertLaneSizeLimits(senderRecords);
      assertLaneSizeLimits(receiverRecords);

      await verifyDisk(receiver, contents.length, expectedHash);
    } finally {
      await sender.close();
      await receiver.close();
    }
  });
});

test.describe("browser → CLI", () => {
  test("browser sender offers max-bundle with inactive video; CLI answers stay small", async ({ page, cliBin, wsUrl }) => {
    await installPolicyRecorder(page);
    const dest = temporaryDirectory("sp2p-policy-recv-");
    const code = await chooseFile(page, contents, "policy-b2c.bin");
    const child = spawn(cliBin, ["receive", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-output", dest, code]);
    const cli = watchCLI(child);
    try {
      await expect(page.locator(".complete")).toBeVisible({ timeout: 60_000 });
      expect(await cli.exited).toBe(0);
      expect(cli.counts).toEqual([LANE_COUNT]);

      const records = await policyRecords(page);
      assertOfferingPolicy(records);
      assertLaneSizeLimits(records);
      for (const record of records) {
        for (const answer of record.remoteDescriptions) {
          expect(answer.byteLength).toBeLessThanOrEqual(CLI_ANSWER_LIMIT);
        }
      }

      const received = readFileSync(join(dest, "policy-b2c.bin"));
      expect(createHash("sha256").update(received).digest("hex")).toBe(expectedHash);
    } finally {
      child.kill();
    }
  });
});

test.describe("CLI → browser", () => {
  test("CLI offers recvonly VP8-only video; browser answers inactive", async ({ page, cliBin, wsUrl }) => {
    await installPolicyRecorder(page);
    await receiveToDisk(page);
    const src = join(temporaryDirectory("sp2p-policy-send-"), "policy-c2b.bin");
    writeFileSync(src, contents);
    const child = spawn(cliBin, ["send", "-format", "json", "-server", wsUrl, "-transport", "webrtc", src]);
    const cli = watchCLI(child);
    try {
      const code = await cli.code;
      await page.goto(`/r#${code}`);
      await page.locator(".confirm-btn").click();
      await expect(page.locator(".complete")).toBeVisible({ timeout: 60_000 });
      expect(cli.counts).toEqual([LANE_COUNT]);

      const records = await policyRecords(page);
      expect(records).toHaveLength(LANE_COUNT);
      assertLaneSizeLimits(records);
      for (const record of records) {
        expect(record.remoteDescriptions.length).toBeGreaterThan(0);
        for (const offer of record.remoteDescriptions) {
          expect(offer.mLines).toContain("video");
          expect(offer.video?.direction).toBe("recvonly");
          expect(offer.video?.codecs).toEqual(["VP8"]);
        }
        expect(record.localDescriptions.length).toBeGreaterThan(0);
        for (const answer of record.localDescriptions) {
          expect(answer.mLines).toContain("video");
          expect(answer.video?.direction).toBe("inactive");
        }
      }

      await verifyDisk(page, contents.length, expectedHash);
    } finally {
      child.kill();
    }
  });
});
