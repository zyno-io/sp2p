// SPDX-License-Identifier: MIT

// Realistic-WAN transfer checks: all four transfer pairings under simulated
// 150 ms RTT with light loss (see scripts/ci/netns.sh, scripts/ci/netem.sh,
// and docs/testing.md for the full design). Skipped unless
// SP2P_NETEM_PROFILE is set, which it only is inside the CI netem job's
// shaped network namespace — running this suite unshaped would silently
// prove nothing.
//
// Each pairing proves: hash integrity, the 8-lane WebRTC policy where
// applicable, Chrome's enlarged UDP receive buffer (the "buffer hint" —
// see web/src/webrtc.ts addBufferHint / internal/conn/webrtc.go
// addBufferHint), that WebRTC traffic is actually shaped while signaling is
// not, and no throughput collapse against a floor in perf-floors.json.
// Per-pairing numeric-only results land in test-results/perf/*.json — never
// addresses, transfer codes, or SDP.

import { execSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Browser, Page } from "@playwright/test";
import { expect, test } from "./fixtures";
import {
  browserProcessPids, chooseFile, cleanupTemporaryDirectories, observeConnections,
  receiveToDisk, temporaryDirectory, udpSockets, verifyDisk, watchCLI,
} from "./helpers";

test.skip(!process.env.SP2P_NETEM_PROFILE, "set SP2P_NETEM_PROFILE (see docs/testing.md) to run this suite inside the shaped sp2p netns");

// Above the 64 MiB parallel-negotiation threshold on both browser and CLI
// automatic mode, so every WebRTC-carrying pairing reaches the full 8 lanes.
const SIZE = 128 * 1024 * 1024;
const contents = randomBytes(SIZE);
const expectedHash = createHash("sha256").update(contents).digest("hex");

const BUFFER_HINT_RB_BYTES = 2 * 1024 * 1024; // 1 MiB requested, doubled by the kernel
const SHAPED_RTT_FLOOR_SEC = 0.12; // profiles add >=150ms RTT; well clear of natural LAN/loopback RTT
const SIGNALING_HEALTH_MEDIAN_MS_CEILING = 20;

const PERF_DIR = join(__dirname, "..", "..", "test-results", "perf");
const PROFILE = process.env.SP2P_NETEM_PROFILE ?? "";
const FLOORS: Record<string, number> =
  (JSON.parse(readFileSync(join(__dirname, "perf-floors.json"), "utf8")) as Record<string, Record<string, number>>)[PROFILE] ?? {};
// wan500 roughly triples per-lane recovery time; allow for it.
const TRANSFER_TIMEOUT_MS = PROFILE === "wan500" ? 600_000 : 180_000;
// Extended checks' repeats gate on medians in perf-summary.mjs instead of per repeat.
const GATE_PER_TEST = process.env.SP2P_NETEM_GATE_PER_TEST !== "0";

function mbps(bytes: number, durationMs: number): number {
  return bytes / 1e6 / (durationMs / 1000);
}

function writePerfRecord(pairing: string, record: Record<string, unknown>): void {
  mkdirSync(PERF_DIR, { recursive: true });
  const full = { pairing, profile: process.env.SP2P_NETEM_PROFILE, ...record };
  const info = test.info();
  // One file per repeat and attempt, so --repeat-each runs don't overwrite each other.
  writeFileSync(join(PERF_DIR, `${pairing}.r${info.repeatEachIndex}.a${info.retry}.json`), JSON.stringify(full, null, 2) + "\n");
  const floor = FLOORS[pairing];
  if (GATE_PER_TEST && floor !== undefined && typeof record.mbps === "number") {
    expect(record.mbps, `${pairing}: ${record.mbps} MB/s below floor ${floor} MB/s`).toBeGreaterThanOrEqual(floor);
  }
}

// ── Signaling bypass check ──────────────────────────────────────────────────

// Five /health round trips from Node (never shaped: signaling TCP on the
// fixed test-server port is filtered to the bypass band in netem.sh).
async function signalingHealthMedianMs(baseURL: string): Promise<number> {
  const samples: number[] = [];
  for (let i = 0; i < 5; i++) {
    const start = performance.now();
    const response = await fetch(`${baseURL}/health`);
    await response.text();
    samples.push(performance.now() - start);
  }
  samples.sort((a, b) => a - b);
  return samples[Math.floor(samples.length / 2)];
}

// ── WebRTC stats (candidate-pair RTT, discarded-on-send) ───────────────────

// Wraps window.RTCPeerConnection before any app code runs so every
// connection (primary + every lane) on this page is reachable for
// getStats(). Only numeric stats are ever read back. Also logs the ICE
// candidate *types* gathered (host/srflx/relay — never addresses) if a
// connection fails, so a future ICE regression inside the namespace is
// debuggable from the job log instead of just "timed out".
async function installStatsRecorder(page: Page): Promise<void> {
  await page.addInitScript(() => {
    (window as any).__pcInstances = [];
    const Native = window.RTCPeerConnection;
    class RecordingPeerConnection extends Native {
      __candidateTypes: string[] = [];
      constructor(config?: RTCConfiguration) {
        super(config);
        (window as any).__pcInstances.push(this);
        this.addEventListener("icecandidate", (event: any) => {
          if (event.candidate?.type) this.__candidateTypes.push(event.candidate.type);
        });
        const logIfFailed = (state: string, label: string) => {
          if (state === "failed") {
            console.log(`netem-debug: ${label} failed; candidate types gathered: ${this.__candidateTypes.join(",") || "(none)"}`);
          }
        };
        this.addEventListener("connectionstatechange", () => logIfFailed(this.connectionState, "connection"));
        this.addEventListener("iceconnectionstatechange", () => logIfFailed(this.iceConnectionState, "ICE"));
      }
    }
    (window as any).RTCPeerConnection = RecordingPeerConnection;
  });
  page.on("console", message => {
    if (message.text().startsWith("netem-debug:")) console.log(`[browser] ${message.text()}`);
  });
}

interface CandidatePairSample { rttSec: number; packetsDiscardedOnSend: number; }

async function candidatePairStats(page: Page): Promise<CandidatePairSample[]> {
  return page.evaluate(async () => {
    const pcs: RTCPeerConnection[] = (window as any).__pcInstances ?? [];
    const out: { rttSec: number; packetsDiscardedOnSend: number }[] = [];
    for (const pc of pcs) {
      const report = await pc.getStats();
      for (const stat of report.values() as any) {
        if (stat.type === "candidate-pair" && (stat.nominated || stat.state === "succeeded")) {
          out.push({
            rttSec: typeof stat.currentRoundTripTime === "number" ? stat.currentRoundTripTime : 0,
            packetsDiscardedOnSend: typeof stat.packetsDiscardedOnSend === "number" ? stat.packetsDiscardedOnSend : 0,
          });
        }
      }
    }
    return out;
  });
}

function assertShapedRtt(samples: CandidatePairSample[]): void {
  // Pairs report no RTT until their first consent check completes.
  const measured = samples.filter(sample => sample.rttSec > 0);
  expect(measured.length, "no candidate-pair RTT sampled during the transfer").toBeGreaterThan(0);
  for (const sample of measured) {
    expect(sample.rttSec).toBeGreaterThanOrEqual(SHAPED_RTT_FLOOR_SEC);
  }
}

function maxDiscardedOnSend(samples: CandidatePairSample[]): number {
  return samples.reduce((max, sample) => Math.max(max, sample.packetsDiscardedOnSend), 0);
}

// ── UDP receive-buffer check (the "buffer hint") ────────────────────────────

function pageBrowser(page: Page): Browser {
  const browser = page.context().browser();
  expect(browser, "page has no attached Browser").not.toBeNull();
  return browser!;
}


// Connections and sockets close when a transfer completes, so RTT and socket
// buffers are sampled while it runs.
interface TransferSamples { pairs: CandidatePairSample[]; rbMax: number; sockets: number; }

function startSampling(pages: Page[], browser: Browser): { stop(): Promise<TransferSamples> } {
  const result: TransferSamples = { pairs: [], rbMax: 0, sockets: 0 };
  let running = true;
  const tick = async () => {
    for (const page of pages) {
      try { result.pairs.push(...await candidatePairStats(page)); } catch { /* page navigating or closed */ }
    }
    try {
      const sockets = udpSockets(await browserProcessPids(browser));
      result.sockets = Math.max(result.sockets, sockets.length);
      for (const socket of sockets) result.rbMax = Math.max(result.rbMax, socket.rb);
    } catch { /* process exited between listing and reading */ }
  };
  // Bounded so a failed assertion can't leave the loop polling forever.
  const deadline = Date.now() + 10 * 60_000;
  const loop = (async () => {
    while (running && Date.now() < deadline) {
      await tick();
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  })();
  return { async stop() { running = false; await loop; return result; } };
}

// ── netem qdisc counters (drops/packets, for the loss-ratio sanity check) ──

const PROFILE_LOSS_FRACTION: Record<string, number> = {
  wan150: 0.001,
  "wan150-cap": 0.001,
  wan500: 0,
};

function netemQdiscStats(): { packets: number; drops: number } {
  let raw: string;
  try {
    raw = execSync("tc -s qdisc show dev lo", { encoding: "utf8" });
  } catch {
    return { packets: 0, drops: 0 };
  }
  const lines = raw.split("\n");
  let capture = false;
  for (const line of lines) {
    if (/^qdisc netem 20:/.test(line)) { capture = true; continue; }
    if (!capture) continue;
    if (/^qdisc /.test(line)) break;
    const match = /Sent \d+ bytes (\d+) pkt \(dropped (\d+)/.exec(line);
    if (match) return { packets: Number(match[1]), drops: Number(match[2]) };
  }
  return { packets: 0, drops: 0 };
}

function assertSignalingUnshaped(healthMedianMs: number): void {
  expect(healthMedianMs, "signaling /health median latency should stay unshaped by netem (proves the bypass)").toBeLessThan(SIGNALING_HEALTH_MEDIAN_MS_CEILING);
}

function assertLossWithinBudget(before: { packets: number; drops: number }, after: { packets: number; drops: number }): { packets: number; drops: number } {
  const delta = { packets: after.packets - before.packets, drops: after.drops - before.drops };
  const profile = process.env.SP2P_NETEM_PROFILE ?? "";
  const lossFraction = PROFILE_LOSS_FRACTION[profile];
  if (lossFraction === undefined || delta.packets === 0) return delta;
  // netem's own configured random loss is expected; this only catches a
  // qdisc `limit` overflow (which drops far more than the configured rate).
  const budget = 2 * lossFraction + 0.005;
  expect(delta.drops / delta.packets, `netem drop ratio ${delta.drops}/${delta.packets} exceeds budget ${budget}`).toBeLessThanOrEqual(budget);
  return delta;
}

test.afterEach(() => { cleanupTemporaryDirectories(); });

test.describe.serial("netem: realistic WAN transfer pairings", () => {
  test("browser to browser", async ({ browser, baseURL }) => {
    const sender = await browser.newPage({ baseURL });
    const receiver = await browser.newPage({ baseURL });
    const senderCounts = observeConnections(sender);
    const receiverCounts = observeConnections(receiver);
    await installStatsRecorder(sender);
    await installStatsRecorder(receiver);
    await receiveToDisk(receiver);
    const before = netemQdiscStats();
    const healthMedianMs = await signalingHealthMedianMs(baseURL!);
    assertSignalingUnshaped(healthMedianMs);
    try {
      const start = Date.now();
      const code = await chooseFile(sender, contents, "netem-b2b.bin");
      await receiver.goto(`/r#${code}`);
      const sampling = startSampling([sender, receiver], browser);
      await receiver.locator(".confirm-btn").click();
      await expect(sender.locator(".complete")).toBeVisible({ timeout: TRANSFER_TIMEOUT_MS });
      await expect(receiver.locator(".complete")).toBeVisible({ timeout: TRANSFER_TIMEOUT_MS });
      const durationMs = Date.now() - start;
      const samples = await sampling.stop();
      const after = netemQdiscStats();

      await verifyDisk(receiver, contents.length, expectedHash);

      expect(senderCounts).toEqual([8]);
      expect(receiverCounts).toEqual([8]);
      const senderStats = samples.pairs;
      assertShapedRtt(senderStats);
      const { rbMax, sockets: socketCount } = samples;
      expect(socketCount, "no UDP sockets sampled for this browser's process tree").toBeGreaterThan(0);
      expect(rbMax).toBeGreaterThanOrEqual(BUFFER_HINT_RB_BYTES);
      const netem = assertLossWithinBudget(before, after);

      writePerfRecord("browser-browser", {
        bytes: SIZE, durationMs, mbps: mbps(SIZE, durationMs),
        transport: "webrtc", lanes: { sender: senderCounts[0], receiver: receiverCounts[0] },
        rbMaxBytes: rbMax, udpSocketCount: socketCount,
        candidateRttSec: senderStats.map(s => s.rttSec),
        packetsDiscardedOnSend: maxDiscardedOnSend(senderStats),
        signalingHealthMedianMs: healthMedianMs, netem,
      });
    } finally {
      await sender.close();
      await receiver.close();
    }
  });

  test("browser to CLI", async ({ page, baseURL, cliBin, wsUrl }) => {
    const browserCounts = observeConnections(page);
    await installStatsRecorder(page);
    const dest = temporaryDirectory("sp2p-netem-recv-");
    const before = netemQdiscStats();
    const healthMedianMs = await signalingHealthMedianMs(baseURL!);
    assertSignalingUnshaped(healthMedianMs);
    const start = Date.now();
    const code = await chooseFile(page, contents, "netem-b2c.bin");
    const child = spawn(cliBin, ["receive", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-output", dest, code]);
    const cli = watchCLI(child);
    const sampling = startSampling([page], pageBrowser(page));
    try {
      await expect(page.locator(".complete")).toBeVisible({ timeout: TRANSFER_TIMEOUT_MS });
      expect(await cli.exited).toBe(0);
      const durationMs = Date.now() - start;
      const samples = await sampling.stop();
      const after = netemQdiscStats();

      const received = readFileSync(join(dest, "netem-b2c.bin"));
      expect(createHash("sha256").update(received).digest("hex")).toBe(expectedHash);
      expect(received.length).toBe(SIZE);

      expect(cli.counts).toEqual([8]);
      expect(browserCounts).toEqual([8]);
      const pageStats = samples.pairs;
      assertShapedRtt(pageStats);
      const { rbMax, sockets: socketCount } = samples;
      expect(socketCount, "no UDP sockets sampled for this browser's process tree").toBeGreaterThan(0);
      expect(rbMax).toBeGreaterThanOrEqual(BUFFER_HINT_RB_BYTES);
      const netem = assertLossWithinBudget(before, after);

      writePerfRecord("browser-cli", {
        bytes: SIZE, durationMs, mbps: mbps(SIZE, durationMs),
        transport: "webrtc", lanes: { browser: browserCounts[0], cli: cli.counts[0] },
        rbMaxBytes: rbMax, udpSocketCount: socketCount,
        candidateRttSec: pageStats.map(s => s.rttSec),
        packetsDiscardedOnSend: maxDiscardedOnSend(pageStats),
        signalingHealthMedianMs: healthMedianMs, netem,
      });
    } finally {
      child.kill();
    }
  });

  test("CLI to browser", async ({ page, baseURL, cliBin, wsUrl }) => {
    const browserCounts = observeConnections(page);
    await installStatsRecorder(page);
    await receiveToDisk(page);
    const src = join(temporaryDirectory("sp2p-netem-send-"), "netem-c2b.bin");
    writeFileSync(src, contents);
    const before = netemQdiscStats();
    const healthMedianMs = await signalingHealthMedianMs(baseURL!);
    assertSignalingUnshaped(healthMedianMs);
    const start = Date.now();
    // -compress 0 keeps this pairing's data path byte-identical to the
    // source for a clean hash check; parallel-interop.spec.ts already
    // exercises compression against parallel lanes.
    const child = spawn(cliBin, ["send", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-compress", "0", src]);
    const cli = watchCLI(child);
    try {
      const code = await cli.code;
      await page.goto(`/r#${code}`);
      const sampling = startSampling([page], pageBrowser(page));
      await page.locator(".confirm-btn").click();
      await expect(page.locator(".complete")).toBeVisible({ timeout: TRANSFER_TIMEOUT_MS });
      expect(await cli.exited).toBe(0);
      const durationMs = Date.now() - start;
      const samples = await sampling.stop();
      const after = netemQdiscStats();

      await verifyDisk(page, contents.length, expectedHash);

      expect(cli.counts).toEqual([8]);
      expect(browserCounts).toEqual([8]);
      const pageStats = samples.pairs;
      assertShapedRtt(pageStats);
      const { rbMax, sockets: socketCount } = samples;
      expect(socketCount, "no UDP sockets sampled for this browser's process tree").toBeGreaterThan(0);
      expect(rbMax).toBeGreaterThanOrEqual(BUFFER_HINT_RB_BYTES);
      const netem = assertLossWithinBudget(before, after);

      writePerfRecord("cli-browser", {
        bytes: SIZE, durationMs, mbps: mbps(SIZE, durationMs),
        transport: "webrtc", lanes: { cli: cli.counts[0], browser: browserCounts[0] },
        rbMaxBytes: rbMax, udpSocketCount: socketCount,
        candidateRttSec: pageStats.map(s => s.rttSec),
        packetsDiscardedOnSend: maxDiscardedOnSend(pageStats),
        signalingHealthMedianMs: healthMedianMs, netem,
      });
    } finally {
      child.kill();
    }
  });

  test("CLI to CLI, transport auto", async ({ baseURL, cliBin, wsUrl }) => {
    const dest = temporaryDirectory("sp2p-netem-recv-");
    const src = join(temporaryDirectory("sp2p-netem-send-"), "netem-cli-auto.bin");
    writeFileSync(src, contents);
    const before = netemQdiscStats();
    const healthMedianMs = await signalingHealthMedianMs(baseURL!);
    assertSignalingUnshaped(healthMedianMs);
    const start = Date.now();
    // No -transport: auto races TCP and WebRTC. On loopback-like paths TCP
    // usually wins; record whichever the CLI actually reports instead of
    // assuming it (see internal/conn/manager.go).
    const sender = spawn(cliBin, ["send", "-format", "json", "-server", wsUrl, src]);
    const senderWatch = watchCLI(sender);
    try {
      const code = await senderWatch.code;
      const receiver = spawn(cliBin, ["receive", "-format", "json", "-server", wsUrl, "-output", dest, code]);
      const receiverWatch = watchCLI(receiver);
      try {
        expect(await receiverWatch.exited).toBe(0);
        expect(await senderWatch.exited).toBe(0);
        const durationMs = Date.now() - start;
        const after = netemQdiscStats();

        const received = readFileSync(join(dest, "netem-cli-auto.bin"));
        expect(createHash("sha256").update(received).digest("hex")).toBe(expectedHash);
        expect(received.length).toBe(SIZE);

        const netem = assertLossWithinBudget(before, after);
        writePerfRecord("cli-cli-auto", {
          bytes: SIZE, durationMs, mbps: mbps(SIZE, durationMs),
          transport: receiverWatch.transports[0] ?? senderWatch.transports[0] ?? "unknown",
          lanes: { sender: senderWatch.counts[0] ?? 1, receiver: receiverWatch.counts[0] ?? 1 },
          signalingHealthMedianMs: healthMedianMs, netem,
        });
      } finally {
        receiver.kill();
      }
    } finally {
      sender.kill();
    }
  });

  test("CLI to CLI, transport webrtc", async ({ baseURL, cliBin, wsUrl }) => {
    const dest = temporaryDirectory("sp2p-netem-recv-");
    const src = join(temporaryDirectory("sp2p-netem-send-"), "netem-cli-webrtc.bin");
    writeFileSync(src, contents);
    const before = netemQdiscStats();
    const healthMedianMs = await signalingHealthMedianMs(baseURL!);
    assertSignalingUnshaped(healthMedianMs);
    const start = Date.now();
    const sender = spawn(cliBin, ["send", "-format", "json", "-server", wsUrl, "-transport", "webrtc", src]);
    const senderWatch = watchCLI(sender);
    try {
      const code = await senderWatch.code;
      const receiver = spawn(cliBin, ["receive", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-output", dest, code]);
      const receiverWatch = watchCLI(receiver);
      try {
        expect(await receiverWatch.exited).toBe(0);
        expect(await senderWatch.exited).toBe(0);
        const durationMs = Date.now() - start;
        const after = netemQdiscStats();

        const received = readFileSync(join(dest, "netem-cli-webrtc.bin"));
        expect(createHash("sha256").update(received).digest("hex")).toBe(expectedHash);
        expect(received.length).toBe(SIZE);

        expect(senderWatch.counts).toEqual([8]);
        expect(receiverWatch.counts).toEqual([8]);
        expect(senderWatch.transports).toEqual(["webrtc"]);
        expect(receiverWatch.transports).toEqual(["webrtc"]);

        const netem = assertLossWithinBudget(before, after);
        writePerfRecord("cli-cli-webrtc", {
          bytes: SIZE, durationMs, mbps: mbps(SIZE, durationMs),
          transport: "webrtc", lanes: { sender: senderWatch.counts[0], receiver: receiverWatch.counts[0] },
          signalingHealthMedianMs: healthMedianMs, netem,
        });
      } finally {
        receiver.kill();
      }
    } finally {
      sender.kill();
    }
  });

  // Negative control: proves the rb sampler actually distinguishes hinted
  // from unhinted connections, rather than always reporting a large number.
  test("negative control: disabling the buffer hint keeps rb at the unhinted size", async ({ playwright, launchOptions, baseURL }) => {
    // Only the socket buffers matter here, not completion: without the hint
    // a transfer at high RTT can stall (the collapse the hint prevents), so
    // sample once connected and stop. 8 MiB keeps the connection busy.
    const controlContents = randomBytes(8 * 1024 * 1024);
    // A fresh browser process (there's no "browserType" fixture; the
    // netem project only ever uses chromium), so sockets from earlier
    // tests can't count.
    const browser = await playwright.chromium.launch(launchOptions);
    const sender = await browser.newPage({ baseURL });
    const receiver = await browser.newPage({ baseURL });
    // addBufferHint (web/src/webrtc.ts) wraps its addTransceiver call in a
    // try/catch and treats failure as "no hint" — making addTransceiver
    // throw reproduces "hint disabled" without touching product source.
    await sender.addInitScript(() => {
      (window as any).RTCPeerConnection.prototype.addTransceiver = () => {
        throw new Error("netem negative control: buffer hint disabled");
      };
    });
    await receiveToDisk(receiver);
    try {
      const code = await chooseFile(sender, controlContents, "netem-control.bin");
      await receiver.goto(`/r#${code}`);
      const sampling = startSampling([sender, receiver], browser);
      await receiver.locator(".confirm-btn").click();
      await expect(sender.locator(".step-p2p")).toContainText("P2P connected via WebRTC", { timeout: 60_000 });
      await new Promise(resolve => setTimeout(resolve, 5000)); // several sampling ticks
      const { rbMax, sockets: socketCount } = await sampling.stop();

      expect(socketCount).toBeGreaterThan(0);
      // An exact match against the unhinted size (131072) is too strict: a
      // plain headless Chromium also opens its own small background UDP
      // sockets unrelated to WebRTC (observed ~1 MiB, well short of the
      // hint's doubled 2 MiB) — assert the hinted *threshold* was never
      // reached instead, which is what actually proves the sampler
      // distinguishes hinted from unhinted connections.
      expect(rbMax).toBeLessThan(BUFFER_HINT_RB_BYTES);
    } finally {
      await sender.close();
      await receiver.close();
      await browser.close();
    }
  });
});
