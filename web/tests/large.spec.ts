// SPDX-License-Identifier: MIT

// Large-transfer checks: catches stalls, integrity bugs, and memory that
// scales with file size on long transfers. Runs a 1 GiB payload (default;
// see SP2P_LARGE_TEST_SIZE_BYTES below) across all four transfer pairings
// (browser-browser, browser-CLI, CLI-browser, CLI-CLI auto) and asserts
// completion, size, SHA-256, WebRTC lane counts where applicable, and that
// peak process memory for each pairing's 1 GiB run doesn't scale with file
// size beyond a small constant relative to a 64 MiB control run of the same
// pairing. This is deliberately NOT part of the PR-gated suite: it's slow
// (minutes per pairing) and belongs in Extended checks (runs after each
// merge to main, weekly, and gates releases) — see docs/testing.md's
// large-transfer section.
//
// Skipped unless SP2P_LARGE_TEST=1, which only the Extended checks `large`
// job (.github/workflows/extended.yml) sets.

import { execSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createReadStream, createWriteStream, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { tmpdir } from "node:os";
import type { Browser } from "@playwright/test";
import { expect } from "./fixtures";
import {
  browserProcessPids, chooseFileAtPath, cleanupTemporaryDirectories, isolatedServerTest as test,
  observeConnections, receiveToDisk, temporaryDirectory, verifyDiskStreaming, watchCLI,
} from "./helpers";

test.skip(process.env.SP2P_LARGE_TEST !== "1", "set SP2P_LARGE_TEST=1 (see docs/testing.md) to run this suite");

// ── Sizes ────────────────────────────────────────────────────────────────

// Overridable for local iteration on a slower/smaller machine; CI always
// uses the 1 GiB default. Control is scaled down to stay proportionate (and
// still meet the >=64 MiB parallel-WebRTC/parallel-TCP threshold by
// default) if the large size is ever overridden below the usual control size.
const LARGE_SIZE = Number(process.env.SP2P_LARGE_TEST_SIZE_BYTES) || 1024 * 1024 * 1024;
const CONTROL_SIZE = Math.min(64 * 1024 * 1024, Math.max(4 * 1024 * 1024, Math.floor(LARGE_SIZE / 4)));
const PARALLEL_THRESHOLD = 64 * 1024 * 1024; // internal/flow: tcpPreferThreshold/parallelMinFileSize; web: PARALLEL_MIN_BYTES

// Generous: wan150 (75ms delay + 0.1% loss) plus a 1 GiB payload can take
// several minutes; this bounds a single pairing's control+large run pair,
// well under the "large" project's 30-minute Playwright test timeout.
const TRANSFER_TIMEOUT_MS = 20 * 60_000;

// ── Disk headroom ────────────────────────────────────────────────────────

// The largest concurrent footprint within one pairing test is roughly:
// 1 source file (large or control) + 1 destination file/OPFS copy of the
// same size, plus the *other* size's files from the previous run not yet
// cleaned up in the worst case. Require comfortable headroom rather than
// compute this exactly — hosted-runner disks are the tight case this guards.
const REQUIRED_FREE_BYTES = 8 * 1024 * 1024 * 1024;

function freeSpaceBytes(path: string): number | null {
  try {
    const out = execSync(`df -k "${path}"`, { encoding: "utf8" }).trim().split("\n");
    const cols = out[out.length - 1].trim().split(/\s+/);
    const availableKB = Number(cols[3]);
    return Number.isFinite(availableKB) ? availableKB * 1024 : null;
  } catch {
    return null;
  }
}

const freeBytes = freeSpaceBytes(tmpdir());
test.skip(
  freeBytes !== null && freeBytes < REQUIRED_FREE_BYTES,
  `insufficient disk headroom for the large-transfer suite in ${tmpdir()} (need >= ${(REQUIRED_FREE_BYTES / 1e9).toFixed(1)} GB free, have ${freeBytes !== null ? (freeBytes / 1e9).toFixed(1) : "unknown"} GB)`,
);

// ── Streaming random-file generation (never buffers the whole file) ────────

// Writes `size` random bytes to `path`, hashing while writing, and resolves
// the hex SHA-256 — the file's content is never held in memory all at once,
// on either the write or (hashFileStreaming below) the read side.
function generateRandomFile(path: string, size: number, chunkBytes = 4 * 1024 * 1024): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = createWriteStream(path);
    let written = 0;
    const writeNext = () => {
      if (written >= size) { stream.end(); return; }
      const chunk = randomBytes(Math.min(chunkBytes, size - written));
      hash.update(chunk);
      written += chunk.length;
      if (stream.write(chunk)) setImmediate(writeNext);
      else stream.once("drain", writeNext);
    };
    stream.on("error", reject);
    stream.on("finish", () => resolve(hash.digest("hex")));
    writeNext();
  });
}

function hashFileStreaming(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path);
    stream.on("data", (chunk: Buffer) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", reject);
  });
}

// ── Peak-memory sampling ─────────────────────────────────────────────────
//
// CLI process: on Linux, /proc/<pid>/status's VmHWM is the kernel's own
// lifetime high-water mark for the process — a single read at any point
// during its life reflects the true peak up to that point, so polling only
// needs to catch a reading shortly before exit (the process is reaped, and
// /proc/<pid> gone, by the time Node's "exit" event fires). Non-Linux
// (local macOS iteration only — CI always runs this suite on ubuntu-latest)
// falls back to `ps -o rss=`, an instantaneous sample rather than a true
// high-water mark, so it can under-count between polls.
//
// Browser process tree: Chromium (browser + renderer + GPU + utility
// processes) exposes no equivalent high-water-mark API, so this is always a
// sampled maximum, summed across every pid in the tree, taken every ~2s
// during the transfer (see docs/testing.md).

function readCLIPeakRSSBytes(pid: number): number | null {
  try {
    const status = readFileSync(`/proc/${pid}/status`, "utf8");
    const match = /^VmHWM:\s+(\d+) kB$/m.exec(status);
    if (match) return Number(match[1]) * 1024;
  } catch { /* not Linux, or the process has already exited */ }
  try {
    const out = execSync(`ps -o rss= -p ${pid}`, { encoding: "utf8" }).trim();
    if (out) return Number(out) * 1024;
  } catch { /* process has already exited */ }
  return null;
}

function trackCLIPeakRSS(pid: number, intervalMs = 500): { stop(): number } {
  let peak = 0;
  const tick = () => {
    const bytes = readCLIPeakRSSBytes(pid);
    if (bytes !== null) peak = Math.max(peak, bytes);
  };
  tick();
  const timer = setInterval(tick, intervalMs);
  return {
    stop() {
      clearInterval(timer);
      tick();
      return peak;
    },
  };
}

function readProcessTreeRSSBytes(pids: ReadonlySet<number>): number | null {
  let total = 0;
  let sawAny = false;
  for (const pid of pids) {
    try {
      const status = readFileSync(`/proc/${pid}/status`, "utf8");
      const match = /^VmRSS:\s+(\d+) kB$/m.exec(status);
      if (match) { total += Number(match[1]) * 1024; sawAny = true; }
    } catch { /* not Linux, or this pid has already exited */ }
  }
  if (sawAny) return total;
  if (pids.size === 0) return null;
  try {
    const out = execSync(`ps -o rss= -p ${[...pids].join(",")}`, { encoding: "utf8" });
    const lines = out.split("\n").map(line => line.trim()).filter(Boolean);
    if (lines.length === 0) return null;
    return lines.reduce((sum, line) => sum + Number(line) * 1024, 0);
  } catch {
    return null;
  }
}

function startBrowserRSSSampling(browser: Browser, intervalMs = 2000): { stop(): Promise<number> } {
  let peak = 0;
  let running = true;
  const tick = async () => {
    try {
      const pids = await browserProcessPids(browser);
      const bytes = readProcessTreeRSSBytes(pids);
      if (bytes !== null) peak = Math.max(peak, bytes);
    } catch { /* browser closing */ }
  };
  const loop = (async () => {
    while (running) {
      await tick();
      await new Promise(resolve => setTimeout(resolve, intervalMs));
    }
  })();
  return {
    async stop() {
      running = false;
      await tick();
      await loop;
      return peak;
    },
  };
}

// ── Memory-scaling assertion ────────────────────────────────────────────

// The large (1 GiB-scale) run's peak must not exceed 1.5x the control
// (64 MiB-scale) run's peak plus 32 MiB slack, and must stay under an
// absolute backstop — see docs/testing.md for the calibration this was
// derived from.
function assertMemoryScaling(label: string, controlPeakBytes: number, largePeakBytes: number, absoluteBackstopBytes: number): void {
  const relativeCeiling = 1.5 * controlPeakBytes + 32 * 1024 * 1024;
  expect(
    largePeakBytes,
    `${label}: peak RSS ${largePeakBytes} bytes exceeds relative ceiling ${relativeCeiling} bytes (1.5x control ${controlPeakBytes} + 32 MiB) — looks like memory scaling with file size`,
  ).toBeLessThanOrEqual(relativeCeiling);
  expect(
    largePeakBytes,
    `${label}: peak RSS ${largePeakBytes} bytes exceeds absolute backstop ${absoluteBackstopBytes} bytes`,
  ).toBeLessThanOrEqual(absoluteBackstopBytes);
}

const CLI_ABSOLUTE_BACKSTOP_BYTES = 512 * 1024 * 1024;
const BROWSER_TREE_ABSOLUTE_BACKSTOP_BYTES = 2 * 1024 * 1024 * 1024;

// ── Perf recording ──────────────────────────────────────────────────────

const PERF_DIR = join(__dirname, "..", "..", "test-results", "perf-large");

function writeRecord(name: string, record: Record<string, unknown>): void {
  mkdirSync(PERF_DIR, { recursive: true });
  const info = test.info();
  writeFileSync(join(PERF_DIR, `${name}.r${info.repeatEachIndex}.a${info.retry}.json`), JSON.stringify(record, null, 2) + "\n");
}

function mbps(bytes: number, durationMs: number): number {
  return bytes / 1e6 / (durationMs / 1000);
}

// ── Fixtures (source files, generated once for the whole run) ──────────────

let sharedDir: string;
let largeSrcPath: string, largeHash: string;
let controlSrcPath: string, controlHash: string;

test.beforeAll(async () => {
  sharedDir = join(temporaryDirectory("sp2p-large-src-"));
  largeSrcPath = join(sharedDir, "large-src.bin");
  controlSrcPath = join(sharedDir, "control-src.bin");
  [largeHash, controlHash] = await Promise.all([
    generateRandomFile(largeSrcPath, LARGE_SIZE),
    generateRandomFile(controlSrcPath, CONTROL_SIZE),
  ]);
});

test.afterAll(() => {
  if (sharedDir) rmSync(sharedDir, { recursive: true, force: true });
});

test.afterEach(() => { cleanupTemporaryDirectories(); });

// ── Pairing runners ──────────────────────────────────────────────────────

interface RunResult {
  durationMs: number;
  bytes: number;
  mbps: number;
  cliPeakBytes?: Record<string, number>;
  browserTreePeakBytes?: number;
  lanes?: Record<string, number | undefined>;
  transport?: string;
}

async function runBrowserToBrowser(playwright: any, launchOptions: any, baseURL: string, srcPath: string, size: number, hash: string): Promise<RunResult> {
  const browser: Browser = await playwright.chromium.launch(launchOptions);
  try {
    const sender = await browser.newPage({ baseURL });
    const receiver = await browser.newPage({ baseURL });
    const senderCounts = observeConnections(sender);
    const receiverCounts = observeConnections(receiver);
    await receiveToDisk(receiver);
    const sampling = startBrowserRSSSampling(browser);
    const start = Date.now();
    const code = await chooseFileAtPath(sender, srcPath);
    await receiver.goto(`/r#${code}`);
    await receiver.locator(".confirm-btn").click();
    await expect(sender.locator(".complete")).toBeVisible({ timeout: TRANSFER_TIMEOUT_MS });
    await expect(receiver.locator(".complete")).toBeVisible({ timeout: TRANSFER_TIMEOUT_MS });
    const durationMs = Date.now() - start;
    const browserTreePeakBytes = await sampling.stop();
    await verifyDiskStreaming(receiver, size, hash);
    if (size >= PARALLEL_THRESHOLD) {
      expect(senderCounts).toEqual([8]);
      expect(receiverCounts).toEqual([8]);
    }
    return {
      durationMs, bytes: size, mbps: mbps(size, durationMs), browserTreePeakBytes,
      lanes: { sender: senderCounts[0], receiver: receiverCounts[0] },
    };
  } finally {
    await browser.close();
  }
}

async function runBrowserToCLI(playwright: any, launchOptions: any, baseURL: string, cliBin: string, wsUrl: string, srcPath: string, size: number, hash: string): Promise<RunResult> {
  const browser: Browser = await playwright.chromium.launch(launchOptions);
  try {
    const page = await browser.newPage({ baseURL });
    const browserCounts = observeConnections(page);
    const dest = temporaryDirectory("sp2p-large-recv-");
    const sampling = startBrowserRSSSampling(browser);
    const start = Date.now();
    const code = await chooseFileAtPath(page, srcPath);
    const child = spawn(cliBin, ["receive", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-output", dest, code]);
    const cli = watchCLI(child);
    const cliPeak = trackCLIPeakRSS(child.pid!);
    try {
      await expect(page.locator(".complete")).toBeVisible({ timeout: TRANSFER_TIMEOUT_MS });
      expect(await cli.exited).toBe(0);
      const durationMs = Date.now() - start;
      const browserTreePeakBytes = await sampling.stop();
      const cliPeakBytes = cliPeak.stop();
      const outPath = join(dest, basename(srcPath));
      expect(statSync(outPath).size).toBe(size);
      expect(await hashFileStreaming(outPath)).toBe(hash);
      if (size >= PARALLEL_THRESHOLD) {
        expect(cli.counts).toEqual([8]);
        expect(browserCounts).toEqual([8]);
      }
      return {
        durationMs, bytes: size, mbps: mbps(size, durationMs), browserTreePeakBytes,
        cliPeakBytes: { receiver: cliPeakBytes },
        lanes: { browser: browserCounts[0], cli: cli.counts[0] },
      };
    } finally {
      child.kill();
    }
  } finally {
    await browser.close();
  }
}

async function runCLIToBrowser(playwright: any, launchOptions: any, baseURL: string, cliBin: string, wsUrl: string, srcPath: string, size: number, hash: string): Promise<RunResult> {
  const browser: Browser = await playwright.chromium.launch(launchOptions);
  try {
    const page = await browser.newPage({ baseURL });
    const browserCounts = observeConnections(page);
    await receiveToDisk(page);
    const sampling = startBrowserRSSSampling(browser);
    const start = Date.now();
    const child = spawn(cliBin, ["send", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-compress", "0", srcPath]);
    const cli = watchCLI(child);
    const cliPeak = trackCLIPeakRSS(child.pid!);
    try {
      const code = await cli.code;
      await page.goto(`/r#${code}`);
      await page.locator(".confirm-btn").click();
      await expect(page.locator(".complete")).toBeVisible({ timeout: TRANSFER_TIMEOUT_MS });
      expect(await cli.exited).toBe(0);
      const durationMs = Date.now() - start;
      const browserTreePeakBytes = await sampling.stop();
      const cliPeakBytes = cliPeak.stop();
      await verifyDiskStreaming(page, size, hash);
      if (size >= PARALLEL_THRESHOLD) {
        expect(cli.counts).toEqual([8]);
        expect(browserCounts).toEqual([8]);
      }
      return {
        durationMs, bytes: size, mbps: mbps(size, durationMs), browserTreePeakBytes,
        cliPeakBytes: { sender: cliPeakBytes },
        lanes: { cli: cli.counts[0], browser: browserCounts[0] },
      };
    } finally {
      child.kill();
    }
  } finally {
    await browser.close();
  }
}

async function runCLIToCLI(cliBin: string, wsUrl: string, srcPath: string, size: number, hash: string): Promise<RunResult> {
  const dest = temporaryDirectory("sp2p-large-recv-");
  const start = Date.now();
  // No -transport: auto races TCP and WebRTC, same as netem.spec.ts's
  // "CLI to CLI, transport auto" — record whichever wins rather than
  // asserting a specific transport/lane count (see internal/conn/manager.go).
  const sender = spawn(cliBin, ["send", "-format", "json", "-server", wsUrl, "-compress", "0", srcPath]);
  const senderWatch = watchCLI(sender);
  const senderPeak = trackCLIPeakRSS(sender.pid!);
  try {
    const code = await senderWatch.code;
    const receiver = spawn(cliBin, ["receive", "-format", "json", "-server", wsUrl, "-output", dest, code]);
    const receiverWatch = watchCLI(receiver);
    const receiverPeak = trackCLIPeakRSS(receiver.pid!);
    try {
      expect(await receiverWatch.exited).toBe(0);
      expect(await senderWatch.exited).toBe(0);
      const durationMs = Date.now() - start;
      const senderPeakBytes = senderPeak.stop();
      const receiverPeakBytes = receiverPeak.stop();
      const outPath = join(dest, basename(srcPath));
      expect(statSync(outPath).size).toBe(size);
      expect(await hashFileStreaming(outPath)).toBe(hash);
      return {
        durationMs, bytes: size, mbps: mbps(size, durationMs),
        cliPeakBytes: { sender: senderPeakBytes, receiver: receiverPeakBytes },
        transport: receiverWatch.transports[0] ?? senderWatch.transports[0] ?? "unknown",
        lanes: { sender: senderWatch.counts[0] ?? 1, receiver: receiverWatch.counts[0] ?? 1 },
      };
    } finally {
      receiver.kill();
    }
  } finally {
    sender.kill();
  }
}

// ── Tests ────────────────────────────────────────────────────────────────

test.describe.serial("large: 1 GiB transfer pairings (memory + integrity + stalls)", () => {
  test("browser to browser", async ({ playwright, launchOptions, baseURL }) => {
    const control = await runBrowserToBrowser(playwright, launchOptions, baseURL!, controlSrcPath, CONTROL_SIZE, controlHash);
    const large = await runBrowserToBrowser(playwright, launchOptions, baseURL!, largeSrcPath, LARGE_SIZE, largeHash);
    assertMemoryScaling("browser-browser: browser tree", control.browserTreePeakBytes!, large.browserTreePeakBytes!, BROWSER_TREE_ABSOLUTE_BACKSTOP_BYTES);
    writeRecord("browser-browser.control", { pairing: "browser-browser", size: "control", ...control });
    writeRecord("browser-browser.large", { pairing: "browser-browser", size: "large", ...large });
  });

  test("browser to CLI", async ({ playwright, launchOptions, baseURL, cliBin, wsUrl }) => {
    const control = await runBrowserToCLI(playwright, launchOptions, baseURL!, cliBin, wsUrl, controlSrcPath, CONTROL_SIZE, controlHash);
    const large = await runBrowserToCLI(playwright, launchOptions, baseURL!, cliBin, wsUrl, largeSrcPath, LARGE_SIZE, largeHash);
    assertMemoryScaling("browser-cli: browser tree", control.browserTreePeakBytes!, large.browserTreePeakBytes!, BROWSER_TREE_ABSOLUTE_BACKSTOP_BYTES);
    assertMemoryScaling("browser-cli: CLI receiver", control.cliPeakBytes!.receiver, large.cliPeakBytes!.receiver, CLI_ABSOLUTE_BACKSTOP_BYTES);
    writeRecord("browser-cli.control", { pairing: "browser-cli", size: "control", ...control });
    writeRecord("browser-cli.large", { pairing: "browser-cli", size: "large", ...large });
  });

  test("CLI to browser", async ({ playwright, launchOptions, baseURL, cliBin, wsUrl }) => {
    const control = await runCLIToBrowser(playwright, launchOptions, baseURL!, cliBin, wsUrl, controlSrcPath, CONTROL_SIZE, controlHash);
    const large = await runCLIToBrowser(playwright, launchOptions, baseURL!, cliBin, wsUrl, largeSrcPath, LARGE_SIZE, largeHash);
    assertMemoryScaling("cli-browser: browser tree", control.browserTreePeakBytes!, large.browserTreePeakBytes!, BROWSER_TREE_ABSOLUTE_BACKSTOP_BYTES);
    assertMemoryScaling("cli-browser: CLI sender", control.cliPeakBytes!.sender, large.cliPeakBytes!.sender, CLI_ABSOLUTE_BACKSTOP_BYTES);
    writeRecord("cli-browser.control", { pairing: "cli-browser", size: "control", ...control });
    writeRecord("cli-browser.large", { pairing: "cli-browser", size: "large", ...large });
  });

  test("CLI to CLI, transport auto", async ({ cliBin, wsUrl }) => {
    const control = await runCLIToCLI(cliBin, wsUrl, controlSrcPath, CONTROL_SIZE, controlHash);
    const large = await runCLIToCLI(cliBin, wsUrl, largeSrcPath, LARGE_SIZE, largeHash);
    assertMemoryScaling("cli-cli-auto: sender", control.cliPeakBytes!.sender, large.cliPeakBytes!.sender, CLI_ABSOLUTE_BACKSTOP_BYTES);
    assertMemoryScaling("cli-cli-auto: receiver", control.cliPeakBytes!.receiver, large.cliPeakBytes!.receiver, CLI_ABSOLUTE_BACKSTOP_BYTES);
    writeRecord("cli-cli-auto.control", { pairing: "cli-cli-auto", size: "control", ...control });
    writeRecord("cli-cli-auto.large", { pairing: "cli-cli-auto", size: "large", ...large });
  });
});
