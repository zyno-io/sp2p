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
//
// Plain describe, not describe.serial: workers:1/fullyParallel:false
// (playwright.config.ts) already run these tests in file order, so .serial
// would only add "skip the rest of the file after one failure" — which
// would hide the CLI-involving pairings (the ones that actually catch the
// os.ReadFile-style mutation this suite is designed to catch) behind an
// unrelated browser-pairing failure.

import { execSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createReadStream, createWriteStream, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { tmpdir } from "node:os";
import type { Browser, BrowserContext } from "@playwright/test";
import { expect } from "./fixtures";
import {
  browserProcessPids, chooseFileAtPath, cleanupTemporaryDirectories, flushDiagnostics, isolatedServerTest as test,
  observeConnections, receiveToDisk, temporaryDirectory, trackCLIForDiagnostics, trackForDiagnostics, verifyDiskStreaming, watchCLI,
} from "./helpers";
import type { CLIWatch } from "./helpers";

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
// several minutes. This is a per-expect()/per-wait timeout — each
// ".complete" visibility check below and each waitForCLIExit call — not a
// bound on a whole pairing test (which runs a control run and a large run
// back to back). What actually bounds the whole test is the "large"
// project's 30-minute Playwright test timeout (web/playwright.config.ts).
const TRANSFER_TIMEOUT_MS = 20 * 60_000;

// Bounds a CLI process's exit wait with a timer instead of relying solely
// on the 30-minute test timeout to eventually catch a CLI hang — without
// this, a CLI process that stalls after the browser/CLI counterpart already
// reported ".complete" (or a code) would hang until the whole test times
// out, with a far less specific failure than this gives. Most call sites
// wait on a CLI process *after* the thing that actually gates transfer
// completion (".complete", or — for runCLIToCLI's receiver, which has no
// browser ".complete" to wait on — the receive itself) already succeeded,
// so those only need a short bound for the process to actually exit
// (CLI_EXIT_TIMEOUT_MS default); runCLIToCLI's receiver wait *is* that
// completion gate, so it explicitly passes the full TRANSFER_TIMEOUT_MS.
const CLI_EXIT_TIMEOUT_MS = 60_000;

async function waitForCLIExit(cli: CLIWatch, label: string, timeoutMs = CLI_EXIT_TIMEOUT_MS): Promise<number | null> {
  let timer!: ReturnType<typeof setTimeout>;
  const timedOut = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`${label}: CLI process did not exit within ${timeoutMs}ms`)), timeoutMs);
  });
  try {
    return await Promise.race([cli.exited, timedOut]);
  } finally {
    clearTimeout(timer);
  }
}

// ── Disk headroom ────────────────────────────────────────────────────────

// A browser receiver now uses a real on-disk profile (launchPersistentContext
// below — real, disk-backed OPFS storage, matching what a real user's
// browser does), so the largest concurrent footprint within one pairing test
// is roughly: 1 source file + 1 destination file/OPFS copy + 1 browser
// profile directory holding that same OPFS copy again, all at the same
// size, plus slack for the previous run's files not yet cleaned up. Require
// comfortable headroom rather than compute this exactly — hosted-runner
// disks are the tight case this guards.
const REQUIRED_FREE_BYTES = 10 * 1024 * 1024 * 1024;

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
// Both the CLI process and every pid in a browser's process tree are read
// the same way: on Linux, /proc/<pid>/status's VmHWM is the kernel's own
// lifetime high-water mark for that process — a single read at any point
// during its life already reflects the true peak up to that point, no
// matter when it's taken. Non-Linux (local macOS iteration only — CI always
// runs this suite on ubuntu-latest) falls back to `ps -o rss=`, an
// instantaneous sample rather than a true high-water mark, so it can
// under-count between polls.
//
// CLI process: polled every 50ms via trackCLIPeakRSS. A control-run
// receiver can exit in well under 500ms, and this suite's whole point is
// comparing peaks between a fast control run and a slow large run, so
// under-sampling the fast one would silently make the relative ceiling too
// tight.
//
// Browser process tree: Chromium (browser + renderer + GPU + utility
// processes) exposes no single tree-wide high-water-mark API, but each
// individual process's own VmHWM is still a true lifetime peak for that one
// process — so rather than sampling the tree's *combined* RSS every tick
// (which, on a period as coarse as 2s, can miss an entire short-lived
// process: a fresh Chromium process can spawn, peak, and exit within one
// sampling window — the clean 64 MiB control run's whole transfer lasts
// only ~1-3s), startBrowserRSSSampling tracks each pid's own VmHWM
// independently, keeps the maximum seen per pid, and sums those per-pid
// maxima on stop(). Browsers are launched fresh per control/large run (see
// launchReceiverContext below), so each *currently-live* pid's VmHWM at
// stop() is that process's true peak for the whole run. The sum across pids
// is still only an upper bound on the tree's actual simultaneous peak, not
// a literal instant-in-time measurement — it adds together maxima each
// process reached at its own point in time, which may not all have been the
// same moment — but that's the right direction to be imprecise in for a
// ceiling check: it can only overstate the tree's memory use, never
// understate it, unlike the old per-tick VmRSS-sum method it replaced,
// which really could miss an entire short-lived process's contribution
// altogether. Ticking every 500ms still matters for two reasons VmHWM
// itself doesn't cover: discovering a new pid (a renderer, GPU, or utility
// process spawning partway through the run) promptly enough to track it at
// all, and catching a process that grows after this loop's last read of it
// but before it exits — VmHWM read at exit time isn't captured if the
// process is already gone by the next tick.

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

function trackCLIPeakRSS(pid: number, intervalMs = 50): { stop(): number } {
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

// Sums per-pid VmHWM maxima across every given Browser's process tree (a
// browser-to-browser run launches the sender and receiver as two separate
// browser processes — see launchReceiverContext below — so their trees are
// tracked together, in one shared per-pid map, not independently).
function startBrowserRSSSampling(browsers: Browser[], intervalMs = 500): { stop(): Promise<number> } {
  const peakByPid = new Map<number, number>();
  let running = true;
  const tick = async () => {
    try {
      const pidSets = await Promise.all(browsers.map(b => browserProcessPids(b)));
      const pids = new Set<number>();
      for (const set of pidSets) for (const pid of set) pids.add(pid);
      for (const pid of pids) {
        const bytes = readCLIPeakRSSBytes(pid);
        if (bytes === null) continue;
        const prev = peakByPid.get(pid) ?? 0;
        if (bytes > prev) peakByPid.set(pid, bytes);
      }
    } catch { /* a browser is closing */ }
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
      let total = 0;
      for (const bytes of peakByPid.values()) total += bytes;
      return total;
    },
  };
}

// ── Browser launch helpers ──────────────────────────────────────────────

// Chromium's default browser.newPage()/newContext() (no explicit userDataDir)
// behaves like an incognito profile: origin storage, including OPFS, is
// memory-backed rather than disk-backed there. That's invisible functionally
// (receiveToDisk/verifyDiskStreaming above still read back exactly what was
// written) but fatal to this suite's memory measurement specifically: writing
// a 1 GiB file to an in-memory OPFS store inflates the browser process's RSS
// by roughly the file's own size, which would fail the memory-scaling
// assertion on every correct build — a false positive from the test harness,
// not a real product regression, and not representative of a real user's
// browser (a real, non-incognito Chrome profile backs OPFS with real disk
// I/O). launchPersistentContext gives every page in the returned context a
// real on-disk profile, so OPFS there is disk-backed exactly like a real
// user's — confirmed locally: writing 512 MiB to OPFS raised RSS by ~530 MiB
// under a plain launch()+newPage(), vs. ~43 MiB under launchPersistentContext
// for the same write. Used for every browser page that *receives* in this
// suite (the one side that writes to OPFS); a browser that only *sends*
// (runBrowserToCLI) never writes to OPFS, so a plain launch() is fine there.
async function launchReceiverContext(playwright: any, launchOptions: any, baseURL: string): Promise<{ context: BrowserContext; browser: Browser; profileDir: string }> {
  const profileDir = temporaryDirectory("sp2p-large-profile-");
  const context: BrowserContext = await playwright.chromium.launchPersistentContext(profileDir, { ...launchOptions, baseURL });
  const browser = context.browser();
  if (!browser) throw new Error("launchPersistentContext: context.browser() was null — can't sample this context's process tree");
  return { context, browser, profileDir };
}

// ── Memory-scaling assertion ────────────────────────────────────────────

// The large (1 GiB-scale) run's peak must not exceed 1.5x the control
// (64 MiB-scale) run's peak plus 32 MiB slack, and must stay under an
// absolute backstop — see docs/testing.md for the calibration this was
// derived from. `additiveCeilingBytes`, when given, adds a third check:
// control + a fixed constant — see BROWSER_TREE_ADDITIVE_CEILING_BYTES
// below for why the browser-tree checks need this and the CLI checks don't.
function assertMemoryScaling(
  label: string, controlPeakBytes: number, largePeakBytes: number, absoluteBackstopBytes: number, additiveCeilingBytes?: number,
): void {
  // A sampler that never got a single successful reading would report 0,
  // which would otherwise pass both checks below vacuously (0 <= anything).
  expect(controlPeakBytes, `${label}: control peak RSS was never sampled (0 bytes) — the sampler likely failed`).toBeGreaterThan(0);
  expect(largePeakBytes, `${label}: large peak RSS was never sampled (0 bytes) — the sampler likely failed`).toBeGreaterThan(0);
  const relativeCeiling = 1.5 * controlPeakBytes + 32 * 1024 * 1024;
  expect(
    largePeakBytes,
    `${label}: peak RSS ${largePeakBytes} bytes exceeds relative ceiling ${relativeCeiling} bytes (1.5x control ${controlPeakBytes} + 32 MiB) — looks like memory scaling with file size`,
  ).toBeLessThanOrEqual(relativeCeiling);
  if (additiveCeilingBytes !== undefined) {
    const additiveCeiling = controlPeakBytes + additiveCeilingBytes;
    expect(
      largePeakBytes,
      `${label}: peak RSS ${largePeakBytes} bytes exceeds additive ceiling ${additiveCeiling} bytes (control ${controlPeakBytes} + ${additiveCeilingBytes} bytes) — looks like memory scaling with file size`,
    ).toBeLessThanOrEqual(additiveCeiling);
  }
  expect(
    largePeakBytes,
    `${label}: peak RSS ${largePeakBytes} bytes exceeds absolute backstop ${absoluteBackstopBytes} bytes`,
  ).toBeLessThanOrEqual(absoluteBackstopBytes);
}

const CLI_ABSOLUTE_BACKSTOP_BYTES = 512 * 1024 * 1024;
const BROWSER_TREE_ABSOLUTE_BACKSTOP_BYTES = 2 * 1024 * 1024 * 1024;

// The 1.5x-relative ceiling alone scales with Chromium's own fixed
// per-process overhead (two-plus processes' baseline RSS, tens to
// hundreds of MiB, gets multiplied by 1.5x right along with the real
// per-byte signal it's meant to catch), so a browser tree's control peak
// being unusually high — e.g. browser-to-browser's two full Chromium
// instances — loosens its own large-run ceiling by more than the relative
// check should really allow. This additive bound catches that: the large
// run's peak may exceed the control run's peak by at most this many bytes,
// regardless of how large the control peak itself is. Initial value: the
// old VmRSS-snapshot method's observed max control→large delta across
// pairings was ~161 MiB (see docs/testing.md); this adds headroom on top
// rather than reusing that number outright, since the new per-process-VmHWM
// method above is a sum of independent per-process maxima and so tends to
// read at or above what the old combined-snapshot method reported for the
// same run (see that method's own comment above) — this hasn't yet been
// confirmed against a real run of the new method. See docs/testing.md for
// whether/how it's been recalibrated since.
const BROWSER_TREE_ADDITIVE_CEILING_BYTES = 256 * 1024 * 1024;

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

// Deliberately NOT allocated via helpers.ts's temporaryDirectory: that
// tracks every directory in one shared, module-level list that
// cleanupTemporaryDirectories() (below, run from afterEach) empties
// completely on every test — which would delete these two source files
// (needed by every pairing test in this file) right after the first test.
// A plain mkdtempSync, cleaned explicitly in afterAll below, outlives each
// individual test's afterEach.
let sharedDir: string;
let largeSrcPath: string, largeHash: string;
let controlSrcPath: string, controlHash: string;

test.beforeAll(async () => {
  sharedDir = mkdtempSync(join(tmpdir(), "sp2p-large-src-"));
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

test.afterEach(async ({}, testInfo) => {
  cleanupTemporaryDirectories();
  await flushDiagnostics(testInfo);
});

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

async function runBrowserToBrowser(
  playwright: any, launchOptions: any, baseURL: string, srcPath: string, size: number, hash: string, runLabel: string,
): Promise<RunResult> {
  const senderBrowser: Browser = await playwright.chromium.launch(launchOptions);
  const { context: receiverCtx, browser: receiverBrowser } = await launchReceiverContext(playwright, launchOptions, baseURL);
  try {
    const sender = await senderBrowser.newPage({ baseURL });
    const receiver = await receiverCtx.newPage();
    trackForDiagnostics(sender, `${runLabel}-sender`);
    trackForDiagnostics(receiver, `${runLabel}-receiver`);
    const senderCounts = observeConnections(sender);
    const receiverCounts = observeConnections(receiver);
    await receiveToDisk(receiver);
    const sampling = startBrowserRSSSampling([senderBrowser, receiverBrowser]);
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
    await senderBrowser.close();
    await receiverCtx.close();
  }
}

async function runBrowserToCLI(
  playwright: any, launchOptions: any, baseURL: string, cliBin: string, wsUrl: string, srcPath: string, size: number, hash: string, runLabel: string,
): Promise<RunResult> {
  // The browser here only sends (reads from disk via File.slice(), never
  // writes to OPFS), so the incognito-style in-memory-OPFS confound above
  // doesn't apply — a plain launch() is representative and simpler.
  const browser: Browser = await playwright.chromium.launch(launchOptions);
  try {
    const page = await browser.newPage({ baseURL });
    trackForDiagnostics(page, `${runLabel}-browser`);
    const browserCounts = observeConnections(page);
    const dest = temporaryDirectory("sp2p-large-recv-");
    const sampling = startBrowserRSSSampling([browser]);
    const start = Date.now();
    const code = await chooseFileAtPath(page, srcPath);
    const child = spawn(cliBin, ["receive", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-output", dest, code]);
    const cli = watchCLI(child);
    trackCLIForDiagnostics(cli, `${runLabel}-cli-receiver`);
    const cliPeak = trackCLIPeakRSS(child.pid!);
    try {
      await expect(page.locator(".complete")).toBeVisible({ timeout: TRANSFER_TIMEOUT_MS });
      expect(await waitForCLIExit(cli, `${runLabel}-cli-receiver`)).toBe(0);
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
      // SIGKILL, not the default SIGTERM: the CLI only treats SIGTERM as a
      // graceful-cancel signal (signal.NotifyContext, cmd/sp2p/main.go) and
      // a process stuck somewhere that ignores context cancellation would
      // otherwise survive this kill — and then flushDiagnostics's `await
      // cli.code` (helpers.ts), which only resolves on process exit for a
      // receiver (it never gets a "session" event), would hang for the rest
      // of the test's afterEach, defeating the point of adding diagnostics
      // for exactly this kind of stall.
      child.kill("SIGKILL");
    }
  } finally {
    await browser.close();
  }
}

async function runCLIToBrowser(
  playwright: any, launchOptions: any, baseURL: string, cliBin: string, wsUrl: string, srcPath: string, size: number, hash: string, runLabel: string,
): Promise<RunResult> {
  const { context, browser } = await launchReceiverContext(playwright, launchOptions, baseURL);
  try {
    const page = await context.newPage();
    trackForDiagnostics(page, `${runLabel}-browser`);
    const browserCounts = observeConnections(page);
    await receiveToDisk(page);
    const sampling = startBrowserRSSSampling([browser]);
    const start = Date.now();
    const child = spawn(cliBin, ["send", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-compress", "0", srcPath]);
    const cli = watchCLI(child);
    trackCLIForDiagnostics(cli, `${runLabel}-cli-sender`);
    const cliPeak = trackCLIPeakRSS(child.pid!);
    try {
      const code = await cli.code;
      await page.goto(`/r#${code}`);
      await page.locator(".confirm-btn").click();
      await expect(page.locator(".complete")).toBeVisible({ timeout: TRANSFER_TIMEOUT_MS });
      expect(await waitForCLIExit(cli, `${runLabel}-cli-sender`)).toBe(0);
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
      child.kill("SIGKILL"); // see runBrowserToCLI's kill() comment above
    }
  } finally {
    await context.close();
  }
}

async function runCLIToCLI(cliBin: string, wsUrl: string, srcPath: string, size: number, hash: string, runLabel: string): Promise<RunResult> {
  const dest = temporaryDirectory("sp2p-large-recv-");
  const start = Date.now();
  // No -transport: auto races TCP and WebRTC, same as netem.spec.ts's
  // "CLI to CLI, transport auto" — record whichever wins rather than
  // asserting a specific transport/lane count (see internal/conn/manager.go).
  const sender = spawn(cliBin, ["send", "-format", "json", "-server", wsUrl, "-compress", "0", srcPath]);
  const senderWatch = watchCLI(sender);
  trackCLIForDiagnostics(senderWatch, `${runLabel}-cli-sender`);
  const senderPeak = trackCLIPeakRSS(sender.pid!);
  try {
    const code = await senderWatch.code;
    const receiver = spawn(cliBin, ["receive", "-format", "json", "-server", wsUrl, "-output", dest, code]);
    const receiverWatch = watchCLI(receiver);
    trackCLIForDiagnostics(receiverWatch, `${runLabel}-cli-receiver`);
    const receiverPeak = trackCLIPeakRSS(receiver.pid!);
    try {
      // This receiver wait is the pairing's actual completion gate (there's
      // no browser ".complete" here), so it gets the full transfer timeout;
      // the sender should already be finished by the time the receiver has
      // everything, so it keeps waitForCLIExit's short default.
      expect(await waitForCLIExit(receiverWatch, `${runLabel}-cli-receiver`, TRANSFER_TIMEOUT_MS)).toBe(0);
      expect(await waitForCLIExit(senderWatch, `${runLabel}-cli-sender`)).toBe(0);
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
      receiver.kill("SIGKILL"); // see runBrowserToCLI's kill() comment above
    }
  } finally {
    sender.kill("SIGKILL");
  }
}

// ── Tests ────────────────────────────────────────────────────────────────

test.describe("large: 1 GiB transfer pairings (memory + integrity + stalls)", () => {
  test("browser to browser", async ({ playwright, launchOptions, baseURL }) => {
    const control = await runBrowserToBrowser(playwright, launchOptions, baseURL!, controlSrcPath, CONTROL_SIZE, controlHash, "browser-browser.control");
    const large = await runBrowserToBrowser(playwright, launchOptions, baseURL!, largeSrcPath, LARGE_SIZE, largeHash, "browser-browser.large");
    // Written before the memory assertion so a failing run still leaves
    // numbers in the uploaded artifact for calibration/debugging.
    writeRecord("browser-browser.control", { pairing: "browser-browser", size: "control", ...control });
    writeRecord("browser-browser.large", { pairing: "browser-browser", size: "large", ...large });
    assertMemoryScaling(
      "browser-browser: browser tree", control.browserTreePeakBytes!, large.browserTreePeakBytes!,
      BROWSER_TREE_ABSOLUTE_BACKSTOP_BYTES, BROWSER_TREE_ADDITIVE_CEILING_BYTES,
    );
  });

  test("browser to CLI", async ({ playwright, launchOptions, baseURL, cliBin, wsUrl }) => {
    const control = await runBrowserToCLI(playwright, launchOptions, baseURL!, cliBin, wsUrl, controlSrcPath, CONTROL_SIZE, controlHash, "browser-cli.control");
    const large = await runBrowserToCLI(playwright, launchOptions, baseURL!, cliBin, wsUrl, largeSrcPath, LARGE_SIZE, largeHash, "browser-cli.large");
    writeRecord("browser-cli.control", { pairing: "browser-cli", size: "control", ...control });
    writeRecord("browser-cli.large", { pairing: "browser-cli", size: "large", ...large });
    assertMemoryScaling(
      "browser-cli: browser tree", control.browserTreePeakBytes!, large.browserTreePeakBytes!,
      BROWSER_TREE_ABSOLUTE_BACKSTOP_BYTES, BROWSER_TREE_ADDITIVE_CEILING_BYTES,
    );
    assertMemoryScaling("browser-cli: CLI receiver", control.cliPeakBytes!.receiver, large.cliPeakBytes!.receiver, CLI_ABSOLUTE_BACKSTOP_BYTES);
  });

  test("CLI to browser", async ({ playwright, launchOptions, baseURL, cliBin, wsUrl }) => {
    const control = await runCLIToBrowser(playwright, launchOptions, baseURL!, cliBin, wsUrl, controlSrcPath, CONTROL_SIZE, controlHash, "cli-browser.control");
    const large = await runCLIToBrowser(playwright, launchOptions, baseURL!, cliBin, wsUrl, largeSrcPath, LARGE_SIZE, largeHash, "cli-browser.large");
    writeRecord("cli-browser.control", { pairing: "cli-browser", size: "control", ...control });
    writeRecord("cli-browser.large", { pairing: "cli-browser", size: "large", ...large });
    assertMemoryScaling(
      "cli-browser: browser tree", control.browserTreePeakBytes!, large.browserTreePeakBytes!,
      BROWSER_TREE_ABSOLUTE_BACKSTOP_BYTES, BROWSER_TREE_ADDITIVE_CEILING_BYTES,
    );
    assertMemoryScaling("cli-browser: CLI sender", control.cliPeakBytes!.sender, large.cliPeakBytes!.sender, CLI_ABSOLUTE_BACKSTOP_BYTES);
  });

  test("CLI to CLI, transport auto", async ({ cliBin, wsUrl }) => {
    const control = await runCLIToCLI(cliBin, wsUrl, controlSrcPath, CONTROL_SIZE, controlHash, "cli-cli-auto.control");
    const large = await runCLIToCLI(cliBin, wsUrl, largeSrcPath, LARGE_SIZE, largeHash, "cli-cli-auto.large");
    writeRecord("cli-cli-auto.control", { pairing: "cli-cli-auto", size: "control", ...control });
    writeRecord("cli-cli-auto.large", { pairing: "cli-cli-auto", size: "large", ...large });
    assertMemoryScaling("cli-cli-auto: sender", control.cliPeakBytes!.sender, large.cliPeakBytes!.sender, CLI_ABSOLUTE_BACKSTOP_BYTES);
    assertMemoryScaling("cli-cli-auto: receiver", control.cliPeakBytes!.receiver, large.cliPeakBytes!.receiver, CLI_ABSOLUTE_BACKSTOP_BYTES);
  });
});
