// SPDX-License-Identifier: MIT

// Shared Playwright test helpers used by more than one spec file: an
// isolated-signaling-server fixture, a throwaway-directory allocator,
// dump-on-failure diagnostics for both browser pages and CLI processes
// (never transfer codes), a CLI JSON event watcher, a WebRTC lane count
// observer, a cross-engine receive-path sink (real OPFS on Chromium, a
// hashed in-memory blob on Firefox/WebKit — each engine's real receive
// path), and a share-code chooser.

import { execSync, spawn } from "node:child_process";
import { writeFileSync, mkdtempSync, readFileSync, renameSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ChildProcess } from "node:child_process";
import type { Browser, Page } from "@playwright/test";
import { test as base, expect } from "./fixtures";

// ── Isolated signaling server ────────────────────────────────────────────────

// Large-transfer and parallel-lane tests get their own real signaling server
// instead of the shared one from global-setup. Do not weaken production rate
// limits or make the full suite depend on a minute of elapsed time in
// unrelated tests.
export const isolatedServerTest = base.extend<{}, { isolatedServer: string }>({
  isolatedServer: [async ({}, use) => {
    const state = JSON.parse(readFileSync(join(__dirname, "../.pw-state.json"), "utf8"));
    const listener = net.createServer();
    await new Promise<void>(resolve => listener.listen(0, "127.0.0.1", resolve));
    const port = (listener.address() as net.AddressInfo).port;
    await new Promise<void>((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
    const url = `http://127.0.0.1:${port}`;
    // global-setup.ts always writes state.serverBin (built or prebuilt,
    // with the platform-correct ".exe" suffix on Windows) — use it directly
    // rather than rebuilding a tmpDir-relative path, which would drop that
    // suffix and silently target a POSIX-only binary name.
    const server = spawn(state.serverBin, ["-addr", `127.0.0.1:${port}`, "-base-url", url], { stdio: "ignore" });
    const exited = new Promise<void>(resolve => { server.once("exit", () => resolve()); server.once("error", () => resolve()); });
    try {
      await expect.poll(async () => {
        const response = await fetch(`${url}/health`).catch(() => null);
        return response?.ok;
      }, { timeout: 10000 }).toBe(true);
      await use(url);
    } finally { server.kill(); await exited; }
  }, { scope: "worker" }],
  baseURL: async ({ isolatedServer }, use) => { await use(isolatedServer); },
  wsUrl: async ({ isolatedServer }, use) => { await use(isolatedServer.replace("http:", "ws:") + "/ws"); },
});

// ── Temporary directories ───────────────────────────────────────────────────

const temporaryDirectories: string[] = [];

export function temporaryDirectory(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirectories.push(dir);
  return dir;
}

// Call from a test.afterEach to remove every directory allocated so far.
export function cleanupTemporaryDirectories(): void {
  // maxRetries/retryDelay: on Windows, a just-killed CLI process can hold a
  // file in this directory open for a brief moment after exit, which would
  // otherwise fail this synchronous removal with EBUSY/EPERM.
  for (const dir of temporaryDirectories.splice(0)) rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}

// ── Failure diagnostics (console + step/status text; never codes/URLs) ─────

// Registers a receiver page's console/pageerror output for dump-on-failure
// diagnostics. Call once per receiver page near the start of a test, and
// call flushDiagnostics(testInfo) from a test.afterEach in the same file —
// see webrtc-policy.spec.ts for the pattern. A failing receive test (e.g. a
// ".complete" that never appears) then logs *why* instead of just the bare
// assertion failure: the page's step/status/error text and buffered console
// output. Never reads URLs, share codes, or SDP.
const diagnosticPages: { page: Page; label: string }[] = [];
const consoleLogs = new WeakMap<Page, string[]>();

export function trackForDiagnostics(page: Page, label = "page"): void {
  const logs: string[] = [];
  consoleLogs.set(page, logs);
  page.on("console", message => { logs.push(`console.${message.type()}: ${message.text()}`); });
  page.on("pageerror", error => { logs.push(`pageerror: ${error.message}`); });
  diagnosticPages.push({ page, label });
}

export async function flushDiagnostics(testInfo: { status?: string; expectedStatus: string }): Promise<void> {
  const pages = diagnosticPages.splice(0);
  const failed = testInfo.status !== testInfo.expectedStatus;
  await flushCLIDiagnostics(failed);
  if (!failed) return;
  for (const { page, label } of pages) {
    // Buffered console/pageerror lines were captured live via page.on(...)
    // and survive the page closing (e.g. a helper's own try/finally closing
    // the browser before this afterEach runs) — dump them regardless. Only
    // the live DOM snapshot below needs an open page.
    if (page.isClosed()) {
      console.log(`[diagnostics] ${label}: page already closed (dumping buffered console/pageerror lines only)`);
    } else {
      try {
        const snapshot = await page.evaluate(() => {
          const text = (selector: string) => document.querySelector(selector)?.textContent ?? null;
          const complete = document.querySelector(".complete");
          return {
            stepP2P: text(".step-p2p"),
            statusText: text(".status-text"),
            errorMessage: text(".error-message"),
            completeVisible: complete ? !complete.classList.contains("hidden") : null,
          };
        });
        console.log(`[diagnostics] ${label} DOM snapshot: ${JSON.stringify(snapshot)}`);
      } catch (error) {
        console.log(`[diagnostics] ${label}: page.evaluate failed: ${error}`);
      }
    }
    const logs = consoleLogs.get(page) ?? [];
    console.log(`[diagnostics] ${label}: ${logs.length} buffered console/pageerror lines`);
    for (const line of logs) console.log(`[diagnostics] ${label} ${line}`);
  }
}

// ── CLI JSON event watcher ──────────────────────────────────────────────────

export interface CLIWatch {
  code: Promise<string>;
  exited: Promise<number | null>;
  counts: number[];
  // Connection methods ("webrtc" | "tcp", from machineConnectionMethod in
  // internal/cli/machine.go) seen on "connection" events with state
  // "connected" — lets a test that runs in transport "auto" record which
  // one the CLI actually picked instead of assuming it.
  transports: string[];
  // Resolves to the "response_file" path from the first "relay_required"
  // event (see internal/cli/machine.go's promptRelay) — a test awaits this
  // via answerRelayPrompt below rather than assuming a prompt happens.
  // Rejects if the process exits before a relay prompt ever occurs.
  relayRequired: Promise<string>;
  // Every response ("allow"/"deny") this CLIWatch has actually had written
  // for it via answerRelayPrompt, in call order.
  relayResponses: string[];
  // Every "result" event seen (internal/cli/machine.go's machineReporter.finish)
  // — outcome plus, on failure, {code, message} — for asserting the exact
  // terminal outcome of a relay consent/denial flow.
  results: { outcome: string; error?: { code: string; message: string } }[];
  // Sanitized event log for dump-on-failure diagnostics (see
  // trackCLIForDiagnostics/flushDiagnostics below): every parsed event's
  // "event" field plus non-sensitive fields — the "session" event's "code"
  // field is dropped, never buffered here in the first place. "log" events
  // (-v verbose output, which can include full SDP blobs) are never
  // buffered here at all — they must never reach a CI log via
  // flushDiagnostics.
  eventLog: string[];
  // Raw stderr chunks. -format json always keeps the human "sp2p receive
  // <code>" announcement (internal/cli/progress.go) off stderr — that's
  // format=human-only — but flushDiagnostics still actively redacts the
  // resolved code from this before printing, as a defense-in-depth measure.
  stderr: string[];
}

// Watches a CLI child process's JSON stdout for its session code, any
// parallel_streams events (the lane count it negotiated), the connection
// method(s) it reports as connected, and (for relay tests) its relay-consent
// prompt and terminal result.
export function watchCLI(child: ChildProcess): CLIWatch {
  let pending = "";
  const counts: number[] = [];
  const transports: string[] = [];
  const relayResponses: string[] = [];
  const results: { outcome: string; error?: { code: string; message: string } }[] = [];
  const eventLog: string[] = [];
  const stderr: string[] = [];
  let resolveCode!: (code: string) => void;
  let rejectCode!: (error: Error) => void;
  const code = new Promise<string>((resolve, reject) => { resolveCode = resolve; rejectCode = reject; });
  void code.catch(() => {});
  let resolveRelayRequired!: (path: string) => void;
  let rejectRelayRequired!: (error: Error) => void;
  const relayRequired = new Promise<string>((resolve, reject) => { resolveRelayRequired = resolve; rejectRelayRequired = reject; });
  void relayRequired.catch(() => {});
  child.stdout?.on("data", bytes => {
    pending += bytes.toString();
    for (;;) {
      const end = pending.indexOf("\n");
      if (end < 0) break;
      const line = pending.slice(0, end); pending = pending.slice(end + 1);
      const event = JSON.parse(line);
      if (event.event === "session") resolveCode(event.code);
      if (event.event === "parallel_streams") counts.push(event.parallel_streams);
      if (event.event === "connection" && event.connection?.state === "connected") {
        transports.push(event.connection.method);
      }
      if (event.event === "relay_required" && event.response_file) resolveRelayRequired(event.response_file);
      if (event.event === "result") {
        const result: { outcome: string; error?: { code: string; message: string } } = { outcome: event.outcome };
        if (event.error) result.error = { code: event.error.code, message: event.error.message };
        results.push(result);
      }
      if (event.event === "log") continue; // never buffer -v output (may include SDP)
      const { code: _omitted, ...safe } = event;
      eventLog.push(JSON.stringify(safe));
    }
  });
  child.stderr?.on("data", bytes => { stderr.push(bytes.toString()); });
  const exited = new Promise<number | null>((resolve, reject) => {
    child.once("error", error => { reject(error); rejectCode(error); rejectRelayRequired(error); });
    child.once("exit", status => {
      resolve(status);
      rejectCode(new Error("CLI exited before session creation"));
      rejectRelayRequired(new Error("CLI exited before a relay prompt occurred"));
    });
  });
  return { code, exited, counts, transports, relayRequired, relayResponses, results, eventLog, stderr };
}

// Answers a CLI relay-consent prompt (see watchCLI's relayRequired above),
// writing the response atomically: the CLI polls the response file every
// 100ms (internal/cli/machine.go's promptRelay), so writing to a sibling
// path first and renaming onto the real path ensures it never observes a
// half-written response.
export async function answerRelayPrompt(cli: CLIWatch, response: "allow" | "deny"): Promise<void> {
  const path = await cli.relayRequired;
  const answerPath = `${path}.answer`;
  writeFileSync(answerPath, response, { mode: 0o600 });
  renameSync(answerPath, path);
  cli.relayResponses.push(response);
}

// ── CLI failure diagnostics (see trackForDiagnostics above) ────────────────

const diagnosticCLIs: { cli: CLIWatch; label: string }[] = [];

export function trackCLIForDiagnostics(cli: CLIWatch, label = "cli"): void {
  diagnosticCLIs.push({ cli, label });
}

// Called by flushDiagnostics (above) — kept as a separate function so a spec
// that only tracks CLI processes (no page) doesn't need to touch pages.
async function flushCLIDiagnostics(failed: boolean): Promise<void> {
  const clis = diagnosticCLIs.splice(0);
  if (!failed) return;
  for (const { cli, label } of clis) {
    // Actively redact the resolved code (if any) from everything printed
    // below, even though -format json keeps it off stdout/stderr already —
    // never log transfer codes.
    const resolvedCode = await cli.code.catch(() => null);
    const redact = (text: string): string => resolvedCode ? text.split(resolvedCode).join("[redacted]") : text;
    console.log(`[diagnostics] ${label}: ${cli.eventLog.length} JSON events`);
    for (const line of cli.eventLog) console.log(`[diagnostics] ${label} event: ${redact(line)}`);
    if (cli.stderr.length) console.log(`[diagnostics] ${label}: ${cli.stderr.length} stderr chunks`);
    for (const chunk of cli.stderr) console.log(`[diagnostics] ${label} stderr: ${redact(chunk.trimEnd())}`);
  }
}

// ── Lane observer ────────────────────────────────────────────────────────────

// Observes the browser console for the "authenticated WebRTC connections: N"
// log line webrtc-parallel.ts prints once setup finishes, returning the
// running list of counts seen (normally just one entry).
export function observeConnections(page: Page): number[] {
  const counts: number[] = [];
  page.on("console", message => {
    const match = /authenticated WebRTC connections: (\d+)/.exec(message.text());
    if (match) counts.push(Number(match[1]));
  });
  return counts;
}

// ── OPFS sink ────────────────────────────────────────────────────────────────

// Redirects the page's save-file picker to an Origin Private File System
// handle instead of a native save dialog, so a browser receiver's output can
// be read back and verified without a download prompt.
export async function receiveToDisk(page: Page): Promise<void> {
  await page.addInitScript(() => {
    (window as any).showSaveFilePicker = async () => {
      const root = await navigator.storage.getDirectory();
      const file = await root.getFileHandle("test-output", { create: true });
      (window as any).__testOutput = file;
      return file;
    };
  });
}

export async function verifyDisk(page: Page, expectedSize: number, expectedHash: string): Promise<void> {
  const received = await page.evaluate(async () => {
    const file = await (window as any).__testOutput.getFile();
    const bytes = await file.arrayBuffer();
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return { size: file.size, hash: Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("") };
  });
  expect(received).toEqual({ size: expectedSize, hash: expectedHash });
}

// ── Cross-engine receive-path sink ──────────────────────────────────────────

// Chromium gets the real OPFS disk path (receiveToDisk/verifyDisk above).
// Firefox and WebKit do not implement showSaveFilePicker for real (Firefox
// 155, WebKit 26.6, as tested here) — a real user on either engine takes
// main.ts's in-memory sink + downloadBlob (ui.ts) path, so this installs no
// picker at all for them, letting `"showSaveFilePicker" in window` read its
// real (false) value. Instead it hooks URL.createObjectURL — which
// downloadBlob calls on the Blob the app already built in memory — to hash
// that same buffer via one-shot Web Crypto, rather than reading anything
// back a second time or depending on Playwright's download handling. (An
// earlier version of this sink faked showSaveFilePicker on every engine,
// which forced Firefox/WebKit down the disk-streaming code path real users
// on those engines never take — see docs/testing.md's Engines section.)
export async function installReceiverSink(page: Page, browserName: string): Promise<void> {
  if (browserName === "chromium") {
    await receiveToDisk(page);
    return;
  }
  await page.addInitScript(() => {
    const native = URL.createObjectURL.bind(URL);
    (window as any).__blobHashPromise = null;
    (URL as any).createObjectURL = (blob: Blob) => {
      (window as any).__blobHashPromise = (async () => {
        const buffer = await blob.arrayBuffer();
        const digest = await crypto.subtle.digest("SHA-256", buffer);
        return {
          size: buffer.byteLength,
          hash: Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join(""),
        };
      })();
      return native(blob);
    };
  });
}

export async function verifyReceiverSink(page: Page, browserName: string, expectedSize: number, expectedHash: string): Promise<void> {
  if (browserName === "chromium") {
    await verifyDisk(page, expectedSize, expectedHash);
    return;
  }
  const received = await page.evaluate(async () => await (window as any).__blobHashPromise);
  expect(received).toEqual({ size: expectedSize, hash: expectedHash });
}

// ── Share code / confirmation ────────────────────────────────────────────────

// Selects a file on the sender page and returns the transfer code from its
// share URL.
export async function chooseFile(page: Page, data: Buffer, filename: string): Promise<string> {
  const path = join(temporaryDirectory("sp2p-webrtc-test-"), filename);
  writeFileSync(path, data);
  await page.goto("/");
  await page.locator(".file-input").setInputFiles(path);
  await expect(page.locator(".share-url")).toBeVisible();
  const url = await page.locator(".share-url").textContent();
  return new URL(url!).hash.slice(1);
}

// Clicks the receiver's confirmation button if one is shown; some flows skip
// it when file info isn't available yet.
export async function maybeConfirmBrowserDownload(page: Page): Promise<void> {
  try {
    await page.locator(".confirm-btn").click({ timeout: 5_000 });
  } catch {
    // Some flows may not show the confirmation card if file-info is unavailable.
  }
}

// ── UDP socket inspection (netem suite only, Linux) ─────────────────────────

export interface UdpSocketInfo {
  pid: number;
  rb: number; // requested/allocated receive buffer size, in bytes
  drops: number; // sk_drops for this socket, if the kernel/iproute2 report it
}

// Playwright's Browser has no process()/pid in the public API (that only
// exists on BrowserServer/ElectronApplication) — SystemInfo.getProcessInfo
// is a Chrome-only CDP method that instead directly lists every process
// (browser, renderer, GPU, utility, ...) belonging to a launched Chromium,
// which is what a page's WebRTC UDP socket is actually owned by.
export async function browserProcessPids(browser: Browser): Promise<Set<number>> {
  const session = await browser.newBrowserCDPSession();
  try {
    const { processInfo } = await session.send("SystemInfo.getProcessInfo");
    return new Set(processInfo.map(p => p.id));
  } finally {
    await session.detach();
  }
}

// Parses the parenthesized "skmem:(r0,rb131072,...)" group from one `ss -m`
// record into {field: value}. Never reads the address/port columns.
function parseSkmem(record: string): Record<string, number> {
  const match = /skmem:\(([^)]*)\)/.exec(record);
  if (!match) return {};
  const out: Record<string, number> = {};
  for (const field of match[1].split(",")) {
    const parsed = /^([a-z]+)(\d+)$/.exec(field.trim());
    if (parsed) out[parsed[1]] = Number(parsed[2]);
  }
  return out;
}

// Returns the UDP sockets owned by any pid in `pids` (see
// browserProcessPids), by running `ss -uanmp` (must run inside the netns —
// this is only ever called from the spec process itself, which does). Only
// numeric socket-memory fields and pids are read; no addresses or ports are
// captured.
//
// A fresh headless Chromium — even one that never touches our app — opens
// its own background UDP sockets (observed with a coincidental ~1 MiB
// receive buffer, unrelated to the WebRTC buffer hint this suite checks).
// Filtering by connection state does NOT reliably separate them from a real
// WebRTC DataChannel's socket (tried ESTAB-only: it excluded the real,
// correctly-hinted 2 MiB socket too), so this intentionally returns every
// UDP socket for the given pids and leaves distinguishing "is this hinted"
// to a threshold comparison against the *maximum* observed rb, which the
// stray ~1 MiB socket is too small to satisfy on its own.
export function udpSockets(pids: ReadonlySet<number>): UdpSocketInfo[] {
  const raw = execSync("ss -H -uanmp", { encoding: "utf8" });
  // ss wraps long lines with leading whitespace on a continuation line
  // (the skmem group in particular); rejoin those into one logical record.
  const records: string[] = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    if (/^\S/.test(line)) records.push(line);
    else if (records.length) records[records.length - 1] += " " + line.trim();
  }

  const sockets: UdpSocketInfo[] = [];
  for (const record of records) {
    const pidMatch = /pid=(\d+)/.exec(record);
    if (!pidMatch) continue;
    const pid = Number(pidMatch[1]);
    if (!pids.has(pid)) continue;
    const skmem = parseSkmem(record);
    if (skmem.rb === undefined) continue;
    sockets.push({ pid, rb: skmem.rb, drops: skmem.d ?? 0 });
  }
  return sockets;
}
