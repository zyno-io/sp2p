// SPDX-License-Identifier: MIT

// Shared Playwright test helpers used by more than one spec file: an
// isolated-signaling-server fixture, a throwaway-directory allocator, a CLI
// JSON event watcher, a WebRTC lane count observer, an OPFS-backed save-file
// sink, and a share-code chooser.

import { execSync, spawn } from "node:child_process";
import { writeFileSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
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
    const server = spawn(join(state.tmpDir, "sp2p-server"), ["-addr", `127.0.0.1:${port}`, "-base-url", url], { stdio: "ignore" });
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
  for (const dir of temporaryDirectories.splice(0)) rmSync(dir, { recursive: true, force: true });
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
}

// Watches a CLI child process's JSON stdout for its session code, any
// parallel_streams events (the lane count it negotiated), and the connection
// method(s) it reports as connected.
export function watchCLI(child: ChildProcess): CLIWatch {
  let pending = "";
  const counts: number[] = [];
  const transports: string[] = [];
  let resolveCode!: (code: string) => void;
  let rejectCode!: (error: Error) => void;
  const code = new Promise<string>((resolve, reject) => { resolveCode = resolve; rejectCode = reject; });
  void code.catch(() => {});
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
    }
  });
  const exited = new Promise<number | null>((resolve, reject) => {
    child.once("error", error => { reject(error); rejectCode(error); });
    child.once("exit", status => { resolve(status); rejectCode(new Error("CLI exited before session creation")); });
  });
  return { code, exited, counts, transports };
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
