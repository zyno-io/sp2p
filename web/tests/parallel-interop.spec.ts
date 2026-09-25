// SPDX-License-Identifier: MIT

import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import net from "node:net";
import { tmpdir } from "node:os";
import { createHash, randomBytes } from "node:crypto";
import type { Page } from "@playwright/test";
import { test as base, expect } from "./fixtures";

// This additional large-transfer group gets its own real signaling server.
// Do not weaken production rate limits or make the full suite depend on a
// minute of elapsed time in unrelated tests.
const test = base.extend<{}, { parallelServer: string }>({
  parallelServer: [async ({}, use) => {
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
  baseURL: async ({ parallelServer }, use) => { await use(parallelServer); },
  wsUrl: async ({ parallelServer }, use) => { await use(parallelServer.replace("http:", "ws:") + "/ws"); },
});

test.setTimeout(90000);
// Incompressible content catches encoded zstd frames slightly larger than
// their 256 KiB decoded chunks, including compression with parallel lanes.
const contents = randomBytes(64 * 1024 * 1024);
const expectedHash = createHash("sha256").update(contents).digest("hex");
const temporaryDirectories: string[] = [];
function temporaryDirectory(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirectories.push(dir);
  return dir;
}
test.afterEach(() => {
  for (const dir of temporaryDirectories.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function observeConnections(page: Page): number[] {
  const counts: number[] = [];
  page.on("console", message => {
    const match = /authenticated WebRTC connections: (\d+)/.exec(message.text());
    if (match) counts.push(Number(match[1]));
  });
  return counts;
}

async function receiveToDisk(page: Page): Promise<void> {
  await page.addInitScript(() => {
    (window as any).showSaveFilePicker = async () => {
      const root = await navigator.storage.getDirectory();
      const file = await root.getFileHandle("parallel-output", { create: true });
      (window as any).__parallelOutput = file;
      return file;
    };
  });
}

async function verifyDisk(page: Page): Promise<void> {
  const received = await page.evaluate(async () => {
    const file = await (window as any).__parallelOutput.getFile();
    const bytes = await file.arrayBuffer();
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return { size: file.size, hash: Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("") };
  });
  expect(received).toEqual({ size: contents.length, hash: expectedHash });
}

async function choose(page: Page): Promise<string> {
  const path = join(temporaryDirectory("sp2p-parallel-browser-"), "parallel.bin");
  writeFileSync(path, contents);
  await page.goto("/");
  await page.locator(".file-input").setInputFiles(path);
  await expect(page.locator(".share-url")).toBeVisible();
  const url = await page.locator(".share-url").textContent();
  return new URL(url!).hash.slice(1);
}

function watchCLI(child: ChildProcess) {
  let pending = "";
  const counts: number[] = [];
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
    }
  });
  const exited = new Promise<number | null>((resolve, reject) => {
    child.once("error", error => { reject(error); rejectCode(error); });
    child.once("exit", status => { resolve(status); rejectCode(new Error("CLI exited before session creation")); });
  });
  return { code, exited, counts };
}

for (const blockedExtras of [0, 1, 3, 7]) {
  test(`browser parallel WebRTC verifies ${8 - blockedExtras} agreed lanes`, async ({ browser, baseURL }) => {
    const sender = await browser.newPage({ baseURL }), receiver = await browser.newPage({ baseURL });
    const senderCounts = observeConnections(sender), receiverCounts = observeConnections(receiver);
    await receiveToDisk(receiver);
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
      await receiver.locator(".confirm-btn").click();
      await expect(sender.locator(".complete")).toBeVisible({ timeout: 60000 });
      await expect(receiver.locator(".complete")).toBeVisible({ timeout: 60000 });
      expect(senderCounts).toEqual([8 - blockedExtras]);
      expect(receiverCounts).toEqual(senderCounts);
      await verifyDisk(receiver);
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
    await receiveToDisk(page);
    const child = spawn(cliBin, ["send", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-compress", String(compression), src]);
    const cli = watchCLI(child);
    try {
      const code = await cli.code;
      await page.goto(`/r#${code}`);
      await page.locator(".confirm-btn").click();
      await expect(page.locator(".complete")).toBeVisible({ timeout: 60000 });
      const status = await cli.exited;
      expect(status).toBe(0);
      expect(counts).toEqual([8]); expect(cli.counts).toEqual([8]);
      await verifyDisk(page);
    } finally { child.kill(); }
  });
}
