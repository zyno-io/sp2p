// SPDX-License-Identifier: MIT
// Opt-in browser/CLI WAN test. SSH targets an operator-owned disposable
// container; transfer codes and raw CLI output are never written to artifacts.
import { chromium } from "playwright";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, readdir, appendFile, stat } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";

const dir = process.env.SP2P_WAN_DIR;
const host = process.env.SP2P_WAN_SSH;
const container = process.env.SP2P_WAN_CONTAINER;
const variant = process.env.SP2P_WAN_VARIANT;
const reverse = process.env.SP2P_WAN_REVERSE === "1";
const parallel = Number(process.env.SP2P_WAN_PARALLEL || 4);
const timeout = Number(process.env.SP2P_WAN_TIMEOUT_MS || 600000);
if (!dir || !host || !container || !variant) throw new Error("Set SP2P_WAN_DIR, SSH, CONTAINER, and VARIANT");
if (!/^[a-zA-Z0-9@._-]+$/.test(host) || host.startsWith("-") || !/^[a-zA-Z0-9_-]+$/.test(container) || !/^[a-zA-Z0-9_-]+$/.test(variant)) throw new Error("Invalid benchmark target or variant");
if (![1, 4].includes(parallel) || !Number.isInteger(timeout) || timeout < 1000 || timeout > 1800000) throw new Error("Invalid parallel count or timeout");
const source = join(dir, "wan-test.bin");
const sourceInfo = await stat(source);
const size = sourceInfo.size;
const hash = createHash("sha256");
for await (const chunk of createReadStream(source)) hash.update(chunk);
const expectedHash = hash.digest("hex");
const output = join(dir, `${variant}.jsonl`);
const emit = async value => {
  const line = JSON.stringify(value);
  console.log(line);
  await appendFile(output, line + "\n");
};
const quote = value => "'" + String(value).replaceAll("'", "'\\''") + "'";
const remoteArgs = args => ["-o", "BatchMode=yes", "-o", "ServerAliveInterval=15", host,
  ["docker", "exec", container, ...args].map(quote).join(" ")];
const exec = promisify(execFile);
const destination = `/work/receive-${variant}`;
if (!reverse) await exec("ssh", remoteArgs(["mkdir", "-p", destination]), { timeout: 30000 });
const browser = await chromium.launch({ headless: true, handleSIGINT: false, handleSIGTERM: false });
const page = await browser.newPage();
await page.bringToFront();
let child;
let interrupted = false;
const interrupt = () => { interrupted = true; void browser.close(); child?.kill("SIGTERM"); };
process.on("SIGINT", interrupt); process.on("SIGTERM", interrupt);
try {
  page.on("dialog", dialog => { void dialog.dismiss(); });
  await page.addInitScript(() => {
    const probe = window.__wanCLI = { connections: 1, diagnostics: null, lagMs: 0, longTasks: 0 };
    const log = console.log;
    console.log = (...args) => {
      if (typeof args[0] === "string") {
        if (args[0].includes("transfer diagnostics")) probe.diagnostics = args[1];
        const match = /authenticated WebRTC connections: (\d+)/.exec(args[0]);
        if (match) probe.connections = Number(match[1]);
      }
      log(...args);
    };
    let last = performance.now();
    setInterval(() => { const now = performance.now(); probe.lagMs = Math.max(probe.lagMs, now - last - 100); last = now; }, 100);
    if (PerformanceObserver.supportedEntryTypes.includes("longtask")) {
      new PerformanceObserver(list => { probe.longTasks += list.getEntries().length; }).observe({ type: "longtask", buffered: true });
    }
    window.showSaveFilePicker = async () => {
      const root = await navigator.storage.getDirectory();
      const file = await root.getFileHandle("wan-cli-output.bin", { create: true });
      window.__wanOutput = file;
      return file;
    };
  });
  if (process.env.SP2P_WAN_ASSETS) {
    const assets = process.env.SP2P_WAN_ASSETS;
    const names = await readdir(assets);
    const bundles = names.filter(name => /^main-.*\.js$/.test(name));
    if (bundles.length !== 1) throw new Error("Expected exactly one replacement bundle");
    const bundle = await readFile(join(assets, bundles[0]));
    await page.route("**/main-*.js", route => route.fulfill({ contentType: "application/javascript", body: bundle }));
  }
  let code;
  if (!reverse) {
    await page.goto("https://sp2p.io/");
    await page.locator(".file-input").setInputFiles(source);
    await page.locator(".share-url").waitFor();
    const url = await page.locator(".share-url").textContent();
    code = new URL(url).hash.slice(1);
  }
  let cli = { connections: 1, bytes: 0, outcome: null, exited: false, status: null };
  let resolveCode, rejectCode;
  const codeReady = new Promise((resolve, reject) => { resolveCode = resolve; rejectCode = reject; });
  void codeReady.catch(() => {});
  const args = [reverse ? "send" : "receive", "-format", "json", "-server", "wss://sp2p.io/ws", "-transport", "webrtc", "-parallel", String(parallel)];
  args.push(...(reverse ? ["-compress", "0", "/work/wan-test.bin"] : ["-output", destination, code]));
  child = spawn("ssh", remoteArgs(["timeout", String(Math.ceil(timeout / 1000)), "/work/sp2p", ...args]), { stdio: ["ignore", "pipe", "pipe"] });
  child.stderr.on("data", () => {}); // Do not echo raw stderr or private command arguments.
  let pending = "";
  child.stdout.on("data", bytes => {
    pending += bytes.toString();
    for (;;) {
      const end = pending.indexOf("\n");
      if (end < 0) break;
      const line = pending.slice(0, end); pending = pending.slice(end + 1);
      let event;
      try { event = JSON.parse(line); } catch { continue; }
      if (event.event === "session") resolveCode(event.code);
      if (event.event === "parallel_streams") cli.connections = event.parallel_streams;
      if (event.event === "progress") cli.bytes = event.bytes_transferred;
      if (event.event === "result") cli.outcome = event.outcome;
    }
  });
  const exited = new Promise(resolve => {
    child.once("error", () => { cli.exited = true; rejectCode(new Error("SSH test process failed")); resolve(null); });
    child.once("exit", status => { cli.exited = true; cli.status = status; rejectCode(new Error("CLI exited before creating a session")); resolve(status); });
  });
  const start = Date.now();
  await emit({ event: "start", variant, reverse, parallel, size, browser: browser.version() });
  if (reverse) {
    let timer;
    try { code = await Promise.race([codeReady, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Session setup timed out")), 30000); })]); }
    finally { clearTimeout(timer); }
    await page.goto(`https://sp2p.io/r#${code}`);
    await page.locator(".confirm-btn").click();
  }
  for (;;) {
    const state = await page.evaluate(() => {
      const done = document.querySelector(".complete");
      return { ...window.__wanCLI, visibility: document.visibilityState, progress: document.querySelector(".progress-info")?.textContent,
        complete: !!done && !done.classList.contains("hidden"), error: !!document.querySelector(".error-message") };
    });
    const elapsed = (Date.now() - start) / 1000;
    await emit({ event: "sample", elapsed, browser: state, cli: { ...cli } });
    if (state.error || (cli.exited && cli.status !== 0)) throw new Error("Browser or CLI transfer failed");
    if (state.visibility !== "visible") throw new Error("Foreground benchmark page became hidden");
    if (state.complete && cli.exited) {
      if (state.connections !== parallel || cli.connections !== parallel) throw new Error("Unexpected authenticated lane count");
      break;
    }
    if (interrupted || elapsed * 1000 > timeout) throw new Error("Transfer observation interrupted or timed out");
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  await exited;
  const elapsed = (Date.now() - start) / 1000;
  let received;
  if (reverse) {
    received = await page.evaluate(async () => {
      const file = await window.__wanOutput.getFile();
      const bytes = await file.arrayBuffer();
      const digest = await crypto.subtle.digest("SHA-256", bytes);
      return { size: file.size, sha256: Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("") };
    });
  } else {
    const digest = await exec("ssh", remoteArgs(["sha256sum", `${destination}/wan-test.bin`]), { timeout: 30000 });
    const length = await exec("ssh", remoteArgs(["stat", "-c", "%s", `${destination}/wan-test.bin`]), { timeout: 30000 });
    received = { sha256: digest.stdout.split(/\s/)[0], size: Number(length.stdout.trim()) };
  }
  if (received.size !== size || received.sha256 !== expectedHash) throw new Error("Persisted output size or SHA-256 mismatch");
  await emit({ event: "verified", elapsed, mbPerSecond: size / elapsed / 1e6, ...received });
} catch {
  // Errors can contain private CLI argv or a URL fragment. Emit only a fixed
  // failure marker; the numeric samples distinguish setup/transfer failure.
  await emit({ event: "failure", message: "WAN CLI benchmark did not complete and verify" });
  process.exitCode = 1;
} finally {
  process.off("SIGINT", interrupt); process.off("SIGTERM", interrupt);
  await browser.close();
  child?.kill("SIGTERM"); // Remote timeout also bounds a lost SSH connection.
}
