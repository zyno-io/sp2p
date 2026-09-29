// SPDX-License-Identifier: MIT
//
// Post-release smoke test against production sp2p.io. Standalone Node
// script, not a Playwright spec — never picked up by `npm test` or CI's
// other jobs. Invoked directly (locally, or by .github/workflows/
// smoke-production.yml after a real deploy). See docs/testing.md's
// "Production smoke test" section.
//
// Privacy: this script talks to real, human-shareable transfer codes and
// URLs. It must never print one, in any output stream, on success or
// failure. See the `protect`/`redact`/`say` helpers below, and
// docs/testing.md for the full privacy contract.

import { parseArgs } from "node:util";
import { mkdtemp, rm, writeFile, chmod, lstat, open } from "node:fs/promises";
import { writeFileSync, renameSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { createHash, randomBytes } from "node:crypto";
import { gunzipSync } from "node:zlib";

// Playwright debug modes log full URLs (including transfer-code fragments)
// to stderr outside this script's control. Refuse to run under them, and
// only import Playwright itself after this check.
if (process.env.DEBUG || process.env.PWDEBUG) {
  console.error("smoke-prod.mjs: refusing to run with DEBUG or PWDEBUG set (would leak URLs to debug logs)");
  process.exit(2);
}
const { chromium } = await import("playwright");

const execFileP = promisify(execFile);

// ── CLI args ─────────────────────────────────────────────────────────────

const { values: args } = parseArgs({
  strict: true,
  options: {
    tag: { type: "string" },
    "expect-bundle": { type: "string", default: "" },
    "cli-tag": { type: "string", default: "" },
    "cli-asset": { type: "string", default: "auto" },
    "deploy-timeout": { type: "string", default: "600" },
    "negative-control": { type: "boolean", default: false },
  },
});

function usageError(message) {
  console.error(`smoke-prod.mjs: ${message}`);
  console.error("Usage: node web/tests/smoke-prod.mjs --tag vX.Y.Z [--expect-bundle main-XXXXXXXX.js] " +
    "[--cli-tag vX.Y.Z] [--cli-asset auto|linux-amd64|linux-arm64|darwin-amd64|darwin-arm64] " +
    "[--deploy-timeout 600] [--negative-control]");
  process.exit(2);
}

if (!args.tag) usageError("--tag is required");
const TAG_RE = /^v(\d+\.\d+\.\d+)(-cli-windows|-cli-linux|-cli-nix|-cli-mac|-server|-cli)?$/;
const tagMatch = TAG_RE.exec(args.tag);
if (!tagMatch) usageError(`--tag '${args.tag}' is not a valid release tag`);
const [, tagVersion, tagScope] = tagMatch;
if (tagScope && tagScope !== "-server") {
  usageError(`--tag '${args.tag}' is a CLI-only release; it doesn't deploy sp2p.io`);
}
const isServerOnly = tagScope === "-server";
if (isServerOnly && !args["cli-tag"]) {
  usageError("--tag is a -server release (no CLI asset); pass --cli-tag for a full release's CLI");
}
const cliTag = args["cli-tag"] || args.tag;
if (args["expect-bundle"] && !/^main-[A-Z0-9]{8}\.js$/.test(args["expect-bundle"])) {
  usageError(`--expect-bundle '${args["expect-bundle"]}' doesn't look like main-XXXXXXXX.js`);
}
const cliAssetMap = { "linux-amd64": "sp2p_linux_amd64.tar.gz", "linux-arm64": "sp2p_linux_arm64.tar.gz",
  "darwin-amd64": "sp2p_darwin_amd64.tar.gz", "darwin-arm64": "sp2p_darwin_arm64.tar.gz" };
let cliAssetKey = args["cli-asset"];
if (cliAssetKey === "auto") {
  const os = process.platform === "darwin" ? "darwin" : process.platform === "linux" ? "linux" : null;
  const arch = process.arch === "x64" ? "amd64" : process.arch === "arm64" ? "arm64" : null;
  if (!os || !arch) usageError(`--cli-asset auto: unsupported host platform/arch ${process.platform}/${process.arch}`);
  cliAssetKey = `${os}-${arch}`;
}
if (!(cliAssetKey in cliAssetMap)) usageError(`--cli-asset '${args["cli-asset"]}' must be one of: auto, ${Object.keys(cliAssetMap).join(", ")}`);
if (cliAssetKey.split("-")[0] !== process.platform.replace("win32", "windows")) {
  usageError(`--cli-asset ${cliAssetKey} doesn't match this host's OS (${process.platform}); the CLI must run locally`);
}
const cliAssetName = cliAssetMap[cliAssetKey];
const deployTimeoutMs = Number(args["deploy-timeout"]) * 1000;
if (!Number.isFinite(deployTimeoutMs) || deployTimeoutMs < 0 || deployTimeoutMs > 3600_000) usageError("--deploy-timeout must be 0-3600");
const negativeControlMode = args["negative-control"];

// ── Constants ────────────────────────────────────────────────────────────

const ORIGIN = "https://sp2p.io";
const REPO = "zyno-io/sp2p";
const MiB = 1024 * 1024;
const CLI_FILE_SIZE = 64 * MiB; // web/src/webrtc-parallel.ts PARALLEL_MIN_BYTES / internal/flow parallelMinFileSize
const BROWSER_FILE_SIZE = 8 * MiB;
// internal/server/session.go's 8-char session-ID alphabet (23456789abcdefghjkmnpqrstuvwxyz,
// i.e. digits 2-9 and a-z minus i/l/o) plus internal/crypto/seed.go's base62 seed (1-22 chars
// for a 128-bit value). FormatCode joins them with "-".
const CODE_RE = /^([2-9a-hjkmnp-z]{8})-([0-9A-Za-z]{1,22})$/;
const CODE_SCAN = /[2-9a-hjkmnp-z]{8}-[0-9A-Za-z]+/g;
const FRAGMENT_SCAN = /#[^\s"'<>)\]]*/g;
const inCI = process.env.GITHUB_ACTIONS === "true";

// ── Privacy: masking/redaction ──────────────────────────────────────────

const secrets = new Set();
// Call the instant a value is known, before it's used for anything else
// (a URL built from it, a log line, an error message). ::add-mask:: only
// hides lines GitHub Actions prints AFTER it, never retroactively, and is
// only emitted in Actions itself — printing it to a local terminal would
// print the code being masked.
function protect(...values) {
  for (const value of values) {
    if (!value || secrets.has(value)) continue;
    secrets.add(value);
    if (inCI) process.stdout.write(`::add-mask::${value}\n`);
  }
}
function redact(text) {
  let out = String(text);
  for (const s of [...secrets].sort((a, b) => b.length - a.length)) out = out.split(s).join("[redacted]");
  return out.replace(CODE_SCAN, "[redacted-code]").replace(FRAGMENT_SCAN, "#[redacted]");
}
const say = message => process.stdout.write(`[smoke] ${redact(message)}\n`);
// First line only: Playwright errors often append a multi-line "Call log"
// with the navigated URL.
const describe = error => redact(String(error?.message ?? error).split("\n")[0]).slice(0, 300);

for (const handler of ["uncaughtException", "unhandledRejection"]) {
  process.on(handler, error => {
    say(`FATAL (${handler}): ${describe(error)}`);
    process.exitCode = 1;
    process.exit(1);
  });
}

// ── Workspace + cleanup ─────────────────────────────────────────────────

const workDir = await mkdtemp(join(tmpdir(), "sp2p-smoke-"));
const cleanups = [];
async function cleanup() {
  for (const fn of cleanups.splice(0).reverse()) {
    try { await fn(); } catch { /* best effort */ }
  }
  await rm(workDir, { recursive: true, force: true }).catch(() => {});
}
for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => { cleanup().finally(() => process.exit(1)); });
}

// ── Download helpers ─────────────────────────────────────────────────────

async function fetchWithRetry(url, { tries = 3, backoffMs = 10_000, timeoutMs = 30_000, method = "GET", headers } = {}) {
  let lastError;
  for (let attempt = 1; attempt <= tries; attempt++) {
    try {
      const res = await fetch(url, { method, headers, redirect: "follow", signal: AbortSignal.timeout(timeoutMs) });
      if (res.status >= 500 && attempt < tries) { lastError = new Error(`HTTP ${res.status}`); await sleep(backoffMs); continue; }
      return res;
    } catch (error) {
      lastError = error;
      if (attempt < tries) await sleep(backoffMs);
    }
  }
  throw lastError;
}

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

const SIZE_CAP = 64 * MiB;

async function downloadAsset(tag, assetName) {
  const url = `https://github.com/${REPO}/releases/download/${tag}/${assetName}`;
  const res = await fetchWithRetry(url, { timeoutMs: 120_000 });
  if (!res.ok) throw new Error(`downloading ${assetName} from ${tag}: HTTP ${res.status}`);
  const buffer = Buffer.from(await res.arrayBuffer());
  if (buffer.length > SIZE_CAP) throw new Error(`${assetName} exceeds the ${SIZE_CAP} byte size cap`);
  return buffer;
}

async function downloadChecksums(tag) {
  const url = `https://github.com/${REPO}/releases/download/${tag}/checksums.txt`;
  const res = await fetchWithRetry(url, { timeoutMs: 30_000 });
  if (!res.ok) throw new Error(`downloading checksums.txt from ${tag}: HTTP ${res.status}`);
  return res.text();
}

// Same strictness as the bootstrap script (README.md): every non-empty line
// must be well-formed, and exactly one line must name the asset.
function checksumFor(checksumsText, assetName) {
  const lineRe = /^([0-9a-f]{64})  (?:\.\/)?([A-Za-z0-9._-]+)$/;
  let match;
  let count = 0;
  for (const line of checksumsText.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const m = lineRe.exec(line);
    if (!m) throw new Error("malformed checksums.txt line");
    if (m[2] === assetName) { match = m[1]; count++; }
  }
  if (count !== 1) throw new Error(`checksums.txt has ${count} line(s) for ${assetName} (expected exactly 1)`);
  return match;
}

function sha256(buffer) { return createHash("sha256").update(buffer).digest("hex"); }

// ── Phase: resolve the expected web bundle (if not given explicitly) ────

async function resolveExpectedBundle() {
  if (args["expect-bundle"]) return args["expect-bundle"];
  say(`resolving expected bundle from sp2p-server_${tagVersion}_linux_amd64.tar.gz (${args.tag})`);
  const checksumsText = await downloadChecksums(args.tag);
  const assetName = `sp2p-server_${tagVersion}_linux_amd64.tar.gz`;
  const expectedSha = checksumFor(checksumsText, assetName);
  const archive = await downloadAsset(args.tag, assetName);
  if (sha256(archive) !== expectedSha) throw new Error(`${assetName}: checksum mismatch`);
  // The Go binary embeds web/dist/index.html verbatim (embed.FS stores file
  // bytes uncompressed inside the binary); a raw substring scan across the
  // decompressed tar for the literal bundle reference avoids needing a tar
  // parser or extracting/running the server binary at all.
  const decompressed = gunzipSync(archive);
  const text = decompressed.toString("latin1"); // lossless byte<->codepoint mapping for a binary blob
  const found = new Set([...text.matchAll(/src="(main-[A-Z0-9]{8}\.js)"/g)].map(m => m[1]));
  if (found.size !== 1) throw new Error(`expected exactly one main-*.js reference in ${assetName}, found ${found.size}`);
  return [...found][0];
}

// ── Phase: install the CLI ──────────────────────────────────────────────

async function installCLI() {
  say(`installing CLI: ${cliAssetName} from ${cliTag}`);
  const checksumsText = await downloadChecksums(cliTag);
  const expectedSha = checksumFor(checksumsText, cliAssetName);
  const archive = await downloadAsset(cliTag, cliAssetName);
  if (sha256(archive) !== expectedSha) throw new Error(`${cliAssetName}: checksum mismatch`);
  const cliDir = join(workDir, "cli");
  await writeFile(join(workDir, "cli.tar.gz"), archive);
  await execFileP("tar", ["-xzf", join(workDir, "cli.tar.gz"), "-C", ensureDirSync(cliDir)]);
  const bin = join(cliDir, "sp2p");
  const stat = await lstat(bin);
  if (!stat.isFile()) throw new Error("extracted sp2p is not a regular file");
  await chmod(bin, 0o755);
  const xdgDir = ensureDirSync(join(workDir, "xdg"));
  const identity = await execFileP(bin, ["version"], { env: cleanCLIEnv(xdgDir), timeout: 15_000 });
  const cliVersionMatch = /^sp2p (\S+)/.exec(identity.stdout);
  if (!cliVersionMatch) throw new Error("could not parse `sp2p version` output");
  say(`CLI identity: sp2p ${cliVersionMatch[1]}`);
  const wantVersion = TAG_RE.exec(cliTag)?.[1];
  if (cliVersionMatch[1] !== wantVersion) {
    throw new Error(`CLI reports version ${cliVersionMatch[1]}, expected ${wantVersion}`);
  }
  return { bin, xdgDir };
}

function ensureDirSync(dir) {
  // mkdtemp already made workDir; subdirectories are created synchronously
  // here so callers (execFile args) can use the path immediately.
  mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanCLIEnv(xdgDir) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.startsWith("SP2P_")) delete env[key];
  env.XDG_CONFIG_HOME = xdgDir;
  return env;
}

// ── Phase: wait for the deploy ───────────────────────────────────────────

async function waitForDeploy(bundle) {
  say(`waiting up to ${deployTimeoutMs / 1000}s for sp2p.io to serve ${bundle}, version ${tagVersion}`);
  const deadline = Date.now() + deployTimeoutMs;
  let streak = 0;
  let last = "no successful check yet";
  for (;;) {
    try {
      const res = await fetch(`${ORIGIN}/?smoke=${Date.now()}`, {
        headers: { accept: "text/html", "cache-control": "no-cache" }, // else the root route serves the curl bootstrap script
        cache: "no-store", redirect: "error", signal: AbortSignal.timeout(15_000),
      });
      const html = res.ok ? await res.text() : "";
      const bundles = new Set([...html.matchAll(/<script\s+src="(main-[A-Z0-9]{8}\.js)"/g)].map(m => m[1]));
      const versions = new Set([...html.matchAll(/data-version="([^"]*)"/g)].map(m => m[1]));
      const bundleOK = bundles.size === 1 && bundles.has(bundle);
      const versionOK = versions.size === 1 && versions.has(tagVersion);
      let assetOK = false;
      if (bundleOK) {
        const head = await fetch(`${ORIGIN}/${bundle}`, { method: "HEAD", signal: AbortSignal.timeout(15_000) });
        assetOK = head.ok;
      }
      last = `HTTP ${res.status}, bundle=${[...bundles].join(",") || "none"}, version=${[...versions].join(",") || "none"}, asset=${assetOK}`;
      streak = (bundleOK && versionOK && assetOK) ? streak + 1 : 0;
      if (streak >= 2) { say(`deploy confirmed: ${bundle}, version ${tagVersion}`); return; }
    } catch (error) {
      last = describe(error);
      streak = 0;
    }
    if (Date.now() > deadline) throw new Error(`sp2p.io did not serve ${bundle} / version ${tagVersion} within ${deployTimeoutMs / 1000}s (last: ${last})`);
    await sleep(15_000);
  }
}

// ── Phase: build source files ────────────────────────────────────────────

async function buildSourceFile(path, size) {
  const fh = await open(path, "w");
  const hash = createHash("sha256");
  try {
    let written = 0;
    while (written < size) {
      const chunkSize = Math.min(MiB, size - written);
      // Fresh random bytes (not a repeated block) each iteration so the
      // CLI's default zstd compression can't shrink the payload — this is
      // meant to simulate a real transfer's wire size, not test compression.
      const chunk = randomBytes(chunkSize);
      hash.update(chunk);
      await fh.write(chunk);
      written += chunkSize;
    }
  } finally { await fh.close(); }
  return hash.digest("hex");
}

// ── Browser helpers ──────────────────────────────────────────────────────

function pageProbeInit({ receiver, forceRelayOnly }) {
  const p = (window.__smoke = { lanes: null, turnAvailable: null, pcs: 0, turnConfigured: 0, relayCandidates: 0 });
  const nativeLog = console.log;
  console.log = (...a) => {
    if (typeof a[0] === "string") {
      const lanes = /authenticated WebRTC connections: (\d+)/.exec(a[0]);
      if (lanes) p.lanes = Number(lanes[1]);
      const turn = /TURN available: (true|false)/.exec(a[0]);
      if (turn) p.turnAvailable = turn[1] === "true";
    }
    return nativeLog.apply(console, a);
  };
  const relayLine = /(?:^|\s)typ relay(?:\s|$)/;
  const scanSdp = sdp => {
    for (const line of String(sdp ?? "").split(/\r?\n/)) {
      if (line.startsWith("a=candidate:") && relayLine.test(line)) p.relayCandidates++;
    }
  };
  const NativePC = window.RTCPeerConnection;
  window.RTCPeerConnection = class extends NativePC {
    constructor(config = {}, ...rest) {
      const urls = (config.iceServers || []).flatMap(s => [].concat(s.urls || []));
      super(forceRelayOnly ? { ...config, iceTransportPolicy: "relay" } : config, ...rest);
      p.pcs++;
      if (urls.some(u => /^turns?:/i.test(u))) p.turnConfigured++;
      this.addEventListener("icecandidate", e => { if (e.candidate?.type === "relay") p.relayCandidates++; });
    }
    setRemoteDescription(desc, ...rest) { scanSdp(desc?.sdp); return super.setRemoteDescription(desc, ...rest); }
    addIceCandidate(candidate, ...rest) {
      if (relayLine.test(String(candidate?.candidate ?? ""))) p.relayCandidates++;
      return super.addIceCandidate(candidate, ...rest);
    }
  };
  if (receiver) {
    window.showSaveFilePicker = async () => {
      const root = await navigator.storage.getDirectory();
      const handle = await root.getFileHandle("smoke-output.bin", { create: true });
      window.__smokeOutput = handle;
      return handle;
    };
  }
}

async function openPage(browser, { receiver, forceRelayOnly }) {
  const context = await browser.newContext({ acceptDownloads: false });
  // Keep analytics/CSP-blocked beacons from ever seeing a live page URL.
  await context.route(/^https:\/\/static\.cloudflareinsights\.com\//, route => route.abort()).catch(() => {});
  await context.route(/\/cdn-cgi\/rum/, route => route.abort()).catch(() => {});
  const state = { relayPrompts: 0, otherDialogs: 0 };
  await context.addInitScript(pageProbeInit, { receiver, forceRelayOnly });
  const page = await context.newPage();
  page.on("dialog", dialog => {
    if (dialog.type() === "confirm" && dialog.message().startsWith("Direct P2P connection failed")) state.relayPrompts++;
    else state.otherDialogs++;
    void dialog.dismiss(); // no implicit relay consent
  });
  return { context, page, state };
}

async function samplePage(page) {
  return page.evaluate(() => {
    const completion = document.querySelector(".complete");
    return {
      ...window.__smoke,
      complete: !!completion && !completion.classList.contains("hidden"),
      error: document.querySelector(".error-message")?.textContent?.slice(0, 200) ?? null,
      step: document.querySelector(".step-p2p")?.textContent?.slice(0, 160) ?? "",
      status: document.querySelector(".status-text")?.textContent?.slice(0, 160) ?? "",
    };
  });
}

async function pollUntilComplete(page, { timeoutMs, otherComplete = () => true, otherFailed = () => false }) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const state = await samplePage(page);
    if (state.error) throw new Error(`browser reported an error: ${state.error}`);
    if (otherFailed()) throw new Error("peer failed before this page completed");
    if (state.complete && otherComplete()) return state;
    if (Date.now() > deadline) throw new Error(`timed out waiting for completion (step="${state.step}", status="${state.status}")`);
    await sleep(1000);
  }
}

// Streams the receiver's OPFS output back to Node in 4 MiB slices and hashes
// it incrementally — production serves no /crypto-test.js, so the
// full-buffer-in-page hashing helpers in web/tests/helpers.ts don't apply.
async function streamHashReceivedFile(page) {
  const size = await page.evaluate(async () => (await window.__smokeOutput.getFile()).size);
  const hash = createHash("sha256");
  const step = 4 * MiB;
  for (let offset = 0; offset < size; offset += step) {
    const end = Math.min(size, offset + step);
    const base64 = await page.evaluate(async ([a, b]) => {
      const file = await window.__smokeOutput.getFile();
      const bytes = new Uint8Array(await file.slice(a, b).arrayBuffer());
      let binary = "";
      for (let i = 0; i < bytes.length; i += 32768) binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
      return btoa(binary);
    }, [offset, end]);
    hash.update(Buffer.from(base64, "base64"));
  }
  return { size, sha256: hash.digest("hex") };
}

const CHROMIUM_ARGS = ["--disable-features=WebRtcHideLocalIpsWithMdns"]; // hosted runners don't resolve mDNS host candidates

// ── Scenario 1: CLI (sender) → Chromium (receiver), 64 MiB ──────────────

async function scenario1({ bin, xdgDir }, sourcePath, expectedHash) {
  const browser = await chromium.launch({ headless: true, handleSIGINT: false, handleSIGTERM: false, args: CHROMIUM_ARGS });
  try {
    const { context, page, state } = await openPage(browser, { receiver: true, forceRelayOnly: false });
    const child = spawn(bin, ["send", "-format", "json", "-server", ORIGIN, "-transport", "webrtc", "-parallel", "0", "-allow-relay=false", sourcePath],
      { env: cleanCLIEnv(xdgDir), stdio: ["ignore", "pipe", "pipe"] });
    child.stderr.resume(); // drained, never printed (may echo argv/paths)
    const events = [];
    const cli = { lanes: null, method: null, relayPrompts: 0, result: null, exited: false, code: null };
    let resolveCode, rejectCode;
    const codeReady = new Promise((resolve, reject) => { resolveCode = resolve; rejectCode = reject; });
    codeReady.catch(() => {});
    let pending = "";
    child.stdout.on("data", bytes => {
      pending += bytes.toString();
      for (;;) {
        const end = pending.indexOf("\n");
        if (end < 0) break;
        const line = pending.slice(0, end);
        pending = pending.slice(end + 1);
        let event;
        try { event = JSON.parse(line); } catch { continue; }
        events.push(event.event);
        if (event.event === "session") {
          protect(event.code, event.session_id, event.share_url);
          if (!CODE_RE.test(event.code || "")) { rejectCode(new Error("CLI session code failed shape validation")); return; }
          cli.code = event.code;
          resolveCode(event.code);
        } else if (event.event === "parallel_streams") {
          cli.lanes = event.parallel_streams;
        } else if (event.event === "connection" && event.connection?.state === "connected") {
          cli.method = event.connection.method;
        } else if (event.event === "relay_required") {
          cli.relayPrompts++;
          try {
            const answerPath = `${event.response_file}.answer`;
            writeFileSync(answerPath, "deny", { mode: 0o600 });
            renameSync(answerPath, event.response_file);
          } catch { /* response file may already be gone if the peer cancelled first */ }
        } else if (event.event === "result") {
          cli.result = { outcome: event.outcome, code: event.error?.code ?? null, message: event.error?.message ? redact(event.error.message) : null };
        }
      }
    });
    const cliExited = new Promise(resolve => {
      child.once("error", () => { cli.exited = true; rejectCode(new Error("CLI process failed to start")); resolve(null); });
      child.once("exit", status => { cli.exited = true; cli.status = status; rejectCode(new Error("CLI exited before creating a session")); resolve(status); });
    });
    try {
      let timer;
      const code = await Promise.race([codeReady, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("CLI did not create a session within 60s")), 60_000); })]);
      clearTimeout(timer);
      await page.goto(`${ORIGIN}/r#${code}`, { waitUntil: "domcontentloaded", timeout: 30_000 }).catch(e => { throw new Error(`receiver page did not load: ${describe(e)}`); });
      await page.locator(".confirm-btn").click({ timeout: 30_000 });
      await pollUntilComplete(page, {
        timeoutMs: 240_000,
        otherFailed: () => cli.exited && cli.status !== 0,
      });
      await cliExited;
      if (cli.status !== 0) throw new Error(`CLI exited ${cli.status}; last result: ${JSON.stringify(cli.result)}`);
      if (cli.result?.outcome !== "completed") throw new Error(`CLI result outcome was '${cli.result?.outcome}', not 'completed'`);
      const browserState = await samplePage(page);
      const received = await streamHashReceivedFile(page);
      if (received.size !== CLI_FILE_SIZE || received.sha256 !== expectedHash) throw new Error("received file size/hash mismatch");
      if (state.relayPrompts !== 0 || cli.relayPrompts !== 0) throw new Error(`unexpected relay prompt(s): browser=${state.relayPrompts} cli=${cli.relayPrompts}`);
      if (state.otherDialogs !== 0) throw new Error(`unexpected non-relay dialog(s): ${state.otherDialogs}`);
      const probe = { ...browserState };
      if (probe.turnConfigured !== 0 || probe.relayCandidates !== 0) throw new Error(`TURN was used: turnConfigured=${probe.turnConfigured} relayCandidates=${probe.relayCandidates}`);
      if (cli.lanes !== 8 || probe.lanes !== 8) throw new Error(`expected 8 lanes on both sides, got cli=${cli.lanes} browser=${probe.lanes}`);
      if (cli.method !== "webrtc") throw new Error(`expected CLI to connect over webrtc, got ${cli.method}`);
      say(`cli-to-chromium: passed — ${received.size} bytes, sha256 match, lanes cli=${cli.lanes} browser=${probe.lanes}, relay prompts 0, TURN never configured`);
    } finally {
      child.kill("SIGTERM");
      await Promise.race([cliExited, sleep(5000)]);
      if (!cli.exited) child.kill("SIGKILL");
      await context.close();
    }
  } finally {
    await browser.close();
  }
}

// ── Scenario 2: Chromium (sender) → Chromium (receiver), 8 MiB ──────────

async function scenario2(sourcePath, expectedHash) {
  const senderBrowser = await chromium.launch({ headless: true, handleSIGINT: false, handleSIGTERM: false, args: CHROMIUM_ARGS });
  const receiverBrowser = await chromium.launch({ headless: true, handleSIGINT: false, handleSIGTERM: false, args: CHROMIUM_ARGS });
  try {
    const sender = await openPage(senderBrowser, { receiver: false, forceRelayOnly: false });
    const receiver = await openPage(receiverBrowser, { receiver: true, forceRelayOnly: false });
    try {
      await sender.page.goto(`${ORIGIN}/`, { waitUntil: "domcontentloaded", timeout: 30_000 });
      await sender.page.locator(".file-input").setInputFiles(sourcePath);
      await sender.page.locator(".share-url").waitFor({ state: "visible", timeout: 60_000 });
      const shareText = (await sender.page.locator(".share-url").textContent()) || "";
      protect(shareText);
      let url;
      try { url = new URL(shareText); } catch { throw new Error("sender share URL has an unexpected shape"); }
      const code = url.hash.slice(1);
      protect(code);
      if (url.origin !== ORIGIN || url.pathname !== "/r" || !CODE_RE.test(code)) throw new Error("sender share URL has an unexpected shape");
      const [, sessionId, seed] = CODE_RE.exec(code);
      protect(sessionId, seed);

      await receiver.page.goto(`${ORIGIN}/r#${code}`, { waitUntil: "domcontentloaded", timeout: 30_000 }).catch(e => { throw new Error(`receiver page did not load: ${describe(e)}`); });
      await receiver.page.locator(".confirm-btn").click({ timeout: 30_000 });

      await Promise.all([
        pollUntilComplete(sender.page, { timeoutMs: 120_000 }),
        pollUntilComplete(receiver.page, { timeoutMs: 120_000 }),
      ]);

      const received = await streamHashReceivedFile(receiver.page);
      if (received.size !== BROWSER_FILE_SIZE || received.sha256 !== expectedHash) throw new Error("received file size/hash mismatch");
      if (sender.state.relayPrompts !== 0 || receiver.state.relayPrompts !== 0) throw new Error("unexpected relay prompt(s)");
      if (sender.state.otherDialogs !== 0 || receiver.state.otherDialogs !== 0) throw new Error("unexpected non-relay dialog(s)");
      const senderProbe = await samplePage(sender.page);
      const receiverProbe = await samplePage(receiver.page);
      for (const [label, probe] of [["sender", senderProbe], ["receiver", receiverProbe]]) {
        if (probe.turnConfigured !== 0 || probe.relayCandidates !== 0) throw new Error(`TURN was used on the ${label}: turnConfigured=${probe.turnConfigured} relayCandidates=${probe.relayCandidates}`);
      }
      say(`chromium-to-chromium: passed — ${received.size} bytes, sha256 match, relay prompts 0, TURN never configured`);
    } finally {
      await sender.context.close();
      await receiver.context.close();
    }
  } finally {
    await senderBrowser.close();
    await receiverBrowser.close();
  }
}

// ── Negative control: prove relay denial actually blocks a relay-only path ─

async function negativeControl(cliHandle, cliSourcePath, browserSourcePath) {
  say("negative control: forcing TURN-only ICE and confirming both scenarios correctly fail");
  let sawRelayPrompt = false;
  let sawTurnAvailable = false;
  let anyTurnConfigured = false;

  const browser = await chromium.launch({ headless: true, handleSIGINT: false, handleSIGTERM: false, args: CHROMIUM_ARGS });
  try {
    const { context, page, state } = await openPage(browser, { receiver: true, forceRelayOnly: true });
    const child = spawn(cliHandle.bin, ["send", "-format", "json", "-server", ORIGIN, "-transport", "webrtc", "-parallel", "0", "-allow-relay=false", cliSourcePath],
      { env: cleanCLIEnv(cliHandle.xdgDir), stdio: ["ignore", "pipe", "pipe"] });
    child.stderr.resume();
    let pending = "";
    let cliFailed = false;
    let resolveCode, rejectCode;
    const codeReady = new Promise((resolve, reject) => { resolveCode = resolve; rejectCode = reject; });
    codeReady.catch(() => {});
    child.stdout.on("data", bytes => {
      pending += bytes.toString();
      for (;;) {
        const end = pending.indexOf("\n");
        if (end < 0) break;
        const line = pending.slice(0, end);
        pending = pending.slice(end + 1);
        let event;
        try { event = JSON.parse(line); } catch { continue; }
        if (event.event === "session") { protect(event.code, event.session_id, event.share_url); resolveCode(event.code); }
        if (event.event === "relay_required") {
          sawRelayPrompt = true;
          try {
            const answerPath = `${event.response_file}.answer`;
            writeFileSync(answerPath, "deny", { mode: 0o600 });
            renameSync(answerPath, event.response_file);
          } catch { /* ignore */ }
        }
        if (event.event === "result" && event.outcome !== "completed") cliFailed = true;
      }
    });
    const exited = new Promise(resolve => {
      child.once("error", () => resolve(null));
      child.once("exit", status => resolve(status));
    });
    try {
      let code;
      try {
        let timer;
        code = await Promise.race([codeReady, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("no session")), 60_000); })]);
        clearTimeout(timer);
      } catch { code = null; }
      if (code) {
        await page.goto(`${ORIGIN}/r#${code}`, { waitUntil: "domcontentloaded", timeout: 30_000 }).catch(() => {});
        await page.locator(".confirm-btn").click({ timeout: 30_000 }).catch(() => {});
      }
      const deadline = Date.now() + 120_000;
      let browserFailed = false;
      while (Date.now() < deadline) {
        const s = await samplePage(page).catch(() => null);
        if (s?.turnAvailable) sawTurnAvailable = true;
        if (s?.error || s?.complete) { browserFailed = !s.complete; break; }
        await sleep(1000);
      }
      const status = await Promise.race([exited, sleep(15_000).then(() => "timeout")]);
      if (status !== "timeout" && status !== 0) cliFailed = true;
      sawRelayPrompt = sawRelayPrompt || state.relayPrompts > 0;
      const finalProbe = await samplePage(page).catch(() => ({ turnConfigured: 0 }));
      anyTurnConfigured = finalProbe.turnConfigured > 0;
      if (!cliFailed && !browserFailed) throw new Error("negative control did not fail — relay denial did not block the transfer as expected");
      if (!sawRelayPrompt) throw new Error("negative control never saw a relay prompt — inconclusive");
      if (anyTurnConfigured) throw new Error("negative control connected via TURN despite denial — relay denial is not enforced");
      if (!sawTurnAvailable) throw new Error("negative control never observed TURN availability — inconclusive (server may have no TURN configured)");
    } finally {
      child.kill("SIGTERM");
      await Promise.race([exited, sleep(5000)]);
      await context.close();
    }
  } finally {
    await browser.close();
  }
  say("NEGATIVE CONTROL PASS");
}

// ── Retry wrapper ────────────────────────────────────────────────────────

async function withRetry(name, fn) {
  for (let attempt = 1; attempt <= 2; attempt++) {
    say(`${name}: attempt ${attempt}/2`);
    try {
      await fn();
      return;
    } catch (error) {
      say(`${name}: attempt ${attempt} failed: ${describe(error)}`);
      if (attempt === 2) throw new Error(`${name} failed after 2 attempts: ${describe(error)}`);
      await sleep(60_000);
    }
  }
}

// ── Main ─────────────────────────────────────────────────────────────────

try {
  const bundle = await resolveExpectedBundle();
  say(`expected bundle: ${bundle}`);
  const cliHandle = await installCLI();
  cleanups.push(async () => rm(join(workDir, "cli.tar.gz"), { force: true }));
  await waitForDeploy(bundle);

  const cliSourcePath = join(workDir, "cli-source.bin");
  const browserSourcePath = join(workDir, "browser-source.bin");
  say("generating source files");
  const cliHash = await buildSourceFile(cliSourcePath, CLI_FILE_SIZE);
  const browserHash = await buildSourceFile(browserSourcePath, BROWSER_FILE_SIZE);

  if (negativeControlMode) {
    // Reuses the already-downloaded CLI and generated files; a fresh browser
    // + CLI process, same as the real scenarios, just with TURN forced on
    // and no retry (a fixed point, not a flaky check).
    await negativeControl(cliHandle, cliSourcePath, browserSourcePath);
  } else {
    await withRetry("cli-to-chromium", () => scenario1(cliHandle, cliSourcePath, cliHash));
    await withRetry("chromium-to-chromium", () => scenario2(browserSourcePath, browserHash));
    say("PASS");
  }
} catch (error) {
  say(`FAIL: ${describe(error)}`);
  if (inCI) process.stdout.write(`::error title=Production smoke test::${redact(describe(error)).replace(/%/g, "%25").replace(/\n/g, "%0A")}\n`);
  process.exitCode = 1;
} finally {
  await cleanup();
}
