// SPDX-License-Identifier: MIT
// Opt-in real-network test. REMOTE_CDP must be an SSH-forwarded loopback CDP
// endpoint for a disposable browser; never expose it to the public network.
import { chromium, webkit, firefox } from "playwright";
import { open, stat, readFile, readdir, appendFile } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { join } from "node:path";

const dir = process.env.SP2P_WAN_DIR;
if (!dir || !process.env.REMOTE_CDP) throw new Error("Set SP2P_WAN_DIR and REMOTE_CDP");
const remoteEndpoint = new URL(process.env.REMOTE_CDP);
if (!["http:", "https:"].includes(remoteEndpoint.protocol) ||
    !["127.0.0.1", "[::1]", "localhost"].includes(remoteEndpoint.hostname) ||
    remoteEndpoint.username || remoteEndpoint.password) {
  throw new Error("REMOTE_CDP must be an SSH-forwarded loopback HTTP endpoint");
}
const size = Number(process.env.SP2P_WAN_BYTES || 500_000_000);
const timeout = Number(process.env.SP2P_WAN_TIMEOUT_MS || 1_800_000);
const cap = Number(process.env.SP2P_WAN_MESSAGE_CAP || 0);
const variant = process.env.SP2P_WAN_VARIANT || "released";
const expectedLanes = Number(process.env.SP2P_WAN_EXPECT_LANES || 0);
if (!Number.isInteger(expectedLanes) || expectedLanes < 0 || expectedLanes > 4) throw new Error("Invalid expected lane count");
if (!/^[a-zA-Z0-9_-]+$/.test(variant)) throw new Error("Use a simple variant name");
if (!Number.isSafeInteger(size) || size <= 0 || size > 1_000_000_000) throw new Error("Use a file size between 1 byte and 1 GB");
if (!Number.isFinite(timeout) || timeout <= 0) throw new Error("Invalid observation timeout");
if (!Number.isSafeInteger(cap) || cap < 0) throw new Error("Invalid message cap");
const output = join(dir, `${variant}.jsonl`);
const filePath = join(dir, "wan-test.bin");
const emit = async value => {
  const line = JSON.stringify(value);
  const pairs = value.sender?.network?.filter(stat => stat.type === "candidate-pair") || [];
  console.log(value.event === "sample" ? JSON.stringify({
    event: value.event, elapsed: value.elapsed, sender: value.sender.progress,
    receiver: value.receiver.progress, bufferedBytes: value.sender.bufferedAmount,
    senderLagMs: value.sender.maxTimerLagMs, receiverLagMs: value.receiver.maxTimerLagMs,
    senderDiscardedPackets: pairs.length && pairs.every(pair => typeof pair.packetsDiscardedOnSend === "number")
      ? pairs.reduce((sum, pair) => sum + pair.packetsDiscardedOnSend, 0) : undefined,
    connections: value.sender.authenticatedLanes,
  }) : line);
  await appendFile(output, line + "\n");
};
let source = await stat(filePath).catch(() => null);
if (!source || source.size !== size) {
  const file = await open(filePath, "w");
  const chunk = randomBytes(1024 * 1024);
  try {
    for (let offset = 0; offset < size; offset += chunk.length) {
      await file.write(chunk.subarray(0, Math.min(chunk.length, size - offset)));
    }
  } finally { await file.close(); }
}
const hash = createHash("sha256");
for await (const chunk of createReadStream(filePath)) hash.update(chunk);
const expectedHash = hash.digest("hex");
const localEngine = process.env.SP2P_WAN_LOCAL_BROWSER || "chromium";
const browserType = { chromium, webkit, firefox }[localEngine];
if (!browserType) throw new Error("Use chromium, webkit, or firefox for the local browser");
const local = await browserType.launch({
  headless: true, handleSIGINT: false, handleSIGTERM: false,
  ...(process.env.SP2P_WAN_SOCKET_SHIM ? { env: { ...process.env, DYLD_INSERT_LIBRARIES: process.env.SP2P_WAN_SOCKET_SHIM } } : {}),
});
const remote = await chromium.connectOverCDP(process.env.REMOTE_CDP).catch(async error => {
  await local.close();
  throw error;
});
const reverse = process.env.SP2P_WAN_REVERSE === "1";
const senderContext = await (reverse ? remote : local).newContext();
const receiverContext = await (reverse ? local : remote).newContext();
const sender = await senderContext.newPage();
const receiver = await receiverContext.newPage();
let start;
let interrupted = false;
const interrupt = () => { interrupted = true; };
process.on("SIGINT", interrupt);
process.on("SIGTERM", interrupt);
try {
  for (const page of [sender, receiver]) {
    page.on("dialog", dialog => { void dialog.dismiss(); }); // No implicit relay consent.
    await page.addInitScript(({ cap }) => {
      const probe = window.__wan = { pcs: [], dcs: [], diagnostics: null, authenticatedLanes: 1, longTasks: 0, maxLongTaskMs: 0, maxTimerLagMs: 0, maxPaintGapMs: 0, receivedWireBytes: 0, sentWireBytes: 0, sentMessages: 0, maxMessageBytes: 0 };
      const originalLog = console.log;
      console.log = (...args) => {
        if (typeof args[0] === "string" && args[0].includes("transfer diagnostics")) probe.diagnostics = args[1];
        if (typeof args[0] === "string") {
          const match = /authenticated WebRTC connections: (\d+)/.exec(args[0]);
          if (match) probe.authenticatedLanes = Number(match[1]);
        }
        originalLog(...args);
      };
      let tick = performance.now(), paint = tick;
      setInterval(() => { const now = performance.now(); probe.maxTimerLagMs = Math.max(probe.maxTimerLagMs, now - tick - 100); tick = now; }, 100);
      const onPaint = now => { probe.maxPaintGapMs = Math.max(probe.maxPaintGapMs, now - paint); paint = now; requestAnimationFrame(onPaint); };
      requestAnimationFrame(onPaint);
      if (PerformanceObserver.supportedEntryTypes.includes("longtask")) {
        new PerformanceObserver(list => {
          for (const task of list.getEntries()) { probe.longTasks++; probe.maxLongTaskMs = Math.max(probe.maxLongTaskMs, task.duration); }
        }).observe({ type: "longtask", buffered: true });
      }
      const observeChannel = dc => {
        probe.dcs.push(dc);
        dc.addEventListener("message", event => { probe.receivedWireBytes += event.data.byteLength; });
        const send = dc.send.bind(dc);
        dc.send = data => {
          const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
          const step = cap || bytes.length;
          for (let offset = 0; offset < bytes.length; offset += step) {
            const piece = bytes.subarray(offset, Math.min(bytes.length, offset + step));
            send(piece); probe.sentWireBytes += piece.length; probe.sentMessages++;
            probe.maxMessageBytes = Math.max(probe.maxMessageBytes, piece.length);
          }
        };
      };
      const NativePeer = RTCPeerConnection;
      window.RTCPeerConnection = class extends NativePeer {
        constructor(...args) {
          super(...args); probe.pcs.push(this);
          this.addEventListener("datachannel", event => observeChannel(event.channel));
        }
        createDataChannel(...args) { const dc = super.createDataChannel(...args); observeChannel(dc); return dc; }
      };
    }, { cap });
    if (process.env.SP2P_WAN_ASSETS) {
      const assets = process.env.SP2P_WAN_ASSETS;
      const names = await readdir(assets);
      const bundles = names.filter(name => /^main-.*\.js$/.test(name));
      if (bundles.length !== 1) throw new Error("Expected exactly one replacement bundle");
      const [main] = bundles;
      const bundle = await readFile(join(assets, main));
      await page.route("**/main-*.js", route => route.fulfill({ contentType: "application/javascript", body: bundle }));
    }
  }
  // Replace only the picker: the production receive path writes through a real
  // FileSystemWritableFileStream in OPFS, with its normal credits and hashing.
  await receiver.addInitScript(() => {
    window.showSaveFilePicker = async () => {
      const root = await navigator.storage.getDirectory();
      const file = await root.getFileHandle("wan-output.bin", { create: true });
      window.__wanOutput = file;
      return file;
    };
  });
  await emit({ event: "start", variant, size, cap, reverse, socketBufferControl: !!process.env.SP2P_WAN_SOCKET_SHIM, localBrowser: local.version(), remoteBrowser: remote.version(), output: "OPFS disk" });
  await sender.goto("https://sp2p.io/");
  if (reverse) {
    const cdp = await senderContext.newCDPSession(sender);
    const document = await cdp.send("DOM.getDocument");
    const input = await cdp.send("DOM.querySelector", { nodeId: document.root.nodeId, selector: ".file-input" });
    await cdp.send("DOM.setFileInputFiles", { nodeId: input.nodeId, files: [process.env.SP2P_WAN_REMOTE_FILE] });
    await cdp.detach();
  } else {
    await sender.locator(".file-input").setInputFiles(filePath);
  }
  await sender.locator(".share-url").waitFor({ state: "visible" });
  const url = await sender.locator(".share-url").textContent();
  // Keep the one-use code in process memory, never in logs or artifacts.
  await receiver.goto(url);
  await sender.bringToFront();
  await receiver.bringToFront(); // Separate browser processes, both foreground.
  await receiver.locator(".confirm-btn").click();
  start = Date.now();
  const sample = page => page.evaluate(async () => {
    const p = window.__wan;
    const completion = document.querySelector(".complete");
    const result = { visibility: document.visibilityState, diagnostics: p.diagnostics, authenticatedLanes: p.authenticatedLanes, sentWireBytes: p.sentWireBytes, receivedWireBytes: p.receivedWireBytes, sentMessages: p.sentMessages, maxMessageBytes: p.maxMessageBytes, maxTimerLagMs: p.maxTimerLagMs, maxPaintGapMs: p.maxPaintGapMs, longTasks: p.longTasks, maxLongTaskMs: p.maxLongTaskMs, status: document.querySelector(".status-text")?.textContent, progress: document.querySelector(".progress-info")?.textContent, p2p: document.querySelector(".step-p2p")?.textContent, complete: !!completion && !completion.classList.contains("hidden"), error: !!document.querySelector(".error-message"), bufferedAmount: p.dcs.reduce((sum, dc) => sum + dc.bufferedAmount, 0), network: [] };
    result.ice = [];
    for (const pc of p.pcs.filter(pc => pc.connectionState !== "closed")) {
      const report = await pc.getStats().catch(() => null);
      if (!report) continue; // Completion can close a connection during sampling.
      const summary = { state: pc.iceConnectionState, local: {}, remote: {}, pairs: {} };
      report.forEach(stat => {
        const group = stat.type === "local-candidate" ? summary.local : stat.type === "remote-candidate" ? summary.remote : stat.type === "candidate-pair" ? summary.pairs : null;
        const category = stat.type === "candidate-pair" ? stat.state : stat.candidateType;
        if (group && typeof category === "string") group[category] = (group[category] || 0) + 1;
        if ((stat.type === "candidate-pair" && stat.nominated) || stat.type === "data-channel" || stat.type === "sctp-transport") {
          // Numeric statistics only: no addresses, SDP, keys, or identifiers.
          result.network.push(Object.fromEntries(Object.entries(stat).filter(([key, value]) => key === "type" || typeof value === "number")));
        }
      });
      result.ice.push(summary); // States/type counts only, never addresses or IDs.
    }
    return result;
  });
  for (;;) {
    const peers = await Promise.all([sample(sender), sample(receiver)]);
    const elapsed = (Date.now() - start) / 1000;
    await emit({ event: "sample", elapsed, sender: peers[0], receiver: peers[1] });
    if (peers.some(peer => peer.error)) throw new Error("Browser reported a connection or transfer error");
    if (peers.some(peer => peer.visibility !== "visible")) throw new Error("Foreground benchmark page became hidden");
    if (peers[0].complete && peers[1].complete) {
      if (expectedLanes && peers.some(peer => peer.authenticatedLanes !== expectedLanes)) throw new Error("Unexpected authenticated lane count");
      break;
    }
    if (interrupted) throw new Error("Transfer observation interrupted");
    if (elapsed * 1000 > timeout) throw new Error("Transfer observation timeout");
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  const elapsed = (Date.now() - start) / 1000;
  const received = await receiver.evaluate(async () => {
    const file = await window.__wanOutput.getFile();
    const bytes = await file.arrayBuffer();
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return { size: file.size, sha256: Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("") };
  });
  if (received.size !== size || received.sha256 !== expectedHash) throw new Error("Persisted file hash mismatch");
  await emit({ event: "verified", elapsed, mbPerSecond: size / elapsed / 1e6, ...received });
} catch (error) {
  const message = String(error.message).replace(/#[A-Za-z0-9_-]+/g, "#[redacted]");
  await emit({ event: "failure", message });
  process.exitCode = 1;
} finally {
  process.off("SIGINT", interrupt);
  process.off("SIGTERM", interrupt);
  await senderContext.close(); await receiverContext.close();
  await local.close(); await remote.close();
}
