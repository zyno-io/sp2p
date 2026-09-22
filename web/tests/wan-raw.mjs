// SPDX-License-Identifier: MIT
// Native WebRTC control: no SP2P framing, credits, file I/O, AES, or hashing.
// This measures delivery of synthetic bytes, not a verified file transfer.
import { chromium } from "playwright";

if (!process.env.REMOTE_CDP) throw new Error("Set the SSH-forwarded REMOTE_CDP endpoint");
const remoteEndpoint = new URL(process.env.REMOTE_CDP);
if (!["http:", "https:"].includes(remoteEndpoint.protocol) ||
    !["127.0.0.1", "[::1]", "localhost"].includes(remoteEndpoint.hostname) ||
    remoteEndpoint.username || remoteEndpoint.password) {
  throw new Error("REMOTE_CDP must be an SSH-forwarded loopback HTTP endpoint");
}
const size = Number(process.env.SP2P_WAN_BYTES || 500_000_000);
const messageBytes = Number(process.env.SP2P_WAN_WIRE_BYTES || 65536);
const highWater = Number(process.env.SP2P_WAN_BUFFER_BYTES || 4 * 1024 * 1024);
const timeout = Number(process.env.SP2P_WAN_TIMEOUT_MS || 180000);
const lanes = Number(process.env.SP2P_WAN_LANES || 1);
if (!Number.isInteger(lanes) || lanes < 1 || lanes > 4) throw new Error("Use between one and four independent connections");
if (!Number.isFinite(timeout) || timeout <= 0) throw new Error("Invalid observation timeout");
if (!Number.isSafeInteger(size) || size < 1 || size > 1_000_000_000) throw new Error("Invalid test size");
if (!Number.isInteger(messageBytes) || messageBytes < 1 || messageBytes > 65536) throw new Error("Invalid message size");
if (!Number.isInteger(highWater) || highWater < 1 || highWater > 8 * 1024 * 1024) throw new Error("Invalid buffer size");
const local = await chromium.launch({ headless: true, handleSIGINT: false, handleSIGTERM: false });
const remote = await chromium.connectOverCDP(process.env.REMOTE_CDP).catch(async error => {
  await local.close();
  throw error;
});
const reverse = process.env.SP2P_WAN_REVERSE !== "0";
const senderContext = await (reverse ? remote : local).newContext();
const receiverContext = await (reverse ? local : remote).newContext();
let interrupted = false;
const interrupt = () => { interrupted = true; };
process.on("SIGINT", interrupt);
process.on("SIGTERM", interrupt);
try {
  const sender = await senderContext.newPage();
  const receiver = await receiverContext.newPage();
  for (const page of [sender, receiver]) {
    await page.goto("https://sp2p.io/");
    await page.evaluate(lanes => {
      window.__rawPCs = Array.from({ length: lanes }, () => new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] }));
      window.__raw = { sent: 0, received: 0, completedLanes: 0 };
      window.__gather = async pc => {
        if (pc.iceGatheringState !== "complete") {
          await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error("ICE gathering timed out")), 15000);
            pc.addEventListener("icegatheringstatechange", () => {
              if (pc.iceGatheringState === "complete") { clearTimeout(timer); resolve(); }
            });
          });
        }
        return pc.localDescription.toJSON();
      };
    }, lanes);
  }
  await receiver.evaluate(() => {
    for (const pc of window.__rawPCs) pc.ondatachannel = ({ channel }) => {
      let received = 0;
      channel.binaryType = "arraybuffer";
      channel.onmessage = ({ data }) => {
        if (typeof data === "string") {
          if (data === String(received)) window.__raw.completedLanes++;
          channel.send(data);
        } else { received += data.byteLength; window.__raw.received += data.byteLength; }
      };
    };
  });
  // SDP stays in memory and is never printed or written to an artifact.
  const offer = await sender.evaluate(async () => {
    window.__rawDCs = window.__rawPCs.map(pc => pc.createDataChannel("raw", { ordered: true }));
    return Promise.all(window.__rawPCs.map(async pc => {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      return window.__gather(pc);
    }));
  });
  const answer = await receiver.evaluate(offer => {
    return Promise.all(window.__rawPCs.map(async (pc, i) => {
      await pc.setRemoteDescription(offer[i]);
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      return window.__gather(pc);
    }));
  }, offer);
  await sender.evaluate(answer => Promise.all(window.__rawPCs.map((pc, i) => pc.setRemoteDescription(answer[i]))), answer);
  await sender.waitForFunction(() => window.__rawDCs.every(dc => dc.readyState === "open"), undefined, { timeout: 30000 });
  const start = Date.now();
  await sender.evaluate(({ size, messageBytes, highWater }) => {
    const chunk = crypto.getRandomValues(new Uint8Array(messageBytes));
    const share = Math.floor(size / window.__rawDCs.length);
    window.__rawDCs.forEach((dc, i) => {
      const total = i === window.__rawDCs.length - 1 ? size - share * i : share;
      let sent = 0;
      dc.bufferedAmountLowThreshold = Math.floor(highWater / 2);
      const pump = () => {
        while (sent < total && dc.bufferedAmount <= highWater) {
          const part = chunk.subarray(0, Math.min(chunk.length, total - sent));
          dc.send(part);
          sent += part.length;
          window.__raw.sent += part.length;
        }
        if (sent === total) {
          dc.onbufferedamountlow = null;
          dc.send(String(total));
        }
      };
      dc.onbufferedamountlow = pump;
      pump();
    });
  }, { size, messageBytes, highWater });
  for (;;) {
    const state = await receiver.evaluate(() => ({ ...window.__raw, connections: window.__rawPCs.map(pc => pc.connectionState) }));
    const elapsed = (Date.now() - start) / 1000;
    console.log(JSON.stringify({ event: "raw", elapsed, reverse, lanes, messageBytes, highWater, ...state, mbPerSecond: state.received / elapsed / 1e6 }));
    if (state.completedLanes === lanes) {
      if (state.received !== size) throw new Error("Unexpected raw byte count");
      break;
    }
    if (interrupted) throw new Error("Raw delivery observation interrupted");
    if (elapsed * 1000 > timeout || state.connections.includes("failed")) throw new Error("Raw delivery observation timed out or failed");
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
} finally {
  process.off("SIGINT", interrupt);
  process.off("SIGTERM", interrupt);
  await senderContext.close();
  await receiverContext.close();
  await local.close();
  await remote.close();
}
