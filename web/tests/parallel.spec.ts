// SPDX-License-Identifier: MIT

import { test, expect } from "@playwright/test";
import { EncryptedChannel, deriveWebRTCLaneKeys } from "../src/crypto";
import { EncryptedFrameIO, FrameBudget, ParallelFrameIO } from "../src/frame-io";
import { DataChannelTransport, receiveFile, sendFile } from "../src/transfer";
import { createHash } from "node:crypto";
import { negotiateParallelWebRTC } from "../src/webrtc-parallel";
import type { DerivedKeys } from "../src/crypto";

class Channel extends EventTarget {
  onmessage?: (event: { data: ArrayBuffer }) => void;
  onclose?: () => void;
  onerror?: () => void;
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 0;
  readyState = "open";
  peer?: Channel;
  held: Uint8Array[] | null = null;
  sent = 0;
  send(data: Uint8Array): void {
    const copy = Uint8Array.from(data);
    this.sent++;
    if (this.held) this.held.push(copy);
    else queueMicrotask(() => this.peer?.onmessage?.({ data: copy.buffer }));
  }
  flush(): void {
    const held = this.held;
    this.held = null;
    for (const data of held || []) this.peer?.onmessage?.({ data: data.buffer as ArrayBuffer });
  }
  close(): void { if (this.readyState !== "closed") { this.readyState = "closed"; this.onclose?.(); this.dispatchEvent(new Event("close")); } }
}

async function setup(count = 2) {
  const sendBudget = new FrameBudget(), receiveBudget = new FrameBudget();
  const send: EncryptedFrameIO[] = [], receive: EncryptedFrameIO[] = [];
  const outbound: Channel[] = [], inbound: Channel[] = [];
  for (let index = 0; index < count; index++) {
    const key = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(index + 1), "AES-GCM", false, ["encrypt", "decrypt"]);
    const a = new Channel(), b = new Channel();
    a.peer = b; b.peer = a; outbound.push(a); inbound.push(b);
    send.push(new EncryptedFrameIO(a as unknown as RTCDataChannel, new EncryptedChannel(key, key), sendBudget));
    receive.push(new EncryptedFrameIO(b as unknown as RTCDataChannel, new EncryptedChannel(key, key), receiveBudget));
  }
  return { send, receive, outbound, inbound, sendBudget, receiveBudget };
}

const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const sequenced = (seq: number, payload = new Uint8Array([1])) => {
  const data = new Uint8Array(8 + payload.length);
  new DataView(data.buffer).setBigUint64(0, BigInt(seq));
  data.set(payload, 8);
  return data;
};

test("WebRTC lane HKDF matches Go and separates lane, direction, and setup nonce", async () => {
  const keys = await deriveWebRTCLaneKeys(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), 1);
  expect(Buffer.from(keys.confirm).toString("hex")).toBe("1db671558ed2f9c7812d62608c2dad77c2174caa7fc00ac3c3cbc6865abe010b");
  const raw = ["2a568d4490c34636cc13bcc236026d5135067ad6d405e522efe9b35c6793f8c6", "013df1f1091470737a0de0f5e9de22f3231189f7720413d0e828304101a5c4ab"];
  for (const [index, actual] of [keys.senderToReceiver, keys.receiverToSender].entries()) {
    const expected = await crypto.subtle.importKey("raw", Buffer.from(raw[index], "hex"), "AES-GCM", false, ["encrypt", "decrypt"]);
    const a = new EncryptedChannel(actual, actual), b = new EncryptedChannel(expected, expected);
    const result = await a.encryptFrame(2, new Uint8Array([7, 8, 9]));
    const vector = await b.encryptFrame(2, new Uint8Array([7, 8, 9]));
    expect(result).toEqual(vector);
  }
  const otherLane = await deriveWebRTCLaneKeys(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), 2);
  const otherSetup = await deriveWebRTCLaneKeys(new Uint8Array(32).fill(1), new Uint8Array(32).fill(3), 1);
  expect(otherLane.confirm).not.toEqual(keys.confirm);
  expect(otherSetup.confirm).not.toEqual(keys.confirm);
  await expect(deriveWebRTCLaneKeys(new Uint8Array(32), new Uint8Array(32), 0)).rejects.toThrow("parameters");
  await expect(deriveWebRTCLaneKeys(new Uint8Array(32), new Uint8Array(31), 1)).rejects.toThrow("parameters");
});

test("parallel receive keeps metadata first and Done behind a slow data lane", async () => {
  const p = await setup();
  const sender = new ParallelFrameIO(p.send, true), receiver = new ParallelFrameIO(p.receive, false);
  try {
    await sender.writeFrame(1, json({ name: "x" }));
    const metadata = await receiver.readFrame();
    expect(metadata.msgType).toBe(1); metadata.release?.();
    p.outbound[1].held = [];
    await sender.writeFrame(2, new Uint8Array([10]));
    await sender.writeFrame(2, new Uint8Array([11]));
    await sender.writeFrame(2, new Uint8Array([12]));
    await sender.writeFrame(4, json({ chunkCount: 3 }));
    const first = await receiver.readFrame();
    expect(first.data).toEqual(new Uint8Array([10])); first.release?.();
    let delivered = false;
    const waiting = receiver.readFrame().then(frame => { delivered = true; return frame; });
    await new Promise(resolve => setTimeout(resolve, 20));
    expect(delivered).toBe(false);
    p.outbound[1].flush();
    const second = await waiting;
    expect(second.data).toEqual(new Uint8Array([11])); second.release?.();
    const third = await receiver.readFrame();
    expect(third.data).toEqual(new Uint8Array([12])); third.release?.();
    const done = await receiver.readFrame();
    expect(done.msgType).toBe(4); done.release?.();
    expect(p.receiveBudget.bytes).toBe(0);
  } finally { sender.close(); receiver.close(); }
});

for (const attack of ["duplicate", "ahead", "control", "replay", "wrong-key"] as const) {
  test(`parallel transport fails closed on ${attack}`, async () => {
    const p = await setup();
    const receiver = new ParallelFrameIO(p.receive, false);
    const transport = new DataChannelTransport(p.inbound[0] as unknown as RTCDataChannel, {} as EncryptedChannel, undefined, undefined, 3, receiver);
    try {
      await p.send[0].writeFrame(1, json({ name: "x", size: 3 }));
      await transport.readFrame();
      if (attack === "duplicate") {
        await p.send[0].writeFrame(2, sequenced(0));
        await transport.readFrame();
        await p.send[1].writeFrame(2, sequenced(0));
      } else if (attack === "ahead") {
        await p.send[1].writeFrame(2, sequenced(64));
      } else if (attack === "control") {
        await p.send[1].writeFrame(4, json({ chunkCount: 0 }));
      } else {
        const key = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(attack === "replay" ? 1 : 9), "AES-GCM", false, ["encrypt", "decrypt"]);
        const forged = new EncryptedChannel(key, key);
        const wire = await forged.encryptFrame(2, sequenced(0));
        p.outbound[0].send(wire); // nonce zero was already consumed by metadata
      }
      await expect(transport.readFrame()).rejects.toThrow();
      expect(p.inbound.every(channel => channel.readyState === "closed")).toBe(true);
      expect(p.receiveBudget.bytes).toBe(0);
      expect(p.receiveBudget.frames).toBe(0);
    } finally { for (const lane of p.send) lane.close(); transport.close(); }
  });
}

test("parallel scheduling avoids an already congested lane", async () => {
  const p = await setup();
  const sender = new ParallelFrameIO(p.send, true);
  try {
    p.outbound[0].bufferedAmount = 2 * 1024 * 1024;
    await sender.writeFrame(2, new Uint8Array([1]));
    expect(p.outbound[0].sent).toBe(0);
    expect(p.outbound[1].sent).toBeGreaterThan(0);
  } finally { sender.close(); for (const lane of p.receive) lane.close(); }
});

test("one aggregate budget includes application queues and bounds every lane", () => {
  const budget = new FrameBudget();
  budget.external = () => ({ bytes: 4 * 1024 * 1024, frames: 64 });
  budget.addBytes(4 * 1024 * 1024);
  expect(() => budget.addBytes(1)).toThrow("Aggregate");
  const release: Array<() => void> = [];
  for (let i = 0; i < 192; i++) release.push(budget.lease(0));
  expect(() => budget.lease(0)).toThrow("Aggregate");
  for (const free of release) { free(); free(); }
  expect(budget.frames).toBe(0);
});

test("closing a lane cancels its pending buffer drain", async () => {
  const p = await setup();
  p.outbound[0].bufferedAmount = 9 * 1024 * 1024;
  const writing = p.send[0].writeFrame(8, new Uint8Array());
  const rejected = expect(writing).rejects.toThrow("closed");
  await new Promise(resolve => setTimeout(resolve, 10));
  p.send[0].close();
  await rejected;
  for (const lane of [...p.send, ...p.receive]) lane.close();
});

for (const hello of [
  { step: "ready" },
  { step: "hello", version: 2, count: 4, nonce: "AA==" },
  { step: "hello", version: 1, count: 5, nonce: "AA==" },
  { step: "hello", version: 1, count: 1.5, nonce: "AA==" },
  { step: "hello", version: 1, count: 4, nonce: "AA==" },
]) {
  test(`encrypted WebRTC setup rejects malformed offer ${JSON.stringify(hello)}`, async () => {
    const p = await setup(1);
    const key = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(1), "AES-GCM", false, ["encrypt", "decrypt"]);
    const pc = { close() {} } as RTCPeerConnection;
    const result = negotiateParallelWebRTC(p.inbound[0] as unknown as RTCDataChannel, pc, new EncryptedChannel(key, key), [], {} as DerivedKeys, new Uint8Array(32), new Uint8Array(32), false, 4);
    const rejected = expect(result).rejects.toThrow();
    await p.send[0].writeFrame(0x0e, json(hello));
    await rejected;
    expect(p.inbound[0].readyState).toBe("closed");
    for (const lane of [...p.send, ...p.receive]) lane.close();
  });
}

test("malformed setup JSON does not echo private negotiation contents", async () => {
  const p = await setup(1);
  const key = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(1), "AES-GCM", false, ["encrypt", "decrypt"]);
  const result = negotiateParallelWebRTC(p.inbound[0] as unknown as RTCDataChannel,
    { close() {} } as RTCPeerConnection, new EncryptedChannel(key, key), [],
    {} as DerivedKeys, new Uint8Array(32), new Uint8Array(32), false, 4);
  const rejected = expect(result).rejects.toThrow(/^Invalid WebRTC setup control$/);
  try {
    await p.send[0].writeFrame(0x0e, new TextEncoder().encode('{"sdp":"private-test-sentinel", INVALID'));
    await rejected;
  } finally { for (const lane of [...p.send, ...p.receive]) lane.close(); }
});

test("one-lane encrypted negotiation preserves primary nonce counters", async () => {
  const p = await setup(1);
  const key = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(1), "AES-GCM", false, ["encrypt", "decrypt"]);
  const result = negotiateParallelWebRTC(p.inbound[0] as unknown as RTCDataChannel, { close() {} } as RTCPeerConnection,
    new EncryptedChannel(key, key), [], {} as DerivedKeys, new Uint8Array(32), new Uint8Array(32), false, 4);
  await p.send[0].writeFrame(0x0e, json({ step: "hello", version: 1, count: 1, nonce: Buffer.alloc(32).toString("base64") }));
  const accepted = await p.send[0].readFrame();
  expect(JSON.parse(new TextDecoder().decode(accepted.data))).toEqual({ step: "accept", count: 1 });
  accepted.release?.();
  const receiver = await result;
  try {
    await p.send[0].writeFrame(1, json({ name: "after-setup" }));
    const next = await receiver.readFrame();
    expect(next.msgType).toBe(1); next.release?.();
    await receiver.writeFrame(8, new Uint8Array());
    const heartbeat = await p.send[0].readFrame();
    expect(heartbeat.msgType).toBe(8); heartbeat.release?.();
  } finally { receiver.close(); for (const lane of [...p.send, ...p.receive]) lane.close(); }
});

for (const attack of ["primary-bit", "outside-mask", "fractional-mask", "overflow-mask", "commit", "early-data"] as const) {
  test(`parallel setup rejects ${attack} before payload starts`, async () => {
    const p = await setup(1);
    const key = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(1), "AES-GCM", false, ["encrypt", "decrypt"]);
    // This Node-side test has no native RTCPeerConnection. Extra construction
    // fails locally, so both peers must explicitly commit an empty ready mask.
    const pc = { close() {}, getConfiguration: () => ({}) } as RTCPeerConnection;
    const result = negotiateParallelWebRTC(p.inbound[0] as unknown as RTCDataChannel, pc, new EncryptedChannel(key, key), [],
      { confirm: new Uint8Array(32) } as DerivedKeys, new Uint8Array(32), new Uint8Array(32), false, 4);
    const rejected = expect(result).rejects.toThrow();
    const read = async () => { const frame = await p.send[0].readFrame(); frame.release?.(); return JSON.parse(new TextDecoder().decode(frame.data)); };
    try {
      await p.send[0].writeFrame(0x0e, json({ step: "hello", version: 1, count: 4, nonce: Buffer.alloc(32).toString("base64") }));
      const accept = await read(); expect(accept.count).toBe(4);
      for (let id = 1; id < 4; id++) await p.send[0].writeFrame(0x0e, json({ step: "offer", id, sdp: "" }));
      for (let id = 1; id < 4; id++) { const answer = await read(); expect(answer).toMatchObject({ step: "answer", id, sdp: "" }); }
      const mask = { "primary-bit": 1, "outside-mask": 16, "fractional-mask": 2.5, "overflow-mask": 2 ** 32, commit: 0, "early-data": 0 }[attack];
      await p.send[0].writeFrame(0x0e, json({ step: "ready", mask }));
      const ready = await read(); expect(ready.mask).toBe(0);
      if (attack === "commit") await p.send[0].writeFrame(0x0e, json({ step: "commit", mask: 2 }));
      if (attack === "early-data") await p.send[0].writeFrame(2, new Uint8Array([1]));
      await rejected;
      expect(p.inbound[0].readyState).toBe("closed");
    } finally { for (const lane of [...p.send, ...p.receive]) lane.close(); }
  });
}

test("failed DataChannel construction closes each unused peer before agreed fallback", async () => {
  const p = await setup(1);
  const key = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(1), "AES-GCM", false, ["encrypt", "decrypt"]);
  const originalPeer = globalThis.RTCPeerConnection;
  let closed = 0;
  globalThis.RTCPeerConnection = class {
    createDataChannel(): never { throw new Error("test: native channel unavailable"); }
    close(): void { closed++; }
  } as unknown as typeof RTCPeerConnection;
  const read = async () => {
    const frame = await p.receive[0].readFrame();
    frame.release?.();
    return JSON.parse(new TextDecoder().decode(frame.data));
  };
  try {
    const result = negotiateParallelWebRTC(p.outbound[0] as unknown as RTCDataChannel,
      { close() {}, getConfiguration: () => ({}) } as RTCPeerConnection, new EncryptedChannel(key, key), [],
      { confirm: new Uint8Array(32) } as DerivedKeys, new Uint8Array(32), new Uint8Array(32), true, 4);
    const hello = await read(); expect(hello.count).toBe(4);
    await p.receive[0].writeFrame(0x0e, json({ step: "accept", count: 4 }));
    for (let id = 1; id < 4; id++) {
      const offer = await read(); expect(offer).toEqual({ step: "offer", id, sdp: "" });
    }
    for (let id = 1; id < 4; id++) await p.receive[0].writeFrame(0x0e, json({ step: "answer", id, sdp: "" }));
    const ready = await read(); expect(ready.mask).toBe(0);
    await p.receive[0].writeFrame(0x0e, json({ step: "ready", mask: 0 }));
    const commit = await read(); expect(commit.mask).toBe(0);
    await p.receive[0].writeFrame(0x0e, json({ step: "committed", mask: 0 }));
    const primary = await result;
    expect(closed).toBe(3);
    expect(primary.diagnostics().connections).toBe(1);
    primary.close();
  } finally {
    if (originalPeer) globalThis.RTCPeerConnection = originalPeer;
    else delete (globalThis as any).RTCPeerConnection;
    for (const lane of [...p.send, ...p.receive]) lane.close();
  }
});

test("stalled parallel negotiation is bounded and closes its primary", async () => {
  const p = await setup(1);
  const key = await crypto.subtle.importKey("raw", new Uint8Array(32).fill(1), "AES-GCM", false, ["encrypt", "decrypt"]);
  const originalTimer = globalThis.setTimeout;
  // Accelerate only the setup deadline; leave transport/drain/test timers alone.
  globalThis.setTimeout = ((callback: (...args: any[]) => void, ms?: number, ...args: any[]) =>
    originalTimer(callback, ms === 25000 ? 20 : ms, ...args)) as typeof setTimeout;
  try {
    const result = negotiateParallelWebRTC(p.inbound[0] as unknown as RTCDataChannel, { close() {} } as RTCPeerConnection,
      new EncryptedChannel(key, key), [], {} as DerivedKeys, new Uint8Array(32), new Uint8Array(32), false, 4);
    await expect(result).rejects.toThrow("timed out");
    expect(p.inbound[0].readyState).toBe("closed");
  } finally { globalThis.setTimeout = originalTimer; for (const lane of [...p.send, ...p.receive]) lane.close(); }
});

test("failure on any payload lane closes every connection", async () => {
  const p = await setup();
  const receiver = new ParallelFrameIO(p.receive, false);
  const transport = new DataChannelTransport(p.inbound[0] as unknown as RTCDataChannel, {} as EncryptedChannel, undefined, undefined, 3, receiver);
  try {
    await p.send[0].writeFrame(1, json({ name: "x", size: 1 }));
    await transport.readFrame();
    const rejected = expect(transport.readFrame()).rejects.toThrow("closed");
    p.inbound[1].close();
    await rejected;
    expect(p.inbound.every(channel => channel.readyState === "closed")).toBe(true);
    expect(p.receiveBudget.bytes).toBe(0);
  } finally { transport.close(); for (const lane of p.send) lane.close(); }
});

for (const failure of ["none", "write", "close", "finack"] as const) {
  test(`parallel output lifecycle and slow sink: ${failure}`, async () => {
    const p = await setup();
    const senderIO = new ParallelFrameIO(p.send, true), receiverIO = new ParallelFrameIO(p.receive, false);
    const sender = new DataChannelTransport(p.outbound[0] as unknown as RTCDataChannel, {} as EncryptedChannel, undefined, undefined, 3, senderIO);
    const receiver = new DataChannelTransport(p.inbound[0] as unknown as RTCDataChannel, {} as EncryptedChannel, undefined, undefined, 3, receiverIO);
    const data = new Uint8Array(8 * 1024 * 1024).fill(42);
    const expected = createHash("sha256").update(data).digest("hex");
    const actual = createHash("sha256");
    let aborted = false, closed = false, bytes = 0, peak = 0;
    if (failure === "finack") {
      const write = p.send[0].writeFrame.bind(p.send[0]);
      p.send[0].writeFrame = async (kind, data) => { if (kind !== 7) await write(kind, data); };
    }
    const receiving = receiveFile(receiver, undefined, async () => ({
      write: async chunk => {
        await new Promise(resolve => setTimeout(resolve, 2));
        peak = Math.max(peak, receiver.diagnostics().queuedBytes);
        if (failure === "write") throw new Error("test disk write failed");
        actual.update(chunk); bytes += chunk.length;
      },
      close: async () => { if (failure === "close") throw new Error("test disk close failed"); closed = true; },
      abort: async () => { aborted = true; },
    }));
    const sending = sendFile(sender, new File([data], "parallel.bin"));
    try {
      if (failure === "write" || failure === "close") {
        // Match the UI's finally cleanup after a sink failure.
        const failed = expect(sending).rejects.toThrow();
        await expect(receiving).rejects.toThrow("test disk");
        receiver.close();
        sender.close();
        await failed;
        expect(aborted).toBe(true); expect(closed).toBe(false);
      } else {
        await sending;
        const received = await receiving;
        expect(received.totalBytes).toBe(data.length);
        expect(bytes).toBe(data.length); expect(actual.digest("hex")).toBe(expected);
        expect(closed).toBe(true); expect(aborted).toBe(false);
      }
      expect(peak).toBeLessThanOrEqual(8 * 1024 * 1024);
    } finally { sender.close(); receiver.close(); }
    expect(p.sendBudget.bytes).toBe(0); expect(p.receiveBudget.bytes).toBe(0);
  });
}
