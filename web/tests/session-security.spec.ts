// SPDX-License-Identifier: MIT

import { test, expect } from "@playwright/test";
import { createHash } from "node:crypto";
import { BoundedMemorySink } from "../src/memory-sink";
import { decompressChunk } from "../src/bounded-zstd";
import { DataChannelTransport, receiveFile, COMPLETION_ACK_TIMEOUT, MSG_METADATA, MSG_DATA, MSG_DONE, MSG_COMPLETE, MSG_HEARTBEAT, MSG_FINACK, MSG_CANCEL, MSG_CREDIT } from "../src/transfer";

test("tiny compressed results do not retain full decoder scratch buffers", () => {
  const raw = new Uint8Array([0x28, 0xb5, 0x2f, 0xfd, 0x20, 1, 9, 0, 0, 65]);
  const chunks = Array.from({ length: 16 }, () => decompressChunk(raw, 256 * 1024));
  expect(chunks.reduce((n, chunk) => n + chunk.length, 0)).toBe(16);
  expect(chunks.reduce((n, chunk) => n + chunk.buffer.byteLength, 0)).toBe(16);
  const unknownSize = new Uint8Array([0x28, 0xb5, 0x2f, 0xfd, 0, 0, 9, 0, 0, 65]);
  expect(decompressChunk(unknownSize, 256 * 1024).buffer.byteLength).toBe(1);
});

test("memory fallback coalesces tiny views and enforces backing allocation and object bounds", async () => {
  const memory = new BoundedMemorySink(1025, 256);
  const scratch = new Uint8Array(256 * 1024);
  scratch[0] = 65;
  for (let i = 0; i < 1025; i++) {
    memory.write(scratch.subarray(0, 1));
    expect(memory.allocatedBytes).toBeLessThanOrEqual(1025);
    expect(memory.blockCount).toBeLessThanOrEqual(5);
  }
  scratch.fill(66); // sink owns copies, not aliases into caller/decoder buffers
  expect(memory.size).toBe(1025);
  expect(memory.allocatedBytes).toBe(1025);
  expect(() => memory.write(new Uint8Array(1))).toThrow("memory limit");
  const blob = memory.toBlob("text/plain");
  const content = await blob.text();
  expect(content).toBe("A".repeat(1025));
  expect(memory.allocatedBytes).toBe(0);
  expect(memory.blockCount).toBe(0);
  expect(() => memory.write(new Uint8Array(1))).toThrow("finalized");
});

test("memory fallback handles partial blocks and rejects quota overflow before mutation", async () => {
  const memory = new BoundedMemorySink(10, 4);
  memory.write(new Uint8Array([1, 2, 3]));
  memory.write(new Uint8Array([4, 5, 6, 7, 8, 9]));
  expect(() => memory.write(new Uint8Array(2))).toThrow("memory limit");
  expect(memory.size).toBe(9);
  const blob = memory.toBlob("application/octet-stream");
  const buffer = await blob.arrayBuffer();
  expect(Array.from(new Uint8Array(buffer))).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
  const empty = new BoundedMemorySink(10).toBlob("text/plain");
  expect(empty.size).toBe(0);
});

function controlledTransport(protocol: 2 | 3 = 3) {
  const frames: { msgType: number; data: Uint8Array }[] = [];
  const sent: number[] = [];
  const dc = {
    bufferedAmount: 0,
    onmessage: null,
    onclose: null,
    send() {},
    close() { this.onclose?.(); },
  } as any;
  const enc = {
    async decryptFrame() {
      const frame = frames.shift();
      if (!frame) throw new Error("Missing controlled frame");
      return frame;
    },
    async encryptFrame(kind: number) { sent.push(kind); return new Uint8Array(29); },
  } as any;
  const transport = new DataChannelTransport(dc, enc, undefined, undefined, protocol);
  const deliver = (msgType: number, data = new Uint8Array()) => {
    frames.push({ msgType, data });
    const wire = new Uint8Array(29);
    new DataView(wire.buffer).setUint32(0, 25);
    dc.onmessage({ data: wire.buffer });
  };
  return { transport, deliver, sent, dc, close: () => { transport.stopHeartbeat(); dc.close(); } };
}

test("negotiated legacy mode has no credits but still bounds queued frames", async () => {
  const {transport,deliver,sent,close} = controlledTransport(2);
  try {
    for (let i=0;i<32;i++) await transport.sendData(new Uint8Array([65]));
    expect(sent).toHaveLength(32);
    for (let i=0;i<32;i++) {
      deliver(MSG_DATA,new Uint8Array([65]));
      await transport.readFrame();
      await transport.consumeData();
    }
    expect(sent).not.toContain(MSG_CREDIT);
    for (let i=0;i<300;i++) deliver(MSG_DATA,new Uint8Array([65]));
    await expect(transport.readFrame()).rejects.toThrow("capacity");
  } finally { close(); }
});

test("legacy mode rejects v3 credit frames rather than switching protocols", async () => {
  const {transport,deliver,close} = controlledTransport(2);
  try {
    deliver(MSG_CREDIT,new Uint8Array(8));
    await expect(transport.readFrame()).rejects.toThrow("legacy credit");
  } finally { close(); }
});

test("FinAck timeout returns verified Blob while peer heartbeats continue", async () => {
  const { transport, deliver, sent, close } = controlledTransport();
  transport.startHeartbeat(() => {}, 100, 1000);
  let heartbeatCount = 0;
  const heartbeat = setInterval(() => { heartbeatCount++; deliver(MSG_HEARTBEAT); }, 100);
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  try {
    const receiving = receiveFile(transport);
    const json = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
    deliver(MSG_METADATA, json({ name: "empty", size: 0, type: "text/plain" }));
    deliver(MSG_DONE, json({ totalBytes: 0, chunkCount: 0, sha256: createHash("sha256").digest("hex") }));
    const start = Date.now();
    const result = await Promise.race([
      receiving,
      new Promise<never>((_, reject) => { watchdog = setTimeout(() => reject(new Error("FinAck wait hung")), COMPLETION_ACK_TIMEOUT + 3000); }),
    ]);
    expect(result.blob?.size).toBe(0);
    expect(sent).toContain(MSG_COMPLETE);
    expect(heartbeatCount).toBeGreaterThan(1);
    expect(Date.now() - start).toBeGreaterThanOrEqual(COMPLETION_ACK_TIMEOUT - 100);
    expect((transport as any).fatalError).toBeNull();
    expect((transport as any).appResolve).toBeNull();
    expect((transport as any).appReject).toBeNull();
  } finally {
    clearTimeout(watchdog);
    clearInterval(heartbeat);
    close();
  }
});

test("timed application reads leave no waiter and cannot steal the next frame", async () => {
  const { transport, deliver, close } = controlledTransport();
  try {
    await expect(transport.readFrame(10)).rejects.toThrow("timed out");
    const next = transport.readFrame(1000);
    deliver(MSG_FINACK);
    const frame = await next;
    expect(frame.msgType).toBe(MSG_FINACK);
    const pending = transport.readFrame(1000);
    close();
    await expect(pending).rejects.toThrow("closed");
    expect((transport as any).appReject).toBeNull();
  } finally { close(); }
});

test("peer cancellation immediately rejects a blocked buffer drain without a close event", async () => {
  const { transport, deliver, dc } = controlledTransport();
  const listeners = new Map<string, Set<() => void>>();
  dc.addEventListener = (name: string, fn: () => void) => {
    if (!listeners.has(name)) listeners.set(name, new Set());
    listeners.get(name)!.add(fn);
  };
  dc.removeEventListener = (name: string, fn: () => void) => { listeners.get(name)?.delete(fn); };
  dc.close = () => {}; // emulate graceful SCTP close still waiting on the network
  dc.bufferedAmount = 9 * 1024 * 1024;
  const writing = transport.sendHeartbeat();
  const rejected = expect(writing).rejects.toThrow("cancelled");
  await expect.poll(() => listeners.get("bufferedamountlow")?.size).toBe(1);
  deliver(MSG_CANCEL, new Uint8Array([1]));
  await rejected;
  expect(Array.from(listeners.values()).every(set => set.size === 0)).toBe(true);
  expect((transport as any).bufferReject).toBeNull();
});
