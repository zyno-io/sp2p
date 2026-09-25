// SPDX-License-Identifier: MIT

import { bufferSource, EncryptedChannel } from "./crypto";

const MAX_FRAME = 512 * 1024;
const MAX_BYTES = 8 * 1024 * 1024;
const MAX_FRAMES = 256;
const DATA = 0x02, DONE = 0x04, ERROR = 0x06, CANCEL = 0x09, METADATA = 0x01;

// Defined here (not in webrtc-parallel.ts, which imports this module) to
// avoid a circular import. Re-exported from webrtc-parallel.ts for callers.
export const PARALLEL_MAX_LANES = 8;

export interface IOFrame {
  msgType: number;
  data: Uint8Array;
  release?: () => void;
}

export interface FrameIO {
  readFrame(): Promise<IOFrame>;
  writeFrame(type: number, data: Uint8Array): Promise<void>;
  close(error?: Error): void;
  diagnostics(): { queuedBytes: number; bufferedBytes: number; connections: number; encryptMs: number; decryptMs: number; bufferWaitMs: number };
  setExternalQueue(get: () => { bytes: number; frames: number }): void;
  peerConnections(): RTCPeerConnection[];
}

// One budget follows ciphertext through decryption, cross-lane reassembly, and
// control delivery. Application queues are included by the external getter.
// Adding a lane never adds another JavaScript receive budget.
export class FrameBudget {
  bytes = 0;
  frames = 0;
  external = () => ({ bytes: 0, frames: 0 });

  addBytes(n: number): void {
    if (n > MAX_BYTES - this.bytes - this.external().bytes) throw new Error("Aggregate receive byte budget exceeded");
    this.bytes += n;
  }

  lease(n: number): () => void {
    if (this.frames + this.external().frames >= MAX_FRAMES) throw new Error("Aggregate receive frame budget exceeded");
    this.frames++;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.bytes -= n;
      this.frames--;
    };
  }
}

type CipherFrame = { payload: Uint8Array; release: () => void };

// A single read/write owner for one independently encrypted DataChannel. The
// primary instance survives negotiation without resetting its AEAD counters.
export class EncryptedFrameIO implements FrameIO {
  private buffer = new Uint8Array(0);
  private frames: CipherFrame[] = [];
  private leases = new Set<() => void>();
  private wake: (() => void) | undefined;
  private ended: Error | undefined;
  private closed = false;
  private reading = false;
  private writes = Promise.resolve();
  private rejectWrites = new Set<(error: Error) => void>();
  private timings = { encryptMs: 0, decryptMs: 0, bufferWaitMs: 0 };
  highWater = 1024 * 1024;
  private maxMessage: number;

  constructor(
    readonly dc: RTCDataChannel,
    private enc: EncryptedChannel,
    readonly budget: FrameBudget,
    readonly pc?: RTCPeerConnection,
    initial: Uint8Array[] = [],
    maxMessage?: number,
  ) {
    const limit = maxMessage ?? pc?.sctp?.maxMessageSize;
    this.maxMessage = limit === 0 ? MAX_FRAME + 4 : limit && limit > 0 ? limit : 16384;
    dc.onmessage = event => {
      if (!(event.data instanceof ArrayBuffer)) { this.close(new Error("Invalid DataChannel input")); return; }
      this.append(new Uint8Array(event.data));
    };
    const end = () => {
      this.ended ??= new Error("DataChannel closed unexpectedly");
      for (const reject of this.rejectWrites) reject(this.ended);
      this.wake?.();
    };
    dc.onclose = end;
    dc.onerror = end;
    for (const data of initial) this.append(data);
  }

  private append(data: Uint8Array): void {
    if (this.closed || this.ended) return;
    try {
      if (!data.length || data.length > MAX_FRAME + 4 || data.length + this.buffer.length > 2 * (MAX_FRAME + 4)) throw new Error("Invalid receive buffer size");
      this.budget.addBytes(data.length);
      const combined = new Uint8Array(this.buffer.length + data.length);
      combined.set(this.buffer); combined.set(data, this.buffer.length);
      this.buffer = combined;
      while (this.buffer.length >= 4) {
        const size = new DataView(this.buffer.buffer, this.buffer.byteOffset).getUint32(0);
        if (size < 25 || size > MAX_FRAME) throw new Error("Invalid encrypted frame size");
        if (this.buffer.length < size + 4) break;
        const releaseBudget = this.budget.lease(size + 4);
        const release = () => { releaseBudget(); this.leases.delete(release); };
        this.leases.add(release);
        this.frames.push({ payload: this.buffer.slice(4, size + 4), release });
        this.buffer = this.buffer.slice(size + 4);
      }
      this.wake?.();
    } catch (error) { this.close(error as Error); }
  }

  async readFrame(): Promise<IOFrame> {
    if (this.reading) throw new Error("Concurrent encrypted reads are not supported");
    this.reading = true;
    try {
      while (!this.frames.length) {
        if (this.ended) throw this.ended;
        await new Promise<void>(resolve => { this.wake = resolve; });
        this.wake = undefined;
      }
      const raw = this.frames.shift()!;
      const start = performance.now();
      try {
        const frame = await this.enc.decryptFrame(raw.payload);
        if (this.closed) throw this.ended;
        return { ...frame, release: raw.release };
      } catch (error) { raw.release(); throw error; }
      finally { this.timings.decryptMs += performance.now() - start; }
    } finally { this.reading = false; }
  }

  writeFrame(type: number, data: Uint8Array): Promise<void> {
    const task = this.writes.then(async () => {
      if (this.ended) throw this.ended;
      const start = performance.now();
      const frame = await this.enc.encryptFrame(type, data);
      this.timings.encryptMs += performance.now() - start;
      for (let offset = 0; offset < frame.length; offset += this.maxMessage) {
        await this.drain();
        if (this.ended) throw this.ended;
        this.dc.send(bufferSource(frame.subarray(offset, offset + this.maxMessage)));
      }
    });
    this.writes = task.catch(error => { this.close(error as Error); });
    return task;
  }

  private async drain(): Promise<void> {
    if (this.dc.bufferedAmount <= this.highWater) return;
    const start = performance.now();
    try {
      await new Promise<void>((resolve, reject) => {
        const cleanup = () => {
          clearTimeout(timer);
          this.dc.removeEventListener("bufferedamountlow", low);
          this.rejectWrites.delete(fail);
        };
        const fail = (error: Error) => { cleanup(); reject(error); };
        const low = () => { if (this.dc.bufferedAmount <= this.highWater) { cleanup(); resolve(); } };
        const timer = setTimeout(() => fail(new Error("Network write timed out")), 120000);
        this.rejectWrites.add(fail);
        this.dc.bufferedAmountLowThreshold = this.highWater / 2;
        this.dc.addEventListener("bufferedamountlow", low);
        if (this.ended) fail(this.ended); else low();
      });
    } finally { this.timings.bufferWaitMs += performance.now() - start; }
  }

  setExternalQueue(get: () => { bytes: number; frames: number }): void { this.budget.external = get; }
  peerConnections(): RTCPeerConnection[] { return this.pc ? [this.pc] : []; }

  diagnostics() {
    return { ...this.timings, queuedBytes: this.budget.bytes, bufferedBytes: this.dc.bufferedAmount, connections: 1 };
  }

  close(error = new Error("Transport closed")): void {
    if (this.closed) return;
    this.closed = true;
    this.ended = error;
    this.budget.bytes -= this.buffer.length;
    this.buffer = new Uint8Array(0);
    this.frames = [];
    for (const release of this.leases) release();
    for (const reject of this.rejectWrites) reject(error);
    this.wake?.();
    this.dc.close();
    this.pc?.close();
  }
}

// Wire-compatible with Go MultiStream: data has an authenticated uint64 global
// sequence prefix inside each lane's encryption; controls use the primary.
export class ParallelFrameIO implements FrameIO {
  private data = new Map<number, IOFrame>();
  private controls: IOFrame[] = [];
  private nextRead = 0;
  private nextWrite = 0;
  private reassemblyBytes = 0;
  private expectMetadata: boolean;
  private wake: (() => void) | undefined;
  private error: Error | undefined;
  private closed = false;
  private reading = false;

  constructor(readonly lanes: EncryptedFrameIO[], sender: boolean) {
    if (lanes.length < 2 || lanes.length > PARALLEL_MAX_LANES) throw new Error("Invalid parallel lane count");
    this.expectMetadata = !sender;
    for (let i = 0; i < lanes.length; i++) void this.readLane(i);
  }

  private async readLane(index: number): Promise<void> {
    try {
      while (!this.closed) {
        const frame = await this.lanes[index].readFrame();
        if (this.closed) { frame.release?.(); return; }
        try {
          if (frame.msgType === DATA) {
            // Encoded zstd can exceed the decoded 256 KiB chunk limit. The
            // frame parser and shared 8 MiB budget bound wire bytes; receiveFile
            // independently bounds decompressed chunks before writing them.
            if (frame.data.length <= 8 || frame.data.length > MAX_FRAME) throw new Error("Invalid parallel data size");
            const seq = Number(new DataView(frame.data.buffer, frame.data.byteOffset, 8).getBigUint64(0));
            if (!Number.isSafeInteger(seq) || seq < this.nextRead || seq - this.nextRead >= 64 || this.data.has(seq)) throw new Error("Invalid parallel data sequence");
            frame.data = frame.data.subarray(8);
            if (frame.data.length > MAX_BYTES - this.reassemblyBytes) throw new Error("Parallel reassembly budget exceeded");
            this.data.set(seq, frame);
            this.reassemblyBytes += frame.data.length;
          } else {
            if (index !== 0 || frame.data.length > 4096 || this.controls.length >= 16) throw new Error("Invalid parallel control frame");
            // Terminal errors bypass a pending Done barrier.
            if (frame.msgType === CANCEL || frame.msgType === ERROR) this.controls.unshift(frame);
            else this.controls.push(frame);
          }
        } catch (error) { frame.release?.(); throw error; }
        this.wake?.();
      }
    } catch (error) { this.error ??= error as Error; this.wake?.(); }
  }

  async readFrame(): Promise<IOFrame> {
    if (this.reading) throw new Error("Concurrent parallel reads are not supported");
    this.reading = true;
    try {
      for (;;) {
        const control = this.controls[0];
        let barrier = 0;
        if (control?.msgType === DONE) {
          const done = JSON.parse(new TextDecoder().decode(control.data));
          if (!Number.isSafeInteger(done.chunkCount) || done.chunkCount < 0) throw new Error("Invalid parallel completion barrier");
          barrier = done.chunkCount;
        }
        if (control && this.nextRead >= barrier && (control.msgType !== DONE || !this.data.has(this.nextRead))) {
          this.controls.shift();
          if (control.msgType === METADATA) this.expectMetadata = false;
          return control;
        }
        if (!this.expectMetadata) {
          const frame = this.data.get(this.nextRead);
          if (frame) {
            this.data.delete(this.nextRead++);
            this.reassemblyBytes -= frame.data.length;
            return frame;
          }
        }
        if (this.error) throw this.error;
        await new Promise<void>(resolve => { this.wake = resolve; });
        this.wake = undefined;
      }
    } finally { this.reading = false; }
  }

  async writeFrame(type: number, data: Uint8Array): Promise<void> {
    if (this.error) throw this.error;
    if (type !== DATA) { await this.lanes[0].writeFrame(type, data); return; }
    const seq = this.nextWrite++;
    if (!Number.isSafeInteger(seq)) throw new Error("Parallel sequence exhausted");
    // Rotate equal-load choices; send the next whole chunk to the least queued
    // association instead of assigning fixed quarters or waiting on one lane.
    let target = seq % this.lanes.length;
    for (let offset = 1; offset < this.lanes.length; offset++) {
      const index = (seq + offset) % this.lanes.length;
      if (this.lanes[index].dc.bufferedAmount < this.lanes[target].dc.bufferedAmount) target = index;
    }
    const payload = new Uint8Array(data.length + 8);
    new DataView(payload.buffer).setBigUint64(0, BigInt(seq));
    payload.set(data, 8);
    await this.lanes[target].writeFrame(type, payload);
  }

  setExternalQueue(get: () => { bytes: number; frames: number }): void { this.lanes[0].setExternalQueue(get); }
  peerConnections(): RTCPeerConnection[] { return this.lanes.flatMap(lane => lane.peerConnections()); }

  diagnostics() {
    const stats = this.lanes.map(lane => lane.diagnostics());
    return { queuedBytes: stats[0].queuedBytes, connections: this.lanes.length,
      bufferedBytes: stats.reduce((sum, s) => sum + s.bufferedBytes, 0),
      encryptMs: stats.reduce((sum, s) => sum + s.encryptMs, 0),
      decryptMs: stats.reduce((sum, s) => sum + s.decryptMs, 0),
      bufferWaitMs: stats.reduce((sum, s) => sum + s.bufferWaitMs, 0) };
  }

  close(error = new Error("Parallel transport closed")): void {
    if (this.closed) return;
    this.closed = true;
    this.error = error;
    for (const frame of this.data.values()) frame.release?.();
    for (const frame of this.controls) frame.release?.();
    this.data.clear(); this.controls = []; this.reassemblyBytes = 0;
    for (const lane of this.lanes) lane.close(error);
    this.wake?.();
  }
}
