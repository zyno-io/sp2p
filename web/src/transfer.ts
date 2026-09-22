// SPDX-License-Identifier: MIT

// Transfer protocol — Go-compatible wire format over encrypted DataChannel.

import { EncryptedChannel } from "./crypto";
import { createTar, type TarArchive } from "./tar";
import { SHA256 } from "./sha256";
import { decompressChunk } from "./bounded-zstd";
import { BoundedMemorySink } from "./memory-sink";
import { log } from "./log";
import type { FrameIO } from "./frame-io";

// Message types (must match Go constants).
export const MSG_METADATA = 0x01;
export const MSG_DATA = 0x02;
export const MSG_DONE = 0x04;
export const MSG_COMPLETE = 0x05;
export const MSG_ERROR = 0x06;
export const MSG_FINACK = 0x07;
export const MSG_HEARTBEAT = 0x08;
export const MSG_CANCEL = 0x09;
export const MSG_CREDIT = 0x0c;
export const MSG_RECEIVE_WINDOW = 0x0d;
const CREDIT_WINDOW = 16;
export const RECEIVE_WINDOW_VERSION = 1;
export const RECEIVE_WINDOW_CHUNKS = 64;
export const COMPLETION_ACK_TIMEOUT = 5000;
const NETWORK_WRITE_TIMEOUT = 120000;
type Frame = { msgType: number; data: Uint8Array };

// Cancel reason codes.
export const CANCEL_USER_ABORT = 0x01;
export const CANCEL_ERROR = 0x02;

export const MAX_CHUNK_SIZE = 256 * 1024;
// Smaller browser-originated chunks keep receive progress responsive on slow
// links while the protocol limit remains compatible with existing peers.
export const SEND_CHUNK_SIZE = 64 * 1024;
export const MAX_FRAME_SIZE = 512 * 1024; // Must match Go's MaxFrameSize
// In-memory receive limit for browsers without File System Access API.
const MAX_RECEIVE_SIZE = 256 * 1024 * 1024; // explicit, bounded memory fallback
const MAX_DISK_RECEIVE_SIZE = 1024 ** 4; // finite 1 TiB disk policy; larger transfers use the CLI override

const SEND_HIGH_WATER = 8 * 1024 * 1024; // 8 MB buffered amount threshold
const MAX_QUEUE_BYTES = 8 * 1024 * 1024; // 8 MB max queued receive data
const MAX_QUEUE_FRAMES = 256;
// Used only when the browser does not expose RTCSctpTransport.maxMessageSize.
// This conservative value is supported by all WebRTC DataChannel implementations.
const FALLBACK_MAX_DATA_CHANNEL_MESSAGE_SIZE = 16 * 1024;
const RECEIVE_RENDER_INTERVAL_MS = 50;

function nowMs(): number {
  return typeof performance === "undefined" ? Date.now() : performance.now();
}

function yieldToBrowser(): Promise<void> {
  // Message tasks allow painting without background-tab timer clamping or a
  // requestAnimationFrame callback that may pause while the tab is hidden.
  if (typeof MessageChannel !== "undefined") {
    return new Promise(resolve => {
      const channel = new MessageChannel();
      channel.port1.onmessage = () => {
        channel.port1.close();
        channel.port2.close();
        resolve();
      };
      channel.port2.postMessage(null);
    });
  }
  return new Promise((resolve) => { setTimeout(resolve, 0); });
}

export interface Metadata {
  name: string;
  size: number;
  type: string;
  isFolder: boolean;
  streamMode: boolean;
  fileCount?: number;
  compression?: string;
  receiveWindow?: number;
}

export interface Done {
  totalBytes: number;
  chunkCount: number;
  sha256: string;
}

// ChunkWriter is the interface for streaming received data to disk.
export interface ChunkWriter {
  write(chunk: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort(reason?: unknown): Promise<void>;
}

// DataChannelFrameRW bridges WebRTC DataChannel ↔ encrypted frames.
// It handles the length-prefixed wire format over the DataChannel.
export class DataChannelTransport {
  private dc: RTCDataChannel;
  private enc: EncryptedChannel;
  private recvQueue: Uint8Array[] = [];
  private recvQueueBytes = 0;
  private recvResolve: ((value: Uint8Array) => void) | null = null;
  private recvReject: ((err: Error) => void) | null = null;
  private recvBuffer: Uint8Array = new Uint8Array(0);
  private fatalError: Error | null = null;
  private maxDataChannelMessageSize: number;
  private appQueue: Frame[] = [];
  private appQueueBytes = 0;
  private appResolve: ((frame: Frame) => void) | null = null;
  private appReject: ((err: Error) => void) | null = null;
  private sentChunks = 0;
  private creditedChunks = 0;
  private receivedChunks = 0;
  private consumedChunks = 0;
  private creditWait: (() => void) | null = null;
  private creditReject: ((err: Error) => void) | null = null;
  private bufferReject: ((err: Error) => void) | null = null;
  private sendWindow = CREDIT_WINDOW;
  private receiveWindow = CREDIT_WINDOW;
  private receiveChunkLimit = MAX_FRAME_SIZE;
  private windowOffered = false;
  private windowGranted = false;
  private metadataReceived = false;
  private timings = { creditWaitMs: 0, bufferWaitMs: 0, encryptMs: 0, decryptMs: 0, readMs: 0, hashMs: 0, writeMs: 0 };

  recordTiming(name: keyof DataChannelTransport["timings"], ms: number): void {
    this.timings[name] += ms;
  }

  diagnostics() {
    const io = this.frameIO?.diagnostics();
    return {
      ...this.timings,
      ...io,
      sendWindow: this.sendWindow,
      receiveWindow: this.receiveWindow,
      outstandingChunks: this.sentChunks - this.creditedChunks,
      unconsumedChunks: this.receivedChunks - this.consumedChunks,
      queuedBytes: this.recvQueueBytes + this.appQueueBytes + this.recvBuffer.length + (io?.queuedBytes ?? 0),
      bufferedBytes: io?.bufferedBytes ?? this.dc.bufferedAmount,
      sentChunks: this.sentChunks,
      consumedChunks: this.consumedChunks,
    };
  }

  constructor(
    dc: RTCDataChannel,
    enc: EncryptedChannel,
    initialData?: Uint8Array[],
    maxDataChannelMessageSize?: number,
    private protocol: 2 | 3 = 3,
    private frameIO?: FrameIO,
  ) {
    this.dc = dc;
    this.enc = enc;
    // A maxMessageSize of zero means the peer did not advertise a limit.
    // Frames are independently capped by MAX_FRAME_SIZE, so send those whole.
    if (maxDataChannelMessageSize === 0) {
      this.maxDataChannelMessageSize = MAX_FRAME_SIZE + 4;
    } else if (maxDataChannelMessageSize && maxDataChannelMessageSize > 0) {
      this.maxDataChannelMessageSize = maxDataChannelMessageSize;
    } else {
      this.maxDataChannelMessageSize = FALLBACK_MAX_DATA_CHANNEL_MESSAGE_SIZE;
    }

    if (frameIO) {
      frameIO.setExternalQueue(() => ({ bytes: this.appQueueBytes, frames: this.appQueue.length }));
      void this.decodeLoop();
      return;
    }

    // Replay any data buffered during key confirmation.
    if (initialData) {
      for (const chunk of initialData) {
        if (chunk.length > MAX_FRAME_SIZE + 4 || this.recvBuffer.length + chunk.length > 2 * (MAX_FRAME_SIZE + 4)) {
          this.fail(new Error("Initial receive buffer exceeded limit"));
          break;
        }
        const combined = new Uint8Array(this.recvBuffer.length + chunk.length);
        combined.set(this.recvBuffer);
        combined.set(chunk, this.recvBuffer.length);
        this.recvBuffer = combined;
        this.tryParseFrames();
        if (this.fatalError) break;
      }
      this.tryParseFrames();
    }

    dc.onmessage = (event) => {
      if (this.fatalError) return; // stop accumulating after error
      // Only the continuous authenticated decoder refreshes liveness.
      const data = new Uint8Array(event.data);
      if (data.length > MAX_FRAME_SIZE + 4 || this.recvBuffer.length + data.length > 2 * (MAX_FRAME_SIZE + 4)) {
        this.fail(new Error("Receive buffer exceeded limit"));
        return;
      }
      // Append to buffer and try to parse frames.
      const combined = new Uint8Array(this.recvBuffer.length + data.length);
      combined.set(this.recvBuffer);
      combined.set(data, this.recvBuffer.length);
      this.recvBuffer = combined;

      // Guard against unbounded buffer growth from malformed/partial frames.
      this.tryParseFrames();
      if (this.recvBuffer.length > MAX_FRAME_SIZE + 4) {
        const err = new Error(`Receive buffer exceeded max frame size`);
        this.fail(err);
        if (this.recvReject) {
          const reject = this.recvReject;
          this.recvReject = null;
          this.recvResolve = null;
          reject(err);
        }
        return;
      }

    };

    const onClosed = () => {
      const err = new Error("DataChannel closed unexpectedly");
      this.fail(err);
      if (this.recvReject) {
        const reject = this.recvReject;
        this.recvReject = null;
        this.recvResolve = null;
        reject(err);
      }
    };
    dc.onclose = onClosed;
    dc.onerror = () => onClosed();
    void this.decodeLoop();
  }

  get protocolVersion(): 2 | 3 {
    return this.protocol;
  }

  close(): void { this.fail(new Error("Transfer closed")); }

  private fail(err: Error): void {
    if (this.fatalError) return;
    this.fatalError = err;
    this.recvBuffer = new Uint8Array(0);
    this.recvQueue = [];
    this.recvQueueBytes = 0;
    this.appQueue = [];
    this.appQueueBytes = 0;
    this.appReject?.(err);
    this.appResolve = null;
    this.appReject = null;
    this.creditReject?.(err);
    this.creditWait = null;
    this.creditReject = null;
    this.bufferReject?.(err);
    this.stopHeartbeat();
    const reject = this.recvReject;
    this.recvReject = null;
    this.recvResolve = null;
    reject?.(err);
    this.frameIO?.close(err);
    this.dc.close();
  }

  private tryParseFrames(): void {
    while (this.recvBuffer.length >= 4) {
      const view = new DataView(this.recvBuffer.buffer, this.recvBuffer.byteOffset);
      const payloadLen = view.getUint32(0);

      if (payloadLen < 25 || payloadLen > MAX_FRAME_SIZE) {
        const err = new Error(`Frame too large: ${payloadLen} bytes (max ${MAX_FRAME_SIZE})`);
        this.fail(err);
        if (this.recvReject) {
          const reject = this.recvReject;
          this.recvReject = null;
          this.recvResolve = null;
          reject(err);
        }
        return;
      }

      const totalLen = 4 + payloadLen;

      if (this.recvBuffer.length < totalLen) break;

      if (this.recvQueue.length + this.appQueue.length >= MAX_QUEUE_FRAMES || payloadLen > MAX_QUEUE_BYTES - this.recvQueueBytes - this.appQueueBytes) {
        this.fail(new Error("Receive queue capacity exceeded"));
        return;
      }

      const frame = this.recvBuffer.slice(4, totalLen);
      this.recvBuffer = this.recvBuffer.slice(totalLen);

      if (this.recvResolve) {
        const resolve = this.recvResolve;
        this.recvResolve = null;
        this.recvReject = null;
        resolve(frame);
      } else {
        this.recvQueue.push(frame);
        this.recvQueueBytes += frame.length;
      }
    }
  }

  private nextFrame(): Promise<Uint8Array> {
    if (this.fatalError) {
      return Promise.reject(this.fatalError);
    }
    if (this.recvQueue.length > 0) {
      const frame = this.recvQueue.shift()!;
      this.recvQueueBytes -= frame.length;
      // Resume parsing frames that were paused due to backpressure.
      if (this.recvBuffer.length >= 4) {
        this.tryParseFrames();
      }
      return Promise.resolve(frame);
    }
    return new Promise((resolve, reject) => {
      this.recvResolve = resolve;
      this.recvReject = reject;
    });
  }

  // Wait for the DataChannel send buffer to drain below the threshold.
  private waitForBufferDrain(): Promise<void> {
    if (this.fatalError) return Promise.reject(this.fatalError);
    if (this.dc.bufferedAmount <= SEND_HIGH_WATER) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve, reject) => {
      const cleanup = () => {
        clearTimeout(timer);
        this.bufferReject = null;
        this.dc.removeEventListener("bufferedamountlow", onLow);
        this.dc.removeEventListener("close", onClose);
        this.dc.removeEventListener("error", onClose);
      };
      const onLow = () => {
        if (this.dc.bufferedAmount <= SEND_HIGH_WATER) {
          cleanup();
          resolve();
        }
      };
      const onClose = () => {
        cleanup();
        reject(this.fatalError || new Error("DataChannel closed"));
      };
      const timer = setTimeout(() => {
        cleanup();
        const err = new Error("Network write timed out");
        this.fail(err);
        reject(err);
      }, NETWORK_WRITE_TIMEOUT);
      // Do not wait for a graceful DataChannel close event to cancel a blocked
      // buffer drain: that close can itself wait for the pending network data.
      this.bufferReject = (err: Error) => { cleanup(); reject(err); };
      this.dc.bufferedAmountLowThreshold = SEND_HIGH_WATER / 2;
      this.dc.addEventListener("bufferedamountlow", onLow);
      this.dc.addEventListener("close", onClose);
      this.dc.addEventListener("error", onClose);
    });
  }

  // Send an encrypted frame. Writes are serialized through a promise chain
  // to prevent nonce reordering when heartbeat timer fires mid-await.
  async sendFrame(msgType: number, data: Uint8Array): Promise<void> {
    if (this.protocol === 2 && msgType === MSG_CREDIT) throw new Error("Credits require protocol v3");
    if (this.protocol === 3 && msgType === MSG_DATA) {
      if (this.windowOffered && data.length > SEND_CHUNK_SIZE) throw new Error("Data exceeds offered chunk limit");
      while (this.sentChunks - this.creditedChunks >= this.sendWindow) {
        if (this.fatalError) throw this.fatalError;
        const start = nowMs();
        try {
          await new Promise<void>((resolve, reject) => { this.creditWait = resolve; this.creditReject = reject; });
        } finally { this.timings.creditWaitMs += nowMs() - start; }
      }
      this.sentChunks++;
    }
    const p = this.writeQueue.then(async () => {
      if (this.fatalError) throw this.fatalError;
      if (this.frameIO) {
        await this.frameIO.writeFrame(msgType, data);
        return;
      }
      const encryptStart = nowMs();
      const frame = await this.enc.encryptFrame(msgType, data);
      this.timings.encryptMs += nowMs() - encryptStart;
      // The encrypted wire frame is larger than its plaintext payload and can
      // therefore exceed SCTP's negotiated max-message-size. DataChannel
      // messages are transport chunks; the length-prefixed frame is reassembled
      // by tryParseFrames() on the receiving side.
      for (let offset = 0; offset < frame.length; offset += this.maxDataChannelMessageSize) {
        const end = Math.min(offset + this.maxDataChannelMessageSize, frame.length);
        if (this.dc.bufferedAmount > SEND_HIGH_WATER) {
          const start = nowMs();
          try { await this.waitForBufferDrain(); }
          finally { this.timings.bufferWaitMs += nowMs() - start; }
        }
        this.dc.send(frame.subarray(offset, end));
      }
      // Legacy peers do not send controls continuously. Successful data writes
      // retain the v2 progress-based liveness contract, not v3 peer heartbeats.
      if (this.protocol === 2 && msgType === MSG_DATA) this.touchHeartbeat();
    });
    this.writeQueue = p.catch((err) => { this.fail(err); });
    return p;
  }

  // A single continuous read owner drains controls while the app sends or writes
  // to disk. Receiver credits bound the application queue as well as raw frames.
  private async decodeLoop(): Promise<void> {
    try {
      while (!this.fatalError) {
        let frame: Frame;
        let release: (() => void) | undefined;
        if (this.frameIO) {
          const received = await this.frameIO.readFrame();
          frame = received;
          release = received.release;
        } else {
          const payload = await this.nextFrame();
          const decryptStart = nowMs();
          frame = await this.enc.decryptFrame(payload);
          this.timings.decryptMs += nowMs() - decryptStart;
        }
        try {
          if (this.fatalError) return;
          if (frame.msgType !== MSG_DATA && frame.data.length > 4096) throw new Error("Control frame too large");
          if (frame.msgType === MSG_HEARTBEAT) {
            if (frame.data.length) throw new Error("Invalid heartbeat");
            this.touchHeartbeat();
            continue;
          }
          if (frame.msgType === MSG_CREDIT) {
            if (this.protocol !== 3) throw new Error("Unexpected legacy credit frame");
            if (frame.data.length !== 8) throw new Error("Invalid credit frame");
            const view = new DataView(frame.data.buffer, frame.data.byteOffset, 8);
            const value = Number(view.getBigUint64(0));
            if (!Number.isSafeInteger(value) || value <= this.creditedChunks || value > this.sentChunks) throw new Error("Invalid receiver credit");
            this.creditedChunks = value;
            const ready = this.creditWait;
            this.creditWait = null; this.creditReject = null;
            ready?.();
            this.touchHeartbeat();
            continue;
          }
          if (frame.msgType === MSG_RECEIVE_WINDOW) {
            if (this.protocol !== 3 || !this.windowOffered || this.windowGranted || frame.data.length !== 12) {
              throw new Error("Unexpected receive window grant");
            }
            const view = new DataView(frame.data.buffer, frame.data.byteOffset, 12);
            if (view.getUint32(0) !== RECEIVE_WINDOW_VERSION || view.getUint32(4) !== RECEIVE_WINDOW_CHUNKS || view.getUint32(8) !== SEND_CHUNK_SIZE) {
              throw new Error("Invalid receive window grant");
            }
            this.windowGranted = true;
            this.sendWindow = RECEIVE_WINDOW_CHUNKS;
            const ready = this.creditWait;
            this.creditWait = null; this.creditReject = null;
            ready?.();
            this.touchHeartbeat();
            log("receive window granted: 64 × 64 KiB (4 MiB)");
            continue;
          }
          if (frame.msgType === MSG_CANCEL) throw new Error("Peer cancelled transfer");
          if (frame.msgType === MSG_ERROR) {
            const peerError = JSON.parse(new TextDecoder().decode(frame.data));
            throw new Error(`Peer error: ${peerError.message}`);
          }
          if (frame.msgType === MSG_DATA) {
            if (!frame.data.length || frame.data.length > this.receiveChunkLimit || (this.protocol === 3 && this.receivedChunks - this.consumedChunks >= this.receiveWindow)) throw new Error("Data exceeds receiver credit or chunk limit");
            this.receivedChunks++;
          } else if (frame.msgType === MSG_METADATA) {
            if (this.metadataReceived) throw new Error("Repeated transfer metadata");
            this.metadataReceived = true;
            const meta: Metadata = JSON.parse(new TextDecoder().decode(frame.data));
            if (this.protocol === 3 && meta.receiveWindow === RECEIVE_WINDOW_VERSION && !meta.compression) {
              // The encrypted offer proves the sender understands this control.
              // Install limits before granting; queued data stays within 8 MiB.
              this.receiveWindow = RECEIVE_WINDOW_CHUNKS;
              this.receiveChunkLimit = SEND_CHUNK_SIZE;
              const grant = new Uint8Array(12);
              const view = new DataView(grant.buffer);
              view.setUint32(0, RECEIVE_WINDOW_VERSION);
              view.setUint32(4, RECEIVE_WINDOW_CHUNKS);
              view.setUint32(8, SEND_CHUNK_SIZE);
              await this.sendFrame(MSG_RECEIVE_WINDOW, grant);
            }
          } else if (![MSG_METADATA, MSG_DONE, MSG_COMPLETE, MSG_ERROR, MSG_FINACK].includes(frame.msgType)) {
            throw new Error("Unexpected transfer control");
          }
          this.touchHeartbeat();
          if (this.appResolve) {
            const resolve = this.appResolve;
            this.appResolve = null; this.appReject = null;
            resolve(frame);
          } else {
            if (this.appQueue.length + this.recvQueue.length >= MAX_QUEUE_FRAMES || frame.data.length > MAX_QUEUE_BYTES - this.appQueueBytes - this.recvQueueBytes) throw new Error("Receive queue capacity exceeded");
            this.appQueue.push(frame);
            this.appQueueBytes += frame.data.length;
          }
        } finally { release?.(); }
      }
    } catch (err) { this.fail(err as Error); }
  }

  async readFrame(timeoutMs?: number): Promise<Frame> {
    if (this.fatalError) throw this.fatalError;
    if (this.appQueue.length) {
      const frame = this.appQueue.shift()!;
      this.appQueueBytes -= frame.data.length;
      return frame;
    }
    if (this.appResolve) throw new Error("Concurrent application frame reads are not supported");
    return new Promise((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const resolveFrame = (frame: Frame) => { clearTimeout(timer); resolve(frame); };
      this.appResolve = resolveFrame;
      this.appReject = (err: Error) => { clearTimeout(timer); reject(err); };
      if (timeoutMs !== undefined) {
        timer = setTimeout(() => {
          if (this.appResolve === resolveFrame) {
            this.appResolve = null;
            this.appReject = null;
          }
          reject(new Error("Frame acknowledgement timed out"));
        }, timeoutMs);
      }
    });
  }

  async consumeData(): Promise<void> {
    if (this.consumedChunks >= this.receivedChunks) throw new Error("Invalid data consumption");
    if (this.protocol === 2) {
      this.consumedChunks++;
      return;
    }
    const data = new Uint8Array(8);
    new DataView(data.buffer).setBigUint64(0, BigInt(++this.consumedChunks));
    await this.sendFrame(MSG_CREDIT, data);
  }

  // Send metadata.
  async sendMetadata(meta: Metadata): Promise<void> {
    if (this.protocol === 3 && !meta.compression) {
      this.windowOffered = true;
      meta = { ...meta, receiveWindow: RECEIVE_WINDOW_VERSION };
    }
    const json = new TextEncoder().encode(JSON.stringify(meta));
    await this.sendFrame(MSG_METADATA, json);
  }

  // Send a data chunk.
  async sendData(chunk: Uint8Array): Promise<void> {
    await this.sendFrame(MSG_DATA, chunk);
  }

  // Send done.
  async sendDone(totalBytes: number, chunkCount: number, sha256: string): Promise<void> {
    const json = new TextEncoder().encode(JSON.stringify({ totalBytes, chunkCount, sha256 }));
    await this.sendFrame(MSG_DONE, json);
  }

  // Send complete.
  async sendComplete(totalBytes: number, chunkCount: number, sha256: string): Promise<void> {
    const json = new TextEncoder().encode(JSON.stringify({ totalBytes, chunkCount, sha256 }));
    await this.sendFrame(MSG_COMPLETE, json);
  }

  // Send error.
  async sendError(message: string): Promise<void> {
    const json = new TextEncoder().encode(JSON.stringify({ message }));
    await this.sendFrame(MSG_ERROR, json);
  }

  // Send cancel frame (best-effort).
  async sendCancel(reason: number = CANCEL_USER_ABORT): Promise<void> {
    try {
      await this.sendFrame(MSG_CANCEL, new Uint8Array([reason]));
    } catch {
      // DataChannel may already be closed.
    }
  }

  // Send heartbeat frame.
  async sendHeartbeat(): Promise<void> {
    await this.sendFrame(MSG_HEARTBEAT, new Uint8Array(0));
  }

  private writeQueue: Promise<void> = Promise.resolve();
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private lastRecvTime = Date.now();
  private heartbeatPending = false;

  // Start sending periodic heartbeats and tracking peer liveness.
  startHeartbeat(onTimeout: () => void, interval = 5000, timeout = 15000): void {
    this.lastRecvTime = Date.now();
    this.heartbeatTimer = setInterval(() => {
      // Send heartbeat (best-effort).
      if (!this.heartbeatPending) {
        this.heartbeatPending = true;
        this.sendHeartbeat().catch(() => {}).finally(() => { this.heartbeatPending = false; });
      }
      // Check peer liveness.
      if (Date.now() - this.lastRecvTime > timeout) {
        this.stopHeartbeat();
        this.fail(new Error("Peer heartbeat timed out"));
        onTimeout();
      }
    }, interval);
  }

  // Stop heartbeat timer.
  stopHeartbeat(): void {
    if (this.heartbeatTimer !== null) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  // Touch the heartbeat tracker — call on every received frame.
  touchHeartbeat(): void {
    this.lastRecvTime = Date.now();
  }
}

// Hex-encode a digest.
function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Send a file over the transport.
export async function sendFile(
  transport: DataChannelTransport,
  file: File,
  onProgress?: (bytesSent: number) => void
): Promise<void> {
  // Send metadata.
  await transport.sendMetadata({
    name: file.name,
    size: file.size,
    type: file.type || "application/octet-stream",
    isFolder: false,
    streamMode: false,
  });

  const hasher = new SHA256();

  // Send data chunks.
  let offset = 0;
  let chunkCount = 0;

  while (offset < file.size) {
    const end = Math.min(offset + SEND_CHUNK_SIZE, file.size);
    const blob = file.slice(offset, end);
    const readStart = nowMs();
    const buffer = await blob.arrayBuffer();
    transport.recordTiming?.("readMs", nowMs() - readStart);
    const chunk = new Uint8Array(buffer);
    const hashStart = nowMs();
    hasher.update(chunk);
    transport.recordTiming?.("hashMs", nowMs() - hashStart);
    await transport.sendData(chunk);
    offset = end;
    chunkCount++;
    onProgress?.(offset);
  }

  // Send done with checksum.
  const sha256 = hexEncode(hasher.digest());
  await transport.sendDone(file.size, chunkCount, sha256);

  // Wait for complete.
  const { msgType, data } = await transport.readFrame();
  if (msgType === MSG_COMPLETE) {
    const complete: Done = JSON.parse(new TextDecoder().decode(data));
    if (complete.totalBytes !== file.size || complete.chunkCount !== chunkCount) {
      throw new Error("Verification mismatch");
    }
    if (complete.sha256 !== sha256) {
      throw new Error("Integrity mismatch: SHA-256 does not match");
    }
    // FinAck so the receiver knows we got Complete before tearing down.
    try { await transport.sendFrame(MSG_FINACK, new Uint8Array(0)); } catch {}
  } else if (msgType === MSG_ERROR) {
    const err = JSON.parse(new TextDecoder().decode(data));
    throw new Error(`Receiver error: ${err.message}`);
  } else {
    throw new Error(`Unexpected message type: 0x${msgType.toString(16)}`);
  }
}

// Send multiple files as a tar archive over the transport.
export async function sendFiles(
  transport: DataChannelTransport,
  files: File[],
  archiveName: string,
  onProgress?: (bytesSent: number) => void,
  preparedArchive?: TarArchive
): Promise<number> {
  const archive = preparedArchive ?? createTar(files);
  const { totalSize, stream } = archive;

  // The TAR size is known exactly, so receivers must enforce it.
  await transport.sendMetadata({
    name: archiveName,
    size: totalSize,
    type: "application/x-tar",
    isFolder: true,
    streamMode: false,
  });

  // Stream tar chunks.
  const hasher = new SHA256();
  let bytesSent = 0;
  let chunkCount = 0;

  // Re-chunk the tar stream into responsive browser send chunks.
  let pending = new Uint8Array(0);

  for await (const { chunk } of stream()) {
    // Append to pending buffer.
    const combined = new Uint8Array(pending.length + chunk.length);
    combined.set(pending);
    combined.set(chunk, pending.length);
    pending = combined;

    // Flush full chunks.
    while (pending.length >= SEND_CHUNK_SIZE) {
      const slice = pending.slice(0, SEND_CHUNK_SIZE);
      pending = pending.slice(SEND_CHUNK_SIZE);
      await transport.sendData(slice);
      hasher.update(slice);
      bytesSent += slice.length;
      chunkCount++;
      onProgress?.(bytesSent);
    }
  }

  // Flush remaining data.
  if (pending.length > 0) {
    await transport.sendData(pending);
    hasher.update(pending);
    bytesSent += pending.length;
    chunkCount++;
    onProgress?.(bytesSent);
  }

  // Send done with checksum.
  const sha256 = hexEncode(hasher.digest());
  await transport.sendDone(bytesSent, chunkCount, sha256);

  // Wait for complete.
  const { msgType, data } = await transport.readFrame();
  if (msgType === MSG_COMPLETE) {
    const complete: Done = JSON.parse(new TextDecoder().decode(data));
    if (complete.totalBytes !== bytesSent || complete.chunkCount !== chunkCount) {
      throw new Error("Verification mismatch");
    }
    if (complete.sha256 !== sha256) {
      throw new Error("Integrity mismatch: SHA-256 does not match");
    }
    // FinAck so the receiver knows we got Complete before tearing down.
    try { await transport.sendFrame(MSG_FINACK, new Uint8Array(0)); } catch {}
  } else if (msgType === MSG_ERROR) {
    const err = JSON.parse(new TextDecoder().decode(data));
    throw new Error(`Receiver error: ${err.message}`);
  } else {
    throw new Error(`Unexpected message type: 0x${msgType.toString(16)}`);
  }

  return bytesSent;
}

// Receive a file over the transport.
// If getWriter is provided and returns a ChunkWriter, data is streamed directly
// to disk via the File System Access API (no in-memory buffering).
// Otherwise, chunks are buffered in memory and returned as a Blob.
export async function receiveFile(
  transport: DataChannelTransport,
  onProgress?: (bytesRecv: number, meta?: Metadata) => void,
  getWriter?: (meta: Metadata) => Promise<ChunkWriter | null>
): Promise<{ meta: Metadata; blob: Blob | null; totalBytes: number }> {
  // Read metadata.
  const metaFrame = await transport.readFrame();
  if (metaFrame.msgType !== MSG_METADATA) {
    throw new Error(`Expected metadata, got 0x${metaFrame.msgType.toString(16)}`);
  }
  const meta: Metadata = JSON.parse(new TextDecoder().decode(metaFrame.data));
  if (!Number.isSafeInteger(meta.size) || meta.size < 0 || meta.size > MAX_DISK_RECEIVE_SIZE || typeof meta.name !== "string") {
    throw new Error("Invalid transfer metadata");
  }
  onProgress?.(0, meta);
  // The v0.4.0 CLI counted every TAR header as one 512-byte block, omitting
  // PAX extension headers for long or Unicode paths. Only negotiated v2 folder
  // archives receive that compatibility allowance.
  const enforceDeclaredSize = !meta.streamMode && !(transport.protocolVersion === 2 && meta.isFolder);

  // Check for compression.
  const useZstd = meta.compression === "zstd";
  if (meta.compression && !useZstd) {
    throw new Error(`Unsupported compression: ${meta.compression}`);
  }

  // Try to get a writer for streaming to disk.
  const writer = getWriter ? await getWriter(meta) : null;
  let finalized = false;
  try {

  // Read data chunks.
  const memory = writer ? null : new BoundedMemorySink(MAX_RECEIVE_SIZE);
  if (memory && meta.size > MAX_RECEIVE_SIZE) throw new Error("File exceeds browser memory limit — use disk streaming or the CLI");
  const hasher = new SHA256();
  let totalBytes = 0;
  let chunkCount = 0;
  let lastRenderYield = nowMs();

  while (true) {
    const frame = await transport.readFrame();

    if (frame.msgType === MSG_DATA) {
      // Decompress if sender indicated zstd compression.
      const data = useZstd ? decompressChunk(frame.data, MAX_CHUNK_SIZE) : frame.data;
      if (data.length > MAX_CHUNK_SIZE) throw new Error("Data chunk exceeds maximum size");
      if (!data.length || !Number.isSafeInteger(totalBytes + data.length) || data.length > MAX_DISK_RECEIVE_SIZE - totalBytes || (enforceDeclaredSize && data.length > meta.size - totalBytes)) {
        throw new Error("Transfer exceeds declared size");
      }
      if (writer) {
        const writeStart = nowMs();
        await writer.write(data);
        transport.recordTiming?.("writeMs", nowMs() - writeStart);
      } else {
        memory!.write(data);
      }
      const hashStart = nowMs();
      hasher.update(data);
      transport.recordTiming?.("hashMs", nowMs() - hashStart);
      totalBytes += data.length;
      chunkCount++;
      await transport.consumeData();
      onProgress?.(totalBytes);
      if (nowMs() - lastRenderYield >= RECEIVE_RENDER_INTERVAL_MS) {
        await yieldToBrowser();
        lastRenderYield = nowMs();
      }
    } else if (frame.msgType === MSG_DONE) {
      const done: Done = JSON.parse(new TextDecoder().decode(frame.data));
      if (enforceDeclaredSize && totalBytes !== meta.size) throw new Error("Transfer does not match declared size");
      if (done.totalBytes !== totalBytes || done.chunkCount !== chunkCount) {
        await transport.sendError("Verification mismatch");
        throw new Error("Verification mismatch");
      }
      // Verify SHA-256.
      const recvSha256 = hexEncode(hasher.digest());
      if (recvSha256 !== done.sha256) {
        await transport.sendError("Integrity check failed: SHA-256 mismatch");
        throw new Error("Integrity check failed: SHA-256 mismatch");
      }
      // Send complete and wait for FinAck so we don't tear down
      // the connection before the sender reads our Complete.
      const blob = memory ? memory.toBlob(meta.type) : null;
      if (writer) await writer.close();
      finalized = true;
      await transport.sendComplete(totalBytes, chunkCount, recvSha256);
      try { await transport.readFrame(COMPLETION_ACK_TIMEOUT); } catch {} // bounded best-effort FinAck wait
      if (writer) {
        return { meta, blob: null, totalBytes };
      }
      return { meta, blob, totalBytes };
    } else if (frame.msgType === MSG_ERROR) {
      const err = JSON.parse(new TextDecoder().decode(frame.data));
      throw new Error(`Sender error: ${err.message}`);
    } else {
      throw new Error(`Unexpected message type: 0x${frame.msgType.toString(16)}`);
    }
  }
  } catch (err) {
    if (writer && !finalized) {
      try { await writer.abort(err); } catch { /* Preserve the original failure. */ }
    }
    throw err;
  }
}
