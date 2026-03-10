// SPDX-License-Identifier: MIT

// Transfer protocol — Go-compatible wire format over encrypted DataChannel.

import { EncryptedChannel } from "./crypto";
import { createTar } from "./tar";
import { SHA256 } from "./sha256";
import { decompress as zstdDecompress } from "fzstd";

// Message types (must match Go constants).
export const MSG_METADATA = 0x01;
export const MSG_DATA = 0x02;
export const MSG_DONE = 0x04;
export const MSG_COMPLETE = 0x05;
export const MSG_ERROR = 0x06;

export const MAX_CHUNK_SIZE = 256 * 1024;
export const MAX_FRAME_SIZE = 512 * 1024; // Must match Go's MaxFrameSize
// In-memory receive limit for browsers without File System Access API.
const MAX_RECEIVE_SIZE = 4 * 1024 * 1024 * 1024; // 4 GB

const SEND_HIGH_WATER = 8 * 1024 * 1024; // 8 MB buffered amount threshold
const MAX_QUEUE_BYTES = 8 * 1024 * 1024; // 8 MB max queued receive data

export interface Metadata {
  name: string;
  size: number;
  type: string;
  isFolder: boolean;
  streamMode: boolean;
  fileCount?: number;
  compression?: string;
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

  constructor(dc: RTCDataChannel, enc: EncryptedChannel, initialData?: Uint8Array[]) {
    this.dc = dc;
    this.enc = enc;

    // Replay any data buffered during key confirmation.
    if (initialData) {
      for (const chunk of initialData) {
        const combined = new Uint8Array(this.recvBuffer.length + chunk.length);
        combined.set(this.recvBuffer);
        combined.set(chunk, this.recvBuffer.length);
        this.recvBuffer = combined;
      }
      this.tryParseFrames();
    }

    dc.onmessage = (event) => {
      if (this.fatalError) return; // stop accumulating after error
      const data = new Uint8Array(event.data);
      // Append to buffer and try to parse frames.
      const combined = new Uint8Array(this.recvBuffer.length + data.length);
      combined.set(this.recvBuffer);
      combined.set(data, this.recvBuffer.length);
      this.recvBuffer = combined;

      // Guard against unbounded buffer growth from malformed/partial frames.
      if (this.recvBuffer.length > MAX_FRAME_SIZE + 4) {
        const err = new Error(`Receive buffer exceeded max frame size`);
        this.fatalError = err;
        this.recvBuffer = new Uint8Array(0);
        if (this.recvReject) {
          const reject = this.recvReject;
          this.recvReject = null;
          this.recvResolve = null;
          reject(err);
        }
        return;
      }

      this.tryParseFrames();
    };

    const onClosed = () => {
      const err = new Error("DataChannel closed unexpectedly");
      this.fatalError = err;
      if (this.recvReject) {
        const reject = this.recvReject;
        this.recvReject = null;
        this.recvResolve = null;
        reject(err);
      }
    };
    dc.onclose = onClosed;
    dc.onerror = () => onClosed();
  }

  private tryParseFrames(): void {
    while (this.recvBuffer.length >= 4) {
      const view = new DataView(this.recvBuffer.buffer, this.recvBuffer.byteOffset);
      const payloadLen = view.getUint32(0);

      if (payloadLen > MAX_FRAME_SIZE) {
        const err = new Error(`Frame too large: ${payloadLen} bytes (max ${MAX_FRAME_SIZE})`);
        this.fatalError = err;
        this.recvBuffer = new Uint8Array(0); // free memory
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
        // Backpressure: stop parsing until the consumer drains the queue.
        // Data stays in recvBuffer and is parsed when nextFrame() is called.
        if (this.recvQueueBytes > MAX_QUEUE_BYTES) {
          break;
        }
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
    if (this.dc.bufferedAmount <= SEND_HIGH_WATER) {
      return Promise.resolve();
    }
    if (this.fatalError) {
      return Promise.reject(this.fatalError);
    }
    return new Promise<void>((resolve, reject) => {
      const cleanup = () => {
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
      this.dc.bufferedAmountLowThreshold = SEND_HIGH_WATER / 2;
      this.dc.addEventListener("bufferedamountlow", onLow);
      this.dc.addEventListener("close", onClose);
      this.dc.addEventListener("error", onClose);
    });
  }

  // Send an encrypted frame.
  async sendFrame(msgType: number, data: Uint8Array): Promise<void> {
    const frame = await this.enc.encryptFrame(msgType, data);
    await this.waitForBufferDrain();
    this.dc.send(frame);
  }

  // Read and decrypt a frame.
  async readFrame(): Promise<{ msgType: number; data: Uint8Array }> {
    const payload = await this.nextFrame();
    return this.enc.decryptFrame(payload);
  }

  // Send metadata.
  async sendMetadata(meta: Metadata): Promise<void> {
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

  // Compute SHA-256 of file content up front (Web Crypto only supports one-shot hashing).
  const fileBuffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", fileBuffer);
  const sha256 = hexEncode(new Uint8Array(digest));

  // Send data chunks.
  let offset = 0;
  let chunkCount = 0;

  while (offset < file.size) {
    const end = Math.min(offset + MAX_CHUNK_SIZE, file.size);
    const chunk = new Uint8Array(fileBuffer, offset, end - offset);
    await transport.sendData(chunk);
    offset = end;
    chunkCount++;
    onProgress?.(offset);
  }

  // Send done with checksum.
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
  onProgress?: (bytesSent: number) => void
): Promise<number> {
  const { totalSize, stream } = createTar(files);

  // Send metadata as a folder/stream.
  await transport.sendMetadata({
    name: archiveName,
    size: totalSize,
    type: "application/x-tar",
    isFolder: true,
    streamMode: true,
  });

  // Stream tar chunks.
  const hasher = new SHA256();
  let bytesSent = 0;
  let chunkCount = 0;

  // Re-chunk the tar stream into MAX_CHUNK_SIZE pieces for the wire.
  let pending = new Uint8Array(0);

  for await (const { chunk } of stream()) {
    // Append to pending buffer.
    const combined = new Uint8Array(pending.length + chunk.length);
    combined.set(pending);
    combined.set(chunk, pending.length);
    pending = combined;

    // Flush full chunks.
    while (pending.length >= MAX_CHUNK_SIZE) {
      const slice = pending.slice(0, MAX_CHUNK_SIZE);
      pending = pending.slice(MAX_CHUNK_SIZE);
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
  onProgress?.(0, meta);

  // Check for compression.
  const useZstd = meta.compression === "zstd";
  if (meta.compression && !useZstd) {
    throw new Error(`Unsupported compression: ${meta.compression}`);
  }

  // Try to get a writer for streaming to disk.
  const writer = getWriter ? await getWriter(meta) : null;

  // Read data chunks.
  const chunks: Uint8Array[] = []; // only used when writer is null
  const hasher = new SHA256();
  let totalBytes = 0;
  let chunkCount = 0;

  while (true) {
    const frame = await transport.readFrame();

    if (frame.msgType === MSG_DATA) {
      // Decompress if sender indicated zstd compression.
      const data = useZstd ? zstdDecompress(frame.data) : frame.data;
      if (writer) {
        await writer.write(data);
      } else {
        chunks.push(data);
        if (totalBytes + data.length > MAX_RECEIVE_SIZE) {
          await transport.sendError("File too large for browser transfer");
          throw new Error(
            "File exceeds browser memory limit — use a browser with File System Access API or the CLI"
          );
        }
      }
      hasher.update(data);
      totalBytes += data.length;
      chunkCount++;
      onProgress?.(totalBytes);
    } else if (frame.msgType === MSG_DONE) {
      const done: Done = JSON.parse(new TextDecoder().decode(frame.data));
      if (done.totalBytes !== totalBytes || done.chunkCount !== chunkCount) {
        if (writer) await writer.close();
        await transport.sendError("Verification mismatch");
        throw new Error("Verification mismatch");
      }
      // Verify SHA-256.
      const recvSha256 = hexEncode(hasher.digest());
      if (recvSha256 !== done.sha256) {
        if (writer) await writer.close();
        await transport.sendError("Integrity check failed: SHA-256 mismatch");
        throw new Error("Integrity check failed: SHA-256 mismatch");
      }
      // Send complete.
      await transport.sendComplete(totalBytes, chunkCount, recvSha256);
      if (writer) {
        await writer.close();
        return { meta, blob: null, totalBytes };
      }
      return { meta, blob: new Blob(chunks, { type: meta.type }), totalBytes };
    } else if (frame.msgType === MSG_ERROR) {
      if (writer) await writer.close();
      const err = JSON.parse(new TextDecoder().decode(frame.data));
      throw new Error(`Sender error: ${err.message}`);
    } else {
      if (writer) await writer.close();
      throw new Error(`Unexpected message type: 0x${frame.msgType.toString(16)}`);
    }
  }
}
