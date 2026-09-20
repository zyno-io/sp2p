// SPDX-License-Identifier: MIT

// Run the compiled Node bundle in a memory-limited container. This deliberately
// uses many valid tiny zstd chunks: the former scratch-view retention could grow
// by 256 KiB per decoded byte, despite the receive payload remaining tiny.
import assert from "node:assert/strict";
import { BoundedMemorySink } from "../src/memory-sink";
import { decompressChunk } from "../src/bounded-zstd";

async function main(): Promise<void> {
  const start = Date.now();
  const known = new Uint8Array([0x28, 0xb5, 0x2f, 0xfd, 0x20, 1, 9, 0, 0, 65]);
  const unknown = new Uint8Array([0x28, 0xb5, 0x2f, 0xfd, 0, 0, 9, 0, 0, 65]);
  const chunks = 200_000;
  const tiny = new BoundedMemorySink(256 * 1024 * 1024);
  let peakRSS = process.memoryUsage().rss;
  for (let i = 0; i < chunks; i++) {
    const decoded = decompressChunk(i % 128 === 0 ? unknown : known, 256 * 1024);
    assert.equal(decoded.buffer.byteLength, 1);
    tiny.write(decoded);
    if (i % 1024 === 0) peakRSS = Math.max(peakRSS, process.memoryUsage().rss);
  }
  assert.equal(tiny.allocatedBytes, 256 * 1024);
  assert.equal(tiny.blockCount, 1);
  const tinyBlob = tiny.toBlob("text/plain");
  const text = await tinyBlob.text();
  assert.equal(text, "A".repeat(chunks));

  const limit = 16 * 1024 * 1024;
  const full = new BoundedMemorySink(limit);
  const block = new Uint8Array(256 * 1024).fill(42);
  for (let i = 0; i < limit / block.length; i++) full.write(block);
  assert.equal(full.allocatedBytes, limit);
  assert.equal(full.blockCount, 64);
  assert.throws(() => full.write(new Uint8Array(1)), /memory limit/);
  const fullBlob = full.toBlob("application/octet-stream");
  assert.equal(fullBlob.size, limit);
  assert.equal(full.allocatedBytes, 0);
  peakRSS = Math.max(peakRSS, process.memoryUsage().rss);
  console.log(JSON.stringify({ chunks, tinyDecodedBytes: chunks, tinyRetainedBytes: 256 * 1024, fullQuotaBytes: limit, peakRSS, elapsedMs: Date.now() - start }));
}

void main().catch((err) => { console.error(err); process.exitCode = 1; });
