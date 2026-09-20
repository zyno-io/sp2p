// SPDX-License-Identifier: MIT

import { Decompress } from "fzstd";

// Validate the complete envelope BEFORE fzstd allocates its history window.
// SP2P emits one independent zstd frame per data chunk. Skippable frames,
// dictionaries, and concatenated frames are not part of that contract.
export function decompressChunk(input: Uint8Array, limit: number): Uint8Array {
  const bad = () => { throw new Error("Invalid or oversized zstd chunk"); };
  if (input.length < 6 || input[0] !== 0x28 || input[1] !== 0xb5 || input[2] !== 0x2f || input[3] !== 0xfd) bad();
  const flags = input[4];
  if (flags & 0x18) bad();
  const single = !!(flags & 0x20);
  let pos = 5;
  let window = 0;
  if (!single) {
    const descriptor = input[pos++];
    const base = 2 ** (10 + (descriptor >>> 3));
    window = base + base / 8 * (descriptor & 7);
    if (window > limit) bad();
  }
  const dictBytes = [0, 1, 2, 4][flags & 3];
  if (pos + dictBytes > input.length) bad();
  for (let i = 0; i < dictBytes; i++) if (input[pos++] !== 0) bad();
  const sizeFlag = flags >>> 6;
  const sizeBytes = sizeFlag ? 2 ** sizeFlag : single ? 1 : 0;
  if (pos + sizeBytes > input.length) bad();
  let size = 0;
  for (let i = 0; i < sizeBytes; i++) size += input[pos++] * 2 ** (8 * i);
  if (sizeFlag === 1) size += 256;
  if (!Number.isSafeInteger(size) || size > limit) bad();
  if (single) window = size;
  if (window > limit) bad();
  let last = false;
  while (!last) {
    if (pos + 3 > input.length) bad();
    const header = input[pos] + input[pos + 1] * 256 + input[pos + 2] * 65536;
    pos += 3;
    last = !!(header & 1);
    const kind = (header >>> 1) & 3;
    const blockSize = header >>> 3;
    if (kind === 3 || blockSize > 128 * 1024) bad();
    pos += kind === 1 ? 1 : blockSize;
    if (pos > input.length) bad();
  }
  if (flags & 4) pos += 4;
  if (pos !== input.length) bad();
  const output = new Uint8Array(sizeBytes ? size : limit);
  let length = 0;
  const decoder = new Decompress((chunk) => {
    if (chunk.length > output.length - length) bad();
    output.set(chunk, length);
    length += chunk.length;
  });
  decoder.push(input, true);
  if (sizeBytes && length !== size) bad();
  // Do not let a retained tiny result keep the entire scratch allocation alive.
  return length === output.length ? output : output.slice(0, length);
}
