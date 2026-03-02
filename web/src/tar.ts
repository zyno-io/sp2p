// SPDX-License-Identifier: MIT

// Minimal tar creation for multi-file browser send.
// Produces a standard POSIX tar archive compatible with Go's archive/tar.

const BLOCK_SIZE = 512;

function encodeOctal(val: number, len: number): string {
  const s = val.toString(8);
  return s.padStart(len - 1, "0") + "\0";
}

function encodeString(s: string, len: number): Uint8Array {
  const buf = new Uint8Array(len);
  const encoded = new TextEncoder().encode(s);
  buf.set(encoded.subarray(0, len));
  return buf;
}

function computeChecksum(header: Uint8Array): number {
  let sum = 0;
  for (let i = 0; i < BLOCK_SIZE; i++) {
    // Checksum field (offset 148, 8 bytes) is treated as spaces during computation.
    if (i >= 148 && i < 156) {
      sum += 0x20;
    } else {
      sum += header[i];
    }
  }
  return sum;
}

function createHeader(name: string, size: number): Uint8Array {
  const header = new Uint8Array(BLOCK_SIZE);

  // File name (0, 100 bytes).
  header.set(encodeString(name, 100), 0);
  // File mode (100, 8 bytes) — 0644.
  header.set(new TextEncoder().encode(encodeOctal(0o644, 8)), 100);
  // uid (108, 8) and gid (116, 8) — 0.
  header.set(new TextEncoder().encode(encodeOctal(0, 8)), 108);
  header.set(new TextEncoder().encode(encodeOctal(0, 8)), 116);
  // File size (124, 12 bytes).
  header.set(new TextEncoder().encode(encodeOctal(size, 12)), 124);
  // Mod time (136, 12 bytes) — current time.
  header.set(new TextEncoder().encode(encodeOctal(Math.floor(Date.now() / 1000), 12)), 136);
  // Type flag (156, 1 byte) — '0' for regular file.
  header[156] = 0x30;
  // USTAR magic (257, 6 bytes).
  header.set(new TextEncoder().encode("ustar\0"), 257);
  // USTAR version (263, 2 bytes).
  header.set(new TextEncoder().encode("00"), 263);

  // Compute and write checksum (148, 8 bytes).
  const checksum = computeChecksum(header);
  header.set(new TextEncoder().encode(encodeOctal(checksum, 7) + " "), 148);

  return header;
}

// Create a tar archive from multiple files.
// Returns the total tar size and an async iterator of chunks.
export function createTar(files: File[]): { totalSize: number; stream: () => AsyncGenerator<{ chunk: Uint8Array; offset: number }> } {
  let totalSize = 0;
  for (const f of files) {
    totalSize += BLOCK_SIZE; // header
    totalSize += Math.ceil(f.size / BLOCK_SIZE) * BLOCK_SIZE; // data (padded)
  }
  totalSize += BLOCK_SIZE * 2; // end-of-archive marker

  async function* stream() {
    let offset = 0;
    for (const file of files) {
      // Emit header.
      const header = createHeader(file.name, file.size);
      yield { chunk: header, offset };
      offset += BLOCK_SIZE;

      // Emit file data in chunks.
      let fileOffset = 0;
      while (fileOffset < file.size) {
        const end = Math.min(fileOffset + 64 * 1024, file.size);
        const blob = file.slice(fileOffset, end);
        const data = new Uint8Array(await blob.arrayBuffer());
        yield { chunk: data, offset };
        offset += data.length;
        fileOffset = end;
      }

      // Pad to block boundary.
      const remainder = file.size % BLOCK_SIZE;
      if (remainder > 0) {
        const padding = new Uint8Array(BLOCK_SIZE - remainder);
        yield { chunk: padding, offset };
        offset += padding.length;
      }
    }

    // End-of-archive: two zero blocks.
    yield { chunk: new Uint8Array(BLOCK_SIZE * 2), offset };
  }

  return { totalSize, stream };
}
