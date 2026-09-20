// SPDX-License-Identifier: MIT

// Minimal tar creation for multi-file browser send.
// Produces a standard POSIX tar archive compatible with Go's archive/tar.

const BLOCK_SIZE = 512;

function encodeOctal(val: number, len: number): string {
  const s = val.toString(8);
  if (!Number.isSafeInteger(val) || val < 0 || s.length > len - 1) throw new Error("TAR numeric field overflow");
  return s.padStart(len - 1, "0") + "\0";
}

function encodeString(s: string, len: number): Uint8Array {
  const buf = new Uint8Array(len);
  const encoded = new TextEncoder().encode(s);
  if (encoded.length > len) throw new Error("TAR path field overflow");
  buf.set(encoded);
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

function createHeader(name: string, size: number, prefix = "", kind = 0x30): Uint8Array {
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
  header[156] = kind;
  header.set(encodeString(prefix, 155), 345);
  // USTAR magic (257, 6 bytes).
  header.set(new TextEncoder().encode("ustar\0"), 257);
  // USTAR version (263, 2 bytes).
  header.set(new TextEncoder().encode("00"), 263);

  // Compute and write checksum (148, 8 bytes).
  const checksum = computeChecksum(header);
  header.set(new TextEncoder().encode(encodeOctal(checksum, 7) + " "), 148);

  return header;
}

function paxRecord(key: string, value: string): Uint8Array {
  const encoder = new TextEncoder();
  const body = ` ${key}=${value}\n`;
  const bodySize = encoder.encode(body).length;
  let size = bodySize + 1;
  while (String(size).length + bodySize !== size) size = String(size).length + bodySize;
  return encoder.encode(`${size}${body}`);
}

function fileHeaders(file: File, index: number): Uint8Array[] {
  const path = file.webkitRelativePath || file.name;
  const encoder = new TextEncoder();
  if (!path || path.includes("\\") || path.includes("\0") || path.split("/").some(p => !p || p === "." || p === "..") || encoder.encode(path).length > 4096) {
    throw new Error("Unsupported archive path");
  }
  if (!Number.isSafeInteger(file.size) || file.size < 0) throw new Error("Unsupported file size");
  let name = path, prefix = "";
  if (encoder.encode(name).length > 100) {
    for (let cut = path.lastIndexOf("/"); cut > 0; cut = path.lastIndexOf("/", cut - 1)) {
      if (encoder.encode(path.slice(0, cut)).length <= 155 && encoder.encode(path.slice(cut + 1)).length <= 100) {
        prefix = path.slice(0, cut); name = path.slice(cut + 1); break;
      }
    }
  }
  const records: Uint8Array[] = [];
  if (encoder.encode(name).length > 100) {
    records.push(paxRecord("path", path)); name = `file-${index}`;
  }
  let size = file.size;
  if (size >= 8 ** 11) { records.push(paxRecord("size", String(size))); size = 0; }
  const headers: Uint8Array[] = [];
  if (records.length) {
    const length = records.reduce((n, record) => n + record.length, 0);
    headers.push(createHeader(`PaxHeaders/${index}`, length, "", 0x78));
    const body = new Uint8Array(Math.ceil(length / BLOCK_SIZE) * BLOCK_SIZE);
    let offset = 0;
    for (const record of records) { body.set(record, offset); offset += record.length; }
    headers.push(body);
  }
  headers.push(createHeader(name, size, prefix));
  return headers;
}

// Create a tar archive from multiple files.
// Returns the total tar size and an async iterator of chunks.
export interface TarArchive {
  totalSize: number;
  stream: () => AsyncGenerator<{ chunk: Uint8Array; offset: number }>;
}

export function createTar(files: File[]): TarArchive {
  if (files.length > 100000) throw new Error("Too many archive entries");
  const names = new Set<string>();
  const headers = files.map((file, index) => {
    const name = file.webkitRelativePath || file.name;
    if (names.has(name)) throw new Error("Duplicate archive path");
    names.add(name);
    return fileHeaders(file, index);
  });
  let totalSize = 0;
  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    totalSize += headers[i].reduce((n, header) => n + header.length, 0);
    totalSize += Math.ceil(f.size / BLOCK_SIZE) * BLOCK_SIZE; // data (padded)
  }
  totalSize += BLOCK_SIZE * 2; // end-of-archive marker
  if (!Number.isSafeInteger(totalSize)) throw new Error("Archive size overflow");

  async function* stream() {
    let offset = 0;
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      // Emit header.
      for (const header of headers[i]) {
        yield { chunk: header, offset };
        offset += header.length;
      }

      // Emit file data in chunks.
      let fileOffset = 0;
      while (fileOffset < file.size) {
        const end = Math.min(fileOffset + 256 * 1024, file.size);
        const blob = file.slice(fileOffset, end);
        const buffer = await blob.arrayBuffer();
        const data = new Uint8Array(buffer);
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
