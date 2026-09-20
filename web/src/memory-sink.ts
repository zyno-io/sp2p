// SPDX-License-Identifier: MIT

// Coalesce arbitrary peer chunks into owned blocks. A byte quota alone is not
// enough: tiny views can retain large backing buffers or millions of objects.
export class BoundedMemorySink {
  private blocks: Uint8Array<ArrayBuffer>[] = [];
  private length = 0;
  private capacity = 0;
  private finished = false;

  constructor(private readonly limit: number, private readonly blockSize = 256 * 1024) {
    if (!Number.isSafeInteger(limit) || limit <= 0 || !Number.isSafeInteger(blockSize) || blockSize <= 0) {
      throw new Error("Invalid memory sink limits");
    }
  }

  get size(): number { return this.length; }
  get allocatedBytes(): number { return this.capacity; }
  get blockCount(): number { return this.blocks.length; }

  write(data: Uint8Array): void {
    if (this.finished) throw new Error("Memory sink is already finalized");
    if (data.length > this.limit - this.length) throw new Error("File exceeds browser memory limit — use disk streaming or the CLI");
    let offset = 0;
    while (offset < data.length) {
      if (this.length === this.capacity) {
        const block = new Uint8Array(Math.min(this.blockSize, this.limit - this.capacity));
        this.blocks.push(block);
        this.capacity += block.length;
      }
      const block = this.blocks[this.blocks.length - 1];
      const used = block.length - (this.capacity - this.length);
      const count = Math.min(data.length - offset, block.length - used);
      block.set(data.subarray(offset, offset + count), used);
      this.length += count;
      offset += count;
    }
  }

  toBlob(type: string): Blob {
    if (this.finished) throw new Error("Memory sink is already finalized");
    const parts = this.blocks.map((block, index) => index === this.blocks.length - 1
      ? block.subarray(0, block.length - (this.capacity - this.length)) : block);
    const blob = new Blob(parts, { type });
    this.finished = true;
    this.blocks = [];
    this.capacity = 0;
    return blob;
  }
}
