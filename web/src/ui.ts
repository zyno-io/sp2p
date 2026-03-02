// SPDX-License-Identifier: MIT

// UI helpers for the web interface.

export function $(selector: string): HTMLElement {
  return document.querySelector(selector)!;
}

export function show(el: HTMLElement): void {
  el.classList.remove("hidden");
}

export function hide(el: HTMLElement): void {
  el.classList.add("hidden");
}

// Update a status step in the step list.
export function setStepStatus(
  stepEl: HTMLElement,
  state: "pending" | "active" | "done" | "error"
): void {
  stepEl.classList.remove("step-pending", "step-active", "step-done", "step-error");
  stepEl.classList.add(`step-${state}`);
}

// Update the progress bar.
export function updateProgress(
  barEl: HTMLElement,
  infoEl: HTMLElement,
  bytes: number,
  total: number,
  startTime: number,
  fileCount?: number
): void {
  const pct = total > 0 ? (bytes / total) * 100 : 0;
  barEl.style.width = `${Math.min(pct, 100)}%`;

  const elapsed = (Date.now() - startTime) / 1000;
  const speed = elapsed > 0 ? bytes / elapsed : 0;
  const eta =
    total > 0 && speed > 0 ? Math.ceil((total - bytes) / speed) : 0;

  const totalLabel = fileCount ? `${formatBytes(total)} (${fileCount} files)` : formatBytes(total);
  infoEl.textContent = `${formatBytes(bytes)} / ${totalLabel}  —  ${formatBytes(speed)}/s  —  ETA ${formatTime(eta)}`;
}

export function formatBytes(b: number): string {
  if (b >= 1 << 30) return `${(b / (1 << 30)).toFixed(1)} GB`;
  if (b >= 1 << 20) return `${(b / (1 << 20)).toFixed(1)} MB`;
  if (b >= 1 << 10) return `${(b / (1 << 10)).toFixed(1)} KB`;
  return `${b} B`;
}

function formatTime(secs: number): string {
  if (secs <= 0) return "—";
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs - m * 60;
  return `${m}m${s}s`;
}

// Set up drag-and-drop on an element.
export function setupDragDrop(
  el: HTMLElement,
  onFiles: (files: File[]) => void
): void {
  el.addEventListener("dragover", (e) => {
    e.preventDefault();
    el.classList.add("drag-over");
  });

  el.addEventListener("dragleave", () => {
    el.classList.remove("drag-over");
  });

  el.addEventListener("drop", async (e) => {
    e.preventDefault();
    el.classList.remove("drag-over");
    if (!e.dataTransfer?.items?.length) return;

    const files = await collectDroppedFiles(e.dataTransfer.items);
    if (files.length > 0) onFiles(files);
  });
}

// Recursively collect files from dropped items, preserving relative paths for directories.
async function collectDroppedFiles(items: DataTransferItemList): Promise<File[]> {
  const files: File[] = [];
  const entries: FileSystemEntry[] = [];

  for (let i = 0; i < items.length; i++) {
    const entry = items[i].webkitGetAsEntry?.();
    if (entry) entries.push(entry);
  }

  for (const entry of entries) {
    await traverseEntry(entry, "", files);
  }

  return files;
}

async function traverseEntry(entry: FileSystemEntry, basePath: string, out: File[]): Promise<void> {
  const path = basePath ? `${basePath}/${entry.name}` : entry.name;

  if (entry.isFile) {
    const file = await new Promise<File>((resolve, reject) => {
      (entry as FileSystemFileEntry).file(resolve, reject);
    });
    // Wrap with the relative path as the name so tar preserves folder structure.
    const named = new File([file], path, { type: file.type, lastModified: file.lastModified });
    out.push(named);
  } else if (entry.isDirectory) {
    const reader = (entry as FileSystemDirectoryEntry).createReader();
    const entries = await readAllEntries(reader);
    for (const child of entries) {
      await traverseEntry(child, path, out);
    }
  }
}

// readAllEntries drains a directory reader (readEntries returns batches).
async function readAllEntries(reader: FileSystemDirectoryReader): Promise<FileSystemEntry[]> {
  const all: FileSystemEntry[] = [];
  while (true) {
    const batch = await new Promise<FileSystemEntry[]>((resolve, reject) => {
      reader.readEntries(resolve, reject);
    });
    if (batch.length === 0) break;
    all.push(...batch);
  }
  return all;
}

// Trigger a file download from a Blob.
export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Show an error message in the UI.
export function showError(container: HTMLElement, message: string): void {
  container.innerHTML = `<div class="error-message">${escapeHtml(message)}</div>`;
}

function escapeHtml(s: string): string {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}
