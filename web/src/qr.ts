// SPDX-License-Identifier: MIT

import QRCode from "qrcode";

let overlay: HTMLDivElement | null = null;
let escHandler: ((e: KeyboardEvent) => void) | null = null;

export function showQRModal(url: string): void {
  // Remove existing modal if open.
  closeQRModal();

  overlay = document.createElement("div");
  overlay.className = "qr-overlay";

  const modal = document.createElement("div");
  modal.className = "qr-modal";

  // Close button.
  const closeBtn = document.createElement("button");
  closeBtn.className = "qr-close";
  closeBtn.innerHTML = "&times;";
  closeBtn.addEventListener("click", closeQRModal);
  modal.appendChild(closeBtn);

  // Canvas for QR code.
  const canvas = document.createElement("canvas");
  modal.appendChild(canvas);

  // URL text below QR.
  const urlText = document.createElement("div");
  urlText.className = "qr-url";
  urlText.textContent = url;
  modal.appendChild(urlText);

  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  // Render QR code to canvas (CSP-safe, no data URLs).
  QRCode.toCanvas(canvas, url, {
    width: 280,
    margin: 2,
    color: {
      dark: "#e0e0e0",
      light: "#141414",
    },
  });

  // Close on backdrop click.
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) closeQRModal();
  });

  // Close on Escape key.
  escHandler = (e: KeyboardEvent) => {
    if (e.key === "Escape") closeQRModal();
  };
  document.addEventListener("keydown", escHandler);
}

export function closeQRModal(): void {
  if (overlay) {
    overlay.remove();
    overlay = null;
  }
  if (escHandler) {
    document.removeEventListener("keydown", escHandler);
    escHandler = null;
  }
}
