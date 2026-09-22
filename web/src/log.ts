// SPDX-License-Identifier: MIT

// Diagnostic logging with [sp2p] prefix.
// Always logs to console — only visible when DevTools is open.

export function log(msg: string, ...args: unknown[]): void {
  const timestamp = new Date().toISOString();
  console.log(`[sp2p] ${timestamp} ${msg}`, ...args);
}
