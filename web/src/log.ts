// SPDX-License-Identifier: MIT

// Diagnostic logging with [sp2p] prefix.
// Always logs to console — only visible when DevTools is open.

export function log(msg: string, ...args: unknown[]): void {
  console.log(`[sp2p] ${msg}`, ...args);
}
