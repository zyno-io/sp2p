import { test as base } from "@playwright/test";
import { readFileSync } from "fs";
import { join } from "path";

interface ServerState {
  pid: number;
  tmpDir: string;
  cliBin: string;
  // The prebuilt/built sp2p-server binary path (see global-setup.ts), which
  // already carries the platform-correct ".exe" suffix on Windows. Always
  // present — global-setup.ts writes it unconditionally — and required so a
  // consumer never falls back to reconstructing a tmpDir-relative path that
  // would drop that suffix.
  serverBin: string;
  port: number;
}

function getState(): ServerState {
  const knownPath = join(__dirname, "..", ".pw-state.json");
  return JSON.parse(readFileSync(knownPath, "utf-8"));
}

export const test = base.extend<{ cliBin: string; wsUrl: string }>({
  cliBin: async ({}, use) => {
    await use(getState().cliBin);
  },
  wsUrl: async ({}, use) => {
    const { port } = getState();
    await use(`ws://localhost:${port}/ws`);
  },
});

export { expect } from "@playwright/test";
