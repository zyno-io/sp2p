import { test as base } from "@playwright/test";
import { readFileSync } from "fs";
import { join } from "path";

interface ServerState {
  pid: number;
  tmpDir: string;
  cliBin: string;
  // Optional: older/other state files may not have this field. When
  // present (see global-setup.ts), it's the prebuilt/built sp2p-server
  // binary path — prefer it over deriving one from tmpDir.
  serverBin?: string;
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
