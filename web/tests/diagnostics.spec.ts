// SPDX-License-Identifier: MIT

import { test, expect } from "@playwright/test";
import { monitorTransfer } from "../src/diagnostics";
import type { DataChannelTransport } from "../src/transfer";

const transport = { diagnostics: () => ({ queuedBytes: 0 }) } as DataChannelTransport;

for (const remoteType of ["host", "relay"]) {
  test(`diagnostics report a selected ${remoteType} path`, async () => {
    const stats = new Map([
      ["transport", { type: "transport", selectedCandidatePairId: "pair" }],
      ["pair", { type: "candidate-pair", localCandidateId: "local", remoteCandidateId: "remote" }],
      ["local", { type: "local-candidate", candidateType: "host" }],
      ["remote", { type: "remote-candidate", candidateType: remoteType }],
    ]);
    const paths: boolean[] = [];
    const pc = { getStats: async () => stats } as unknown as RTCPeerConnection;
    const stop = monitorTransfer(pc, transport, relay => paths.push(relay));
    try {
      await expect.poll(() => paths).toEqual([remoteType === "relay"]);
    } finally { stop(); }
  });
}

test("diagnostics ignore late statistics after transfer teardown", async () => {
  let resolveStats!: (stats: Map<string, unknown>) => void;
  const pending = new Promise<Map<string, unknown>>(resolve => { resolveStats = resolve; });
  const pc = { getStats: () => pending } as unknown as RTCPeerConnection;
  const paths: boolean[] = [];
  const stop = monitorTransfer(pc, transport, relay => paths.push(relay));
  stop();
  resolveStats(new Map([
    ["pair", { type: "candidate-pair", nominated: true, state: "succeeded", localCandidateId: "local", remoteCandidateId: "remote" }],
    ["local", { candidateType: "host" }],
    ["remote", { candidateType: "relay" }],
  ]));
  await pending;
  await Promise.resolve();
  expect(paths).toEqual([]);
});

test("unavailable statistics do not fail a transfer or invent a path", async () => {
  const pc = { getStats: async () => { throw new Error("stats unavailable"); } } as unknown as RTCPeerConnection;
  const paths: boolean[] = [];
  const stop = monitorTransfer(pc, transport, relay => paths.push(relay));
  await Promise.resolve();
  stop();
  expect(paths).toEqual([]);
});
