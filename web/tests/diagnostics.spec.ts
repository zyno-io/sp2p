// SPDX-License-Identifier: MIT

import { test, expect } from "@playwright/test";
import { monitorTransfer } from "../src/diagnostics";
import type { DataChannelTransport } from "../src/transfer";

const transport = { diagnostics: () => ({ queuedBytes: 0 }) } as DataChannelTransport;

test("diagnostics distinguish socket discards from delivery and omit addresses", async () => {
  const stats = new Map<string, any>([
    ["transport", { type: "transport", selectedCandidatePairId: "pair" }],
    ["pair", { type: "candidate-pair", localCandidateId: "local", remoteCandidateId: "remote", packetsDiscardedOnSend: 12, bytesDiscardedOnSend: 14400, bytesSent: 500000, bytesReceived: 8000 }],
    ["local", { candidateType: "host", address: "192.0.2.10" }],
    ["remote", { candidateType: "srflx", address: "198.51.100.20" }],
  ]);
  const pc = { getStats: async () => stats } as unknown as RTCPeerConnection;
  const entries: unknown[][] = [];
  const originalLog = console.log;
  console.log = (...args) => { entries.push(args); };
  const stop = monitorTransfer(pc, transport, () => {});
  try {
    await expect.poll(() => entries.length).toBe(1);
    expect(entries).toHaveLength(1);
    expect(entries[0][1]).toMatchObject({
      packetsDiscardedOnSend: 12, bytesDiscardedOnSend: 14400,
      networkBytesSent: 500000, networkBytesReceived: 8000,
    });
    expect(JSON.stringify(entries)).not.toContain("192.0.2.10");
    expect(JSON.stringify(entries)).not.toContain("198.51.100.20");
    // Absent browser counters stay unavailable, rather than implying no drops.
    delete stats.get("pair").packetsDiscardedOnSend;
    delete stats.get("pair").bytesDiscardedOnSend;
    const stopMissing = monitorTransfer(pc, transport, () => {});
    try {
      await expect.poll(() => entries.length).toBe(2);
      expect(entries).toHaveLength(2);
      expect(entries[1][1]).toMatchObject({ packetsDiscardedOnSend: undefined, bytesDiscardedOnSend: undefined });
    } finally { stopMissing(); }
  } finally {
    stop();
    console.log = originalLog;
  }
});

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

test("parallel diagnostics aggregate all paths and retain missing counters", async () => {
  const peers = ["host", "relay", "srflx"].map((type, index) => ({
    getStats: async () => new Map<string, any>([
      ["pair", { type: "candidate-pair", nominated: true, state: "succeeded", localCandidateId: "local", remoteCandidateId: "remote",
        bytesSent: 100 + index, packetsDiscardedOnSend: index === 2 ? undefined : 1, currentRoundTripTime: (index + 1) / 100 }],
      ["local", { candidateType: "host" }], ["remote", { candidateType: type }],
    ]),
  })) as unknown as RTCPeerConnection[];
  const entries: any[][] = [], paths: boolean[] = [];
  const original = console.log;
  console.log = (...args) => { entries.push(args); };
  const stop = monitorTransfer(peers[0], transport, relay => paths.push(relay), peers);
  try {
    await expect.poll(() => entries.length).toBe(1);
    expect(paths).toEqual([true]);
    expect(entries[0][1]).toMatchObject({ connections: 3, path: "TURN relay", networkBytesSent: 303, packetsDiscardedOnSend: undefined, rttMs: 30 });
  } finally { stop(); console.log = original; }
});
