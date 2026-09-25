// SPDX-License-Identifier: MIT
// Numeric summaries of an opt-in WAN JSONL artifact; never print private URLs.
import { readFile } from "node:fs/promises";
const input = process.argv[2];
if (!input) throw new Error("Pass a WAN JSONL artifact path");
const source = await readFile(input, "utf8");
const rows = source.trim().split("\n").map(line => JSON.parse(line));
const samples = rows.filter(row => row.event === "sample");
const latest = samples.at(-1);
const size = rows.find(row => row.event === "start")?.size ?? 500_000_000;
const median = values => {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) return null;
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
};
const summary = { variant: rows[0]?.variant, lastEvent: rows.at(-1)?.event, elapsed: latest?.elapsed };
for (const role of ["sender", "receiver"]) {
  const states = samples.map(row => row[role]).filter(Boolean);
  const diagnostics = states.map(state => state.diagnostics).filter(Boolean);
  const last = diagnostics.at(-1);
  summary[role] = {
    progress: states.at(-1)?.progress,
    medianRttMs: median(diagnostics.map(d => d.rttMs)),
    maxRttMs: Math.max(0, ...diagnostics.map(d => d.rttMs || 0)),
    maxTimerLagMs: Math.max(0, ...states.map(s => s.maxTimerLagMs || 0)),
    maxDiscards: Math.max(0, ...diagnostics.map(d => d.packetsDiscardedOnSend || 0)),
    maxReassemblyFrames: Math.max(0, ...diagnostics.map(d => d.reassemblyFrames || 0)),
    creditWaitMs: last?.creditWaitMs, bufferWaitMs: last?.bufferWaitMs,
    reorderWaitMs: last?.reorderWaitMs, deliveryWaitMs: last?.deliveryWaitMs,
    nextRead: last?.nextRead, nextWrite: last?.nextWrite,
    bufferedByLane: last?.bufferedByLane,
  };
}
let near = 0, longestNear = 0, gap = 0, longestGap = 0;
for (let i = 1; i < samples.length; i++) {
  const before = samples[i - 1], after = samples[i];
  const seconds = after.elapsed - before.elapsed;
  const bytes = after.receiver?.receivedWireBytes - before.receiver?.receivedWireBytes;
  if (before.receiver?.receivedWireBytes > 1048576 && before.receiver.receivedWireBytes < size - 1048576 && !after.receiver.complete && bytes / seconds < 262144) near += seconds;
  else near = 0;
  longestNear = Math.max(longestNear, near);
  const previousReceiver = before.receiver?.diagnostics;
  const receiver = after.receiver?.diagnostics;
  if (previousReceiver?.waitingForSequence && receiver?.waitingForSequence && previousReceiver.nextRead === receiver.nextRead) gap += seconds;
  else gap = 0;
  longestGap = Math.max(longestGap, gap);
}
summary.longestNearStallSeconds = longestNear;
summary.longestUnchangedMissingSequenceSeconds = longestGap;
const verified = rows.findLast(row => row.event === "verified");
if (verified) summary.verified = { size: verified.size, sha256: verified.sha256, elapsed: verified.elapsed, MBps: verified.mbPerSecond };
console.log(JSON.stringify(summary));
