// SPDX-License-Identifier: MIT

import type { DataChannelTransport } from "./transfer";
import { log } from "./log";

// Diagnostics are aggregate counters, never frame payloads or ICE addresses.
// Missing browser statistics are allowed and must not interrupt a transfer.
export function monitorTransfer(
  pc: RTCPeerConnection,
  transport: DataChannelTransport,
  onPath: (relay: boolean) => void,
): () => void {
  let stopped = false;
  let sampling = false;
  let pathReported = false;
  const sample = async () => {
    if (stopped || sampling) return;
    sampling = true;
    try {
      const stats = await pc.getStats();
      if (stopped) return;
      let pair: any;
      const channels: any[] = [];
      stats.forEach(stat => {
        if (stat.type === "transport" && stat.selectedCandidatePairId) pair = stats.get(stat.selectedCandidatePairId);
        if (stat.type === "data-channel") channels.push(stat);
      });
      if (!pair) stats.forEach(stat => {
        if (stat.type === "candidate-pair" && stat.nominated && stat.state === "succeeded") pair = stat;
      });
      const localType = pair && stats.get(pair.localCandidateId)?.candidateType;
      const remoteType = pair && stats.get(pair.remoteCandidateId)?.candidateType;
      const relay = localType === "relay" || remoteType === "relay";
      if (!pathReported && (relay || (localType && remoteType))) {
        pathReported = true;
        onPath(relay);
      }
      log("transfer diagnostics", {
        ...transport.diagnostics(),
        path: relay ? "TURN relay" : localType && remoteType ? "direct" : "unknown",
        localCandidateType: localType,
        remoteCandidateType: remoteType,
        rttMs: typeof pair?.currentRoundTripTime === "number" ? Math.round(pair.currentRoundTripTime * 1000) : undefined,
        maxMessageSize: pc.sctp?.maxMessageSize,
        dataChannelBytesSent: channels.length ? channels.reduce((sum, channel) => sum + (channel.bytesSent || 0), 0) : undefined,
        dataChannelBytesReceived: channels.length ? channels.reduce((sum, channel) => sum + (channel.bytesReceived || 0), 0) : undefined,
      });
    } catch {
      if (!stopped) log("transfer diagnostics", transport.diagnostics());
    } finally { sampling = false; }
  };
  const timer = setInterval(() => { void sample(); }, 2000);
  void sample();
  return () => {
    stopped = true;
    clearInterval(timer);
    log("final transfer diagnostics", transport.diagnostics());
  };
}
