// SPDX-License-Identifier: MIT

import type { DataChannelTransport } from "./transfer";
import { log } from "./log";

// Diagnostics are aggregate counters, never frame payloads or ICE addresses.
// Missing browser statistics are allowed and must not interrupt a transfer.
export function monitorTransfer(
  pc: RTCPeerConnection,
  transport: DataChannelTransport,
  onPath: (relay: boolean) => void,
  peers: RTCPeerConnection[] = [pc],
): () => void {
  let stopped = false;
  let sampling = false;
  let reportedPath: boolean | undefined;
  const sample = async () => {
    if (stopped || sampling) return;
    sampling = true;
    try {
      const reports = await Promise.all(peers.map(async peer => {
        try { return await peer.getStats(); }
        catch { return new Map<string, any>(); }
      }));
      if (stopped) return;
      const pairs: any[] = [];
      const channels: any[] = [];
      const paths = reports.map(stats => {
        let pair: any;
        stats.forEach(stat => {
          if (stat.type === "transport" && stat.selectedCandidatePairId) pair = stats.get(stat.selectedCandidatePairId);
          if (stat.type === "data-channel") channels.push(stat);
        });
        if (!pair) stats.forEach(stat => {
          if (stat.type === "candidate-pair" && stat.nominated && stat.state === "succeeded") pair = stat;
        });
        pairs.push(pair);
        return {
          localCandidateType: pair && stats.get(pair.localCandidateId)?.candidateType,
          remoteCandidateType: pair && stats.get(pair.remoteCandidateId)?.candidateType,
          rttMs: typeof pair?.currentRoundTripTime === "number" ? Math.round(pair.currentRoundTripTime * 1000) : undefined,
        };
      });
      const relay = paths.some(path => path.localCandidateType === "relay" || path.remoteCandidateType === "relay");
      const known = paths.length > 0 && paths.every(path => path.localCandidateType && path.remoteCandidateType);
      if ((relay || known) && relay !== reportedPath) {
        reportedPath = relay;
        onPath(relay);
      }
      const sum = (field: string): number | undefined => pairs.length && pairs.every(pair => typeof pair?.[field] === "number")
        ? pairs.reduce((total, pair) => total + pair[field], 0) : undefined;
      const rtts = paths.flatMap(path => path.rttMs === undefined ? [] : [path.rttMs]);
      log("transfer diagnostics", {
        ...transport.diagnostics(),
        connections: peers.length,
        path: relay ? "TURN relay" : known ? "direct" : "unknown",
        localCandidateType: paths[0]?.localCandidateType,
        remoteCandidateType: paths[0]?.remoteCandidateType,
        rttMs: rtts.length ? Math.max(...rtts) : undefined,
        paths,
        // These are local socket handoff failures, not an end-to-end loss rate.
        packetsDiscardedOnSend: sum("packetsDiscardedOnSend"),
        bytesDiscardedOnSend: sum("bytesDiscardedOnSend"),
        networkBytesSent: sum("bytesSent"),
        networkBytesReceived: sum("bytesReceived"),
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
