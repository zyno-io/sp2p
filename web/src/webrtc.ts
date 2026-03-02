// SPDX-License-Identifier: MIT

// WebRTC connection establishment for the web UI.

import { log } from "./log";
import { SignalClient } from "./signal";

const DEFAULT_STUN_SERVERS = [
  "stun:stun.l.google.com:19302",
  "stun:stun1.l.google.com:19302",
];

const DATA_CHANNEL_LABEL = "sp2p";

export interface WebRTCResult {
  dc: RTCDataChannel;
  pc: RTCPeerConnection;
}

export interface ICEServerConfig {
  urls: string[];
  username?: string;
  credential?: string;
}

// Split ICE servers into STUN-only and TURN servers.
export function splitIceServers(
  iceServers?: ICEServerConfig[]
): { stun: RTCIceServer[]; turn: RTCIceServer[] } {
  const stun: RTCIceServer[] = [];
  const turn: RTCIceServer[] = [];

  if (!iceServers || iceServers.length === 0) {
    return {
      stun: DEFAULT_STUN_SERVERS.map((url) => ({ urls: url })),
      turn: [],
    };
  }

  for (const s of iceServers) {
    const hasTurn = s.urls.some(
      (u) => u.startsWith("turn:") || u.startsWith("turns:")
    );
    if (hasTurn) {
      turn.push({ urls: s.urls, username: s.username, credential: s.credential });
    } else {
      stun.push({ urls: s.urls });
    }
  }

  if (stun.length === 0) {
    stun.push(...DEFAULT_STUN_SERVERS.map((url) => ({ urls: url as string | string[] })));
  }

  return { stun, turn };
}

// Establish a WebRTC connection using the signaling client.
// Only the provided rtcIceServers are used (caller controls STUN vs TURN inclusion).
export function establishWebRTC(
  sigClient: SignalClient,
  isSender: boolean,
  onStatus?: (method: string, state: string, detail?: string) => void,
  iceServers?: ICEServerConfig[],
  timeoutMs = 15000,
  rtcIceServersOverride?: RTCIceServer[]
): Promise<WebRTCResult> {
  return new Promise((resolve, reject) => {
    onStatus?.("WebRTC", "trying", "ICE gathering...");

    // Clean up handlers from any previous attempt to prevent cross-attempt interference.
    const handlerTypes = ["candidate", "answer", "offer", "error", "peer-left"];
    for (const t of handlerTypes) {
      sigClient.off(t);
    }

    const rtcIceServers: RTCIceServer[] =
      rtcIceServersOverride ??
      (iceServers && iceServers.length > 0
        ? iceServers.map((s) => ({
            urls: s.urls,
            username: s.username,
            credential: s.credential,
          }))
        : DEFAULT_STUN_SERVERS.map((url) => ({ urls: url })));

    log(`WebRTC: creating peer connection with ${rtcIceServers.length} ICE servers (isSender=${isSender})`);
    const pc = new RTCPeerConnection({
      iceServers: rtcIceServers,
    });

    let settled = false;
    let timer: ReturnType<typeof setTimeout>;

    function cleanup() {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      for (const t of handlerTypes) {
        sigClient.off(t);
      }
    }

    function resolveClean(result: WebRTCResult) {
      cleanup();
      resolve(result);
    }

    function rejectClean(err: unknown) {
      if (settled) return;
      cleanup();
      pc.close();
      reject(err);
    }

    // Register error/peer-left handlers immediately so there's no gap
    // where these events could be missed.
    sigClient.on("error", (env) => {
      rejectClean(new Error(env.payload?.message || "Signaling error"));
    });
    sigClient.on("peer-left", () => {
      rejectClean(new Error("Peer disconnected"));
    });

    pc.onconnectionstatechange = () => {
      log(`WebRTC: connection state → ${pc.connectionState}`);
    };

    // Send ICE candidates.
    pc.onicecandidate = (event) => {
      if (event.candidate) {
        log(`WebRTC: local ICE candidate: ${event.candidate.type || "unknown"} ${event.candidate.address || ""}`);
        sigClient.send("candidate", {
          candidate: event.candidate.candidate,
          sdpMid: event.candidate.sdpMid,
          sdpMLineIndex: event.candidate.sdpMLineIndex,
        });
      }
    };

    // Handle incoming ICE candidates.
    sigClient.on("candidate", (env) => {
      const c = env.payload;
      log(`WebRTC: received remote ICE candidate: ${c.candidate}`);
      pc.addIceCandidate(
        new RTCIceCandidate({
          candidate: c.candidate,
          sdpMid: c.sdpMid,
          sdpMLineIndex: c.sdpMLineIndex,
        })
      ).catch(() => {});
    });

    if (isSender) {
      // Sender creates data channel and offer.
      const dc = pc.createDataChannel(DATA_CHANNEL_LABEL, {
        ordered: true,
      });
      dc.binaryType = "arraybuffer";

      dc.onopen = () => {
        log("WebRTC: data channel open");
        onStatus?.("WebRTC", "connected");
        sigClient.send("connected", {});
        resolveClean({ dc, pc });
      };

      pc.createOffer()
        .then((offer) => pc.setLocalDescription(offer))
        .then(() => {
          // Wait for ICE gathering to complete for a complete SDP.
          return new Promise<void>((res) => {
            if (pc.iceGatheringState === "complete") {
              res();
            } else {
              pc.onicegatheringstatechange = () => {
                if (pc.iceGatheringState === "complete") res();
              };
              // Timeout after 3s and send what we have.
              setTimeout(res, 3000);
            }
          });
        })
        .then(() => {
          log("WebRTC: sending SDP offer:\n" + pc.localDescription!.sdp);
          sigClient.send("offer", {
            sdp: pc.localDescription!.sdp,
            type: pc.localDescription!.type,
          });
        })
        .catch(rejectClean);

      // Wait for answer.
      sigClient.on("answer", (env) => {
        log("WebRTC: received SDP answer:\n" + env.payload.sdp);
        pc.setRemoteDescription(
          new RTCSessionDescription({
            sdp: env.payload.sdp,
            type: env.payload.type,
          })
        ).catch(rejectClean);
      });
    } else {
      // Receiver waits for data channel.
      pc.ondatachannel = (event) => {
        const dc = event.channel;
        dc.binaryType = "arraybuffer";
        dc.onopen = () => {
          log("WebRTC: data channel open");
          onStatus?.("WebRTC", "connected");
          sigClient.send("connected", {});
          resolveClean({ dc, pc });
        };
      };

      // Wait for offer.
      sigClient.on("offer", async (env) => {
        log("WebRTC: received SDP offer:\n" + env.payload.sdp);
        try {
          await pc.setRemoteDescription(
            new RTCSessionDescription({
              sdp: env.payload.sdp,
              type: env.payload.type,
            })
          );
          const answer = await pc.createAnswer();
          await pc.setLocalDescription(answer);

          // Wait for ICE gathering.
          await new Promise<void>((res) => {
            if (pc.iceGatheringState === "complete") {
              res();
            } else {
              pc.onicegatheringstatechange = () => {
                if (pc.iceGatheringState === "complete") res();
              };
              setTimeout(res, 3000);
            }
          });

          log("WebRTC: sending SDP answer:\n" + pc.localDescription!.sdp);
          sigClient.send("answer", {
            sdp: pc.localDescription!.sdp,
            type: pc.localDescription!.type,
          });
        } catch (err) {
          rejectClean(err);
        }
      });
    }

    // Timeout.
    timer = setTimeout(() => {
      rejectClean(new Error("WebRTC connection timed out"));
    }, timeoutMs);
  });
}
