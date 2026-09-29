// SPDX-License-Identifier: MIT

import { base64ToBytes, bytesToBase64, deriveWebRTCLaneKeys, EncryptedChannel, type DerivedKeys } from "./crypto";
import { confirmDataChannel } from "./handshake";
import { EncryptedFrameIO, FrameBudget, ParallelFrameIO, PARALLEL_MAX_LANES, type FrameIO } from "./frame-io";
import { log } from "./log";
import { addBufferHint } from "./webrtc";

const CONTROL = 0x0e;
export const PARALLEL_MIN_BYTES = 64 * 1024 * 1024;
export { PARALLEL_MAX_LANES };

// The largest lane count already-released peers understand in the plain
// hello.count field. A sender wanting more lanes caps count at this value
// and carries the real request in max instead, so old receivers — which
// ignore unknown JSON fields — still see a valid count <= 4.
const PARALLEL_LEGACY_MAX_LANES = 4;

interface Setup {
  step: string;
  version?: number;
  count?: number;
  max?: number;
  nonce?: string;
  id?: number;
  sdp?: string;
  mask?: number;
}

// Splits a desired lane count into the hello step/max fields. Requests at or
// below the legacy limit are sent exactly as before, with max omitted;
// larger requests keep count at the legacy cap and carry the real request in
// max, so old receivers still see a plain, understood count.
function helloCountAndMax(count: number): { count: number; max?: number } {
  if (count > PARALLEL_LEGACY_MAX_LANES) return { count: PARALLEL_LEGACY_MAX_LANES, max: count };
  return { count };
}

// Validates an incoming hello and returns the lane count actually being
// requested. The existing 1..4 count bounds and nonce length always apply;
// an optional max of 5..PARALLEL_MAX_LANES is only valid alongside the
// legacy cap count, and then replaces it as the request.
function resolveHelloRequest(hello: Setup): number {
  if (hello.version !== 1 || !Number.isInteger(hello.count) || hello.count! < 1 || hello.count! > PARALLEL_LEGACY_MAX_LANES || typeof hello.nonce !== "string") {
    throw new Error("Invalid WebRTC parallel offer");
  }
  if (!hello.max) return hello.count!;
  if (!Number.isInteger(hello.max) || hello.max < PARALLEL_LEGACY_MAX_LANES + 1 || hello.max > PARALLEL_MAX_LANES || hello.count !== PARALLEL_LEGACY_MAX_LANES) {
    throw new Error("Invalid WebRTC parallel offer");
  }
  return hello.max;
}

// TraceEvent is one address-free state transition recorded for a Lane: a
// millisecond offset from the lane's creation and a short event name such
// as "ice=connected", "conn=failed", "dc=open", or "close=timeout". Mirrors
// internal/conn.LaneTraceEvent on the Go side. Never includes IPs, ports,
// ICE ufrags/pwds, or SDP.
export interface TraceEvent { ms: number; event: string }

// A small, fixed set of handshake.ts error messages that are safe to log
// verbatim: every one of them is a hard-coded literal (see handshake.ts's
// HandshakeIO), never derived from network or peer-controlled data.
const KNOWN_HANDSHAKE_MESSAGES = new Set([
  "Candidate authentication failed",
  "Candidate selection failed",
  "Invalid candidate selection",
  "Key confirmation failed",
  "Connection closed during handshake",
  "Connection failed during handshake",
  "Connection is not open during handshake",
  "Invalid or excessive handshake data",
]);

// describeError reduces an arbitrary Error into a short, address-free
// reason. handshake.ts's own fixed messages (including its "<phase> timed
// out" template, whose phase is always one of our own literal strings) pass
// through unchanged; anything else — e.g. a raw RTCPeerConnection/DOM
// exception, which is not guaranteed address-free — is bucketed into one of
// a handful of generic reasons, mirroring classifyLaneError on the Go side.
function describeError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  if (KNOWN_HANDSHAKE_MESSAGES.has(message) || /^[A-Za-z ]+ timed out$/.test(message)) return message;
  if (/closed/i.test(message)) return "closed";
  if (/time(d)? ?out/i.test(message)) return "timeout";
  return "error";
}

class Lane {
  readonly pc: RTCPeerConnection;
  readonly trace: TraceEvent[] = [];
  stage?: string;
  reason?: string;
  private readonly start = Date.now();
  private dc?: RTCDataChannel;
  private result?: EncryptedFrameIO;
  private closed = false;
  private signalClose!: () => void;
  private closedSignal = new Promise<void>(resolve => { this.signalClose = resolve; });
  private resolve!: (io: EncryptedFrameIO | null) => void;
  private authenticated = new Promise<EncryptedFrameIO | null>(resolve => { this.resolve = resolve; });

  constructor(readonly id: number, configuration: RTCConfiguration, sender: boolean, keys: DerivedKeys, senderPub: Uint8Array, receiverPub: Uint8Array, budget: FrameBudget) {
    this.pc = new RTCPeerConnection(configuration);
    const attach = (dc: RTCDataChannel) => {
      if (this.closed || this.dc || dc.label !== "sp2p" || !dc.ordered || dc.maxRetransmits !== null || dc.maxPacketLifeTime !== null) {
        dc.close(); this.close("attach", "label_rejected"); return;
      }
      this.dc = dc;
      dc.binaryType = "arraybuffer";
      dc.addEventListener("close", () => this.record("dc=close"));
      let started = false;
      const authenticate = async () => {
        if (started || this.closed) return;
        started = true;
        try {
          const initial = await confirmDataChannel(dc, keys, senderPub, receiverPub, sender, 3, { selection: 5000 });
          // Install the new reader synchronously after confirmation, retaining
          // anything that arrived with its last handshake record.
          const enc = new EncryptedChannel(sender ? keys.senderToReceiver : keys.receiverToSender, sender ? keys.receiverToSender : keys.senderToReceiver);
          const io = new EncryptedFrameIO(dc, enc, budget, this.pc, initial);
          if (this.closed) { io.close(); return; }
          this.result = io;
          this.resolve(io);
        } catch (error) { this.close("confirm", describeError(error)); }
      };
      dc.onopen = () => { this.record("dc=open"); void authenticate(); };
      if (dc.readyState === "open") void authenticate();
    };
    this.pc.onconnectionstatechange = () => {
      this.record("conn=" + this.pc.connectionState);
      if (this.pc.connectionState === "failed" || this.pc.connectionState === "closed") this.close("connect", "peer_connection_failed");
    };
    this.pc.oniceconnectionstatechange = () => { this.record("ice=" + this.pc.iceConnectionState); };
    try {
      if (sender) { attach(this.pc.createDataChannel("sp2p", { ordered: true })); addBufferHint(this.pc); }
      else this.pc.ondatachannel = event => attach(event.channel);
    } catch (error) {
      // Construction can fail after the peer connection has allocated native
      // resources. The caller cannot close a Lane it never received.
      this.close("create", describeError(error));
      throw error;
    }
  }

  private record(event: string): void {
    this.trace.push({ ms: Date.now() - this.start, event });
  }

  async description(offer: boolean): Promise<string> {
    const description = await this.untilClosed(offer ? this.pc.createOffer() : this.pc.createAnswer());
    if (this.closed) throw new Error("WebRTC lane closed during gathering");
    await this.untilClosed(this.pc.setLocalDescription(description));
    if (this.pc.iceGatheringState !== "complete") {
      await new Promise<void>(resolve => {
        const finish = () => { clearTimeout(timer); this.pc.removeEventListener("icegatheringstatechange", changed); resolve(); };
        const changed = () => { if (this.pc.iceGatheringState === "complete") finish(); };
        const timer = setTimeout(finish, 3000);
        void this.closedSignal.then(finish);
        this.pc.addEventListener("icegatheringstatechange", changed);
        changed();
      });
    }
    if (this.closed) throw new Error("WebRTC lane closed during gathering");
    const sdp = this.pc.localDescription?.sdp;
    if (!sdp || sdp.length > 12 * 1024) throw new Error("Invalid WebRTC lane SDP size");
    return sdp;
  }

  async setDescription(sdp: string, offer: boolean): Promise<void> {
    if (!sdp || sdp.length > 12 * 1024) throw new Error("Invalid WebRTC lane SDP size");
    await this.untilClosed(this.pc.setRemoteDescription({ type: offer ? "offer" : "answer", sdp }));
  }

  private async untilClosed<T>(operation: Promise<T>): Promise<T> {
    return await Promise.race([operation, this.closedSignal.then(() => { throw new Error("WebRTC lane closed during setup"); })]);
  }

  async wait(): Promise<EncryptedFrameIO | null> {
    const timer = setTimeout(() => this.close("connect", "timeout"), 8000);
    try { return await this.authenticated; }
    finally { clearTimeout(timer); }
  }

  // close is idempotent: only the first call's stage/reason are recorded,
  // matching the address-free discard sites in negotiateParallelWebRTC
  // below, which each call close exactly once per lane.
  close(stage?: string, reason?: string): void {
    if (this.closed) return;
    this.closed = true;
    if (stage) { this.stage = stage; this.reason = reason; this.record("close=" + reason); }
    this.signalClose();
    this.result?.close();
    this.dc?.close();
    this.pc.close();
    this.resolve(null);
  }
}

// The signaling flag is only a compatibility hint. Every setup message below
// is encrypted with the already-confirmed v3 keys; no lane can carry payload
// before fresh candidate authentication and a mutually acknowledged commit.
export async function negotiateParallelWebRTC(
  dc: RTCDataChannel, pc: RTCPeerConnection, enc: EncryptedChannel, initial: Uint8Array[],
  keys: DerivedKeys, senderPub: Uint8Array, receiverPub: Uint8Array,
  sender: boolean, count: number, onStage: (stage: string) => void = () => {},
): Promise<FrameIO> {
  if (!Number.isInteger(count) || count < 1 || count > PARALLEL_MAX_LANES) throw new Error("Invalid WebRTC lane count");
  const budget = new FrameBudget();
  const primary = new EncryptedFrameIO(dc, enc, budget, pc, initial);
  primary.highWater = 8 * 1024 * 1024;
  const lanes: Array<Lane | null> = [];
  const gathering: Array<Promise<string>> = [];
  // laneRecords keeps every lane ever constructed, even after lanes[id] is
  // nulled out on discard, so the finally block below can still read its
  // trace/stage/reason for the one-line failure summary. constructFailures
  // covers the id's a Lane was never even created for.
  const laneRecords: Array<Lane | null> = [];
  const constructFailures: Array<{ id: number; reason: string }> = [];
  let keep = 0;
  let ours = 0;
  let peerMask = 0;
  let success = false;
  let expired = false;
  const timer = setTimeout(() => {
    expired = true;
    primary.close(new Error("Parallel WebRTC setup timed out"));
    for (const lane of lanes) lane?.close("timeout", "setup_timeout");
  }, 25000);
  const write = async (message: Setup) => {
    if (expired) throw new Error("Parallel WebRTC setup timed out");
    const data = new TextEncoder().encode(JSON.stringify(message));
    if (data.length > 16 * 1024) throw new Error("WebRTC setup control too large");
    await primary.writeFrame(CONTROL, data);
  };
  const read = async (step: string): Promise<Setup> => {
    const frame = await primary.readFrame();
    try {
      if (frame.msgType !== CONTROL || frame.data.length > 16 * 1024) throw new Error("Unexpected WebRTC setup control");
      let value: Setup;
      try { value = JSON.parse(new TextDecoder().decode(frame.data)); }
      catch { throw new Error("Invalid WebRTC setup control"); }
      if (value?.step !== step) throw new Error("Invalid WebRTC setup step");
      return value;
    } finally { frame.release?.(); }
  };
  try {
    onStage("Negotiating parallel WebRTC support");
    let nonce: Uint8Array;
    if (sender) {
      nonce = crypto.getRandomValues(new Uint8Array(32));
      await write({ step: "hello", version: 1, ...helloCountAndMax(count), nonce: bytesToBase64(nonce) });
      const accepted = await read("accept");
      if (!Number.isInteger(accepted.count) || accepted.count! < 1 || accepted.count! > count) throw new Error("Invalid WebRTC accepted count");
      count = accepted.count!;
    } else {
      const hello = await read("hello");
      const requested = resolveHelloRequest(hello);
      nonce = base64ToBytes(hello.nonce!);
      if (nonce.length !== 32) throw new Error("Invalid WebRTC setup nonce");
      count = Math.min(count, requested);
      await write({ step: "accept", count });
    }
    if (expired) throw new Error("Parallel WebRTC setup timed out");
    if (count === 1) { success = true; return primary; }
    onStage(`Gathering addresses for ${count} independent WebRTC connections`);
    for (let id = 1; id < count; id++) {
      const laneKeys = await deriveWebRTCLaneKeys(keys.confirm, nonce, id);
      if (expired) throw new Error("Parallel WebRTC setup timed out");
      let lane: Lane | null = null;
      try {
        lane = new Lane(id, pc.getConfiguration(), sender, laneKeys, senderPub, receiverPub, budget);
        laneRecords[id] = lane;
      } catch (error) { constructFailures.push({ id, reason: describeError(error) }); } // bounded setup fallback
      lanes[id] = lane;
      if (!sender) {
        const offer = await read("offer");
        if (offer.id !== id || (offer.sdp !== undefined && (typeof offer.sdp !== "string" || offer.sdp.length > 12 * 1024))) throw new Error("Invalid WebRTC lane offer");
        if (lane) {
          if (!offer.sdp) {
            lane.close("offer", "peer_offer_empty");
            lane = null; lanes[id] = null;
          } else {
            try { await lane.setDescription(offer.sdp, true); }
            catch (error) { lane.close("offer", describeError(error)); lane = null; lanes[id] = null; }
          }
        }
      }
      // Close (not just discard) a lane whose description gathering fails,
      // instead of leaving it open until wait()'s own 8s timer — the same
      // failure would otherwise cost the full timeout for no reason.
      gathering[id] = lane ? lane.description(sender).catch(error => { lane?.close("gather", describeError(error)); return ""; }) : Promise.resolve("");
    }
    const descriptions = await Promise.all(gathering);
    for (let id = 1; id < count; id++) await write({ step: sender ? "offer" : "answer", id, sdp: descriptions[id] });
    if (sender) {
      for (let id = 1; id < count; id++) {
        const answer = await read("answer");
        if (answer.id !== id || (answer.sdp !== undefined && (typeof answer.sdp !== "string" || answer.sdp.length > 12 * 1024))) throw new Error("Invalid WebRTC lane answer");
        const lane = lanes[id];
        if (lane) {
          if (!answer.sdp) {
            lane.close("answer", "peer_answer_empty");
            lanes[id] = null;
          } else {
            try { await lane.setDescription(answer.sdp, false); }
            catch (error) { lane.close("answer", describeError(error)); lanes[id] = null; }
          }
        }
      }
    }
    onStage("Authenticating additional WebRTC connections");
    const authenticated = await Promise.all(lanes.map(lane => lane?.wait() ?? Promise.resolve(null)));
    for (let id = 1; id < count; id++) if (authenticated[id]?.dc.readyState === "open" && descriptions[id]) ours |= 1 << id;
    let theirs: Setup;
    if (sender) { await write({ step: "ready", mask: ours }); theirs = await read("ready"); }
    else { theirs = await read("ready"); await write({ step: "ready", mask: ours }); }
    peerMask = theirs.mask ?? 0;
    if (!Number.isInteger(peerMask) || peerMask < 0 || peerMask > (1 << count) - 2 || (peerMask & 1) !== 0) throw new Error("Invalid WebRTC ready mask");
    const selected = ours & peerMask;
    if (sender) {
      await write({ step: "commit", mask: selected });
      const ack = await read("committed");
      if ((ack.mask ?? 0) !== selected) throw new Error("WebRTC commit mismatch");
    } else {
      const commit = await read("commit");
      if ((commit.mask ?? 0) !== selected) throw new Error("WebRTC commit mismatch");
      await write({ step: "committed", mask: selected });
    }
    if (expired) throw new Error("Parallel WebRTC setup timed out");
    keep = selected;
    const active = [primary];
    for (let id = 1; id < count; id++) if (selected & (1 << id)) active.push(authenticated[id]!);
    if (active.length > 1) for (const lane of active) lane.highWater = 1024 * 1024;
    const result = active.length > 1 ? new ParallelFrameIO(active, sender) : primary;
    log(`authenticated WebRTC connections: ${active.length}`);
    onStage(active.length > 1 ? `${active.length} authenticated WebRTC connections ready` : "Using primary WebRTC connection");
    success = true;
    return result;
  } finally {
    clearTimeout(timer);
    for (let id = 1; id < lanes.length; id++) {
      if (!success) lanes[id]?.close("abort", "setup_aborted");
      else if (!(keep & (1 << id))) lanes[id]?.close("select", "peer_not_ready");
    }
    if (!success) primary.close(new Error("Parallel WebRTC setup failed"));
    await Promise.all(gathering);
    logLaneFailures(lanes.length, ours, peerMask, keep, success, laneRecords, constructFailures);
  }
}

// logLaneFailures logs ONE console line (via log(), already dumped on test
// failure) naming the masks and every lane that never made it into the
// selected set, with its stage/reason/trace — matching
// internal/flow.ParallelLaneReport on the Go side. Address-free by
// construction: masks and Trace events come only from our own recording,
// and reason strings are either fixed handshake.ts literals or one of the
// small generic buckets from describeError (see its own comment).
function logLaneFailures(
  laneCount: number, ours: number, peerMask: number, keep: number, success: boolean,
  laneRecords: Array<Lane | null>, constructFailures: Array<{ id: number; reason: string }>,
): void {
  if (laneCount <= 1) return;
  const failures: Array<{ id: number; stage: string; reason: string; trace: TraceEvent[] }> = [];
  for (let id = 1; id < laneCount; id++) {
    if (success && (keep & (1 << id))) continue;
    const lane = laneRecords[id];
    if (lane) {
      failures.push({ id, stage: lane.stage ?? "unknown", reason: lane.reason ?? "unknown", trace: lane.trace });
    } else {
      const cf = constructFailures.find(f => f.id === id);
      failures.push({ id, stage: "create", reason: cf?.reason ?? "unknown", trace: [] });
    }
  }
  if (failures.length === 0) return;
  log(`parallel WebRTC lanes: ours=0x${ours.toString(16)} theirs=0x${peerMask.toString(16)} selected=0x${keep.toString(16)} failures=${JSON.stringify(failures)}`);
}
