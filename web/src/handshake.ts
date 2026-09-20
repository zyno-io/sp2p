// SPDX-License-Identifier: MIT

import { bufferSource, computeConfirmation, type DerivedKeys } from "./crypto";

// One bounded reader owns the channel from candidate authentication through
// key confirmation. Go treats DataChannel messages as a byte stream, so handle
// fragmented/coalesced handshake records and preserve early encrypted frames.
class HandshakeIO {
  readonly queued: Uint8Array[] = [];
  readonly aborted: Promise<never>;
  private rejectAbort!: (error: Error) => void;
  private bytes = 0;
  private error: Error | null = null;
  private wake: (() => void) | null = null;
  private timer: ReturnType<typeof setTimeout> | undefined;

  constructor(private dc: RTCDataChannel) {
    this.aborted = new Promise<never>((_, reject) => { this.rejectAbort = reject; });
    // Install before any asynchronous crypto work or outbound handshake data.
    dc.onmessage = event => {
      if (this.error) return;
      const data = event.data;
      if (!(data instanceof ArrayBuffer) || data.byteLength === 0 ||
          this.queued.length >= 256 || data.byteLength > 8 * 1024 * 1024 - this.bytes) {
        this.fail(new Error("Invalid or excessive handshake data"));
        return;
      }
      this.queued.push(new Uint8Array(data));
      this.bytes += data.byteLength;
      this.wake?.();
      this.wake = null;
    };
    dc.onclose = () => this.fail(new Error("Connection closed during handshake"));
    dc.onerror = () => this.fail(new Error("Connection failed during handshake"));
  }

  deadline(ms: number, phase: string): void {
    this.check();
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.fail(new Error(`${phase} timed out`)), ms);
  }

  check(): void {
    if (this.error) throw this.error;
    if (this.dc.readyState !== "open") throw new Error("Connection is not open during handshake");
  }

  send(data: Uint8Array): void {
    this.check();
    this.dc.send(bufferSource(data));
  }

  async read(): Promise<Uint8Array> {
    while (this.bytes < 32) {
      this.check();
      await new Promise<void>(resolve => { this.wake = resolve; });
    }
    this.check();
    const out = new Uint8Array(32);
    let offset = 0;
    while (offset < out.length) {
      const chunk = this.queued[0];
      const count = Math.min(chunk.length, out.length - offset);
      out.set(chunk.subarray(0, count), offset);
      if (count === chunk.length) this.queued.shift();
      else this.queued[0] = chunk.slice(count);
      offset += count;
      this.bytes -= count;
    }
    return out;
  }

  fail(error: Error): void {
    if (this.error) return;
    this.error = error;
    this.queued.length = 0;
    this.bytes = 0;
    clearTimeout(this.timer);
    this.wake?.();
    this.wake = null;
    this.rejectAbort(error);
    this.dc.close();
  }

  detach(): void {
    clearTimeout(this.timer);
    this.dc.onmessage = null;
    this.dc.onclose = null;
    this.dc.onerror = null;
  }
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

// Matches internal/crypto/candidate.go exactly. The v3 requirement depends only
// on transcript-bound key markers, never on a server's claimed client type.
// The caller must install DataChannelTransport immediately after awaiting this
// function, before yielding to another event-loop task, with the returned queue.
export async function confirmDataChannel(
  dc: RTCDataChannel,
  keys: DerivedKeys,
  senderPub: Uint8Array,
  receiverPub: Uint8Array,
  sender: boolean,
  protocol: 2 | 3,
  timeouts: { proof?: number; selection?: number; confirmation?: number } = {},
): Promise<Uint8Array[]> {
  const io = new HandshakeIO(dc);
  const handshake = async () => {
    const role = sender ? "sender" : "receiver";
    const peerRole = sender ? "receiver" : "sender";
    if (protocol === 3) {
      io.deadline(timeouts.proof ?? 5000, "Candidate authentication");
      const mine = crypto.getRandomValues(new Uint8Array(32));
      const exchange = async (out: Uint8Array): Promise<Uint8Array> => {
        if (sender) {
          io.send(out);
          return io.read();
        }
        const received = await io.read();
        io.send(out);
        return received;
      };
      const peer = await exchange(mine);
      const sn = sender ? mine : peer;
      const rn = sender ? peer : mine;
      const key = await crypto.subtle.importKey("raw", bufferSource(keys.confirm), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      const proof = async (label: string) => {
        const prefix = new TextEncoder().encode(`sp2p/v3/candidate/${label}`);
        const parts = [prefix, senderPub, receiverPub, sn, rn];
        const data = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
        let offset = 0;
        for (const part of parts) { data.set(part, offset); offset += part.length; }
        const mac = await crypto.subtle.sign("HMAC", key, data);
        return new Uint8Array(mac);
      };
      const myProof = await proof(role);
      const peerProof = await exchange(myProof);
      const expectedProof = await proof(peerRole);
      if (!equal(peerProof, expectedProof)) throw new Error("Candidate authentication failed");

      // A receiver may wait while the CLI sender chooses another transport.
      io.deadline(sender ? (timeouts.proof ?? 5000) : (timeouts.selection ?? 30000), "Candidate selection");
      const selection = await proof("select");
      const selected = await proof("selected");
      if (sender) {
        io.send(selection);
        const ack = await io.read();
        if (!equal(ack, selected)) throw new Error("Candidate selection failed");
      } else {
        const choice = await io.read();
        if (!equal(choice, selection)) throw new Error("Invalid candidate selection");
        io.send(selected);
      }
    }

    // V2 starts here, byte-for-byte compatible with 0.4.0 peers.
    io.deadline(timeouts.confirmation ?? 5000, "Key confirmation");
    const mine = await computeConfirmation(keys.confirm, role, senderPub, receiverPub);
    io.send(mine);
    const peer = await io.read();
    const expected = await computeConfirmation(keys.confirm, peerRole, senderPub, receiverPub);
    if (!equal(peer, expected)) throw new Error("Key confirmation failed");
    io.check();
    return io.queued;
  };
  try {
    return await Promise.race([handshake(), io.aborted]);
  } catch (error) {
    io.fail(error instanceof Error ? error : new Error(String(error)));
    throw error;
  } finally {
    io.detach();
  }
}
