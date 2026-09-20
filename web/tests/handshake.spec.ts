// SPDX-License-Identifier: MIT

import { test, expect } from "@playwright/test";
import { createHmac } from "node:crypto";
import { confirmDataChannel } from "../src/handshake";
import type { DerivedKeys } from "../src/crypto";

const keys = { confirm: new Uint8Array(32).fill(19) } as DerivedKeys;
const senderPub = new Uint8Array(32).fill(21);
const receiverPub = new Uint8Array(32).fill(23);
senderPub[31] |= 0x80;
receiverPub[31] |= 0x80;

class Channel {
  readyState = "open";
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  sent: Uint8Array[] = [];
  onSend: (data: Uint8Array, count: number) => void = () => {};
  closeCalls = 0;
  send(data: Uint8Array) {
    const owned = data.slice();
    this.sent.push(owned);
    this.onSend(owned, this.sent.length);
  }
  close() {
    this.closeCalls++;
    this.readyState = "closed";
    this.onclose?.();
  }
  deliver(data: Uint8Array) {
    this.onmessage?.({ data: data.slice().buffer });
  }
  rtc(): RTCDataChannel { return this as unknown as RTCDataChannel; }
}

type Fault = "proof" | "selection" | "confirmation" | "stall-proof" | "stall-selection" | "stall-confirmation";

// Independent HMAC oracle using Node crypto, with the Go protocol's exact
// domain labels and byte order. Deliberately fragments handshake records and
// coalesces key confirmation with early encrypted input to exercise handoff.
function scriptedPeer(dc: Channel, sender: boolean, protocol: 2 | 3, fault?: Fault) {
  const peerNonce = new Uint8Array(32).fill(29);
  let sn = peerNonce, rn = peerNonce;
  const mac = (label: string, candidate: boolean) => {
    const hmac = createHmac("sha256", keys.confirm).update(label).update(senderPub).update(receiverPub);
    if (candidate) hmac.update(sn).update(rn);
    return new Uint8Array(hmac.digest());
  };
  const proof = (label: string) => mac(`sp2p/v3/candidate/${label}`, true);
  const confirmation = (label: string) => mac(label, false);
  const peerRole = sender ? "receiver" : "sender";
  const ownRole = sender ? "sender" : "receiver";
  const earlyData = new Uint8Array(512).fill(31);
  const deliver = (data: Uint8Array) => {
    dc.deliver(data.subarray(0, 7));
    dc.deliver(data.subarray(7));
  };
  const reply = (phase: "proof" | "selection" | "confirmation", data: Uint8Array) => {
    if (fault === `stall-${phase}`) return;
    if (fault === phase) data[0] ^= 1;
    if (phase === "confirmation") {
      const combined = new Uint8Array(32 + earlyData.length);
      combined.set(data);
      combined.set(earlyData, 32);
      deliver(combined);
    } else deliver(data);
  };
  dc.onSend = (data, count) => {
    if (protocol === 2 || count === 4) {
      expect(data).toEqual(confirmation(ownRole));
      if (sender || protocol === 2) reply("confirmation", confirmation(peerRole));
      return;
    }
    if (count === 1) {
      if (sender) { sn = data; deliver(peerNonce); }
      else { rn = data; reply("proof", proof(peerRole)); }
    } else if (count === 2) {
      expect(data).toEqual(proof(ownRole));
      if (sender) reply("proof", proof(peerRole));
      else reply("selection", proof("select"));
    } else if (count === 3) {
      expect(data).toEqual(proof(sender ? "select" : "selected"));
      if (sender) reply("selection", proof("selected"));
      else reply("confirmation", confirmation(peerRole));
    }
  };
  return { earlyData, start: () => { if (!sender && protocol === 3) deliver(peerNonce); } };
}

for (const sender of [false, true]) {
  for (const protocol of [2, 3] as const) {
    test(`browser ${sender ? "sender" : "receiver"} v${protocol} authenticates and preserves buffered frames`, async () => {
      const dc = new Channel();
      const peer = scriptedPeer(dc, sender, protocol);
      const promise = confirmDataChannel(dc.rtc(), keys, senderPub, receiverPub, sender, protocol);
      peer.start();
      const queued = await promise;
      expect(Buffer.concat(queued)).toEqual(Buffer.from(peer.earlyData));
      expect(dc.sent).toHaveLength(protocol === 3 ? 4 : 1);
      expect(dc.closeCalls).toBe(0);
      expect(dc.onmessage).toBeNull();
      expect(dc.onclose).toBeNull();
      expect(dc.onerror).toBeNull();
    });
  }

  for (const fault of ["proof", "selection", "confirmation"] as const) {
    test(`browser ${sender ? "sender" : "receiver"} rejects invalid ${fault}`, async () => {
      const dc = new Channel();
      const peer = scriptedPeer(dc, sender, 3, fault);
      const promise = confirmDataChannel(dc.rtc(), keys, senderPub, receiverPub, sender, 3);
      const rejected = expect(promise).rejects.toThrow(/authentication failed|selection|confirmation failed/);
      peer.start();
      await rejected;
      expect(dc.closeCalls).toBe(1);
      if (fault !== "confirmation") expect(dc.sent.length).toBeLessThan(4);
      expect(dc.onmessage).toBeNull();
    });
  }
}

for (const phase of ["proof", "selection", "confirmation"] as const) {
  test(`browser bounds a stalled ${phase} and releases its channel`, async () => {
    const dc = new Channel();
    const peer = scriptedPeer(dc, false, 3, `stall-${phase}`);
    const promise = confirmDataChannel(dc.rtc(), keys, senderPub, receiverPub, false, 3, { proof: 100, selection: 100, confirmation: 100 });
    const rejected = expect(promise).rejects.toThrow("timed out");
    peer.start();
    await rejected;
    expect(dc.closeCalls).toBe(1);
    expect(dc.onmessage).toBeNull();
  });
}

for (const kind of ["oversize", "many", "text", "empty", "close", "error"] as const) {
  test(`browser rejects ${kind} input during handshake`, async () => {
    const dc = new Channel();
    const promise = confirmDataChannel(dc.rtc(), keys, senderPub, receiverPub, false, 3);
    const rejected = expect(promise).rejects.toThrow(/handshake/);
    if (kind === "oversize") dc.deliver(new Uint8Array(8 * 1024 * 1024 + 1));
    if (kind === "many") for (let i = 0; i < 257; i++) dc.deliver(new Uint8Array(1));
    if (kind === "text") dc.onmessage?.({ data: "not binary" });
    if (kind === "empty") dc.deliver(new Uint8Array());
    if (kind === "close") { dc.readyState = "closed"; dc.onclose?.(); }
    if (kind === "error") dc.onerror?.();
    await rejected;
    expect(dc.sent).toHaveLength(0);
    expect(dc.closeCalls).toBe(1);
    expect(dc.onmessage).toBeNull();
    expect(dc.onclose).toBeNull();
    expect(dc.onerror).toBeNull();
  });
}
