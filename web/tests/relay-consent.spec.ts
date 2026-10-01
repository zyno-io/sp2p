// SPDX-License-Identifier: MIT

// Node-side unit tests for relay-consent.ts's RelayConsentWatch (mirroring
// internal/conn/relay_test.go's RelayWatch cases against a fake signal
// client) and a regression guard for webrtc.ts's own-handlers-only cleanup
// fix (bug #3 in the relay-consent design: establishWebRTC used to remove
// *every* handler of its types, including a longer-lived listener like
// RelayConsentWatch's own peer-left handler). This file matches
// /relay-consent\.spec\.ts/, not /relay\.spec\.ts/, so it runs in the
// chromium project without the Linux-network-namespace TURN suite's gating.

import { test, expect } from "@playwright/test";
import {
  RelayConsentWatch,
  isAborted,
  watchError,
  peerErrorMessage,
  PeerDeclinedRelayError,
  RELAY_CONSENT_GRANTED,
  RELAY_CONSENT_PENDING,
} from "../src/relay-consent";
import type { Envelope } from "../src/signal";
import { establishWebRTC } from "../src/webrtc";

// ── Fake signal client (satisfies both RelaySignal and the subset of
// SignalClient that webrtc.ts's establishWebRTC uses) ─────────────────────

class FakeSignal {
  handlers = new Map<string, ((env: Envelope) => void)[]>();
  sent: { type: string; payload: any }[] = [];
  discardHeldCalls = 0;
  closed = false;

  on(type: string, fn: (env: Envelope) => void): void {
    const list = this.handlers.get(type) ?? [];
    list.push(fn);
    this.handlers.set(type, list);
  }
  removeHandler(type: string, fn: (env: Envelope) => void): void {
    const list = this.handlers.get(type);
    if (!list) return;
    const idx = list.indexOf(fn);
    if (idx >= 0) list.splice(idx, 1);
  }
  off(type: string): void {
    this.handlers.delete(type);
  }
  send(type: string, payload?: any): void {
    this.sent.push({ type, payload });
  }
  discardHeld(_types?: string[]): void {
    this.discardHeldCalls++;
  }
  dispatch(type: string, payload?: any): void {
    for (const fn of [...(this.handlers.get(type) ?? [])]) fn({ type, payload });
  }
  handlerCount(type: string): number {
    return (this.handlers.get(type) ?? []).length;
  }
}

// ── RelayConsentWatch: cases mirroring internal/conn/relay_test.go ────────

test("granted stays false until the peer's relay-retry carries granted consent (case 2 analog)", async () => {
  const sig = new FakeSignal();
  const watch = new RelayConsentWatch(sig as any);
  expect(watch.granted).toBe(false);
  expect(watch.state).toBe("pending");

  sig.dispatch("relay-retry", { consent: RELAY_CONSENT_PENDING });
  expect(watch.granted).toBe(false);
  expect(watch.sawRetry).toBe(true);
  expect(watch.state).toBe("pending");

  sig.dispatch("relay-retry", { consent: RELAY_CONSENT_GRANTED });
  expect(watch.granted).toBe(true);
  expect(watch.state).toBe("granted");
});

test("peer decline aborts exit and resolves waitForDecision promptly (case 3 analog)", async () => {
  const sig = new FakeSignal();
  const watch = new RelayConsentWatch(sig as any);
  const decisionPromise = watch.waitForDecision(5000);
  expect(watch.exit.aborted).toBe(false);

  sig.dispatch("relay-denied", { reason: "declined" });
  expect(watch.exit.aborted).toBe(true);
  expect(watch.state).toBe("declined");
  expect(await decisionPromise).toBe("denied");
});

test("an already-known decline is reflected immediately (case 4 analog)", async () => {
  const sig = new FakeSignal();
  const watch = new RelayConsentWatch(sig as any);
  sig.dispatch("relay-denied", { reason: "unavailable" });
  expect(isAborted(watch)).toBe(true);
  expect(watch.state).toBe("declined");
  expect(watch.denyReason).toBe("unavailable");
});

test("decline is sticky: a later relay-retry granted does not override it (case 5 analog)", async () => {
  const sig = new FakeSignal();
  const watch = new RelayConsentWatch(sig as any);
  sig.dispatch("relay-denied", { reason: "declined" });
  sig.dispatch("relay-retry", { consent: RELAY_CONSENT_GRANTED });
  expect(watch.state).toBe("declined");
  expect(watchError(watch)).toBeInstanceOf(PeerDeclinedRelayError);
});

test("an old client's empty relay-retry payload means granted (case 6 analog)", async () => {
  const sig = new FakeSignal();
  const watch = new RelayConsentWatch(sig as any);
  sig.dispatch("relay-retry", {});
  expect(watch.granted).toBe(true);
  expect(watch.state).toBe("granted");
});

test("peer-left aborts exit and resolves waitForDecision as left (case 7 analog)", async () => {
  const sig = new FakeSignal();
  const watch = new RelayConsentWatch(sig as any);
  const decisionPromise = watch.waitForDecision(5000);
  sig.dispatch("peer-left");
  expect(watch.exit.aborted).toBe(true);
  expect(watch.state).toBe("left");
  expect(await decisionPromise).toBe("left");
});

test("decline always wins over peer-left regardless of arrival order (cases 8/9 analog)", async () => {
  for (const order of ["decline-first", "left-first"] as const) {
    const sig = new FakeSignal();
    const watch = new RelayConsentWatch(sig as any);
    if (order === "decline-first") {
      sig.dispatch("relay-denied", { reason: "declined" });
      sig.dispatch("peer-left");
    } else {
      sig.dispatch("peer-left");
      sig.dispatch("relay-denied", { reason: "declined" });
    }
    expect(watch.state).toBe("declined");
  }
});

test("signaling loss (closed) aborts exit and resolves waitForDecision as closed", async () => {
  const sig = new FakeSignal();
  const watch = new RelayConsentWatch(sig as any);
  const decisionPromise = watch.waitForDecision(5000);
  sig.dispatch("_closed");
  expect(watch.state).toBe("closed");
  expect(await decisionPromise).toBe("closed");
});

test("an unknown consent value is treated as pending (case 11 analog)", async () => {
  const sig = new FakeSignal();
  const watch = new RelayConsentWatch(sig as any);
  sig.dispatch("relay-retry", { consent: "bogus-value" });
  expect(watch.sawRetry).toBe(true);
  expect(watch.granted).toBe(false);
  expect(watch.state).toBe("pending");
});

test("waitForDecision resolves timeout when nothing arrives", async () => {
  const sig = new FakeSignal();
  const watch = new RelayConsentWatch(sig as any);
  expect(await watch.waitForDecision(30)).toBe("timeout");
});

test("discardHeld is called on each peer relay-retry", async () => {
  const sig = new FakeSignal();
  const watch = new RelayConsentWatch(sig as any);
  sig.dispatch("relay-retry", { consent: RELAY_CONSENT_PENDING });
  sig.dispatch("relay-retry", { consent: RELAY_CONSENT_GRANTED });
  expect(sig.discardHeldCalls).toBe(2);
});

test("dispose removes the watch's handlers so later messages have no effect", async () => {
  const sig = new FakeSignal();
  const watch = new RelayConsentWatch(sig as any);
  watch.dispose();
  sig.dispatch("relay-denied", { reason: "declined" });
  expect(watch.state).toBe("pending");
  expect(watch.exit.aborted).toBe(false);
});

test("peerErrorMessage names the peer's role for a decline and an unavailable reason", async () => {
  const sig = new FakeSignal();
  const declined = new RelayConsentWatch(sig as any);
  sig.dispatch("relay-denied", { reason: "declined" });
  expect(peerErrorMessage(declined, "receiver")).toBe("Direct connection failed and the receiver declined the relay.");

  const sig2 = new FakeSignal();
  const unavailable = new RelayConsentWatch(sig2 as any);
  sig2.dispatch("relay-denied", { reason: "unavailable" });
  expect(peerErrorMessage(unavailable, "sender")).toBe(
    "Direct connection failed and the sender could not be asked to allow the relay. They can rerun sp2p with -allow-relay."
  );
});

// ── webrtc.ts regression guard: own-handlers-only cleanup ─────────────────

// A minimal RTCPeerConnection stub. establishWebRTC only needs it to accept
// the calls it makes without throwing; none of its async operations need to
// resolve for this test, which only exercises the timeout/cleanup path.
class FakePeerConnection {
  iceGatheringState: string = "complete";
  connectionState = "new";
  iceConnectionState = "new";
  localDescription: any = null;
  onconnectionstatechange: (() => void) | null = null;
  oniceconnectionstatechange: (() => void) | null = null;
  onicecandidate: ((event: any) => void) | null = null;
  ondatachannel: ((event: any) => void) | null = null;
  closeCalls = 0;
  addEventListener(): void {}
  removeEventListener(): void {}
  addTransceiver(): void {}
  createDataChannel(): any {
    return { binaryType: "", onopen: null, send() {}, close() {} };
  }
  // Never resolve: this test only drives establishWebRTC to its timeout.
  createOffer(): Promise<any> { return new Promise(() => {}); }
  createAnswer(): Promise<any> { return new Promise(() => {}); }
  setLocalDescription(): Promise<void> { return new Promise(() => {}); }
  setRemoteDescription(): Promise<void> { return new Promise(() => {}); }
  addIceCandidate(): Promise<void> { return Promise.resolve(); }
  close(): void { this.closeCalls++; }
}

test("establishWebRTC's cleanup leaves other code's peer-left handler in place", async () => {
  const originalPC = (globalThis as any).RTCPeerConnection;
  (globalThis as any).RTCPeerConnection = FakePeerConnection;
  try {
    const sig = new FakeSignal();

    // Simulate a RelayConsentWatch-style long-lived peer-left listener,
    // registered before establishWebRTC runs — exactly the bug: a blanket
    // sigClient.off("peer-left") at attempt start or cleanup used to remove
    // this too.
    let otherHandlerCalls = 0;
    const otherHandler = () => { otherHandlerCalls++; };
    sig.on("peer-left", otherHandler);
    expect(sig.handlerCount("peer-left")).toBe(1);

    const attempt = establishWebRTC(sig as any, true, undefined, undefined, 20);
    // establishWebRTC registers its own peer-left/error handlers synchronously.
    expect(sig.handlerCount("peer-left")).toBe(2);

    await expect(attempt).rejects.toThrow("WebRTC connection timed out");

    // The attempt's own handler is gone; the other code's handler survives.
    expect(sig.handlerCount("peer-left")).toBe(1);
    sig.dispatch("peer-left");
    expect(otherHandlerCalls).toBe(1);
  } finally {
    (globalThis as any).RTCPeerConnection = originalPC;
  }
});
