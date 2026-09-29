// SPDX-License-Identifier: MIT

// Relay-consent state machine shared by web/src/main.ts's send and receive
// flows. Mirrors internal/conn/relay.go's RelayWatch/RetryWithRelay: the
// same additive message payloads (relay-retry{consent}, relay-denied
// {reason}) and the same fixed priority order — peer declined, then peer
// left, then signaling lost, then go (granted or an old client's empty
// payload), then pending — so a browser and a CLI/rsync/tunnel peer always
// agree on the outcome, regardless of which side is which.

import type { Envelope } from "./signal";

// Consent stages carried by relay-retry's payload. Empty/missing means an
// old client (≤0.6.2) and is always treated as RELAY_CONSENT_GRANTED.
export const RELAY_CONSENT_PENDING = "pending";
export const RELAY_CONSENT_GRANTED = "granted";

// Decline reasons carried by relay-denied's payload. Empty/missing means an
// old client and is always treated as RELAY_DENIED_DECLINED.
export const RELAY_DENIED_DECLINED = "declined";
export const RELAY_DENIED_UNAVAILABLE = "unavailable";

export type RelayWatchState = "pending" | "granted" | "declined" | "left" | "closed";

// Minimal signaling surface RelayConsentWatch needs. SignalClient (signal.ts)
// satisfies this structurally, so no adapter is needed at call sites.
export interface RelaySignal {
  on(type: string, handler: (env: Envelope) => void): void;
  removeHandler(type: string, handler: (env: Envelope) => void): void;
  send(type: string, payload?: any): void;
  discardHeld(types?: string[]): void;
  readonly closed: boolean;
}

// PeerDeclinedRelayError reports that the peer sent relay-denied (or is an
// old client, whose empty relay-denied payload is always "declined").
export class PeerDeclinedRelayError extends Error {
  reason: string;
  constructor(reason: string) {
    super(reason ? `peer declined relay: ${reason}` : "peer declined relay");
    this.name = "PeerDeclinedRelayError";
    this.reason = reason;
  }
}

// RelayConsentWatch tracks the peer's relay-retry/relay-denied/peer-left
// messages (and signaling loss) in arrival order, for one connection
// attempt — created before attempt 1 and disposed once the connection is
// established (or the attempt is abandoned).
//
// Priority when more than one condition is true is always: peer declined,
// then peer left, then signaling lost. This is a property of `state`
// (checked at read time), not of arrival order: a decline that arrives
// before or after a peer-left or signaling-loss event is always reported
// as a decline.
export class RelayConsentWatch {
  denyReason = "";
  granted = false;
  sawRetry = false;

  // exit fires the instant the peer declines, leaves, or signaling is
  // lost. Pass it to establishWebRTC's `abort` option for attempt 2.
  readonly exit: AbortSignal;

  private declined = false;
  private left = false;
  private closedFlag = false;
  private abortController = new AbortController();
  private events = new EventTarget();
  private sig: RelaySignal;
  private bound: { type: string; fn: (env: Envelope) => void }[] = [];
  private disposed = false;

  constructor(sig: RelaySignal) {
    this.sig = sig;
    this.exit = this.abortController.signal;
    this.bind("relay-retry", env => this.handleRetry(env));
    this.bind("relay-denied", env => this.handleDenied(env));
    this.bind("peer-left", () => this.handleLeft());
    this.bind("_closed", () => this.handleClosed());
    this.bind("_error", () => this.handleClosed());
  }

  private bind(type: string, fn: (env: Envelope) => void): void {
    this.sig.on(type, fn);
    this.bound.push({ type, fn });
  }

  // dispose removes this watch's own handlers — never another attempt's or
  // another watch's. Idempotent.
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    for (const { type, fn } of this.bound) this.sig.removeHandler(type, fn);
  }

  // state summarizes the watch's current knowledge, applying the fixed
  // priority order above.
  get state(): RelayWatchState {
    if (this.declined) return "declined";
    if (this.left) return "left";
    if (this.closedFlag) return "closed";
    if (this.granted) return "granted";
    return "pending";
  }

  private handleRetry(env: Envelope): void {
    // Everything the peer sent before its relay-retry belongs to attempt 1.
    this.sig.discardHeld();
    this.sawRetry = true;
    const consent = env.payload?.consent;
    // Consent "" (or missing) or "granted" means go (old client or explicit
    // grant). Anything else — including "pending" or an unrecognized value
    // — is pending: this watch never treats an unrecognized signal as
    // consent.
    if ((consent === undefined || consent === "" || consent === RELAY_CONSENT_GRANTED) && !this.granted) {
      this.granted = true;
      this.events.dispatchEvent(new Event("granted"));
    }
  }

  private handleDenied(env: Envelope): void {
    if (this.declined) return;
    this.declined = true;
    this.denyReason = (env.payload?.reason as string) || "";
    this.abortController.abort();
  }

  private handleLeft(): void {
    if (this.left) return;
    this.left = true;
    this.abortController.abort();
  }

  private handleClosed(): void {
    if (this.closedFlag) return;
    this.closedFlag = true;
    this.abortController.abort();
  }

  // waitForDecision waits for the peer's relay decision: granted ("go"), a
  // decline/leave/close (following state's priority order), or "timeout"
  // after ms milliseconds. Bounded at 2 minutes by callers, since a human
  // may be answering on the other side.
  waitForDecision(ms: number): Promise<"go" | "denied" | "left" | "closed" | "timeout"> {
    const now = this.resolvedDecision();
    if (now) return Promise.resolve(now);
    return new Promise(resolve => {
      let settled = false;
      const finish = (result: "go" | "denied" | "left" | "closed" | "timeout") => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.events.removeEventListener("granted", onGranted);
        this.exit.removeEventListener("abort", onExit);
        resolve(result);
      };
      const onGranted = () => finish("go");
      const onExit = () => finish(this.resolvedDecision() ?? "closed");
      const timer = setTimeout(() => finish("timeout"), ms);
      this.events.addEventListener("granted", onGranted);
      this.exit.addEventListener("abort", onExit);
    });
  }

  private resolvedDecision(): "go" | "denied" | "left" | "closed" | undefined {
    if (this.declined) return "denied";
    if (this.left) return "left";
    if (this.closedFlag) return "closed";
    if (this.granted) return "go";
    return undefined;
  }
}

// isAborted reports whether the watch has reached an abort condition
// (declined, left, or closed) — equivalent to watch.exit.aborted, but
// readable at call sites that check `watch.state` for other reasons too.
export function isAborted(watch: RelayConsentWatch): boolean {
  const state = watch.state;
  return state === "declined" || state === "left" || state === "closed";
}

// watchError builds the error matching the watch's current abort condition
// (declined/left/closed). Only meaningful once watch.exit has fired.
export function watchError(watch: RelayConsentWatch): Error {
  switch (watch.state) {
    case "declined":
      return new PeerDeclinedRelayError(watch.denyReason);
    case "left":
      return new Error("Peer disconnected");
    case "closed":
      return new Error("Signaling server disconnected");
    default:
      return new Error("relay watch: no abort condition present");
  }
}

// raceExit rejects with watchError(watch) the instant watch.exit fires,
// racing it against p. Used to bound the TURN-credential wait so a peer
// decline or disconnect during it is reported immediately.
export function raceExit<T>(watch: RelayConsentWatch, p: Promise<T>): Promise<T> {
  if (watch.exit.aborted) return Promise.reject(watchError(watch));
  return new Promise((resolve, reject) => {
    let settled = false;
    const onExit = () => {
      if (settled) return;
      settled = true;
      reject(watchError(watch));
    };
    watch.exit.addEventListener("abort", onExit);
    p.then(
      value => { if (!settled) { settled = true; watch.exit.removeEventListener("abort", onExit); resolve(value); } },
      error => { if (!settled) { settled = true; watch.exit.removeEventListener("abort", onExit); reject(error); } },
    );
  });
}

// ── User-facing message helpers (see internal/conn/relay.go's message
// table — CLI and web use the same wording, naming the peer's role). ─────

export function relayDeclinedMessage(reason: string, peerRole: string): string {
  if (reason === RELAY_DENIED_UNAVAILABLE) {
    return `Direct connection failed and the ${peerRole} could not be asked to allow the relay. They can rerun sp2p with -allow-relay.`;
  }
  return `Direct connection failed and the ${peerRole} declined the relay.`;
}

export function relayTimeoutMessage(peerRole: string): string {
  return `Timed out waiting for the ${peerRole} to allow the relay.`;
}

export function relayWaitingMessage(peerRole: string): string {
  return `Waiting for the ${peerRole} to allow the relay`;
}

// peerErrorMessage turns watchError(watch)'s result into the exact
// user-facing text: a friendlier wording than PeerDeclinedRelayError's own
// Error() for the declined case, and the generic (unchanged) text for
// left/closed.
export function peerErrorMessage(watch: RelayConsentWatch, peerRole: string): string {
  switch (watch.state) {
    case "declined":
      return relayDeclinedMessage(watch.denyReason, peerRole);
    case "left":
      return "Peer disconnected";
    case "closed":
      return "Signaling server disconnected";
    default:
      return "relay watch: no abort condition present";
  }
}
