// SPDX-License-Identifier: MIT

// WebSocket signaling client for the web UI.

import { log } from "./log";

// Stable signaling version; transfer capabilities are authenticated end-to-end.
export const PROTOCOL_VERSION = 2;

export interface Envelope {
  type: string;
  payload?: any;
}

export type MessageHandler = (env: Envelope) => void;

// WebRTC negotiation messages can arrive before their handler exists: a CLI
// sender can send its offer before the browser has finished deriving keys and
// started listening. Hold these until a handler is registered.
const HELD_TYPES = new Set(["offer", "answer", "candidate"]);
const MAX_HELD = 128;

export class SignalClient {
  private ws: WebSocket;
  private handlers: Map<string, MessageHandler[]> = new Map();
  private held: Envelope[] = [];
  private _closed = false;

  constructor(ws: WebSocket) {
    this.ws = ws;
    ws.onmessage = (event) => {
      try {
        const env: Envelope = JSON.parse(event.data);
        this.dispatch(env);
      } catch {
        // ignore malformed messages
      }
    };
    ws.onclose = () => {
      log("signaling connection closed");
      this._closed = true;
      this.dispatch({ type: "_closed" });
    };
    ws.onerror = () => {
      log("signaling connection error");
      this._closed = true;
      this.dispatch({ type: "_error" });
    };
  }

  static connect(serverURL: string): Promise<SignalClient> {
    return new Promise((resolve, reject) => {
      log("connecting to signaling server:", serverURL);
      const ws = new WebSocket(serverURL);
      ws.onopen = () => {
        log("signaling server connected");
        resolve(new SignalClient(ws));
      };
      ws.onerror = () => reject(new Error("Cannot connect to signaling server"));
    });
  }

  send(type: string, payload?: any): void {
    if (this._closed) return;
    try {
      this.ws.send(JSON.stringify({ type, payload }));
    } catch {
      // Best-effort: WebSocket may already be closing.
    }
  }

  on(type: string, handler: MessageHandler): void {
    const handlers = this.handlers.get(type) || [];
    handlers.push(handler);
    this.handlers.set(type, handlers);
    if (this.held.some(env => env.type === type)) {
      const ready = this.held.filter(env => env.type === type);
      this.held = this.held.filter(env => env.type !== type);
      // Deliver after the caller finishes registering its other handlers.
      queueMicrotask(() => { for (const env of ready) this.dispatch(env); });
    }
  }

  // Drop held negotiation messages from a finished attempt. Safe before
  // sending relay-retry: the peer only starts its next attempt after
  // receiving it.
  discardHeld(): void {
    this.held = [];
  }

  // Remove all handlers for a specific message type.
  off(type: string): void {
    this.handlers.delete(type);
  }

  // Remove a specific handler for a message type.
  removeHandler(type: string, handler: MessageHandler): void {
    const handlers = this.handlers.get(type);
    if (!handlers) return;
    const idx = handlers.indexOf(handler);
    if (idx >= 0) handlers.splice(idx, 1);
  }

  // Wait for a specific message type. Returns the envelope.
  // Cleans up its handler on both resolve and timeout.
  waitFor(type: string, timeoutMs = 30000): Promise<Envelope> {
    // If already closed, reject immediately.
    if (this._closed) {
      return Promise.reject(new Error(`Connection closed while waiting for ${type}`));
    }
    return new Promise((resolve, reject) => {
      const cleanup = () => {
        clearTimeout(timer);
        this.removeHandler(type, handler);
        this.removeHandler("_closed", closeHandler);
        this.removeHandler("_error", closeHandler);
      };
      const handler: MessageHandler = (env) => {
        cleanup();
        resolve(env);
      };
      const closeHandler: MessageHandler = () => {
        cleanup();
        reject(new Error(`Connection closed while waiting for ${type}`));
      };
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error(`Timeout waiting for ${type}`));
      }, timeoutMs);
      this.on(type, handler);
      this.on("_closed", closeHandler);
      this.on("_error", closeHandler);
    });
  }

  close(): void {
    this._closed = true;
    this.ws.close();
  }

  get closed(): boolean {
    return this._closed;
  }

  private dispatch(env: Envelope): void {
    // Snapshot handler arrays so handlers can safely remove themselves during dispatch.
    const handlers = [...(this.handlers.get(env.type) || [])];
    if (!handlers.length && HELD_TYPES.has(env.type)) {
      if (this.held.length < MAX_HELD) this.held.push(env);
      return;
    }
    for (const h of handlers) {
      h(env);
    }
    const wildcard = [...(this.handlers.get("*") || [])];
    for (const h of wildcard) {
      h(env);
    }
  }
}
