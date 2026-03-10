// SPDX-License-Identifier: MIT

// WebSocket signaling client for the web UI.

import { log } from "./log";

export const PROTOCOL_VERSION = 2;

export interface Envelope {
  type: string;
  payload?: any;
}

export type MessageHandler = (env: Envelope) => void;

export class SignalClient {
  private ws: WebSocket;
  private handlers: Map<string, MessageHandler[]> = new Map();
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
    for (const h of handlers) {
      h(env);
    }
    const wildcard = [...(this.handlers.get("*") || [])];
    for (const h of wildcard) {
      h(env);
    }
  }
}
