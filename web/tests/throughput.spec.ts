// SPDX-License-Identifier: MIT

// Opt-in application-credit benchmark, not a network/WebRTC benchmark.
// SP2P_BENCHMARK=1 npx playwright test tests/throughput.spec.ts
import { test, expect } from "@playwright/test";
import { EncryptedChannel } from "../src/crypto";
import { DataChannelTransport, MSG_METADATA, receiveFile, sendFile } from "../src/transfer";

test("measure the receive window with real encryption and controlled acknowledgement latency", async () => {
  test.skip(!process.env.SP2P_BENCHMARK, "Opt-in latency benchmark");
  test.setTimeout(180_000);
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const reverseKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const file = new File([new Uint8Array(32 * 1024 * 1024).fill(73)], "benchmark.bin");

  async function measure(rtt: number, expanded: boolean) {
    const timers = new Set<ReturnType<typeof setTimeout>>();
    const channel = () => ({
      bufferedAmount: 0, readyState: "open", onmessage: null, onclose: null,
      send: (_bytes: Uint8Array) => {}, close: () => {},
    });
    const left = channel(), right = channel();
    for (const [from, to] of [[left, right], [right, left]]) {
      from.send = bytes => {
        const copy = bytes.slice();
        from.bufferedAmount += copy.length;
        const timer = setTimeout(() => {
          timers.delete(timer);
          from.bufferedAmount -= copy.length;
          (to.onmessage as any)?.({ data: copy.buffer });
        }, rtt / 2);
        timers.add(timer);
      };
    }
    const receiverCipher = new EncryptedChannel(reverseKey, key);
    const receiverEncryption = {
      encryptFrame: receiverCipher.encryptFrame.bind(receiverCipher),
      decryptFrame: async (payload: Uint8Array) => {
        const frame = await receiverCipher.decryptFrame(payload);
        // Model an existing v3 receiver that ignores the metadata extension.
        if (!expanded && frame.msgType === MSG_METADATA) {
          const metadata = JSON.parse(new TextDecoder().decode(frame.data));
          delete metadata.receiveWindow;
          frame.data = new TextEncoder().encode(JSON.stringify(metadata));
        }
        return frame;
      },
    };
    const sender = new DataChannelTransport(left as any, new EncryptedChannel(key, reverseKey), undefined, 65536);
    const receiver = new DataChannelTransport(right as any, receiverEncryption as EncryptedChannel, undefined, 65536);
    try {
      const start = performance.now();
      const receiving = receiveFile(receiver);
      await sendFile(sender, file);
      const result = await receiving;
      expect(result.totalBytes).toBe(file.size);
      return { mibPerSecond: 32 / ((performance.now() - start) / 1000), creditWaitMs: sender.diagnostics().creditWaitMs };
    } finally {
      for (const timer of timers) clearTimeout(timer);
      sender.stopHeartbeat(); receiver.stopHeartbeat();
    }
  }

  for (const rtt of [100, 200]) {
    const baseline: number[] = [], negotiated: number[] = [];
    for (let run = 0; run < 3; run++) {
      const original = await measure(rtt, false);
      const expanded = await measure(rtt, true);
      baseline.push(original.mibPerSecond); negotiated.push(expanded.mibPerSecond);
      console.log(JSON.stringify({ rttMs: rtt, run, baseline: original, negotiated: expanded }));
    }
    const median = (values: number[]) => values.sort((a, b) => a - b)[1];
    const ratio = median(negotiated) / median(baseline);
    console.log(JSON.stringify({ rttMs: rtt, baselineMedian: median(baseline), negotiatedMedian: median(negotiated), ratio }));
    expect(ratio).toBeGreaterThan(2);
  }
});
