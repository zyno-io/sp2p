// SPDX-License-Identifier: MIT
// Build single-connection queue/message controls without editing production
// code. Disable parallel negotiation so these knobs affect the measured path.
import { build } from "esbuild";
import { readFile } from "node:fs/promises";

const limit = Number(process.env.SP2P_WAN_BUFFER_BYTES);
const messageLimit = Number(process.env.SP2P_WAN_WIRE_BYTES || 0);
const frameDelay = Number(process.env.SP2P_WAN_FRAME_DELAY_MS || 0);
if (!Number.isInteger(limit) || limit < 0 || limit > 8 * 1024 * 1024 || !process.env.SP2P_WAN_ASSETS) throw new Error("Set a bounded buffer size and output directory");
await build({
  entryPoints: ["src/main.ts"], bundle: true, minify: true, target: "es2020",
  outdir: process.env.SP2P_WAN_ASSETS, entryNames: "main-[hash]",
  plugins: [{
    name: "experimental-send-buffer",
    setup(builder) {
      builder.onLoad({ filter: /\/main\.ts$/ }, async args => {
        const original = await readFile(args.path, "utf8");
        const hint = "parallelWebRTC: true";
        const activation = "protocol === 3 && cryptoMsg.payload.parallelWebRTC === true";
        if (original.split(hint).length !== 3 || original.split(activation).length !== 3) {
          throw new Error("Parallel negotiation source changed; inspect before experimenting");
        }
        return { contents: original.replaceAll(hint, "parallelWebRTC: false").replaceAll(activation, "false"), loader: "ts" };
      });
      builder.onLoad({ filter: /\/transfer\.ts$/ }, async args => {
        const original = await readFile(args.path, "utf8");
        const needle = "const SEND_HIGH_WATER = 8 * 1024 * 1024;";
        if (!original.includes(needle)) throw new Error("Send-buffer source changed; inspect before experimenting");
        let contents = original.replace(needle, `const SEND_HIGH_WATER = ${limit};`);
        if (messageLimit) {
          if (!Number.isInteger(messageLimit) || messageLimit < 1024 || messageLimit > 65536) throw new Error("Invalid message cap");
          const marker = "// Replay any data buffered during key confirmation.";
          if (!contents.includes(marker)) throw new Error("Message-size source changed; inspect before experimenting");
          contents = contents.replace(marker, `this.maxDataChannelMessageSize = Math.min(this.maxDataChannelMessageSize, ${messageLimit});\n    ${marker}`);
        }
        if (frameDelay) {
          if (!Number.isInteger(frameDelay) || frameDelay < 1 || frameDelay > 10) throw new Error("Invalid frame delay");
          const marker = "// Legacy peers do not send controls continuously.";
          if (!contents.includes(marker)) throw new Error("Send-loop source changed; inspect before experimenting");
          contents = contents.replace(marker, `if (msgType === MSG_DATA) await new Promise<void>(resolve => setTimeout(resolve, ${frameDelay}));\n      ${marker}`);
        }
        return { contents, loader: "ts" };
      });
    },
  }],
});
