// SPDX-License-Identifier: MIT
// Isolated WAN experiment bundles only. Production files are never rewritten.
// No knobs are enabled without explicit environment variables.
import { build } from "esbuild";
import { readFile } from "node:fs/promises";

const outdir = process.env.SP2P_WAN_ASSETS;
if (!outdir) throw new Error("Set a dedicated SP2P_WAN_ASSETS output directory");
const water = Number(process.env.SP2P_WAN_LANE_HIGH_WATER || 0);
const wire = Number(process.env.SP2P_WAN_WIRE_BYTES || 0);
const ramp = Number(process.env.SP2P_WAN_RAMP_ACKS || 0);
const pace = Number(process.env.SP2P_WAN_PACE_MS || 0);
if (!Number.isInteger(water) || (water !== 0 && (water < 16384 || water > 1048576))) throw new Error("Invalid lane queue threshold");
if (!Number.isInteger(wire) || (wire !== 0 && (wire < 1024 || wire > 65536))) throw new Error("Invalid wire message size");
if (!Number.isInteger(ramp) || ramp < 0 || ramp > 64) throw new Error("Invalid startup ramp");
if (!Number.isInteger(pace) || pace < 0 || pace > 10) throw new Error("Invalid message pacing");
const replace = (source, before, after) => {
  if (source.split(before).length !== 2) throw new Error("Experiment source changed; inspect the instrumentation");
  return source.replace(before, after);
};

await build({
  entryPoints: ["src/main.ts"], bundle: true, minify: true, target: "es2020",
  outdir, entryNames: "main-[hash]",
  plugins: [{ name: "wan-parallel-observation", setup(builder) {
    builder.onLoad({ filter: /\/frame-io\.ts$/ }, async args => {
      let source = await readFile(args.path, "utf8");
      source = replace(source, "private reassemblyBytes = 0;", `private reassemblyBytes = 0;
  private reorderWaitMs = 0;
  private deliveryWaitMs = 0;
  private assignments: Array<{ sequence: number; lane: number }> = [];`);
      source = replace(source, `if (this.error) throw this.error;
        await new Promise<void>(resolve => { this.wake = resolve; });`, `if (this.error) throw this.error;
        const gap = this.data.size > 0 && !this.data.has(this.nextRead);
        const waitStart = performance.now();
        try { await new Promise<void>(resolve => { this.wake = resolve; }); }
        finally {
          const waited = performance.now() - waitStart;
          this.deliveryWaitMs += waited;
          if (gap) this.reorderWaitMs += waited;
        }`);
      source = replace(source, "await this.lanes[target].writeFrame(type, payload);", `this.assignments.push({ sequence: seq, lane: target });
    if (this.assignments.length > 64) this.assignments.shift();
    await this.lanes[target].writeFrame(type, payload);`);
      source = replace(source, "return { queuedBytes: stats[0].queuedBytes, connections: this.lanes.length,", `return { queuedBytes: stats[0].queuedBytes, connections: this.lanes.length,
      reorderWaitMs: this.reorderWaitMs, deliveryWaitMs: this.deliveryWaitMs,
      reassemblyBytes: this.reassemblyBytes, reassemblyFrames: this.data.size,
      nextRead: this.nextRead, nextWrite: this.nextWrite,
      waitingForSequence: this.data.size > 0 && !this.data.has(this.nextRead),
      bufferedByLane: stats.map(stat => stat.bufferedBytes),
      assignments: this.assignments.slice(),`);
      if (wire) source = replace(source,
        "this.maxMessage = limit === 0 ? MAX_FRAME + 4 : limit && limit > 0 ? limit : 16384;",
        `this.maxMessage = Math.min(${wire}, limit === 0 ? MAX_FRAME + 4 : limit && limit > 0 ? limit : 16384);`);
      if (pace) source = replace(source,
        "this.dc.send(bufferSource(frame.subarray(offset, offset + this.maxMessage)));",
        `this.dc.send(bufferSource(frame.subarray(offset, offset + this.maxMessage)));
        if (type === DATA) await new Promise<void>(resolve => setTimeout(resolve, ${pace}));`);
      return { contents: source, loader: "ts" };
    });
    if (water) builder.onLoad({ filter: /\/webrtc-parallel\.ts$/ }, async args => {
      const original = await readFile(args.path, "utf8");
      const contents = replace(original, "lane.highWater = 1024 * 1024;", `lane.highWater = ${water};`);
      return { contents, loader: "ts" };
    });
    if (ramp) builder.onLoad({ filter: /\/transfer\.ts$/ }, async args => {
      let contents = await readFile(args.path, "utf8");
      const cap = `Math.min(this.sendWindow, 4 + Math.floor(this.creditedChunks / ${ramp}))`;
      contents = replace(contents, "while (this.sentChunks - this.creditedChunks >= this.sendWindow) {",
        `while (this.sentChunks - this.creditedChunks >= ${cap}) {`);
      contents = replace(contents, "sendWindow: this.sendWindow,", `sendWindow: this.sendWindow, startupWindow: ${cap},`);
      return { contents, loader: "ts" };
    });
  } }],
});
