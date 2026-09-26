#!/usr/bin/env node
// SPDX-License-Identifier: MIT
//
// Reads test-results/perf/*.json (one file per netem.spec.ts pairing, or
// several per pairing under nightly's --repeat-each), prints a markdown
// table to $GITHUB_STEP_SUMMARY (or stdout if unset), and with --gate exits
// non-zero if any pairing's median MB/s is below its floor in
// web/tests/perf-floors.json. See docs/testing.md.
//
// Usage: node tests/perf-summary.mjs [--gate] [--dir <perf-dir>]

import { appendFileSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  let gate = false;
  let dir = join(HERE, "..", "..", "test-results", "perf");
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--gate") gate = true;
    else if (argv[i] === "--dir") dir = argv[++i];
  }
  return { gate, dir };
}

function median(values) {
  if (values.length === 0) return NaN;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

function loadRecords(dir) {
  let files;
  try {
    files = readdirSync(dir).filter(name => name.endsWith(".json")).sort();
  } catch {
    return [];
  }
  return files.map(name => JSON.parse(readFileSync(join(dir, name), "utf8")));
}

function loadFloors() {
  return JSON.parse(readFileSync(join(HERE, "perf-floors.json"), "utf8"));
}

function formatLanes(lanes) {
  if (lanes === undefined || lanes === null) return "—";
  if (typeof lanes === "object") return Object.entries(lanes).map(([k, v]) => `${k}:${v}`).join(" ");
  return String(lanes);
}

function main() {
  const { gate, dir } = parseArgs(process.argv.slice(2));
  const records = loadRecords(dir);
  const floors = loadFloors();

  const byPairing = new Map();
  for (const record of records) {
    if (!record.pairing) continue;
    if (!byPairing.has(record.pairing)) byPairing.set(record.pairing, []);
    byPairing.get(record.pairing).push(record);
  }

  const rows = [];
  let failed = false;

  for (const [pairing, group] of byPairing) {
    const mbpsValues = group.map(r => r.mbps).filter(v => typeof v === "number");
    const medianMbps = median(mbpsValues);
    const floor = floors[pairing];
    const pass = floor === undefined ? null : medianMbps >= floor;
    if (pass === false) failed = true;
    const latest = group[group.length - 1];
    rows.push({
      pairing, runs: group.length, medianMbps, floor, pass,
      transport: latest.transport, lanes: latest.lanes,
      rbMaxBytes: latest.rbMaxBytes, signalingHealthMedianMs: latest.signalingHealthMedianMs,
      netem: latest.netem,
    });
  }

  // A pairing with a floor that produced no record at all is a hard failure
  // — it means the job didn't even get that far, not that it was slow.
  for (const pairing of Object.keys(floors)) {
    if (!byPairing.has(pairing)) {
      rows.push({ pairing, runs: 0, medianMbps: NaN, floor: floors[pairing], pass: false, missing: true });
      failed = true;
    }
  }

  rows.sort((a, b) => a.pairing.localeCompare(b.pairing));

  const lines = [];
  lines.push("| Pairing | Runs | Median MB/s | Floor | Transport | Lanes | Max rb (bytes) | Signaling /health p50 (ms) | Netem drops/pkts | Result |");
  lines.push("|---|---:|---:|---:|---|---|---:|---:|---:|---|");
  for (const row of rows) {
    const result = row.missing ? "MISSING" : row.pass === null ? "n/a" : row.pass ? "PASS" : "FAIL";
    const netem = row.netem ? `${row.netem.drops}/${row.netem.packets}` : "—";
    lines.push([
      "", row.pairing, row.runs,
      Number.isFinite(row.medianMbps) ? row.medianMbps.toFixed(2) : "—",
      row.floor ?? "—", row.transport ?? "—", formatLanes(row.lanes),
      row.rbMaxBytes ?? "—",
      typeof row.signalingHealthMedianMs === "number" ? row.signalingHealthMedianMs.toFixed(2) : "—",
      netem, result, "",
    ].join(" | ").trim());
  }
  const table = lines.join("\n") + "\n";

  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    appendFileSync(summaryPath, `## netem performance summary (${process.env.SP2P_NETEM_PROFILE ?? "profile unknown"})\n\n${table}\n`);
  }
  // Always echo to stdout too, so a local/non-CI run (or a CI log) shows it
  // even when nothing appended to $GITHUB_STEP_SUMMARY.
  console.log(table);

  if (gate && failed) {
    console.error("perf-summary: one or more pairings are missing or below their floor (see table above)");
    process.exit(1);
  }
}

main();
