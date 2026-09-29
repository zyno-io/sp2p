#!/usr/bin/env node
// SPDX-License-Identifier: MIT
//
// Reads test-results/perf-large/*.json (one file per large.spec.ts pairing
// and size — see large.spec.ts's writeRecord), prints a markdown table to
// $GITHUB_STEP_SUMMARY (or stdout if unset), and with --gate exits non-zero
// if any expected pairing is missing a control or large record. The actual
// pass/fail memory-scaling assertions run inside large.spec.ts itself (via
// expect()); this script is a report, not a second gate on those numbers.
//
// Usage: node tests/large-summary.mjs [--gate] [--dir <perf-dir>]

import { appendFileSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

const EXPECTED_PAIRINGS = ["browser-browser", "browser-cli", "cli-browser", "cli-cli-auto"];

function parseArgs(argv) {
  let gate = false;
  let dir = join(HERE, "..", "..", "test-results", "perf-large");
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--gate") gate = true;
    else if (argv[i] === "--dir") dir = argv[++i];
  }
  return { gate, dir };
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

function mib(bytes) {
  return typeof bytes === "number" ? Math.round(bytes / 1024 / 1024) : undefined;
}

function formatLanes(lanes) {
  if (!lanes) return "—";
  return Object.entries(lanes).filter(([, v]) => v !== undefined).map(([k, v]) => `${k}:${v}`).join(" ") || "—";
}

function main() {
  const { gate, dir } = parseArgs(process.argv.slice(2));
  const records = loadRecords(dir);

  // Latest attempt/repeat wins per (pairing, size).
  const bySizeKey = new Map();
  for (const record of records) {
    if (!record.pairing || !record.size) continue;
    bySizeKey.set(`${record.pairing}:${record.size}`, record);
  }

  const rows = [];
  const missing = [];
  for (const pairing of EXPECTED_PAIRINGS) {
    for (const size of ["control", "large"]) {
      const record = bySizeKey.get(`${pairing}:${size}`);
      if (!record) {
        rows.push({ pairing, size, missing: true });
        missing.push(`${pairing}:${size}`);
        continue;
      }
      rows.push({
        pairing, size, missing: false,
        mbps: record.mbps, durationMs: record.durationMs,
        cliSenderMiB: mib(record.cliPeakBytes?.sender), cliReceiverMiB: mib(record.cliPeakBytes?.receiver),
        browserTreeMiB: mib(record.browserTreePeakBytes),
        transport: record.transport, lanes: record.lanes,
      });
    }
  }

  const lines = [];
  lines.push("| Pairing | Size | MB/s | Duration (ms) | CLI sender peak (MiB) | CLI receiver peak (MiB) | Browser tree peak (MiB) | Transport | Lanes |");
  lines.push("|---|---|---:|---:|---:|---:|---:|---|---|");
  for (const row of rows) {
    if (row.missing) {
      lines.push(`| ${row.pairing} | ${row.size} | MISSING | — | — | — | — | — | — |`);
      continue;
    }
    lines.push([
      "", row.pairing, row.size,
      typeof row.mbps === "number" ? row.mbps.toFixed(2) : "—",
      row.durationMs ?? "—",
      row.cliSenderMiB ?? "—", row.cliReceiverMiB ?? "—", row.browserTreeMiB ?? "—",
      row.transport ?? "—", formatLanes(row.lanes), "",
    ].join(" | ").trim());
  }
  const table = lines.join("\n") + "\n";

  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    appendFileSync(summaryPath, `## large-transfer summary\n\n${table}\n`);
  }
  console.log(table);

  if (gate && missing.length > 0) {
    console.error(`large-summary: missing record(s) for: ${missing.join(", ")}`);
    process.exit(1);
  }
}

main();
