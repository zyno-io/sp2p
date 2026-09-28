#!/usr/bin/env node
// SPDX-License-Identifier: MIT
//
// Reads test-results/relay/*.json (one file per relay.spec.ts pairing/label,
// per repeat and attempt — see relay.spec.ts's writeRelayRecord), prints a
// markdown table to $GITHUB_STEP_SUMMARY (or stdout if unset), and with
// --gate exits non-zero if any expected label (per --expect pr|full) has no
// record at all. See docs/testing.md.
//
// Usage: node tests/relay-summary.mjs [--gate] [--expect pr|full] [--dir <relay-dir>]

import { appendFileSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

const PR_LABELS = ["chromium-chromium", "cli-chromium", "chromium-cli", "cli-cli"];
const FULL_LABELS = [
  ...PR_LABELS,
  "firefox-chromium", "chromium-firefox", "cli-firefox", "firefox-cli",
  "abandon-chromium-chromium", "quota8-chromium-chromium",
  "consent-both-decline", "consent-cli-deny",
];

function parseArgs(argv) {
  let gate = false;
  let expect = null;
  let dir = join(HERE, "..", "..", "test-results", "relay");
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--gate") gate = true;
    else if (argv[i] === "--expect") expect = argv[++i];
    else if (argv[i] === "--dir") dir = argv[++i];
  }
  return { gate, expect, dir };
}

function expectedLabels(expect) {
  if (expect === "pr") return PR_LABELS;
  if (expect === "full") return FULL_LABELS;
  return [];
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

function relayedMiB(record) {
  const bytes = record.relayedBytes;
  if (!bytes) return null;
  const total = (bytes.fromPeers ?? 0) + (bytes.toPeers ?? 0);
  return Math.round(total / 1024 / 1024);
}

function main() {
  const { gate, expect, dir } = parseArgs(process.argv.slice(2));
  const records = loadRecords(dir);

  const byLabel = new Map();
  for (const record of records) {
    if (!record.pairing) continue;
    if (!byLabel.has(record.pairing)) byLabel.set(record.pairing, []);
    byLabel.get(record.pairing).push(record);
  }

  const rows = [];
  for (const [label, group] of byLabel) {
    // Latest attempt/repeat wins when a label has more than one record.
    const latest = group[group.length - 1];
    rows.push({
      label, runs: group.length,
      lanes: latest.lanes,
      created: latest.turn?.created,
      peakLive: latest.turn?.peakLive,
      quotaRejected: latest.turn?.quotaRejected,
      relayedMiB: relayedMiB(latest),
      releaseMs: latest.releaseMs,
      missing: false,
    });
  }

  const expected = expectedLabels(expect);
  const missingLabels = [];
  for (const label of expected) {
    if (!byLabel.has(label)) {
      rows.push({ label, runs: 0, missing: true });
      missingLabels.push(label);
    }
  }

  rows.sort((a, b) => a.label.localeCompare(b.label));

  const lines = [];
  lines.push("| Label | Runs | Connections/lanes | Created | Peak live | Quota rejected | Relayed MiB | Release ms |");
  lines.push("|---|---:|---:|---:|---:|---:|---:|---:|");
  for (const row of rows) {
    if (row.missing) {
      lines.push(`| ${row.label} | 0 | MISSING | — | — | — | — | — |`);
      continue;
    }
    lines.push([
      "", row.label, row.runs,
      row.lanes ?? "—", row.created ?? "—", row.peakLive ?? "—", row.quotaRejected ?? "—",
      row.relayedMiB ?? "—", row.releaseMs ?? "—", "",
    ].join(" | ").trim());
  }
  const table = lines.join("\n") + "\n";

  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    appendFileSync(summaryPath, `## TURN relay summary${expect ? ` (${expect})` : ""}\n\n${table}\n`);
  }
  // Always echo to stdout too, so a local/non-CI run (or a CI log) shows it
  // even when nothing appended to $GITHUB_STEP_SUMMARY.
  console.log(table);

  if (gate && missingLabels.length > 0) {
    console.error(`relay-summary: missing record(s) for: ${missingLabels.join(", ")}`);
    process.exit(1);
  }
}

main();
