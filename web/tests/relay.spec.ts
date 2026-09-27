// SPDX-License-Identifier: MIT

// TURN relay CI: proves relay-ONLY WebRTC transfers actually work through a
// real (test-only) TURN server (internal/testturn/testturnd), with exact
// TURN allocation accounting and no leaked allocations, inside the
// relay-firewalled "sp2p" network namespace (scripts/ci/netns.sh,
// scripts/ci/relay-firewall.sh — both applied by CI *before* Playwright
// runs; see docs/testing.md). Skipped unless SP2P_RELAY_TEST is set, which
// it only is inside that namespace — running this suite unfirewalled would
// silently prove nothing (same rationale as netem.spec.ts's
// SP2P_NETEM_PROFILE gate).
//
// Unlike netem.spec.ts, these describe blocks do NOT use `.serial`: each
// test creates its own fresh sp2p session against the shared
// testturnd/signaling-server instances and independently verifies its OWN
// allocation cleanup via a before/after stats.json diff, so tests are
// properly independent — a failure in one pairing must not cascade into
// skipping or misattributing the others.
//
// Per-pairing numeric-only results land in test-results/relay/*.json (see
// writeRelayRecord) — never transfer codes, TURN credentials, or SDP.

import { execSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import dgram from "node:dgram";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ChildProcess } from "node:child_process";
import type { Browser, Page, PlaywrightWorkerArgs } from "@playwright/test";
import { expect, test as base } from "./fixtures";
import {
  answerRelayPrompt, chooseFile, cleanupTemporaryDirectories, flushDiagnostics, installReceiverSink,
  observeConnections, temporaryDirectory, trackCLIForDiagnostics, trackForDiagnostics, verifyReceiverSink, watchCLI,
} from "./helpers";
import type { CLIWatch } from "./helpers";

const ROOT = join(__dirname, "..", "..");

// ── Constants shared with scripts/ci/relay-firewall.sh and CI (do not
// change any of these without updating that script and the Go testturnd
// contract in lockstep) ──────────────────────────────────────────────────

// The relay suite's OWN isolated signaling server. Port 18090 stays reserved
// for the shared global-setup server other suites use throughout the whole
// run — this suite must never collide with it.
const SIGNAL_PORT = 18091;
const TURN_LISTEN = "10.99.0.1:3478";
const TURN_HOST = "10.99.0.1"; // for ICE URLs the browser/CLI use
const ICE_URLS = "stun:10.99.0.1:3478,turn:10.99.0.1:3478?transport=udp";
const RELAY_MIN_PORT = 31000;
const RELAY_MAX_PORT = 31127;

// Meets both PARALLEL_MIN_BYTES (web/src/webrtc-parallel.ts) and
// parallelMinFileSize (internal/flow) — the auto threshold at which both
// sides request the full 8-lane parallel WebRTC policy.
const SIZE = 64 * 1024 * 1024;
const LANES = 8;
const PEERS = 2;

// Every lane (primary + each authenticated extra lane) on every peer that
// actually attempts the relay makes its OWN TURN allocation: each lane is
// its own RTCPeerConnection/ICE agent reusing the primary's ICE server
// config —
//   - browser: web/src/webrtc-parallel.ts's Lane constructor calls
//     `new RTCPeerConnection(pc.getConfiguration())` (see the `new Lane(...)`
//     call inside negotiateParallelWebRTC's lane loop);
//   - CLI: pion's own ICE agent, one per lane.
// So 8 lanes x 2 peers = 16 allocations when both peers relay all 8 lanes.
//
// Chromium's `bundlePolicy: "max-bundle"` (web/src/webrtc.ts's BUFFER_HINT
// check — true for non-Firefox — gates setting it on RTCPeerConnection
// construction) keeps each *connection* to exactly one ICE transport, i.e.
// one allocation per connection, which is what makes "one lane = one
// allocation" hold for Chromium-offering connections specifically. A
// mutation test that removed bundlePolicy would be expected to change the
// observed per-connection allocation count for those connections — a real
// CI run must empirically confirm the number below, and docs/testing.md's
// TURN relay CI section (being written alongside this file) records that
// confirmed value.
const EXPECTED_ALLOCATIONS_FULL = PEERS * LANES; // 16

const LEAK_WINDOW_MS = 10_000;
const TRANSFER_TIMEOUT_MS = 150_000;

// Exact text from web/src/main.ts's confirmRelay() confirm(...) call
// (identical for sender and receiver — see establishP2PWithRetry's two call
// sites, ~line 505 and ~line 810).
const RELAY_CONFIRM =
  "Direct P2P connection failed. Allow relaying encrypted data through the server?\n\n" +
  "Your data remains end-to-end encrypted, but the relay server will see connection metadata.";
// web/src/main.ts's establishP2PWithRetry, thrown when confirmRelay() itself
// resolves false (this side's own dialog was declined) — ~line 153.
const DECLINED = "P2P connection failed and relay was declined";
// internal/flow/helpers.go's message when this side's own relay prompt is
// denied (~lines 145/167); internal/cli/machine.go's finish() (~line 523)
// tags this with error code "relay_denied" because r.relayResponse == "deny".
const CLI_DENIED = "Could not establish direct connection. Use -allow-relay to route encrypted data through a TURN relay.";

// Mirrors web/src/main.ts's connectionDetail construction (~line 550/854):
// `connectionCount > 1 ? ", ${connectionCount} connections" : ""`.
function relayStepText(connections: number): string {
  const detail = connections > 1 ? `, ${connections} connections` : "";
  return `Connected via WebRTC (TURN relay${detail})`;
}

// ── TURN stats.json contract (internal/testturn/stats.go) — read-only ─────

interface TurnAllocationRecord {
  clientPort: number;
  createdAtMs: number;
  deletedAtMs?: number;
}

interface TurnUserStats {
  created: number;
  deleted: number;
  live: number;
  peakLive: number;
  quotaRejected: number;
  relayedBytesFromPeers: number;
  relayedBytesToPeers: number;
  // Leak-debugging aid (see internal/testturn/stats.go's AllocationRecord).
  allocations?: TurnAllocationRecord[];
}

interface TurnSnapshot {
  version: number;
  seq: number;
  ready: boolean;
  closed: boolean;
  userQuota: number;
  created: number;
  deleted: number;
  live: number;
  peakLive: number;
  quotaRejected: number;
  authFailures: number;
  relayAllocFailures: number;
  anomalies: number;
  pionLive: number;
  relayedBytesFromPeers: number;
  relayedBytesToPeers: number;
  users: Record<string, TurnUserStats>;
}

// ── Dialog recording ────────────────────────────────────────────────────

interface DialogRecord {
  type: string;
  message: string;
}

// Registers this page's relay-consent dialog handler BEFORE any navigation
// (Playwright auto-dismisses a dialog with no handler registered, which
// would look exactly like a real user declining — so a handler must always
// exist and explicitly accept/dismiss). Records every dialog seen.
function registerDialog(page: Page, accept: boolean): DialogRecord[] {
  const dialogs: DialogRecord[] = [];
  page.on("dialog", dialog => {
    dialogs.push({ type: dialog.type(), message: dialog.message() });
    void (accept ? dialog.accept() : dialog.dismiss());
  });
  return dialogs;
}

// ── Worker fixture: relayEnv ────────────────────────────────────────────

interface RelayEnv {
  url: string;
  wsUrl: string;
  secret: string;
  cliBin: string;
  testturndBin: string;
}

// Confirms we're actually inside the relay-firewalled namespace before
// starting anything expensive. This is a lightweight, best-effort check
// (binding a UDP socket on the TURN host address) — NOT a full firewall-rule
// verification; that's scripts/ci/relay-firewall.sh's own `verify`
// subcommand's job, run separately by CI before Playwright starts.
function preflightNamespace(): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    socket.once("error", (error: NodeJS.ErrnoException) => {
      socket.close();
      reject(new Error(
        `relay.spec.ts: could not bind a UDP socket on ${TURN_HOST} (${error.code ?? error.message}) — ` +
        "run inside the relay-firewalled sp2p netns, e.g. via 'scripts/ci/netns.sh exec -- ...' (see docs/testing.md)",
      ));
    });
    socket.bind({ address: TURN_HOST, port: 0 }, () => { socket.close(); resolve(); });
  });
}

export const test = base.extend<{}, { relayEnv: RelayEnv }>({
  relayEnv: [async ({}, use) => {
    await preflightNamespace();

    const state = JSON.parse(readFileSync(join(__dirname, "../.pw-state.json"), "utf8"));
    const serverBin: string = state.serverBin ?? join(state.tmpDir, "sp2p-server");

    let testturndBin: string;
    if (process.env.SP2P_PW_TESTTURND_BIN) {
      testturndBin = process.env.SP2P_PW_TESTTURND_BIN;
    } else {
      const buildDir = mkdtempSync(join(tmpdir(), "sp2p-relay-build-"));
      testturndBin = join(buildDir, "testturnd");
      execSync(`go build -o ${testturndBin} ./internal/testturn/testturnd`, { cwd: ROOT, stdio: "pipe" });
    }

    const secret = randomBytes(32).toString("hex");
    const url = `http://127.0.0.1:${SIGNAL_PORT}`;
    // -turn-secret/-turn-username/-turn-password are mutually exclusive
    // (cmd/sp2p-server/main.go) — delete the static-credential env vars
    // entirely rather than setting them to undefined, so a developer's own
    // shell environment can never smuggle in the static-credential mode.
    const env: NodeJS.ProcessEnv = { ...process.env, SP2P_TURN_SECRET: secret };
    delete env.SP2P_TURN_USERNAME;
    delete env.SP2P_TURN_PASSWORD;

    // Server logs may contain session IDs — never capture them.
    const server = spawn(serverBin, [
      "-addr", `127.0.0.1:${SIGNAL_PORT}`, "-base-url", url, "-turn-servers", ICE_URLS,
    ], { env, stdio: "ignore" });
    const exited = new Promise<void>(resolve => { server.once("exit", () => resolve()); server.once("error", () => resolve()); });

    try {
      await expect.poll(async () => {
        const response = await fetch(`${url}/health`).catch(() => null);
        return response?.ok;
      }, { timeout: 10_000 }).toBe(true);

      await use({ url, wsUrl: `ws://127.0.0.1:${SIGNAL_PORT}/ws`, secret, cliBin: state.cliBin, testturndBin });
    } finally {
      server.kill();
      await exited;
    }
  }, { scope: "worker" }],
});

// Declared only after `test` above is fully defined (test.skip is a method
// on the extended test object, not a free function) — mirrors
// netem.spec.ts's top-level test.skip(!process.env.SP2P_NETEM_PROFILE, ...) gate.
test.skip(!process.env.SP2P_RELAY_TEST, "set SP2P_RELAY_TEST=1 inside the relay-firewalled sp2p netns (docs/testing.md)");

// ── Turn-server helper ──────────────────────────────────────────────────

interface TurnHandle {
  snapshot(): TurnSnapshot;
  stop(): Promise<void>;
}

// Deliberately NOT the shared temporaryDirectory() helper: that helper's
// directories are all deleted together by cleanupTemporaryDirectories() in
// afterEach, which would delete this stats directory out from under a
// still-running testturnd process. This directory's lifetime is tied to
// stop() instead.
async function startTurn(env: RelayEnv, quota: number): Promise<TurnHandle> {
  const dir = mkdtempSync(join(tmpdir(), "sp2p-relay-turn-"));
  const statsPath = join(dir, "stats.json");
  const stderr: string[] = [];

  const child = spawn(env.testturndBin, [
    "-listen", TURN_LISTEN, "-relay-ip", TURN_HOST,
    "-min-port", String(RELAY_MIN_PORT), "-max-port", String(RELAY_MAX_PORT),
    "-realm", "sp2p.test", "-user-quota", String(quota),
    "-stats", statsPath, "-exit-with-parent",
    // NOT passing -allocation-lifetime: a short value (tried 8s) fixed the
    // CLI<->CLI leak-window race (pion/turn's client refreshes at
    // lifetime/2, verified in internal/client/udp_conn.go) but broke every
    // Firefox pairing with "your TURN server appears to be broken" --
    // Firefox's own (non-pion) WebRTC/ICE stack does not refresh
    // proportionally to a short granted lifetime the same way, and 8s
    // wasn't enough for it. Confirmed on real CI: reverted. See
    // docs/testing.md's "Known rough edges" section.
  ], { env: { ...process.env, SP2P_TESTTURN_SECRET: env.secret } });
  child.stderr?.on("data", chunk => { stderr.push(chunk.toString()); });
  let earlyExitCode: number | null = null;
  child.once("exit", code => { earlyExitCode = code; });

  try {
    await expect.poll(() => {
      if (earlyExitCode !== null) throw new Error(`testturnd exited early (code ${earlyExitCode})`);
      try {
        return (JSON.parse(readFileSync(statsPath, "utf8")) as Partial<TurnSnapshot>).ready === true;
      } catch {
        return false;
      }
    }, { timeout: 10_000, intervals: [100] }).toBe(true);
  } catch (error) {
    child.kill("SIGKILL");
    rmSync(dir, { recursive: true, force: true });
    throw new Error(`relay.spec.ts: testturnd (quota=${quota}) failed to become ready: ${(error as Error).message}\nstderr: ${stderr.join("")}`);
  }

  return {
    snapshot(): TurnSnapshot {
      return JSON.parse(readFileSync(statsPath, "utf8"));
    },
    async stop(): Promise<void> {
      child.kill("SIGTERM");
      const exitedCleanly = await Promise.race([
        new Promise<boolean>(resolve => child.once("exit", () => resolve(true))),
        new Promise<boolean>(resolve => setTimeout(() => resolve(false), 5000)),
      ]);
      if (!exitedCleanly) {
        child.kill("SIGKILL");
        // Wait for the actual exit event after SIGKILL too, so the OS has
        // released the UDP port (3478) before the next describe block's
        // startTurn() tries to bind it again -- otherwise that bind can
        // race an address-already-in-use failure.
        await new Promise<void>(resolve => child.once("exit", () => resolve()));
      }
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

// ── Test-record writer (mirrors netem.spec.ts's writePerfRecord) ──────────

const RELAY_DIR = join(ROOT, "test-results", "relay");

function writeRelayRecord(label: string, record: Record<string, unknown>): void {
  mkdirSync(RELAY_DIR, { recursive: true });
  const info = test.info();
  const full = { pairing: label, ...record };
  // One file per repeat and attempt, so --repeat-each runs don't overwrite each other.
  writeFileSync(join(RELAY_DIR, `${label}.r${info.repeatEachIndex}.a${info.retry}.json`), JSON.stringify(full, null, 2) + "\n");
}

// ── Shared content ───────────────────────────────────────────────────────

const contents = randomBytes(SIZE);
const expectedHash = createHash("sha256").update(contents).digest("hex");

// ── Browser launch options (mirrors netem.spec.ts's "netem" project chromium
// launch args / docs/testing.md's Engines section rationale) ──────────────

const CHROMIUM_LAUNCH = {
  headless: true,
  channel: "chromium" as const,
  // mDNS on a dummy interface inside the netns isn't guaranteed to resolve,
  // so host candidates would otherwise be unusable .local names.
  args: ["--disable-features=WebRtcHideLocalIpsWithMdns"],
};
const FIREFOX_LAUNCH = {
  headless: true,
  firefoxUserPrefs: { "media.peerconnection.ice.obfuscate_host_addresses": false },
};

type EngineName = "chromium" | "firefox";
type Playwright = PlaywrightWorkerArgs["playwright"];
type Peer = { kind: "browser"; engine: EngineName } | { kind: "cli" };

// ── Relay-consent guard: fire-and-forget-then-await-with-timeout ─────────

// Answers a CLI's relay prompt once it appears, but never hangs forever if
// it never does (which would mean the direct connection unexpectedly
// succeeded despite the firewall — a real bug in the test setup, not a
// reason to hang). cli.relayRequired already rejects immediately if the
// process exits before prompting; this adds a bounded fallback in case it
// hangs without exiting either.
function guardedAnswerRelayPrompt(cli: CLIWatch, response: "allow" | "deny", timeoutMs = TRANSFER_TIMEOUT_MS): Promise<void> {
  return Promise.race([
    answerRelayPrompt(cli, response),
    new Promise<void>((_, reject) => setTimeout(() => reject(new Error(
      `relay.spec.ts: no relay_required prompt from this CLI within ${timeoutMs}ms — did the direct connection unexpectedly succeed despite the firewall?`,
    )), timeoutMs)),
  ]);
}

// Pushes a relay-answer promise into the shared list AND separately marks
// it "handled" (mirrors helpers.ts's watchCLI: `void code.catch(() => {})`)
// so a rejection is never reported as an unhandled promise rejection if the
// caller throws for an unrelated reason before ever reaching the
// `await Promise.all(relayAnswerPromises)` below — the array element itself
// is untouched and still rejects normally when that await runs.
function trackRelayAnswer(list: Promise<void>[], promise: Promise<void>): void {
  void promise.catch(() => {});
  list.push(promise);
}

// ── Session-release poll (shared by every scenario below) ────────────────

async function pollSessionRelease(
  turn: TurnHandle, before: TurnSnapshot,
  debug?: { pids: { label: string; pid: number | undefined }[]; portHistory: () => string[] },
): Promise<{ releaseMs: number; newKey: string | undefined; after: TurnSnapshot }> {
  const pollStart = Date.now();
  let after!: TurnSnapshot;
  const beforeKeys = new Set(Object.keys(before.users));
  let newKey: string | undefined;
  try {
    await expect.poll(() => {
      after = turn.snapshot();
      const newKeys = Object.keys(after.users).filter(k => !beforeKeys.has(k));
      newKey = newKeys[0];
      return {
        newSessions: newKeys.length,
        live: newKeys.reduce((sum, k) => sum + after.users[k].live, 0),
        pionLiveDelta: after.pionLive - before.pionLive,
      };
    }, { timeout: LEAK_WINDOW_MS, intervals: [250] }).toEqual({ newSessions: 1, live: 0, pionLiveDelta: 0 });
  } catch (error) {
    if (debug) dumpLeakDiagnostics(turn, before, debug.pids, debug.portHistory());
    throw error;
  }
  return { releaseMs: Date.now() - pollStart, newKey, after };
}

// TEMPORARY, investigation-only (see docs/testing.md's "Known rough edges"
// -- the CLI<->CLI leak-window finding). Both CLI processes will have
// already exited (with code 0) by the time a leak-window failure is
// detected -- the kernel reclaims every FD, including any leaked TURN
// client socket, the instant a process exits, so checking `ss -uanp`
// *after* exit can never show who owned a leaked port; the mapping has to
// be captured *while the processes are still alive*. samplePortPids below
// polls `ss -H -uanp` every 300ms for the CLI-visible lifetime of a test
// and keeps every raw snapshot; dumpLeakDiagnostics then searches all of
// them for the specific leaked port(s), so even a port whose owning
// process already exited by the time of the *next* sample can still be
// attributed to a known CLI pid/role from an earlier one. Remove once the
// leak is root-caused and fixed and this is no longer needed.
interface PortPidSampler {
  // Live snapshot of everything captured so far, without stopping the
  // sampler -- call this from inside a failure handler, since the sampler
  // must keep running through pollSessionRelease's own up-to-10s poll.
  peek(): string[];
  // Stops the background loop. Call once the pairing is fully done
  // (success or failure), typically from a `finally` block.
  stop(): void;
}

function samplePortPidHistory(intervalMs = 300): PortPidSampler {
  const snapshots: string[] = [];
  let running = true;
  const loop = (async () => {
    while (running) {
      try {
        snapshots.push(execSync("ss -H -uanp", { encoding: "utf8" }));
      } catch {
        // best effort -- a transient exec failure just skips this tick.
      }
      await new Promise(resolve => setTimeout(resolve, intervalMs));
    }
  })();
  return {
    peek(): string[] {
      return snapshots.slice();
    },
    stop(): void {
      running = false;
      void loop;
    },
  };
}

// Dumps, for a leak-window failure: the known CLI pids/roles, every
// allocation record for the new session(s) (client port + timestamps, from
// testturn's stats.json), and -- for each still-live (leaked) port -- every
// line from the sampled `ss -uanp` history that mentions that port,
// including its pid, so the leaked connection's owner (sender vs receiver,
// and whether/when that pid stopped appearing) can be read off the CI log.
// Each CLI's own [pc-debug] PeerConnection lifecycle lines (see debugLeak's
// SP2P_DEBUG_PC_LIFECYCLE wiring in runRelayPairing) are NOT repeated here --
// they're already printed, per pid, by the existing flushCLIDiagnostics
// failure path (trackCLIForDiagnostics + "[diagnostics] <label> stderr:"),
// which every test in this file already relies on. Cross-reference a pid
// from this dump's "known CLI pids" line against those stderr lines to see
// which PeerConnection (primary vs lane#N) that process created and whether
// it ever logged "Close() returned".
function dumpLeakDiagnostics(
  turn: TurnHandle, before: TurnSnapshot, pids: { label: string; pid: number | undefined }[], portHistory: string[],
): void {
  const after = turn.snapshot();
  const beforeKeys = new Set(Object.keys(before.users));
  const newKeys = Object.keys(after.users).filter(k => !beforeKeys.has(k));
  console.log(`[leak-debug] known CLI pids: ${pids.map(p => `${p.label}=${p.pid ?? "(none)"}`).join(", ")}`);
  console.log(`[leak-debug] new session keys: ${newKeys.length}, ss snapshots captured: ${portHistory.length}`);
  for (const key of newKeys) {
    const u = after.users[key];
    console.log(`[leak-debug] session ${key}: live=${u.live} created=${u.created} deleted=${u.deleted}`);
    for (const rec of u.allocations ?? []) {
      const status = rec.deletedAtMs ? `deleted ${rec.deletedAtMs - rec.createdAtMs}ms after creation` : "STILL LIVE";
      console.log(`[leak-debug]   allocation clientPort=${rec.clientPort} createdAtMs=${rec.createdAtMs} ${status}`);
      if (!rec.deletedAtMs) {
        const needle = `:${rec.clientPort} `;
        let hits = 0;
        for (let i = 0; i < portHistory.length; i++) {
          for (const line of portHistory[i].split("\n")) {
            if (line.includes(needle)) {
              hits++;
              console.log(`[leak-debug]     ss[${i}]: ${line.trim()}`);
            }
          }
        }
        if (hits === 0) console.log(`[leak-debug]     port ${rec.clientPort} never appeared in any ss snapshot`);
      }
    }
  }
}

// ── Browser side setup ────────────────────────────────────────────────────

interface BrowserSide {
  browser: Browser;
  page: Page;
  dialogs: DialogRecord[];
  counts: number[];
}

async function launchBrowserSide(
  playwright: Playwright, relayEnv: RelayEnv, engine: EngineName, role: "sender" | "receiver", label: string,
): Promise<BrowserSide> {
  const browser = engine === "chromium" ? await playwright.chromium.launch(CHROMIUM_LAUNCH) : await playwright.firefox.launch(FIREFOX_LAUNCH);
  // Self-contained cleanup: if anything below throws, this function must
  // not leak the browser it just launched, regardless of whether the
  // caller ever gets a chance to register it for its own cleanup (it
  // can't, since launchBrowserSide never returns to hand the browser back).
  try {
    const page = await browser.newPage({ baseURL: relayEnv.url });
    // Registered before any navigation, always allow — the standard pairings
    // and the quota test all expect consent to be granted.
    const dialogs = registerDialog(page, true);
    if (role === "receiver") await installReceiverSink(page, engine);
    trackForDiagnostics(page, `${label}-${role}`);
    const counts = observeConnections(page);
    return { browser, page, dialogs, counts };
  } catch (error) {
    await browser.close().catch(() => {});
    throw error;
  }
}

// ── Shared pairing runner ─────────────────────────────────────────────────

interface RunRelayPairingOptions {
  playwright: Playwright;
  relayEnv: RelayEnv;
  turn: TurnHandle;
  sender: Peer;
  receiver: Peer;
  label: string;
  expectedConnections: number;
  expectedCreated: number;
  expectedQuotaRejected?: number;
  // TEMPORARY, investigation-only (see dumpLeakDiagnostics/samplePortPidHistory
  // above): when true, samples `ss -uanp` for the duration of this pairing
  // and dumps a port/pid-correlated diagnostic if the leak-window check
  // fails. Remove once the CLI<->CLI leak is root-caused and fixed.
  debugLeak?: boolean;
}

async function runRelayPairing(opts: RunRelayPairingOptions): Promise<void> {
  const { playwright, relayEnv, turn, sender, receiver, label, expectedConnections, expectedCreated } = opts;
  const expectedQuotaRejected = opts.expectedQuotaRejected ?? 0;

  const before = turn.snapshot();
  const start = Date.now();
  const portSampler = opts.debugLeak ? samplePortPidHistory() : undefined;

  const browsers: Browser[] = [];
  const childProcesses: ChildProcess[] = [];
  const relayAnswerPromises: Promise<void>[] = [];
  let senderSide: BrowserSide | undefined;
  let receiverSide: BrowserSide | undefined;
  let senderCLI: CLIWatch | undefined;
  let receiverCLI: CLIWatch | undefined;
  let receiverDestDir = "";
  let senderPid: number | undefined;
  let receiverPid: number | undefined;

  try {
    let code: string;

    // ── Sender ──
    if (sender.kind === "browser") {
      senderSide = await launchBrowserSide(playwright, relayEnv, sender.engine, "sender", label);
      browsers.push(senderSide.browser);
      code = await chooseFile(senderSide.page, contents, `${label}-send.bin`);
    } else {
      const srcDir = temporaryDirectory("sp2p-relay-send-");
      const srcPath = join(srcDir, `${label}-send.bin`);
      writeFileSync(srcPath, contents);
      const xdg = temporaryDirectory("sp2p-relay-xdg-");
      const args = [
        "send", "-format", "json", "-v", "-allow-relay=false", "-server", relayEnv.wsUrl, "-compress", "0",
        ...(receiver.kind === "browser" ? ["-transport", "webrtc"] : []),
        srcPath,
      ];
      const child = spawn(relayEnv.cliBin, args, {
        env: { ...process.env, XDG_CONFIG_HOME: xdg, ...(opts.debugLeak ? { SP2P_DEBUG_PC_LIFECYCLE: "1" } : {}) },
      });
      childProcesses.push(child);
      senderPid = child.pid;
      senderCLI = watchCLI(child);
      trackCLIForDiagnostics(senderCLI, `${label}-sender`);
      trackRelayAnswer(relayAnswerPromises, guardedAnswerRelayPrompt(senderCLI, "allow"));
      code = await senderCLI.code;
    }

    // ── Receiver ──
    if (receiver.kind === "browser") {
      receiverSide = await launchBrowserSide(playwright, relayEnv, receiver.engine, "receiver", label);
      browsers.push(receiverSide.browser);
      await receiverSide.page.goto(`/r#${code}`);
      await receiverSide.page.locator(".confirm-btn").click();
    } else {
      receiverDestDir = temporaryDirectory("sp2p-relay-recv-");
      const xdg = temporaryDirectory("sp2p-relay-xdg-");
      const args = [
        "receive", "-format", "json", "-v", "-allow-relay=false", "-server", relayEnv.wsUrl,
        ...(sender.kind === "browser" ? ["-transport", "webrtc"] : []),
        "-output", receiverDestDir, code,
      ];
      const child = spawn(relayEnv.cliBin, args, {
        env: { ...process.env, XDG_CONFIG_HOME: xdg, ...(opts.debugLeak ? { SP2P_DEBUG_PC_LIFECYCLE: "1" } : {}) },
      });
      childProcesses.push(child);
      receiverPid = child.pid;
      receiverCLI = watchCLI(child);
      trackCLIForDiagnostics(receiverCLI, `${label}-receiver`);
      trackRelayAnswer(relayAnswerPromises, guardedAnswerRelayPrompt(receiverCLI, "allow"));
    }

    // ── Wait for completion ──
    if (senderSide) await expect(senderSide.page.locator(".complete")).toBeVisible({ timeout: TRANSFER_TIMEOUT_MS });
    if (receiverSide) await expect(receiverSide.page.locator(".complete")).toBeVisible({ timeout: TRANSFER_TIMEOUT_MS });
    if (senderCLI) expect(await senderCLI.exited).toBe(0);
    if (receiverCLI) expect(await receiverCLI.exited).toBe(0);

    // Confirm the relay-consent path was actually exercised for every CLI
    // side, rather than hanging forever if it never was.
    await Promise.all(relayAnswerPromises);

    // ── Verify integrity ──
    if (receiverSide) await verifyReceiverSink(receiverSide.page, receiver.kind === "browser" ? receiver.engine : "chromium", contents.length, expectedHash);
    if (receiverCLI) {
      const received = readFileSync(join(receiverDestDir, `${label}-send.bin`));
      expect(createHash("sha256").update(received).digest("hex")).toBe(expectedHash);
      expect(received.length).toBe(contents.length);
    }

    // ── Session release (no leaked allocations) ──
    const { releaseMs, newKey, after } = await pollSessionRelease(turn, before, portSampler && {
      pids: [{ label: "sender", pid: senderPid }, { label: "receiver", pid: receiverPid }],
      portHistory: () => portSampler.peek(),
    });
    expect(newKey, "no new TURN session key appeared for this transfer").toBeDefined();
    const userStats = after.users[newKey!];

    // ── Consent path was actually exercised ──
    if (senderSide) expect(senderSide.dialogs).toEqual([{ type: "confirm", message: RELAY_CONFIRM }]);
    if (receiverSide) expect(receiverSide.dialogs).toEqual([{ type: "confirm", message: RELAY_CONFIRM }]);
    if (senderCLI) {
      await senderCLI.relayRequired; // already resolved by guardedAnswerRelayPrompt above
      expect(senderCLI.relayResponses).toEqual(["allow"]);
      expect(senderCLI.results[0]?.outcome).toBe("completed");
      expect(senderCLI.transports).toEqual(["webrtc"]);
    }
    if (receiverCLI) {
      await receiverCLI.relayRequired;
      expect(receiverCLI.relayResponses).toEqual(["allow"]);
      expect(receiverCLI.results[0]?.outcome).toBe("completed");
      expect(receiverCLI.transports).toEqual(["webrtc"]);
    }

    // ── Relay path ──
    const stepText = relayStepText(expectedConnections);
    if (senderSide) expect(await senderSide.page.locator(".step-p2p").textContent()).toBe(stepText);
    if (receiverSide) expect(await receiverSide.page.locator(".step-p2p").textContent()).toBe(stepText);

    // ── Allocation accounting ──
    expect(userStats.created).toBe(expectedCreated);
    expect(userStats.deleted).toBe(expectedCreated);
    expect(userStats.peakLive).toBe(expectedCreated);
    expect(userStats.quotaRejected).toBe(expectedQuotaRejected);
    expect(after.authFailures - before.authFailures).toBe(0);
    expect(after.relayAllocFailures - before.relayAllocFailures).toBe(0);
    expect(after.anomalies - before.anomalies).toBe(0);

    // ── Lane count agreement ──
    if (senderSide) expect(senderSide.counts).toEqual([expectedConnections]);
    if (receiverSide) expect(receiverSide.counts).toEqual([expectedConnections]);
    if (senderCLI) expect(senderCLI.counts).toEqual([expectedConnections]);
    if (receiverCLI) expect(receiverCLI.counts).toEqual([expectedConnections]);

    writeRelayRecord(label, {
      lanes: expectedConnections,
      turn: { created: userStats.created, peakLive: userStats.peakLive, quotaRejected: userStats.quotaRejected },
      relayedBytes: { fromPeers: userStats.relayedBytesFromPeers, toPeers: userStats.relayedBytesToPeers },
      releaseMs,
      durationMs: Date.now() - start,
    });
  } finally {
    portSampler?.stop();
    for (const child of childProcesses) child.kill();
    for (const browser of browsers) await browser.close();
  }
}

test.afterEach(async ({}, testInfo) => {
  cleanupTemporaryDirectories();
  await flushDiagnostics(testInfo);
});

// ── Main describe block: the 8 sender/receiver pairings + abandon test ────
//
// Not .serial: each test is independently self-verifying (its own
// before/after TURN snapshot diff), so one pairing's failure must not
// skip or misattribute the others.
test.describe("relay: sender/receiver pairings", () => {
  let turn: TurnHandle;
  test.beforeAll(async ({ relayEnv }) => { turn = await startTurn(relayEnv, 0); });
  test.afterAll(async () => { await turn?.stop(); });

  test("chromium to chromium", { tag: "@pr" }, async ({ playwright, relayEnv }) => {
    await runRelayPairing({
      playwright, relayEnv, turn,
      sender: { kind: "browser", engine: "chromium" }, receiver: { kind: "browser", engine: "chromium" },
      label: "chromium-chromium", expectedConnections: LANES, expectedCreated: EXPECTED_ALLOCATIONS_FULL,
    });
  });

  test("cli to chromium", { tag: "@pr" }, async ({ playwright, relayEnv }) => {
    await runRelayPairing({
      playwright, relayEnv, turn,
      sender: { kind: "cli" }, receiver: { kind: "browser", engine: "chromium" },
      label: "cli-chromium", expectedConnections: LANES, expectedCreated: EXPECTED_ALLOCATIONS_FULL,
    });
  });

  test("chromium to cli", { tag: "@pr" }, async ({ playwright, relayEnv }) => {
    await runRelayPairing({
      playwright, relayEnv, turn,
      sender: { kind: "browser", engine: "chromium" }, receiver: { kind: "cli" },
      label: "chromium-cli", expectedConnections: LANES, expectedCreated: EXPECTED_ALLOCATIONS_FULL,
    });
  });

  test("cli to cli", { tag: "@pr" }, async ({ playwright, relayEnv }) => {
    // No -transport flag on either side: auto-negotiation must itself
    // discover that direct TCP is blocked (relay-firewall.sh rejects all
    // TCP except the signaling ports) and fall back to WebRTC+relay. The
    // shared runner's CLI assertions (transports === ["webrtc"]) turn a
    // silent "TCP actually succeeded" into a loud, specific failure instead
    // of a quiet pass.
    await runRelayPairing({
      playwright, relayEnv, turn,
      sender: { kind: "cli" }, receiver: { kind: "cli" },
      label: "cli-cli", expectedConnections: LANES, expectedCreated: EXPECTED_ALLOCATIONS_FULL,
      // TEMPORARY, investigation-only: see dumpLeakDiagnostics/samplePortPidHistory
      // above. Remove this flag once the CLI<->CLI leak is root-caused and fixed.
      debugLeak: true,
    });
  });

  test("firefox to chromium", async ({ playwright, relayEnv }) => {
    await runRelayPairing({
      playwright, relayEnv, turn,
      sender: { kind: "browser", engine: "firefox" }, receiver: { kind: "browser", engine: "chromium" },
      label: "firefox-chromium", expectedConnections: LANES, expectedCreated: EXPECTED_ALLOCATIONS_FULL,
    });
  });

  test("chromium to firefox", async ({ playwright, relayEnv }) => {
    await runRelayPairing({
      playwright, relayEnv, turn,
      sender: { kind: "browser", engine: "chromium" }, receiver: { kind: "browser", engine: "firefox" },
      label: "chromium-firefox", expectedConnections: LANES, expectedCreated: EXPECTED_ALLOCATIONS_FULL,
    });
  });

  test("cli to firefox", async ({ playwright, relayEnv }) => {
    await runRelayPairing({
      playwright, relayEnv, turn,
      sender: { kind: "cli" }, receiver: { kind: "browser", engine: "firefox" },
      label: "cli-firefox", expectedConnections: LANES, expectedCreated: EXPECTED_ALLOCATIONS_FULL,
    });
  });

  test("firefox to cli", async ({ playwright, relayEnv }) => {
    await runRelayPairing({
      playwright, relayEnv, turn,
      sender: { kind: "browser", engine: "firefox" }, receiver: { kind: "cli" },
      label: "firefox-cli", expectedConnections: LANES, expectedCreated: EXPECTED_ALLOCATIONS_FULL,
    });
  });

  // Derivation of the expected total allocation count for this test:
  //
  // Sender (Chromium): web/src/webrtc-parallel.ts's negotiateParallelWebRTC
  // gathers ALL extra lanes' local descriptions (Promise.all(gathering))
  // BEFORE writing ANY "offer" control message (the write loop runs only
  // after that Promise.all resolves) — so by the time the receiver sees the
  // FIRST offer, the sender has already constructed and started ICE
  // gathering for all 7 extra lanes, each making its own TURN allocation,
  // plus its own already-established primary connection: 1 + 7 = 8.
  //
  // Receiver (Chromium): the injected abandon hook fires the instant the
  // FIRST extra-lane RTCPeerConnection's setRemoteDescription resolves —
  // which happens BEFORE that lane ever calls setLocalDescription (the step
  // that actually starts its ICE/TURN gathering; see the `if (!sender)`
  // block preceding `gathering[id] = lane.description(sender)` in
  // negotiateParallelWebRTC). So the receiver's extra lane never allocates
  // at all; only its own already-established primary connection did: 1.
  //
  // Total: 8 (sender) + 1 (receiver) = 9.
  const EXPECTED_ABANDON_CREATED = 1 /* sender primary */ + (LANES - 1) /* sender extra lanes */ + 1 /* receiver primary only */;

  test("receiver abandons lane setup", async ({ playwright, relayEnv }) => {
    const before = turn.snapshot();
    const start = Date.now();

    const senderBrowser = await playwright.chromium.launch(CHROMIUM_LAUNCH);
    const receiverBrowser = await playwright.chromium.launch(CHROMIUM_LAUNCH);
    // Everything from here on is inside try/finally: if any setup call
    // below throws, both browsers must still be closed rather than leaked.
    try {
      const senderPage = await senderBrowser.newPage({ baseURL: relayEnv.url });
      const receiverPage = await receiverBrowser.newPage({ baseURL: relayEnv.url });
      registerDialog(senderPage, true);
      registerDialog(receiverPage, true);

      // Abandon hook: identify an "extra lane" RTCPeerConnection (as opposed
      // to the primary) by its ICE server config containing a "turn:" URL AND
      // not being the FIRST such connection constructed on this page. This is
      // robust against attempt-1 (STUN-only, web/src/main.ts's
      // establishP2PWithRetry) also constructing a (TURN-less) connection
      // before the real (TURN-bearing) primary from attempt 2 — see
      // web/src/webrtc.ts's establishWebRTC, which only ever receives TURN
      // servers on the relay-retry attempt. The very first extra-lane offer
      // is exactly the first setRemoteDescription call on such a connection.
      await receiverPage.addInitScript(() => {
        const Native = window.RTCPeerConnection;
        const allPCs: RTCPeerConnection[] = [];
        let primarySeen: RTCPeerConnection | null = null;
        const extraLanePCs = new Set<RTCPeerConnection>();
        let triggered = false;
        function hasTurnServer(config?: RTCConfiguration): boolean {
          for (const server of config?.iceServers ?? []) {
            const urls = Array.isArray(server.urls) ? server.urls : [server.urls];
            if (urls.some(u => typeof u === "string" && u.startsWith("turn:"))) return true;
          }
          return false;
        }
        class AbandoningPeerConnection extends Native {
          constructor(config?: RTCConfiguration) {
            super(config);
            allPCs.push(this);
            if (hasTurnServer(config)) {
              if (!primarySeen) primarySeen = this;
              else extraLanePCs.add(this);
            }
          }
          setRemoteDescription(description: RTCSessionDescriptionInit): Promise<void> {
            const isFirstExtraLaneOffer = extraLanePCs.has(this) && !triggered;
            const result = super.setRemoteDescription(description);
            if (isFirstExtraLaneOffer) {
              triggered = true;
              for (const pc of allPCs) pc.close();
            }
            return result;
          }
        }
        (window as any).RTCPeerConnection = AbandoningPeerConnection;
      });

      await installReceiverSink(receiverPage, "chromium");
      trackForDiagnostics(senderPage, "abandon-sender");
      trackForDiagnostics(receiverPage, "abandon-receiver");

      const code = await chooseFile(senderPage, contents, "relay-abandon.bin");
      await receiverPage.goto(`/r#${code}`);
      await receiverPage.locator(".confirm-btn").click();

      await expect(senderPage.locator(".error-message")).toBeVisible({ timeout: 60_000 });
      const errorSeenAt = Date.now();

      let after!: TurnSnapshot;
      const beforeKeys = new Set(Object.keys(before.users));
      let newKey: string | undefined;
      await expect.poll(() => {
        after = turn.snapshot();
        const newKeys = Object.keys(after.users).filter(k => !beforeKeys.has(k));
        newKey = newKeys[0];
        return { newSessions: newKeys.length, live: newKeys.reduce((sum, k) => sum + after.users[k].live, 0) };
      }, { timeout: Math.max(1000, LEAK_WINDOW_MS - (Date.now() - errorSeenAt)), intervals: [250] }).toEqual({ newSessions: 1, live: 0 });

      const userStats = after.users[newKey!];
      expect(userStats.created).toBe(EXPECTED_ABANDON_CREATED);
      expect(userStats.deleted).toBe(EXPECTED_ABANDON_CREATED);

      writeRelayRecord("abandon-chromium-chromium", {
        lanes: null,
        turn: { created: userStats.created, peakLive: userStats.peakLive, quotaRejected: userStats.quotaRejected },
        relayedBytes: { fromPeers: userStats.relayedBytesFromPeers, toPeers: userStats.relayedBytesToPeers },
        releaseMs: Date.now() - errorSeenAt,
        durationMs: Date.now() - start,
      });
    } finally {
      await Promise.allSettled([senderBrowser.close(), receiverBrowser.close()]);
    }
  });
});

// ── Quota describe block ──────────────────────────────────────────────────

test.describe("relay: quota", () => {
  let turn: TurnHandle;
  test.beforeAll(async ({ relayEnv }) => { turn = await startTurn(relayEnv, 8); });
  test.afterAll(async () => { await turn?.stop(); });

  test("quota degrades gracefully", async ({ playwright, relayEnv }) => {
    const before = turn.snapshot();
    const start = Date.now();

    const senderBrowser = await playwright.chromium.launch(CHROMIUM_LAUNCH);
    const receiverBrowser = await playwright.chromium.launch(CHROMIUM_LAUNCH);
    // Everything from here on is inside try/finally: if any setup call
    // below throws, both browsers must still be closed rather than leaked.
    try {
      const senderPage = await senderBrowser.newPage({ baseURL: relayEnv.url });
      const receiverPage = await receiverBrowser.newPage({ baseURL: relayEnv.url });
      registerDialog(senderPage, true);
      registerDialog(receiverPage, true);
      await installReceiverSink(receiverPage, "chromium");
      trackForDiagnostics(senderPage, "quota8-sender");
      trackForDiagnostics(receiverPage, "quota8-receiver");
      const senderCounts = observeConnections(senderPage);
      const receiverCounts = observeConnections(receiverPage);

      const code = await chooseFile(senderPage, contents, "relay-quota.bin");
      await receiverPage.goto(`/r#${code}`);
      await receiverPage.locator(".confirm-btn").click();
      await expect(senderPage.locator(".complete")).toBeVisible({ timeout: TRANSFER_TIMEOUT_MS });
      await expect(receiverPage.locator(".complete")).toBeVisible({ timeout: TRANSFER_TIMEOUT_MS });

      await verifyReceiverSink(receiverPage, "chromium", contents.length, expectedHash);

      // Structural assertions only — the exact reduced lane count is not
      // hardcoded (see the parent task description): a shared quota of 8
      // allocations for the WHOLE session (both peers combined) cannot
      // cover all 16 that a full 8-lane both-relayed transfer would need,
      // so negotiation must converge on a smaller mutually-agreed count.
      expect(senderCounts.length).toBe(1);
      expect(receiverCounts.length).toBe(1);
      const observedConnections = senderCounts[0];
      expect(observedConnections).toBeGreaterThanOrEqual(1);
      expect(observedConnections).toBeLessThan(LANES);
      expect(receiverCounts[0]).toBe(observedConnections); // mutual agreement

      const { releaseMs, newKey, after } = await pollSessionRelease(turn, before);
      expect(newKey, "no new TURN session key appeared for this transfer").toBeDefined();
      const userStats = after.users[newKey!];
      expect(userStats.created).toBe(8); // capped exactly at the quota
      expect(userStats.quotaRejected).toBeGreaterThan(0);

      writeRelayRecord("quota8-chromium-chromium", {
        lanes: observedConnections,
        turn: { created: userStats.created, peakLive: userStats.peakLive, quotaRejected: userStats.quotaRejected },
        relayedBytes: { fromPeers: userStats.relayedBytesFromPeers, toPeers: userStats.relayedBytesToPeers },
        releaseMs,
        durationMs: Date.now() - start,
      });
    } finally {
      await Promise.allSettled([senderBrowser.close(), receiverBrowser.close()]);
    }
  });
});

// ── Consent describe block ─────────────────────────────────────────────────

test.describe("relay: consent", () => {
  let turn: TurnHandle;
  test.beforeAll(async ({ relayEnv }) => { turn = await startTurn(relayEnv, 0); });
  test.afterAll(async () => { await turn?.stop(); });

  test("both browsers decline consent", async ({ playwright, relayEnv }) => {
    const before = turn.snapshot();

    const senderBrowser = await playwright.chromium.launch(CHROMIUM_LAUNCH);
    const receiverBrowser = await playwright.chromium.launch(CHROMIUM_LAUNCH);
    // Everything from here on is inside try/finally: if any setup call
    // below throws, both browsers must still be closed rather than leaked.
    try {
      const senderPage = await senderBrowser.newPage({ baseURL: relayEnv.url });
      const receiverPage = await receiverBrowser.newPage({ baseURL: relayEnv.url });
      const senderDialogs = registerDialog(senderPage, false);
      const receiverDialogs = registerDialog(receiverPage, false);
      // web/src/main.ts calls showSaveFilePicker() synchronously inside the
      // confirm button's click handler, before the receiver even connects to
      // signaling ("Invoke the picker in the click handler itself, before
      // transient activation expires during ICE/key exchange"). Without this
      // shim, the real (unshimmed) browser API hangs forever in headless
      // Chromium -- there is no display for a native picker to resolve
      // against -- which blocks everything downstream on both pages (the
      // sender waits for the receiver to join, which never happens). Every
      // other test in this suite calls this for its browser receiver(s);
      // this one is declined before any actual file moves, but still needs
      // the shim purely so the confirm click's awaited promise resolves.
      await installReceiverSink(receiverPage, "chromium");
      trackForDiagnostics(senderPage, "consent-both-decline-sender");
      trackForDiagnostics(receiverPage, "consent-both-decline-receiver");

      const code = await chooseFile(senderPage, contents, "relay-consent-both.bin");
      await receiverPage.goto(`/r#${code}`);
      await receiverPage.locator(".confirm-btn").click();

      await expect(senderPage.locator(".error-message")).toBeVisible({ timeout: 60_000 });
      await expect(receiverPage.locator(".error-message")).toBeVisible({ timeout: 60_000 });
      expect(await senderPage.locator(".error-message").textContent()).toBe(DECLINED);
      expect(await receiverPage.locator(".error-message").textContent()).toBe(DECLINED);

      expect(senderDialogs).toEqual([{ type: "confirm", message: RELAY_CONFIRM }]);
      expect(receiverDialogs).toEqual([{ type: "confirm", message: RELAY_CONFIRM }]);

      // Keys are content-addressed hashes of unique session IDs, so a
      // strict "no new key at all" check is exactly equivalent to a
      // created-delta of 0 — this is the simpler one to write correctly.
      const after = turn.snapshot();
      expect(Object.keys(after.users).sort()).toEqual(Object.keys(before.users).sort());

      writeRelayRecord("consent-both-decline", {
        lanes: 0, turn: { created: 0, peakLive: 0, quotaRejected: 0 }, releaseMs: 0, durationMs: 0,
      });
    } finally {
      await Promise.allSettled([senderBrowser.close(), receiverBrowser.close()]);
    }
  });

  test("CLI receiver denies, browser sender declines", async ({ playwright, relayEnv }) => {
    const before = turn.snapshot();

    const senderBrowser = await playwright.chromium.launch(CHROMIUM_LAUNCH);
    // Everything from here on is inside try/finally: if any setup call
    // below throws, the browser and any spawned CLI must still be closed
    // rather than leaked.
    let child: ChildProcess | undefined;
    try {
      const senderPage = await senderBrowser.newPage({ baseURL: relayEnv.url });
      // The dialog handler is registered before navigation, as always. Its
      // decision is a constant .dismiss() regardless of the CLI's timing:
      // web/src/main.ts's confirmRelay() (inside establishP2PWithRetry) is
      // called unconditionally on THIS side's own P2P attempt-1 failure — it
      // never checks the peer's prior response before prompting, so there is
      // no dialog-decision race to gate on a "hasCliDenied" flag here. The
      // ordering this test actually needs — confirming the CLI's own denial
      // landed before asserting the browser's outcome — is enforced below by
      // explicitly awaiting answerRelayPrompt and the CLI's exit/result
      // first, not by conditioning the dialog handler itself.
      const senderDialogs = registerDialog(senderPage, false);
      trackForDiagnostics(senderPage, "consent-cli-deny-sender");

      const xdg = temporaryDirectory("sp2p-relay-xdg-");
      const destDir = temporaryDirectory("sp2p-relay-recv-");

      const code = await chooseFile(senderPage, contents, "relay-consent-cli.bin");
      child = spawn(relayEnv.cliBin, [
        "receive", "-format", "json", "-v", "-allow-relay=false", "-server", relayEnv.wsUrl,
        "-transport", "webrtc", "-output", destDir, code,
      ], { env: { ...process.env, XDG_CONFIG_HOME: xdg } });
      const cli = watchCLI(child);
      trackCLIForDiagnostics(cli, "consent-cli-deny-receiver");

      // Confirmed on real CI (internal/cli/machine.go's finish()): this
      // CLI's own answerRelayPrompt("deny") and the browser sender's
      // independent decline (which notifies the peer as soon as it
      // happens, without waiting to learn the peer's own answer first --
      // see the DECLINED-vs-"Receiver denied" asymmetric-messaging note in
      // the main describe block above) are a genuine, unavoidable race with
      // THREE possible outcomes, not two -- all correct, none hardcoded:
      //  1. this CLI's own answered "deny" resolves first (code
      //     "relay_denied", CLI_DENIED -- what an interactive user would see);
      //  2. the peer's relay-denied signal is observed first
      //     (internal/flow/helpers.go's <-deniedCh case, code
      //     "operation_failed", "Peer denied relay connection"); or
      //  3. the peer's signaling connection is *also* torn down (e.g. the
      //     browser's own decline path closing its page/signaling shortly
      //     after sending relay-denied) and <-peerLeftCh wins the same
      //     select instead (helpers.go has this exact "Peer disconnected"
      //     message at more than one such select, e.g. ~line 108 and ~152)
      //     -- machine.go's finish() falls through to errorCode
      //     "relay_not_allowed" here (relayResponse never got set to
      //     "deny" on this path either, same as case 2, but
      //     snapshot.RelayRequired is true by this point).
      await answerRelayPrompt(cli, "deny");
      expect(await cli.exited).toBe(1);
      const cliResult = cli.results[0];
      expect(cliResult?.outcome).toBe("failed");
      expect([
        { code: "relay_denied", message: CLI_DENIED },
        { code: "operation_failed", message: "Peer denied relay connection" },
        { code: "relay_not_allowed", message: "Peer disconnected" },
      ]).toContainEqual(cliResult?.error);

      await expect(senderPage.locator(".error-message")).toBeVisible({ timeout: 60_000 });
      expect(await senderPage.locator(".error-message").textContent()).toBe(DECLINED);
      expect(senderDialogs).toEqual([{ type: "confirm", message: RELAY_CONFIRM }]);

      const after = turn.snapshot();
      expect(Object.keys(after.users).sort()).toEqual(Object.keys(before.users).sort());

      writeRelayRecord("consent-cli-deny", {
        lanes: 0, turn: { created: 0, peakLive: 0, quotaRejected: 0 }, releaseMs: 0, durationMs: 0,
      });
    } finally {
      child?.kill();
      await senderBrowser.close();
    }
  });
});
