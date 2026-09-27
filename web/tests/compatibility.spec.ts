// SPDX-License-Identifier: MIT

import { execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import type { Page } from "@playwright/test";
import { test, expect } from "./fixtures";
import {
  chooseFile, cleanupTemporaryDirectories, isolatedServerTest, observeConnections,
  receiveToDisk, temporaryDirectory, verifyDisk, watchCLI,
} from "./helpers";

// Serves a built web/dist directory (any release's, including the current
// one) over routes the app actually requests, instead of Playwright's normal
// webServer. Used for both the pinned v0.4.0/v0.5.0 fixtures above and the
// resolved-at-runtime "previous release" fixture below.
async function serveLegacyBrowser(page: Page, dir: string): Promise<void> {
  // Intercepted HTML has no network address-space provenance in Chromium.
  // Allow this isolated test context to reach its real loopback signaling server.
  await page.context().grantPermissions(["local-network-access"]);
  // Exercise the old browser's memory-download path, not a native save dialog.
  await page.addInitScript(() => {
    delete (window as any).showSaveFilePicker;
  });
  await page.route("**/*", async route => {
    const path = new URL(route.request().url()).pathname;
    let file: string | undefined;
    if (path === "/") file = "index.html";
    else if (path === "/r") file = "receive.html";
    else if (/^\/(?:assets\/)?(?:main-.*\.js|style-.*\.css)$/.test(path)) file = basename(path);
    if (!file) { await route.continue(); return; }
    const contentType = file.endsWith(".html") ? "text/html" : file.endsWith(".css") ? "text/css" : "application/javascript";
    await route.fulfill({status:200,contentType,body:readFileSync(join(dir,file))});
  });
}

// Confirms the page actually loaded the bundle from `dir`, not the live app
// on a route-interception miss in serveLegacyBrowser (e.g. a regex that no
// longer matches a renamed asset) — a miss would otherwise silently test
// new-vs-new instead of old/previous-vs-new, and nothing else here would
// notice.
async function assertBundleIdentity(page: Page, dir: string): Promise<void> {
  const src = await page.locator('script[src*="main-"]').getAttribute("src");
  if (!src) throw new Error("page has no main-*.js script tag to check");
  const expected = readdirSync(dir).find(file => /^main-.*\.js$/.test(file));
  expect(basename(src)).toBe(expected);
}

for (const [oldCLI,oldBrowser,oldProtocol] of [[false,false,3],[true,false,2],[false,true,2],[true,false,3],[false,true,3]] as const) {
  const oldBinary = oldProtocol === 3 ? process.env.SP2P_TEST_V3_BINARY : process.env.SP2P_TEST_LEGACY_BINARY;
  const oldWeb = oldProtocol === 3 ? process.env.SP2P_TEST_V3_WEB_DIR : process.env.SP2P_TEST_LEGACY_WEB_DIR;
  const version = oldProtocol === 3 ? "original 0.5.0" : "0.4.0";
  test.describe(oldBrowser ? `cached ${version} browser compatibility` : oldCLI ? `${version} CLI compatibility` : "automatic v3 negotiation", () => {
    test.skip(oldCLI && !oldBinary, `Configure an unmodified ${version} CLI fixture`);
    test.skip(oldBrowser && !oldWeb, `Configure an unmodified ${version} web fixture`);

    const protocol = oldCLI || oldBrowser ? oldProtocol : 3;

    test("browser sends automatically beyond a v3 credit window", async ({page,cliBin,wsUrl}) => {
      const dest = mkdtempSync(join(tmpdir(),"sp2p-legacy-browser-"));
      const content = Buffer.alloc(5*1024*1024,65);
      if (oldBrowser) await serveLegacyBrowser(page, oldWeb!);
      await page.goto("/?protocol=2"); // URL parameters cannot force a downgrade.
      if (oldBrowser) await assertBundleIdentity(page, oldWeb!);
      if (!oldBrowser) {
        await expect(page.locator(".legacy-protocol")).toHaveCount(0);
        await expect(page.locator(".legacy-warning")).toBeHidden();
      }
      await page.locator(".file-input").setInputFiles({name:"legacy.bin",mimeType:"application/octet-stream",buffer:content});
      await expect(page.locator(".share-url")).toBeVisible();
      if (!oldBrowser) {
        await expect(page.locator(".share-cli")).not.toContainText("-protocol");
      }
      const share = await page.locator(".share-url").textContent();
      const code = new URL(share!).hash.slice(1);
      const args = ["receive","-format","json","-server",wsUrl,"-output",dest];
      args.push(code);
      const cli = spawn(oldCLI ? oldBinary! : cliBin,args);
      let output = "";
      cli.stdout.on("data",chunk=>{output += chunk;});
      cli.stderr.on("data",chunk=>{output += chunk;});
      const exited = new Promise<number|null>((resolve,reject)=>{cli.once("error",reject);cli.once("exit",resolve);});
      try {
        await expect(page.locator(".complete")).toBeVisible({timeout:30000});
        const status = await exited;
        expect(status,output).toBe(0);
        expect(readFileSync(join(dest,"legacy.bin"))).toEqual(content);
        if (!oldCLI) {
          expect(output).toContain(`"event":"protocol","protocol":${protocol}`);
          expect(output.includes('"event":"warning"')).toBe(protocol === 2);
        }
        if (!oldBrowser && protocol === 2) await expect(page.locator(".legacy-warning")).toBeVisible();
        if (!oldBrowser && protocol === 3) await expect(page.locator(".legacy-warning")).toBeHidden();
      } finally { cli.kill(); }
    });

    test("browser receives on the first attempt without version selection", async ({page,cliBin,wsUrl}) => {
      const src = join(mkdtempSync(join(tmpdir(),"sp2p-legacy-cli-")),"legacy.bin");
      const content = Buffer.alloc(5*1024*1024,66);
      writeFileSync(src,content);
      const args = ["send","-format","json","-server",wsUrl,"-compress","3"];
      args.push(src);
      const cli = spawn(oldCLI ? oldBinary! : cliBin,args);
      let output = "", pending = "";
      const codeReady = new Promise<string>((resolve,reject)=>{
        cli.once("error",reject);
        cli.stdout.on("data",chunk=>{
          output += chunk; pending += chunk;
          for (;;) {
            const end = pending.indexOf("\n");
            if (end < 0) break;
            const line = pending.slice(0,end); pending = pending.slice(end+1);
            const event = JSON.parse(line);
            if (event.event === "session") resolve(event.code);
          }
        });
        cli.once("exit",()=>reject(new Error(`CLI exited before session: ${output}`)));
      });
      cli.stderr.on("data",chunk=>{output += chunk;});
      const exited = new Promise<number|null>((resolve,reject)=>{cli.once("error",reject);cli.once("exit",resolve);});
      try {
        const code = await codeReady;
        await page.addInitScript(() => { delete (window as any).showSaveFilePicker; });
        if (oldBrowser) await serveLegacyBrowser(page, oldWeb!);
        await page.goto(`/r#${code}`);
        if (oldBrowser) await assertBundleIdentity(page, oldWeb!);
        if (!oldBrowser) {
          await expect(page.locator(".legacy-protocol")).toHaveCount(0);
          await expect(page.locator(".confirm-cli")).not.toContainText("-protocol");
        }
        const downloaded = page.waitForEvent("download");
        await page.locator(".confirm-btn").click();
        await expect(page.locator(".complete")).toBeVisible({timeout:30000});
        const download = await downloaded;
        const path = await download.path();
        expect(path).not.toBeNull();
        expect(readFileSync(path!)).toEqual(content);
        const status = await exited;
        expect(status,output).toBe(0);
        if (!oldCLI) expect(output).toContain(`"event":"protocol","protocol":${protocol}`);
        if (!oldBrowser && protocol === 2) await expect(page.locator(".legacy-warning")).toBeVisible();
        if (!oldBrowser && protocol === 3) await expect(page.locator(".legacy-warning")).toBeHidden();
      } finally { cli.kill(); }
    });
  });
}

// ── Previous-release compatibility (resolved at CI/nightly time) ───────────
//
// Driven entirely by env vars plus testdata/release-capabilities.json, never
// a hardcoded version: SP2P_TEST_PREVIOUS_BINARY (CLI), SP2P_TEST_PREVIOUS_WEB_DIR
// (a built web/dist), SP2P_TEST_PREVIOUS_VERSION (its plain vX.Y.Z version,
// without the "v"). ci.yml's protocol-compatibility job points these at the
// resolved N-1 release; nightly.yml's compat-n2 job points them at N-2 — this
// file doesn't know or care which. Unset any of the three and every test
// below skips cleanly.
//
// All six pairings run at 64 MiB (PARALLEL_MIN_BYTES in
// web/src/webrtc-parallel.ts, parallelMinFileSize in internal/flow/send.go
// and receive.go) so both a browser sender and a previous-release CLI sender
// in auto mode actually request more than one WebRTC lane — anything smaller
// silently tests only the single-lane path (see webrtc-lanes in
// internal/compatibility_test.go for the equivalent CLI<->CLI coverage).
// This describe block gets its own isolated signaling server (helpers.ts
// isolatedServerTest, worker-scoped so all tests below share one instance)
// instead of the shared server other spec files' tests run against, to stay
// well under its per-minute connection rate limit.

interface ReleaseCapabilities { protocol: number; webrtcLanes: number; }

// Fails closed: an unlisted version fails the test rather than silently
// assuming a default lane cap — mirrors previousReleaseCapabilities in
// internal/compatibility_test.go.
function releaseCapabilities(version: string): ReleaseCapabilities {
  const path = join(__dirname, "..", "..", "testdata", "release-capabilities.json");
  const table = JSON.parse(readFileSync(path, "utf8")) as Record<string, ReleaseCapabilities>;
  const caps = table[version];
  if (!caps) throw new Error(`no release-capabilities.json entry for version ${JSON.stringify(version)}; add one before testing against it`);
  return caps;
}

// Both sides skip parallel WebRTC negotiation entirely whenever the
// negotiated count is 1 (negotiateParallelWebRTC in webrtc-parallel.ts,
// negotiateWebRTC in webrtc_parallel.go both short-circuit before ever
// logging/reporting a lane count), which is exactly a webrtcLanes cap of 1 —
// e.g. a pre-v3 previous release such as v0.4.0. Gating on webrtcLanes
// directly (rather than protocol) matches that real mechanism, not just
// today's correlation between "protocol 2" and "webrtcLanes 1".
function expectedLaneCounts(caps: ReleaseCapabilities): number[] {
  return caps.webrtcLanes <= 1 ? [] : [Math.min(8, caps.webrtcLanes)];
}

const prevBinary = process.env.SP2P_TEST_PREVIOUS_BINARY;
const prevWebDir = process.env.SP2P_TEST_PREVIOUS_WEB_DIR;
const prevVersion = process.env.SP2P_TEST_PREVIOUS_VERSION;
const prevReady = Boolean(prevBinary && prevWebDir && prevVersion);
const prevCaps = prevReady ? releaseCapabilities(prevVersion!) : undefined;

isolatedServerTest.describe("previous release", () => {
  isolatedServerTest.skip(!prevReady,
    "Configure SP2P_TEST_PREVIOUS_BINARY, SP2P_TEST_PREVIOUS_WEB_DIR, and SP2P_TEST_PREVIOUS_VERSION for previous-release compatibility tests");
  isolatedServerTest.setTimeout(90000);

  // Incompressible content, like parallel-interop.spec.ts, so a compression
  // bug can't hide inside a lucky ratio on repetitive test data.
  const large = randomBytes(64 * 1024 * 1024);
  const largeHash = createHash("sha256").update(large).digest("hex");

  isolatedServerTest.afterEach(() => { cleanupTemporaryDirectories(); });

  isolatedServerTest("previous-release CLI reports the expected version", async () => {
    const output = execFileSync(prevBinary!, ["version"]).toString();
    expect(output).toContain(prevVersion!);
  });

  isolatedServerTest("new browser sender interoperates with previous-release CLI receiver", async ({ page, wsUrl }) => {
    const counts = observeConnections(page);
    const code = await chooseFile(page, large, "prev-release.bin");
    const dest = temporaryDirectory("sp2p-prev-recv-");
    const child = spawn(prevBinary!, ["receive", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-output", dest, code]);
    const cli = watchCLI(child);
    try {
      await expect(page.locator(".complete")).toBeVisible({ timeout: 60000 });
      const status = await cli.exited;
      expect(status).toBe(0);
      expect(counts).toEqual(expectedLaneCounts(prevCaps!));
      expect(cli.counts).toEqual(expectedLaneCounts(prevCaps!));
      const received = readFileSync(join(dest, "prev-release.bin"));
      expect(createHash("sha256").update(received).digest("hex")).toBe(largeHash);
    } finally { child.kill(); }
  });

  isolatedServerTest("previous-release CLI sender interoperates with new browser receiver", async ({ page, wsUrl }) => {
    const counts = observeConnections(page);
    await receiveToDisk(page);
    const src = join(temporaryDirectory("sp2p-prev-send-"), "prev-release.bin");
    writeFileSync(src, large);
    const child = spawn(prevBinary!, ["send", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-compress", "0", src]);
    const cli = watchCLI(child);
    try {
      const code = await cli.code;
      await page.goto(`/r#${code}`);
      await page.locator(".confirm-btn").click();
      await expect(page.locator(".complete")).toBeVisible({ timeout: 60000 });
      const status = await cli.exited;
      expect(status).toBe(0);
      expect(counts).toEqual(expectedLaneCounts(prevCaps!));
      expect(cli.counts).toEqual(expectedLaneCounts(prevCaps!));
      await verifyDisk(page, large.length, largeHash);
    } finally { child.kill(); }
  });

  isolatedServerTest("previous-release browser sender interoperates with new CLI receiver", async ({ page, cliBin, wsUrl }) => {
    const dest = temporaryDirectory("sp2p-prev-recv-");
    await serveLegacyBrowser(page, prevWebDir!);
    const code = await chooseFile(page, large, "prev-release.bin");
    await assertBundleIdentity(page, prevWebDir!);
    const child = spawn(cliBin, ["receive", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-output", dest, code]);
    const cli = watchCLI(child);
    try {
      await expect(page.locator(".complete")).toBeVisible({ timeout: 60000 });
      const status = await cli.exited;
      expect(status).toBe(0);
      expect(cli.counts).toEqual(expectedLaneCounts(prevCaps!));
      const received = readFileSync(join(dest, "prev-release.bin"));
      expect(createHash("sha256").update(received).digest("hex")).toBe(largeHash);
    } finally { child.kill(); }
  });

  isolatedServerTest("new CLI sender interoperates with previous-release browser receiver", async ({ page, cliBin, wsUrl }) => {
    const src = join(temporaryDirectory("sp2p-prev-send-"), "prev-release.bin");
    writeFileSync(src, large);
    await serveLegacyBrowser(page, prevWebDir!);
    await receiveToDisk(page);
    const child = spawn(cliBin, ["send", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-compress", "0", src]);
    const cli = watchCLI(child);
    try {
      const code = await cli.code;
      await page.goto(`/r#${code}`);
      await assertBundleIdentity(page, prevWebDir!);
      await page.locator(".confirm-btn").click();
      await expect(page.locator(".complete")).toBeVisible({ timeout: 60000 });
      const status = await cli.exited;
      expect(status).toBe(0);
      expect(cli.counts).toEqual(expectedLaneCounts(prevCaps!));
      await verifyDisk(page, large.length, largeHash);
    } finally { child.kill(); }
  });

  // Both directions share one test/one pair of pages (rather than four page
  // launches across two tests) since standing up two 64 MiB WebRTC browser
  // transfers is the most expensive pairing here.
  isolatedServerTest("previous-release and new browsers interoperate in both directions", async ({ browser, baseURL }) => {
    const newPage = await browser.newPage({ baseURL });
    const prevPage = await browser.newPage({ baseURL });
    await serveLegacyBrowser(prevPage, prevWebDir!);
    try {
      { // new browser -> previous-release browser
        const newCounts = observeConnections(newPage), prevCounts = observeConnections(prevPage);
        await receiveToDisk(prevPage);
        const code = await chooseFile(newPage, large, "prev-release-a.bin");
        await prevPage.goto(`/r#${code}`);
        await assertBundleIdentity(prevPage, prevWebDir!);
        await prevPage.locator(".confirm-btn").click();
        await expect(newPage.locator(".complete")).toBeVisible({ timeout: 60000 });
        await expect(prevPage.locator(".complete")).toBeVisible({ timeout: 60000 });
        expect(newCounts).toEqual(expectedLaneCounts(prevCaps!));
        expect(prevCounts).toEqual(expectedLaneCounts(prevCaps!));
        await verifyDisk(prevPage, large.length, largeHash);
      }
      { // previous-release browser -> new browser (fresh content, since
        // prevPage now switches roles from receiver to sender)
        const other = randomBytes(64 * 1024 * 1024);
        const otherHash = createHash("sha256").update(other).digest("hex");
        const newCounts = observeConnections(newPage), prevCounts = observeConnections(prevPage);
        await receiveToDisk(newPage);
        const code = await chooseFile(prevPage, other, "prev-release-b.bin");
        await assertBundleIdentity(prevPage, prevWebDir!);
        await newPage.goto(`/r#${code}`);
        await newPage.locator(".confirm-btn").click();
        await expect(prevPage.locator(".complete")).toBeVisible({ timeout: 60000 });
        await expect(newPage.locator(".complete")).toBeVisible({ timeout: 60000 });
        expect(prevCounts).toEqual(expectedLaneCounts(prevCaps!));
        expect(newCounts).toEqual(expectedLaneCounts(prevCaps!));
        await verifyDisk(newPage, other.length, otherHash);
      }
    } finally { await newPage.close(); await prevPage.close(); }
  });

  // Cheap sanity check below the 64 MiB parallel-lane threshold: proves basic
  // cross-release compatibility (handshake, protocol negotiation, single-lane
  // transfer) without another 64 MiB buffer and CLI process — the cases above
  // already cover lane negotiation.
  isolatedServerTest("previous-release CLI sender interoperates with new browser receiver, small file", async ({ page, wsUrl }) => {
    const small = randomBytes(5 * 1024 * 1024);
    const smallHash = createHash("sha256").update(small).digest("hex");
    await receiveToDisk(page);
    const src = join(temporaryDirectory("sp2p-prev-send-small-"), "prev-release-small.bin");
    writeFileSync(src, small);
    const child = spawn(prevBinary!, ["send", "-format", "json", "-server", wsUrl, "-transport", "webrtc", "-compress", "0", src]);
    const cli = watchCLI(child);
    try {
      const code = await cli.code;
      await page.goto(`/r#${code}`);
      await page.locator(".confirm-btn").click();
      await expect(page.locator(".complete")).toBeVisible({ timeout: 30000 });
      const status = await cli.exited;
      expect(status).toBe(0);
      await verifyDisk(page, small.length, smallHash);
    } finally { child.kill(); }
  });
});
