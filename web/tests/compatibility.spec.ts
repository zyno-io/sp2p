// SPDX-License-Identifier: MIT

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import type { Page } from "@playwright/test";
import { test, expect } from "./fixtures";

async function serveLegacyBrowser(page: Page): Promise<void> {
  const dir = process.env.SP2P_TEST_LEGACY_WEB_DIR!;
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

for (const [oldCLI,oldBrowser] of [[false,false],[true,false],[false,true]]) {
  test.describe(oldBrowser ? "cached 0.4.0 browser compatibility" : oldCLI ? "0.4.0 CLI compatibility" : "automatic v3 negotiation", () => {
    test.skip(oldCLI && !process.env.SP2P_TEST_LEGACY_BINARY, "Set SP2P_TEST_LEGACY_BINARY to an unmodified v0.4.0 CLI");
    test.skip(oldBrowser && !process.env.SP2P_TEST_LEGACY_WEB_DIR, "Set SP2P_TEST_LEGACY_WEB_DIR to web/dist built from v0.4.0");

    const protocol = oldCLI || oldBrowser ? 2 : 3;

    test("browser sends automatically beyond a v3 credit window", async ({page,cliBin,wsUrl}) => {
      const dest = mkdtempSync(join(tmpdir(),"sp2p-legacy-browser-"));
      const content = Buffer.alloc(5*1024*1024,65);
      if (oldBrowser) await serveLegacyBrowser(page);
      await page.goto("/?protocol=2"); // URL parameters cannot force a downgrade.
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
      const cli = spawn(oldCLI ? process.env.SP2P_TEST_LEGACY_BINARY! : cliBin,args);
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
      const cli = spawn(oldCLI ? process.env.SP2P_TEST_LEGACY_BINARY! : cliBin,args);
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
        if (oldBrowser) await serveLegacyBrowser(page);
        await page.goto(`/r#${code}`);
        if (!oldBrowser) {
          await expect(page.locator(".legacy-protocol")).toHaveCount(0);
          await expect(page.locator(".confirm-cli")).not.toContainText("-protocol");
        }
        const downloaded = page.waitForEvent("download");
        await page.locator(".memory-download-btn, .confirm-btn").last().click();
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
