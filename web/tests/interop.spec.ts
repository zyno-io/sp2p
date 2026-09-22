import { spawn } from "child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { createHash } from "node:crypto";
import { test, expect } from "./fixtures";

async function extractCodeFromShareUrl(page: { locator: (selector: string) => any }): Promise<string> {
  const shareUrl = page.locator(".share-url");
  await expect(shareUrl).toBeVisible({ timeout: 10_000 });
  const text = await shareUrl.textContent();
  expect(text).toBeTruthy();
  return new URL(text!).hash.slice(1);
}

async function maybeConfirmBrowserDownload(page: { locator: (selector: string) => any }): Promise<void> {
  const confirmButton = page.locator(".confirm-btn");
  try {
    await confirmButton.click({ timeout: 5_000 });
  } catch {
    // Some flows may not show the confirmation card if file-info is unavailable.
  }
}

// ── Browser → Browser ───────────────────────────────────────────────────────

test("browser sender → browser receiver transfers a file", async ({
  browser,
}) => {
  const senderContext = await browser.newContext();
  const senderPage = await senderContext.newPage();
  const receiverContext = await browser.newContext();
  const receiverPage = await receiverContext.newPage();
  if (process.env.SP2P_TEST_WEBRTC_DEBUG === "1") {
    for (const [role, page] of [["sender", senderPage], ["receiver", receiverPage]] as const) {
      page.on("console", message => {
        if (message.text().includes("WebRTC:")) console.log(`${role}: ${message.text()}`);
      });
    }
  }
  await receiverPage.addInitScript(() => { delete (window as any).showSaveFilePicker; });

  try {
    // Exercise a full protocol chunk, which may exceed the DataChannel's
    // negotiated message limit after encryption and framing.
    const fileContent = Buffer.alloc(256 * 1024, "B");

    // Sender: open send page and select file.
    await senderPage.goto("/");
    await senderPage.locator(".file-input").setInputFiles({
      name: "b2b-test.txt",
      mimeType: "text/plain",
      buffer: Buffer.from(fileContent),
    });

    // Wait for transfer link to appear and extract the code.
    const code = await extractCodeFromShareUrl(senderPage);
    expect(code).toBeTruthy();

    // Receiver: open receive page with the code.
    await receiverPage.goto(`/r#${code}`);
    await maybeConfirmBrowserDownload(receiverPage);

    // Wait for transfer to complete on both sides.
    await expect(senderPage.locator(".complete")).toBeVisible({
      timeout: 30_000,
    });
    await expect(senderPage.locator(".complete-title")).toContainText("Sent");
    await expect(senderPage.locator(".complete-name")).toContainText("b2b-test.txt");

    await expect(receiverPage.locator(".complete")).toBeVisible({
      timeout: 30_000,
    });
    await expect(receiverPage.locator(".complete-title")).toContainText("Received");
    await expect(receiverPage.locator(".complete-name")).toContainText("b2b-test.txt");

    // Verify step indicators show done.
    await expect(senderPage.locator(".step-p2p")).toContainText(
      "P2P connected via WebRTC"
    );
    await expect(receiverPage.locator(".step-p2p")).toContainText(
      "P2P connected via WebRTC"
    );
  } finally {
    await senderContext.close();
    await receiverContext.close();
  }
});

// ── CLI → Browser ───────────────────────────────────────────────────────────

test("active browser transfer removes commands and reports sending and connection stages", async ({ browser }) => {
  const sender = await browser.newPage();
  const receiver = await browser.newPage();
  const stages: string[] = [];
  sender.on("console", message => { if (message.text().includes("WebRTC:")) stages.push(message.text()); });
  await receiver.addInitScript(() => {
    const chunks: Uint8Array[] = [];
    (window as any).showSaveFilePicker = async () => ({
      createWritable: async () => ({
        write: async (chunk: Uint8Array) => {
          if (!chunks.length) await new Promise<void>(resolve => { (window as any).__releaseSink = resolve; });
          chunks.push(chunk.slice());
        },
        close: async () => {
          const blob = new Blob(chunks);
          const bytes = await blob.arrayBuffer();
          const hash = await crypto.subtle.digest("SHA-256", bytes);
          (window as any).__receivedHash = Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, "0")).join("");
        },
        abort: async () => {},
      }),
    });
    (window as any).__p2pStages = [];
    new MutationObserver(() => {
      const text = document.querySelector(".step-p2p")?.textContent;
      if (text) (window as any).__p2pStages.push(text);
    }).observe(document, { subtree: true, childList: true, characterData: true });
  });
  try {
    const content = Buffer.alloc(6 * 1024 * 1024, "W");
    await sender.goto("/");
    await sender.locator(".file-input").setInputFiles({ name: "window.bin", mimeType: "application/octet-stream", buffer: content });
    const code = await extractCodeFromShareUrl(sender);
    await receiver.goto(`/r#${code}`);
    await receiver.locator(".confirm-btn").click();
    await receiver.waitForFunction(() => typeof (window as any).__releaseSink === "function");
    await expect(sender.locator(".status-text")).toHaveText("Sending file...");
    await expect(sender.locator(".share-display")).toHaveCount(0);
    await expect(receiver.locator(".confirm-transfer, .confirm-cli, .confirm-curl, .confirm-wget, .confirm-powershell")).toHaveCount(0);
    const observed: string[] = await receiver.evaluate(() => (window as any).__p2pStages);
    expect(observed.some(stage => stage.includes("Establishing P2P connection —"))).toBe(true);
    expect(stages.some(stage => stage.includes("Waiting for receiver's answer"))).toBe(true);
    // Let the receiver continue while the sender's page has focus.
    await sender.bringToFront();
    await receiver.evaluate(() => (window as any).__releaseSink());
    await expect(receiver.locator(".complete")).toBeVisible();
    await expect(sender.locator(".complete")).toBeVisible();
    const hash = await receiver.evaluate(() => (window as any).__receivedHash);
    expect(hash).toBe(createHash("sha256").update(content).digest("hex"));
  } finally {
    await sender.close();
    await receiver.close();
  }
});

test("CLI sender → browser receiver transfers a file", async ({
  page,
  cliBin,
  wsUrl,
}) => {
  const tmpDir = mkdtempSync(join(tmpdir(), "sp2p-pw-cli-"));
  const srcFile = join(tmpDir, "cli-to-browser.txt");
  const fileContent = "CLI to browser test — " + Date.now();
  writeFileSync(srcFile, fileContent);

  // Start CLI sender.
  const sender = spawn(cliBin, ["send", srcFile], {
    env: {
      ...process.env,
      SP2P_SERVER: wsUrl,
      SP2P_URL: "http://localhost:18090",
    },
  });

  // Extract code from sender's stderr.
  const code = await new Promise<string>((resolve, reject) => {
    const codeRe = /sp2p receive ([A-Za-z0-9-]+)/;
    let output = "";
    const timer = setTimeout(() => {
      sender.kill();
      reject(new Error(`Timeout waiting for code.\nstderr: ${output}`));
    }, 15_000);

    sender.stderr?.on("data", (chunk: Buffer) => {
      output += chunk.toString();
      const match = codeRe.exec(output);
      if (match) {
        clearTimeout(timer);
        resolve(match[1]);
      }
    });

    sender.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });

  try {
    // Browser receiver: navigate to receive page with the code.
    // Set up download listener before navigating.
    await page.addInitScript(() => { delete (window as any).showSaveFilePicker; });
    const downloadPromise = page.waitForEvent("download", { timeout: 30_000 });
    await page.goto(`/r#${code}`);
    await maybeConfirmBrowserDownload(page);

    // Wait for transfer to complete.
    await expect(page.locator(".complete")).toBeVisible({ timeout: 30_000 });
    await expect(page.locator(".complete-title")).toContainText("Received");
    await expect(page.locator(".complete-name")).toContainText("cli-to-browser.txt");

    // Verify the download was triggered.
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe("cli-to-browser.txt");

    // Read download content and verify.
    const downloadPath = await download.path();
    if (downloadPath) {
      const downloadedContent = readFileSync(downloadPath, "utf-8");
      expect(downloadedContent).toBe(fileContent);
    }
  } finally {
    sender.kill();
  }
});

// ── Browser → CLI ───────────────────────────────────────────────────────────

test("browser sender → CLI receiver transfers a file", async ({
  page,
  cliBin,
  wsUrl,
}) => {
  const tmpDir = mkdtempSync(join(tmpdir(), "sp2p-pw-cli-"));
  // This spans multiple responsive browser send chunks and verifies that the
  // CLI accepts the complete encrypted transfer.
  const fileContent = Buffer.alloc(256 * 1024, "B");

  // Browser sender: open send page and select file.
  await page.goto("/");
  await page.locator(".file-input").setInputFiles({
    name: "browser-to-cli.txt",
    mimeType: "text/plain",
    buffer: Buffer.from(fileContent),
  });

  // Wait for transfer link and extract the code.
  const code = await extractCodeFromShareUrl(page);
  expect(code).toBeTruthy();

  // Start CLI receiver.
  const receiver = spawn(cliBin, ["receive", "-output", tmpDir, code], {
    env: { ...process.env, SP2P_SERVER: wsUrl },
  });

  let receiverStderr = "";
  receiver.stderr?.on("data", (chunk: Buffer) => {
    receiverStderr += chunk.toString();
  });

  // Set up exit promise early so we don't miss the event.
  const exitPromise = new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => {
      receiver.kill();
      reject(
        new Error(
          `CLI receiver timed out.\nstderr: ${receiverStderr}`
        )
      );
    }, 30_000);
    receiver.on("exit", (code) => {
      clearTimeout(timer);
      resolve(code ?? 1);
    });
  });

  try {
    // Wait for transfer to complete on the browser side.
    await expect(page.locator(".complete")).toBeVisible({ timeout: 30_000 });
    await expect(page.locator(".complete-title")).toContainText("Sent");
    await expect(page.locator(".complete-name")).toContainText("browser-to-cli.txt");

    // Wait for CLI receiver to exit.
    const exitCode = await exitPromise;
    expect(exitCode).toBe(0);

    // Verify received file.
    const received = readFileSync(join(tmpDir, "browser-to-cli.txt"));
    expect(received.equals(fileContent)).toBe(true);
  } finally {
    receiver.kill();
  }
});
