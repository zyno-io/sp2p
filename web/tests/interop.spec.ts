import { spawn } from "child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { test, expect } from "./fixtures";

// ── Browser → Browser ───────────────────────────────────────────────────────

test("browser sender → browser receiver transfers a file", async ({
  browser,
}) => {
  const senderContext = await browser.newContext();
  const senderPage = await senderContext.newPage();
  const receiverContext = await browser.newContext();
  const receiverPage = await receiverContext.newPage();

  try {
    // Create test file content.
    const fileContent = "Browser to browser test content — " + Date.now();

    // Sender: open send page and select file.
    await senderPage.goto("/");
    await senderPage.locator(".file-input").setInputFiles({
      name: "b2b-test.txt",
      mimeType: "text/plain",
      buffer: Buffer.from(fileContent),
    });

    // Wait for transfer code to appear.
    await expect(senderPage.locator(".code-text")).toBeVisible({
      timeout: 10_000,
    });
    const code = await senderPage.locator(".code-text").textContent();
    expect(code).toBeTruthy();

    // Receiver: open receive page with the code.
    await receiverPage.goto(`/r#${code}`);

    // Wait for transfer to complete on both sides.
    await expect(senderPage.locator(".complete")).toBeVisible({
      timeout: 30_000,
    });
    await expect(senderPage.locator(".complete-message")).toContainText(
      "Transfer complete"
    );

    await expect(receiverPage.locator(".complete")).toBeVisible({
      timeout: 30_000,
    });
    await expect(receiverPage.locator(".complete-message")).toContainText(
      "Received b2b-test.txt"
    );

    // Verify connection type indicator.
    await expect(senderPage.locator(".complete-message")).toContainText(
      "WebRTC"
    );
    await expect(receiverPage.locator(".complete-message")).toContainText(
      "WebRTC"
    );

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
    const codeRe = /([23456789a-hj-np-z]{8}#[A-Za-z0-9+/=]+)/;
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
    const downloadPromise = page.waitForEvent("download", { timeout: 30_000 });
    await page.goto(`/r#${code}`);

    // Wait for transfer to complete.
    await expect(page.locator(".complete")).toBeVisible({ timeout: 30_000 });
    await expect(page.locator(".complete-message")).toContainText(
      "Received cli-to-browser.txt"
    );

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
  const fileContent = "Browser to CLI test — " + Date.now();

  // Browser sender: open send page and select file.
  await page.goto("/");
  await page.locator(".file-input").setInputFiles({
    name: "browser-to-cli.txt",
    mimeType: "text/plain",
    buffer: Buffer.from(fileContent),
  });

  // Wait for transfer code.
  await expect(page.locator(".code-text")).toBeVisible({ timeout: 10_000 });
  const code = await page.locator(".code-text").textContent();
  expect(code).toBeTruthy();

  // Start CLI receiver.
  const receiver = spawn(cliBin, ["receive", "-output", tmpDir, code!], {
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
    await expect(page.locator(".complete-message")).toContainText(
      "Transfer complete"
    );

    // Wait for CLI receiver to exit.
    const exitCode = await exitPromise;
    expect(exitCode).toBe(0);

    // Verify received file.
    const received = readFileSync(
      join(tmpDir, "browser-to-cli.txt"),
      "utf-8"
    );
    expect(received).toBe(fileContent);
  } finally {
    receiver.kill();
  }
});
