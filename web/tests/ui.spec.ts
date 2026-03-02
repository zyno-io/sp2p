import { test, expect } from "./fixtures";

test.describe("Send page", () => {
  test("shows drop zone", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".drop-zone")).toBeVisible();
    await expect(page.locator(".drop-zone")).toContainText("Drop files/folders here or click to select");
  });

  test("shows header and subtitle", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("h1")).toContainText("SP2P");
    await expect(page.locator(".subtitle")).toContainText("peer-to-peer");
  });

  test("file input is hidden", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".file-input")).toBeHidden();
  });

  test("steps are initially hidden", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".steps")).toBeHidden();
  });

  test("selecting a file shows steps and hides drop zone", async ({ page }) => {
    await page.goto("/");

    // Set a file via the hidden file input.
    const fileInput = page.locator(".file-input");
    await fileInput.setInputFiles({
      name: "test.txt",
      mimeType: "text/plain",
      buffer: Buffer.from("hello world"),
    });

    // Drop zone should be hidden, steps should be visible.
    await expect(page.locator(".drop-zone")).toBeHidden();
    await expect(page.locator(".steps")).toBeVisible();

    // Should show connecting step.
    await expect(page.locator(".step-connect")).toBeVisible();
  });

  test("selecting a file connects and shows transfer code", async ({ page }) => {
    await page.goto("/");

    const fileInput = page.locator(".file-input");
    await fileInput.setInputFiles({
      name: "test.txt",
      mimeType: "text/plain",
      buffer: Buffer.from("hello world"),
    });

    // Wait for code to appear (server connection + welcome).
    await expect(page.locator(".code-text")).toBeVisible({ timeout: 10_000 });
    const code = await page.locator(".code-text").textContent();
    expect(code).toMatch(/^[23456789a-hj-np-z]{8}#/);

    // URL should also be shown.
    await expect(page.locator(".url-text")).toBeVisible();
    const url = await page.locator(".url-text").textContent();
    expect(url).toContain("/r#");
  });
});

test.describe("Receive page", () => {
  test("shows error when no code in URL", async ({ page }) => {
    await page.goto("/r");
    await expect(page.locator(".error-message")).toBeVisible({ timeout: 5_000 });
    await expect(page.locator(".error-message")).toContainText(
      "No transfer code"
    );
  });

  test("shows steps", async ({ page }) => {
    await page.goto("/r");
    await expect(page.locator(".steps")).toBeVisible();
  });

  test("shows expected step labels", async ({ page }) => {
    // Block app.js so the static HTML step labels stay visible
    // (otherwise JS replaces them with an error before we can check).
    await page.route("**/app.js", (route) => route.abort());
    await page.goto("/r#fakecode#seed");
    await expect(page.locator(".step-connect")).toContainText("Connecting");
    await expect(page.locator(".step-join")).toContainText("Joining");
    await expect(page.locator(".step-crypto")).toContainText("encryption");
    await expect(page.locator(".step-p2p")).toContainText("P2P");
    await expect(page.locator(".step-transfer")).toContainText("Receiving");
  });
});

test.describe("Health and static assets", () => {
  test("health endpoint returns ok", async ({ request }) => {
    const resp = await request.get("/health");
    expect(resp.status()).toBe(200);
    expect(await resp.text()).toBe("ok");
  });

  test("app.js is served", async ({ request }) => {
    const resp = await request.get("/app.js");
    expect(resp.status()).toBe(200);
  });

  test("style.css is served", async ({ request }) => {
    const resp = await request.get("/style.css");
    expect(resp.status()).toBe(200);
  });

  test("unknown path returns 404", async ({ request }) => {
    const resp = await request.get("/does-not-exist");
    expect(resp.status()).toBe(404);
  });

  test("curl user-agent gets plain text script", async ({ request }) => {
    const resp = await request.get("/", {
      headers: { "User-Agent": "curl/7.81" },
    });
    expect(resp.status()).toBe(200);
    const ct = resp.headers()["content-type"] || "";
    expect(ct).toContain("text/plain");
    const body = await resp.text();
    expect(body).toContain("#!/bin/sh");
  });
});
