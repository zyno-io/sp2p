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

    // Wait for the share URL to appear after server registration.
    const shareURL = page.locator(".share-url");
    await expect(shareURL).toBeVisible({ timeout: 10_000 });
    const url = await shareURL.textContent();
    expect(url).not.toBeNull();
    expect(url).toContain("/r#");
    expect(url).toMatch(/\/r#[23456789a-hj-np-z]{8}-.+$/);
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
    // Block the hashed JavaScript bundle so the static HTML step labels stay
    // visible (otherwise JS replaces them with an error before we can check).
    await page.route("**/*.js", (route) => route.abort());
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

  test("built JavaScript asset is served", async ({ request }) => {
    const indexResponse = await request.get("/", {
      headers: { Accept: "text/html" },
    });
    expect(indexResponse.status()).toBe(200);
    const html = await indexResponse.text();
    const scriptMatch = html.match(/<script src="([^"?]+\.js)"><\/script>/);
    expect(scriptMatch).not.toBeNull();

    const assetResponse = await request.get(`/${scriptMatch![1]}`);
    expect(assetResponse.status()).toBe(200);
  });

  test("built stylesheet asset is served", async ({ request }) => {
    const indexResponse = await request.get("/", {
      headers: { Accept: "text/html" },
    });
    expect(indexResponse.status()).toBe(200);
    const html = await indexResponse.text();
    const stylesheetMatch = html.match(/<link rel="stylesheet" href="([^"?]+\.css)">/);
    expect(stylesheetMatch).not.toBeNull();

    const assetResponse = await request.get(`/${stylesheetMatch![1]}`);
    expect(assetResponse.status()).toBe(200);
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
