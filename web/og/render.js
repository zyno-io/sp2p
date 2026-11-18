// SPDX-License-Identifier: MIT
// Renders og-image.html to og-image.png (the Open Graph share image).
// Usage (from web/): node og/render.js
const path = require("path");
const { chromium } = require("playwright");

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1200, height: 630 } });
  await page.goto("file://" + path.join(__dirname, "og-image.html"));
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: path.join(__dirname, "og-image.png") });
  await browser.close();
})();
