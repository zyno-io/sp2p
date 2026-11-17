import { test, expect } from "./fixtures";

test.describe("Send page", () => {
  test("shows drop zone", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".drop-zone")).toBeVisible();
    await expect(page.locator(".drop-zone")).toContainText("Drop files or folders here, or click to select");
  });

  test("shows header and subtitle", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("h1")).toHaveText("sp2p");
    await expect(page.locator(".subtitle")).toContainText("peer-to-peer");
  });

  test("file input is hidden", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".file-input")).toBeHidden();
  });

  test("shows AI-agent prompts in the initially selected tab", async ({ page }) => {
    await page.goto("/");
    const agentGuide = new URL("/llm", page.url()).href;
    const agentTab = page.getByRole("tab", { name: "AI agent" });
    await expect(agentTab).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("tabpanel", { name: "AI agent" })).toContainText(
      `Please send [file] using ${agentGuide}`
    );
    await expect(page.locator(".agent-rsync-prompt")).toContainText(agentGuide);
    await expect(page.locator(".agent-tunnel-prompt")).toContainText(
      `Please forward [TCP or Unix target endpoint] to [TCP or Unix local listener endpoint] using ${agentGuide}`
    );
    await expect(page.locator('.agent-section a[href="/llm"]')).toBeVisible();
  });

  test("selects usage tabs by click and roving keyboard focus", async ({ page }) => {
    await page.goto("/");

    const agentTab = page.getByRole("tab", { name: "AI agent" });
    const rsyncTab = page.getByRole("tab", { name: "rsync" });
    const tunnelTab = page.getByRole("tab", { name: "Tunnels" });

    await rsyncTab.click();
    await expect(rsyncTab).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("tabpanel", { name: "rsync" })).toBeVisible();
    await expect(page.getByRole("tabpanel", { name: "AI agent" })).toBeHidden();
    await expect(agentTab).toHaveAttribute("tabindex", "-1");

    await rsyncTab.press("ArrowRight");
    await expect(tunnelTab).toBeFocused();
    await expect(tunnelTab).toHaveAttribute("aria-selected", "true");
    await tunnelTab.press("ArrowRight");
    await expect(agentTab).toBeFocused();
    await expect(agentTab).toHaveAttribute("aria-selected", "true");
    await agentTab.press("End");
    await expect(tunnelTab).toBeFocused();
    await expect(tunnelTab).toHaveAttribute("aria-selected", "true");
    await tunnelTab.press("Home");
    await expect(agentTab).toBeFocused();
    await expect(agentTab).toHaveAttribute("aria-selected", "true");
  });

  test("uses the current origin and placeholders in rsync and tunnel commands", async ({ page }) => {
    await page.goto("/");
    const origin = new URL(page.url()).origin;

    await page.getByRole("tab", { name: "rsync" }).click();
    await expect(page.locator(".rsync-send-command")).toHaveText(
      `sp2p rsync send --server ${origin} -- -av --partial ./photos/ sp2p::share/`
    );
    await expect(page.locator(".rsync-recv-command")).toHaveText(
      `sp2p rsync recv --server ${origin} CODE ./backup`
    );
    await expect(page.getByRole("tabpanel", { name: "rsync" })).toContainText(
      "create ./backup"
    );
    await expect(page.locator(".rsync-serve-command")).toHaveText(
      `sp2p rsync send --server ${origin} ./photos`
    );
    await expect(page.locator(".rsync-download-command")).toHaveText(
      `sp2p rsync recv --server ${origin} CODE -- -av --partial sp2p::share/ ./photos/`
    );

    await page.getByRole("tab", { name: "Tunnels" }).click();
    await expect(page.locator(".tunnel-serve-tcp-command")).toHaveText(
      `sp2p tunnel serve --server ${origin} --to tcp://127.0.0.1:5432`
    );
    await expect(page.locator(".tunnel-connect-tcp-command")).toHaveText(
      `sp2p tunnel connect --server ${origin} --listen tcp://127.0.0.1:15432 CODE`
    );
    const commandText = await page.getByRole("tabpanel", { name: "Tunnels" }).textContent();
    expect(commandText).toContain(`--server ${origin}`);
    expect(commandText).not.toMatch(/[23456789a-hj-np-z]{8}-[A-Za-z0-9_-]{20,}/);
  });

  test("copies a command from the keyboard and reports feedback", async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: (text: string) => {
            (window as typeof window & { copiedCommand?: string }).copiedCommand = text;
            return Promise.resolve();
          },
        },
      });
    });
    await page.goto("/");
    await page.getByRole("tab", { name: "rsync" }).click();
    const senderCommand = page.getByRole("button", { name: /Sender/ });
    await senderCommand.focus();
    await senderCommand.press("Enter");
    await expect(senderCommand.locator(".copy-hint")).toHaveText("copied!");
    const copiedCommand = await page.evaluate(() =>
      (window as typeof window & { copiedCommand?: string }).copiedCommand
    );
    expect(copiedCommand).toContain("sp2p rsync send --server");
  });

  for (const width of [1280, 390]) {
    test(`keeps zero-install commands between the drop zone and usage tabs at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.goto("/");
      const commands = page.getByRole("region", { name: "Send without installing" });
      const origin = new URL(page.url()).origin;
      const expected: Array<[string, string, string]> = [
        ["curl", "send-curl", `curl -f ${origin} | sh -s <file>`],
        ["wget", "send-wget", `wget -O- ${origin} | sh -s <file>`],
        ["PowerShell", "send-powershell", `& ([scriptblock]::Create((irm ${origin}/ps))) '<file>'`],
      ];
      for (const [tab, command, text] of expected) {
        await commands.getByRole("tab", { name: tab, exact: true }).click();
        await expect(commands.locator(`.${command}`)).toBeVisible();
        await expect(commands.locator(`.${command}`)).toHaveText(text);
      }

      const dropBox = await page.locator(".drop-zone").boundingBox();
      const commandsBox = await commands.boundingBox();
      const tabsBox = await page.getByRole("tablist", { name: "SP2P usage guides" }).boundingBox();
      expect(dropBox).not.toBeNull();
      expect(commandsBox).not.toBeNull();
      expect(tabsBox).not.toBeNull();
      expect(commandsBox!.y).toBeGreaterThanOrEqual(dropBox!.y + dropBox!.height);
      expect(tabsBox!.y).toBeGreaterThanOrEqual(commandsBox!.y + commandsBox!.height);

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      expect(overflow).toBeLessThanOrEqual(0);
    });
  }

  test("copies zero-install command prefixes without selecting a tab", async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: (text: string) => {
            (window as typeof window & { copiedCommand?: string }).copiedCommand = text;
            return Promise.resolve();
          },
        },
      });
    });
    await page.goto("/");
    const origin = new URL(page.url()).origin;
    const commands = [
      ["send-curl", `curl -f ${origin} | sh -s `],
      ["send-wget", `wget -O- ${origin} | sh -s `],
      ["send-powershell", `& ([scriptblock]::Create((irm ${origin}/ps))) '`],
    ];
    const tabFor: Record<string, string> = { "send-curl": "curl", "send-wget": "wget", "send-powershell": "PowerShell" };
    const zeroInstall = page.getByRole("region", { name: "Send without installing" });
    for (const [name, prefix] of commands) {
      await zeroInstall.getByRole("tab", { name: tabFor[name], exact: true }).click();
      const command = page.locator(`button[data-copy="${name}"]`);
      await command.focus();
      await command.press("Enter");
      await expect(command.locator(".copy-hint")).toHaveText("copied!");
      const copiedCommand = await page.evaluate(() =>
        (window as typeof window & { copiedCommand?: string }).copiedCommand
      );
      expect(copiedCommand).toBe(prefix);
    }
    await expect(page.getByRole("tab", { name: "AI agent" })).toHaveAttribute("aria-selected", "true");
  });

  test("keeps platform downloads, packages, and installed CLI commands in Install", async ({ page }) => {
    await page.goto("/");
    const install = page.getByRole("region", { name: "Install the CLI" });
    const origin = new URL(page.url()).origin;
    for (const [tab, os] of [["macOS", "darwin"], ["Linux", "linux"], ["Windows", "windows"]]) {
      await install.getByRole("tab", { name: tab, exact: true }).click();
      const panel = install.getByRole("tabpanel", { name: tab, exact: true });
      await expect(panel.locator(".download-btn")).toHaveAttribute("href", new RegExp(`^/dl/${os}/(amd64|arm64)$`));
      if (os !== "linux") {
        await expect(panel.locator(".download-alt")).toHaveAttribute("href", new RegExp(`^/dl/${os}/(amd64|arm64)$`));
      }
      await expect(panel.locator(".download-platform")).not.toBeEmpty();
    }
    await install.getByRole("tab", { name: "Linux", exact: true }).click();
    await expect(install.getByRole("tabpanel", { name: "Linux" })).toContainText(`curl -fLO ${origin}/dl/sp2p_amd64.deb`);
    await expect(install.getByRole("tabpanel", { name: "Linux" })).toContainText(`curl -fLO ${origin}/dl/sp2p_amd64.rpm`);
    await expect(install.getByRole("tabpanel", { name: "Linux" })).toContainText(`apk add sp2p_amd64.apk`);
    const linux = install.getByRole("tabpanel", { name: "Linux" });
    await expect(linux.getByRole("button", { name: /^amd64/ })).toHaveAttribute("aria-pressed", "true");
    await linux.getByRole("button", { name: /^arm64/ }).click();
    await expect(linux.getByRole("button", { name: /^arm64/ })).toHaveAttribute("aria-pressed", "true");
    await expect(linux.locator(".download-btn")).toHaveAttribute("href", "/dl/linux/arm64");
    await expect(linux).toContainText(`curl -fLO ${origin}/dl/sp2p_arm64.deb`);
    await expect(linux).toContainText(`apk add sp2p_arm64.apk`);
    await expect(linux).toContainText("yay -S sp2p-bin");
    await install.getByRole("tab", { name: "Windows", exact: true }).click();
    await expect(install.getByRole("tabpanel", { name: "Windows" })).toContainText("winget install zyno-io.sp2p");
    await expect(install.getByRole("tabpanel", { name: "Windows" })).toContainText("choco install sp2p");
    await expect(page.locator(".cli-send-command")).toHaveText(`sp2p send -server ${origin} <file>`);
    await expect(page.locator(".cli-recv-command")).toHaveText(`sp2p receive -server ${origin} CODE`);
    await expect(install.locator(".send-curl, .send-wget, .send-powershell")).toHaveCount(0);
  });

  test("preselects platform tabs and architecture from the browser", async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(Navigator.prototype, "userAgentData", {
        configurable: true,
        get: () => ({
          platform: "Windows",
          getHighEntropyValues: () => Promise.resolve({ architecture: "arm" }),
        }),
      });
    });
    await page.goto("/");
    const install = page.getByRole("region", { name: "Install the CLI" });
    await expect(install.getByRole("tab", { name: "Windows", exact: true })).toHaveAttribute("aria-selected", "true");
    await expect(install.getByRole("tabpanel", { name: "Windows" }).locator(".download-btn")).toHaveAttribute("href", "/dl/windows/arm64");
    await expect(install.getByRole("tabpanel", { name: "Windows" }).locator(".download-alt")).toHaveAttribute("href", "/dl/windows/amd64");
    const zeroInstall = page.getByRole("region", { name: "Send without installing" });
    await expect(zeroInstall.getByRole("tab", { name: "PowerShell" })).toHaveAttribute("aria-selected", "true");
    await expect(zeroInstall.locator(".send-powershell")).toBeVisible();
    // Usage guides keep their fixed default.
    await expect(page.getByRole("tab", { name: "AI agent" })).toHaveAttribute("aria-selected", "true");
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
    await expect(page.locator(".zero-install-section")).toBeHidden();
    await expect(page.locator(".usage-section")).toBeHidden();
    await expect(page.locator(".install-section")).toBeHidden();
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

    const agentPrompt = page.locator(".share-agent");
    await expect(agentPrompt).toContainText("AI Agent: Please receive file session");
    await expect(agentPrompt).toContainText(new URL("/llm", page.url()).href);
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

  test("serves agent documentation as Markdown", async ({ request }) => {
    let canonicalGuide: string | undefined;
    for (const path of ["/llm", "/llm.md", "/llms.txt", "/llms-full.txt", "/agents.md"]) {
      const response = await request.get(path);
      expect(response.status(), path).toBe(200);
      expect(response.headers()["content-type"] || "").toContain("text/markdown");
      const body = await response.text();
      expect(body).toContain("SP2P");
      expect(body).not.toContain("{{SP2P_SERVER_URL}}");
      expect(body).toContain("rsync");
      expect(body).toContain("socket");
      if (path !== "/llms.txt") {
        if (canonicalGuide === undefined) {
          canonicalGuide = body;
        } else {
          expect(body, path).toBe(canonicalGuide);
        }
        expect(body).toContain('sp2p rsync send --server "http://localhost:18090"');
        expect(body).toContain("sp2p tunnel connect");
        expect(body).toContain("subprocess_output");
        expect(body).toContain("curl -f");
        expect(body).toContain("wget -O-");
        expect(body).toContain("irm");
        expect(body).toContain("api.github.com/repos/zyno-io/sp2p/releases/latest");
      }
    }
  });
});
