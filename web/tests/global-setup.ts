import { execSync, spawn, ChildProcess } from "child_process";
import { existsSync, writeFileSync, mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import net from "net";

const ROOT = join(__dirname, "../..");
const PORT = 18090;

function waitForPort(port: number, timeout = 10_000): Promise<void> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const sock = net.createConnection({ port, host: "127.0.0.1" });
      sock.on("connect", () => {
        sock.destroy();
        resolve();
      });
      sock.on("error", () => {
        sock.destroy();
        if (Date.now() - start > timeout) {
          reject(new Error(`Port ${port} not available after ${timeout}ms`));
        } else {
          setTimeout(attempt, 100);
        }
      });
    };
    attempt();
  });
}

export default async function globalSetup() {
  const tmpDir = mkdtempSync(join(tmpdir(), "sp2p-pw-"));

  // The netem suite runs inside a network namespace with no route to the
  // internet (see docs/testing.md), so its CI job pre-builds everything
  // outside the namespace and points these at the prebuilt outputs instead
  // of letting global-setup rebuild (which could otherwise reach for npm/go
  // module resolution over the network). Unset for every other spec/project,
  // which keeps building fresh like before.
  const skipWebBuild = process.env.SP2P_PW_SKIP_WEB_BUILD === "1";
  const prebuiltCLI = process.env.SP2P_PW_CLI_BIN;
  const prebuiltServer = process.env.SP2P_PW_SERVER_BIN;

  if (skipWebBuild) {
    console.log("Skipping web build (SP2P_PW_SKIP_WEB_BUILD=1; using prebuilt web/dist)...");
  } else {
    // Build the web UI.
    console.log("Building web assets...");
    execSync("npm run build", { cwd: join(ROOT, "web"), stdio: "pipe" });

    // Build the crypto test bundle for vector tests.
    console.log("Building crypto test bundle...");
    execSync(
      "npx esbuild src/crypto-test-entry.ts --bundle --outfile=dist/crypto-test.js --target=es2020",
      { cwd: join(ROOT, "web"), stdio: "pipe" }
    );
  }

  // Build (or reuse prebuilt) binaries.
  let serverBin: string;
  let cliBin: string;
  if (prebuiltCLI && prebuiltServer) {
    cliBin = prebuiltCLI;
    serverBin = prebuiltServer;
    console.log(`Using prebuilt Go binaries: ${cliBin}, ${serverBin}`);
  } else {
    console.log("Building Go binaries...");
    serverBin = join(tmpDir, "sp2p-server");
    cliBin = join(tmpDir, "sp2p");
    execSync(`go build -o ${serverBin} ./cmd/sp2p-server`, {
      cwd: ROOT,
      stdio: "pipe",
    });
    execSync(`go build -o ${cliBin} ./cmd/sp2p`, {
      cwd: ROOT,
      stdio: "pipe",
    });
  }

  // Start the signaling server.
  console.log(`Starting server on :${PORT}...`);
  const server = spawn(serverBin, [
    "--addr", `:${PORT}`,
    "--base-url", `http://localhost:${PORT}`,
  ], {
    cwd: ROOT,
    stdio: "pipe",
    env: { ...process.env },
  });

  server.stderr?.on("data", (data: Buffer) => {
    // Uncomment for debugging:
    // process.stderr.write(`[server] ${data}`);
  });

  // Store references for teardown.
  const stateFile = join(tmpDir, "state.json");
  writeFileSync(stateFile, JSON.stringify({
    pid: server.pid,
    tmpDir,
    cliBin,
    port: PORT,
  }));

  // Write the state file path to a well-known location so tests can find it.
  const knownPath = join(ROOT, "web", ".pw-state.json");
  writeFileSync(knownPath, JSON.stringify({
    pid: server.pid,
    tmpDir,
    cliBin,
    port: PORT,
    stateFile,
  }));
  process.env.SP2P_PW_STATE = knownPath;

  await waitForPort(PORT);
  console.log("Server ready.");
}
