import { execSync, execFileSync, spawn, ChildProcess } from "child_process";
import { existsSync, writeFileSync, mkdtempSync, rmSync } from "fs";
import { tmpdir, platform } from "os";
import { join } from "path";
import net from "net";

const ROOT = join(__dirname, "../..");
const PORT = 18090;
// Windows needs the .exe suffix for exec.Command/spawn to find the binary
// (libuv/os/exec only append PATHEXT extensions to an extension-less path);
// on every other platform this is "".
const EXE = platform() === "win32" ? ".exe" : "";

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
  // Stale records from an earlier local run would hide a MISSING pairing.
  if (process.env.SP2P_NETEM_PROFILE) rmSync(join(__dirname, "..", "..", "test-results", "perf"), { recursive: true, force: true });
  if (process.env.SP2P_RELAY_TEST) rmSync(join(__dirname, "..", "..", "test-results", "relay"), { recursive: true, force: true });
  if (process.env.SP2P_LARGE_TEST) rmSync(join(__dirname, "..", "..", "test-results", "perf-large"), { recursive: true, force: true });

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
    serverBin = join(tmpDir, `sp2p-server${EXE}`);
    cliBin = join(tmpDir, `sp2p${EXE}`);
    // execFileSync (no shell) avoids Windows cmd.exe quoting entirely.
    execFileSync("go", ["build", "-o", serverBin, "./cmd/sp2p-server"], {
      cwd: ROOT,
      stdio: "pipe",
    });
    execFileSync("go", ["build", "-o", cliBin, "./cmd/sp2p"], {
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

  // Buffered (never streamed live) so a bind failure — e.g. a port landing in
  // a Windows reserved dynamic-port-range exclusion — surfaces a real error
  // instead of a bare "port not available" timeout below. The server has no
  // sessions yet at startup, so nothing here can be a transfer code.
  let serverStderr = "";
  server.stderr?.on("data", (data: Buffer) => { serverStderr += data.toString(); });
  let serverExited = false;
  server.once("exit", () => { serverExited = true; });

  // Store references for teardown.
  const stateFile = join(tmpDir, "state.json");
  writeFileSync(stateFile, JSON.stringify({
    pid: server.pid,
    tmpDir,
    cliBin,
    serverBin,
    port: PORT,
  }));

  // Write the state file path to a well-known location so tests can find it.
  const knownPath = join(ROOT, "web", ".pw-state.json");
  writeFileSync(knownPath, JSON.stringify({
    pid: server.pid,
    tmpDir,
    cliBin,
    serverBin,
    port: PORT,
    stateFile,
  }));
  process.env.SP2P_PW_STATE = knownPath;

  try {
    await waitForPort(PORT);
  } catch (error) {
    const detail = serverExited
      ? `server process exited before port ${PORT} opened`
      : `server process still running; no port ${PORT} listener yet`;
    throw new Error(`${(error as Error).message} (${detail})\nserver stderr:\n${serverStderr}`);
  }
  console.log("Server ready.");
}
