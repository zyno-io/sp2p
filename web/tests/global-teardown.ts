import { readFileSync, rmSync, unlinkSync } from "fs";
import { join } from "path";

export default async function globalTeardown() {
  const knownPath = join(__dirname, "..", ".pw-state.json");

  let state: { pid?: number; tmpDir?: string } = {};
  try {
    state = JSON.parse(readFileSync(knownPath, "utf-8"));
  } catch {
    return; // Nothing recorded (or already torn down) — best-effort cleanup.
  }

  if (state.pid) {
    try {
      // Node has no real SIGTERM on Windows: any signal here forcibly
      // terminates the process, same as SIGKILL. Fine for teardown.
      process.kill(state.pid, "SIGTERM");
    } catch {
      // Already dead.
    }
  }
  if (state.tmpDir) {
    try {
      // maxRetries/retryDelay: on Windows, deleting a just-killed process's
      // own exe (or a file it still had open) can transiently fail with
      // EBUSY/EPERM until the OS finishes releasing the handle.
      rmSync(state.tmpDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    } catch {
      // Best-effort: an ephemeral CI runner reclaims this either way.
    }
  }
  try {
    unlinkSync(knownPath);
  } catch {
    // Already removed, or never written.
  }
}
