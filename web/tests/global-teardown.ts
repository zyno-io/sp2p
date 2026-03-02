import { readFileSync, rmSync, unlinkSync } from "fs";
import { join } from "path";

export default async function globalTeardown() {
  const knownPath = join(__dirname, "..", ".pw-state.json");

  try {
    const state = JSON.parse(readFileSync(knownPath, "utf-8"));
    if (state.pid) {
      try {
        process.kill(state.pid, "SIGTERM");
      } catch {
        // Already dead.
      }
    }
    if (state.tmpDir) {
      rmSync(state.tmpDir, { recursive: true, force: true });
    }
    unlinkSync(knownPath);
  } catch {
    // Best-effort cleanup.
  }
}
