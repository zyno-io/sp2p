#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# serve.sh — serve a directory of goreleaser-snapshot assets over plain HTTP
# on 127.0.0.1, so render.sh can be pointed at it as a baseURL during
# pull_request validation (no real release to download assets from yet).
# Backgrounds the server and waits for it to answer before returning, so a
# caller can just run this then start rendering/validating.
#
# Usage: serve.sh <dir>
# Env:   SERVE_PORT (default 8765)
#
# Bash/Linux/macOS/archlinux-container entry point. Windows jobs start
# python -m http.server directly in PowerShell instead (see
# packaging-validate.yml) since a backgrounded process here wouldn't
# survive into a later step on that runner.

set -euo pipefail

DIR="${1:?Usage: $0 <dir>}"
PORT="${SERVE_PORT:-8765}"
LOG="${RUNNER_TEMP:-/tmp}/packaging-http-server.log"

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python

nohup "$PY" -m http.server "$PORT" --bind 127.0.0.1 --directory "$DIR" >"$LOG" 2>&1 </dev/null &

for _ in $(seq 1 30); do
  if curl -fsS -o /dev/null "http://127.0.0.1:${PORT}/checksums.txt"; then
    echo "Serving $DIR on http://127.0.0.1:${PORT}"
    exit 0
  fi
  sleep 1
done

echo "::error::local asset server did not start" >&2
cat "$LOG" >&2 || true
exit 1
