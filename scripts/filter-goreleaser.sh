#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# filter-goreleaser.sh — filter .goreleaser.yaml by release scope
#
# Usage: ./scripts/filter-goreleaser.sh <scope> <output-path>
#
# Scopes:
#   all           No filtering (copy as-is)
#   server        Server binary only, all platforms + Docker
#   cli           CLI only, all platforms
#   cli-nix       CLI only, Linux + macOS
#   cli-linux     CLI only, Linux
#   cli-mac       CLI only, macOS
#   cli-windows   CLI only, Windows

set -euo pipefail

SCOPE="${1:?Usage: $0 <scope> <output-path>}"
OUTPUT="${2:?Usage: $0 <scope> <output-path>}"
SOURCE="$(cd "$(dirname "$0")/.." && pwd)/.goreleaser.yaml"

if ! command -v yq &>/dev/null; then
  echo "error: yq is required but not found in PATH" >&2
  exit 1
fi

cp "$SOURCE" "$OUTPUT"

# Helper: remove server build/archive
remove_server() {
  yq -i 'del(.builds[] | select(.id == "sp2p-server"))' "$OUTPUT"
  yq -i 'del(.archives[] | select(.id == "sp2p-server"))' "$OUTPUT"
}

case "$SCOPE" in
  all)
    # No filtering needed
    ;;

  server)
    # Keep only sp2p-server build/archive, remove CLI build/archive and nfpms
    yq -i 'del(.builds[] | select(.id == "sp2p"))' "$OUTPUT"
    yq -i 'del(.archives[] | select(.id == "sp2p"))' "$OUTPUT"
    yq -i 'del(.nfpms)' "$OUTPUT"
    ;;

  cli)
    # Keep only CLI, all platforms
    remove_server
    ;;

  cli-nix)
    # Keep only CLI, Linux + macOS
    remove_server
    yq -i '(.builds[] | select(.id == "sp2p")).goos = ["linux", "darwin"]' "$OUTPUT"
    ;;

  cli-linux)
    # Keep only CLI, Linux only
    remove_server
    yq -i '(.builds[] | select(.id == "sp2p")).goos = ["linux"]' "$OUTPUT"
    ;;

  cli-mac)
    # Keep only CLI, macOS only
    remove_server
    yq -i '(.builds[] | select(.id == "sp2p")).goos = ["darwin"]' "$OUTPUT"
    yq -i 'del(.nfpms)' "$OUTPUT"
    ;;

  cli-windows)
    # Keep only CLI, Windows only
    remove_server
    yq -i '(.builds[] | select(.id == "sp2p")).goos = ["windows"]' "$OUTPUT"
    yq -i 'del(.nfpms)' "$OUTPUT"
    ;;

  *)
    echo "error: unknown scope '$SCOPE'" >&2
    echo "Valid scopes: all, server, cli, cli-nix, cli-linux, cli-mac, cli-windows" >&2
    exit 1
    ;;
esac

echo "Filtered .goreleaser.yaml for scope '$SCOPE' → $OUTPUT"
