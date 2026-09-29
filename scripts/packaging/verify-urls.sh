#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# verify-urls.sh — cross-check every asset URL/sha256 a rendered manifest
# references: the sha256 must match checksums.txt, the URL must actually
# serve (HEAD), and the downloaded bytes must hash to the same sha256. This
# catches anything render.sh's own strict checksum lookup can't: a stale or
# unreachable URL, or an asset whose real bytes don't match what
# checksums.txt (and therefore the manifest) claims.
#
# Usage: verify-urls.sh <channel> <dir> <checksums-file>
#
#   channel  homebrew | scoop | aur | chocolatey | winget
#   dir      Directory holding the channel's rendered manifest file(s)
#            (render.sh's <outdir>, or a winget output directory).
#
# Portable bash only (no gawk-only features): this runs on macos-15,
# windows-latest (Git Bash), ubuntu-latest, and inside an archlinux
# container.

set -euo pipefail

CHANNEL="${1:?Usage: $0 <channel> <dir> <checksums-file>}"
DIR="${2:?Usage: $0 <channel> <dir> <checksums-file>}"
CHECKSUMS="${3:?Usage: $0 <channel> <dir> <checksums-file>}"

# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

EXPECT_COUNT=""
case "$CHANNEL" in
  homebrew) EXPECT_COUNT=4 ;;
  scoop) EXPECT_COUNT=2 ;;
  aur) EXPECT_COUNT=2 ;;
  chocolatey) EXPECT_COUNT=1 ;;
  winget) EXPECT_COUNT=2 ;;
  *)
    echo "::error::unknown channel '$CHANNEL'" >&2
    exit 2
    ;;
esac

# Each parse_* function prints "<sha256> <url>" pairs, one per line, read
# from its channel's rendered file(s).

parse_homebrew() {
  local pending_url=""
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ url\ \"([^\"]+)\" ]]; then
      pending_url="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ sha256\ \"([^\"]+)\" ]] && [ -n "$pending_url" ]; then
      printf '%s %s\n' "${BASH_REMATCH[1]}" "$pending_url"
      pending_url=""
    fi
  done <"$DIR/sp2p.rb"
}

parse_scoop() {
  local pending_url=""
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ \"url\":\ \"([^\"]+)\" ]]; then
      pending_url="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ \"hash\":\ \"([^\"]+)\" ]] && [ -n "$pending_url" ]; then
      printf '%s %s\n' "${BASH_REMATCH[1]}" "$pending_url"
      pending_url=""
    fi
  done <"$DIR/sp2p.json"
}

parse_aur() {
  local url_x86="" url_aarch=""
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ ^[[:space:]]*source_x86_64\ =\ (.+)$ ]]; then
      url_x86="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^[[:space:]]*source_aarch64\ =\ (.+)$ ]]; then
      url_aarch="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^[[:space:]]*sha256sums_x86_64\ =\ (.+)$ ]] && [ -n "$url_x86" ]; then
      printf '%s %s\n' "${BASH_REMATCH[1]}" "$url_x86"
    elif [[ "$line" =~ ^[[:space:]]*sha256sums_aarch64\ =\ (.+)$ ]] && [ -n "$url_aarch" ]; then
      printf '%s %s\n' "${BASH_REMATCH[1]}" "$url_aarch"
    fi
  done <"$DIR/.SRCINFO"
}

parse_chocolatey() {
  local url="" hash=""
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ url64bit[[:space:]]*=[[:space:]]*\'([^\']+)\' ]]; then
      url="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ checksum64[[:space:]]*=[[:space:]]*\'([^\']+)\' ]]; then
      hash="${BASH_REMATCH[1]}"
    fi
  done <"$DIR/tools/chocolateyInstall.ps1"
  if [ -n "$url" ] && [ -n "$hash" ]; then printf '%s %s\n' "$hash" "$url"; fi
}

parse_winget() {
  local url=""
  local files=("$DIR"/*.installer.yaml)
  [ -e "${files[0]}" ] || files=("$DIR"/*.yaml)
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    if [[ "$line" =~ InstallerUrl:[[:space:]]*(.+)$ ]]; then
      url="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ InstallerSha256:[[:space:]]*(.+)$ ]] && [ -n "$url" ]; then
      local hash
      hash="$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')"
      printf '%s %s\n' "$hash" "$url"
      url=""
    fi
  done < <(cat "${files[@]}" 2>/dev/null)
}

pairs="$("parse_$CHANNEL")"
count=0
if [ -n "$pairs" ]; then count=$(printf '%s\n' "$pairs" | grep -c '^.'); fi
if [ "$count" -ne "$EXPECT_COUNT" ]; then
  echo "::error::$CHANNEL manifest has $count url/sha256 pair(s), expected $EXPECT_COUNT" >&2
  exit 1
fi

rc=0
while IFS=' ' read -r manifest_sha url; do
  [ -n "$manifest_sha" ] || continue
  if [[ ! "$manifest_sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "::error::$CHANNEL manifest has a malformed sha256 for $url: '$manifest_sha'" >&2
    rc=1
    continue
  fi
  asset="$(basename "${url%%\?*}")"
  expected_sha="$(sha "$asset")"
  if [ "$manifest_sha" != "$expected_sha" ]; then
    echo "::error::$CHANNEL manifest sha256 for $url is $manifest_sha, checksums file says $expected_sha" >&2
    rc=1
    continue
  fi
  if ! curl -fsSIL --retry 3 --retry-connrefused --retry-delay 2 -o /dev/null "$url"; then
    echo "::error::HEAD request failed for $url" >&2
    rc=1
    continue
  fi
  tmp="$(mktemp)"
  if ! curl -fsSL --retry 3 --retry-connrefused --retry-delay 2 -o "$tmp" "$url"; then
    echo "::error::download failed for $url" >&2
    rm -f "$tmp"
    rc=1
    continue
  fi
  downloaded_sha="$(sha256_file "$tmp")"
  rm -f "$tmp"
  if [ "$downloaded_sha" != "$manifest_sha" ]; then
    echo "::error::sha256 mismatch for $url: manifest $manifest_sha, downloaded $downloaded_sha" >&2
    rc=1
    continue
  fi
  echo "ok $manifest_sha $url"
done <<<"$pairs"

exit "$rc"
