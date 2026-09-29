# SPDX-License-Identifier: MIT
#
# lib.sh — shared helpers for scripts/packaging/*.sh. Source it; don't run it.

# sha <asset>: print the sha256 recorded for <asset> in "$CHECKSUMS" (the
# caller must set CHECKSUMS before calling this).
#
# Require exactly one checksums-file line for the asset and a well-formed
# sha256, so a missing/renamed asset fails loudly instead of rendering an
# empty or malformed checksum. Moved verbatim from publish-packages.yml —
# scripts/packaging/render_test.sh pins these semantics.
#
# Callers: assign the result directly, e.g. `X=$(sha file)`, under `set -e`.
# Never `local X=$(sha …)` (local swallows the command's exit status) and
# never call this inside a heredoc or `echo "$(sha …)"`.
sha() {
  local want="$1" line count value
  # release.yml writes "<sha>  ./<file>"; a bare goreleaser snapshot's own
  # checksums.txt has no "./" prefix. Accept both, plus a binary-mode "*" prefix.
  line=$(awk -v want="$want" '{ f = $2; sub(/^\*?\.\//, "", f); sub(/^\*/, "", f) } f == want' "$CHECKSUMS")
  count=$(printf '%s\n' "$line" | grep -c '^.' || true)
  if [ "$count" -ne 1 ]; then
    echo "::error::checksums file has $count line(s) for $want (expected exactly 1)" >&2
    exit 1
  fi
  value=$(printf '%s' "$line" | awk '{print $1}')
  if [[ ! "$value" =~ ^[0-9a-f]{64}$ ]]; then
    echo "::error::invalid sha256 for $want: '$value'" >&2
    exit 1
  fi
  printf '%s' "$value"
}

# sha256_file <path>: lowercase hex sha256 of a local file.
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
