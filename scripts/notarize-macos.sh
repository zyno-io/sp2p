#!/usr/bin/env bash
set -euo pipefail

# Skip if notarization is not configured.
if [[ -z "${APP_STORE_CONNECT_API_KEY_PATH:-}" ]]; then
  echo "Skipping notarization: APP_STORE_CONNECT_API_KEY_PATH not set"
  exit 0
fi

# Extract signed binaries from the macOS archives and submit them for
# notarization.  The archives were already repacked with signed binaries
# by sign-macos.sh.
found=0
for archive in dist/*darwin*.tar.gz; do
  [[ -f "$archive" ]] || continue

  tmpdir=$(mktemp -d)
  tar xzf "$archive" -C "$tmpdir"

  for binary in "$tmpdir"/*; do
    [[ -f "$binary" && -x "$binary" ]] || continue
    found=1

    name=$(basename "$binary")
    zip_path="/tmp/notarize-${name}-$$.zip"

    echo "Notarizing: $name (from $(basename "$archive"))"
    zip -j "$zip_path" "$binary"

    rcodesign notary-submit \
      --api-key-file "$APP_STORE_CONNECT_API_KEY_PATH" \
      --wait \
      "$zip_path"

    echo "Notarization complete: $name"
    rm "$zip_path"
  done

  rm -rf "$tmpdir"
done

if [[ "$found" -eq 0 ]]; then
  echo "Warning: no darwin binaries found in dist/"
fi
