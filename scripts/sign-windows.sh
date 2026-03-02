#!/usr/bin/env bash
set -euo pipefail

# Skip if signing is not configured (e.g. local builds).
if [[ -z "${CODESIGNER_PATH:-}" ]]; then
  echo "Skipping Windows signing: CODESIGNER_PATH not set"
  exit 0
fi

# GoReleaser creates zip archives before this script runs, so they contain
# unsigned binaries. Extract each zip, sign its executables, and repack.
found=0
for zip in dist/*windows*.zip; do
  [[ -f "$zip" ]] || continue
  found=1

  echo "Signing: $(basename "$zip")"
  tmpdir=$(mktemp -d)
  unzip -q -o "$zip" -d "$tmpdir"

  "$CODESIGNER_PATH" "$tmpdir"

  rm "$zip"
  (cd "$tmpdir" && zip -q -r - .) > "$zip"
  rm -rf "$tmpdir"
  echo "Signed: $(basename "$zip")"
done

if [[ "$found" -eq 0 ]]; then
  echo "Warning: no Windows archives found in dist/"
  exit 0
fi

# Regenerate checksums to reflect the repacked archives.
(cd dist && sha256sum *.tar.gz *.zip *.deb *.rpm *.apk 2>/dev/null > checksums.txt)
echo "Checksums updated"
