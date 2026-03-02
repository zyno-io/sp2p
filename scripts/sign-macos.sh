#!/usr/bin/env bash
set -euo pipefail

# Skip if signing is not configured (e.g. local builds).
if [[ -z "${APPLE_CERTIFICATE_P12_PATH:-}" ]]; then
  echo "Skipping macOS signing: APPLE_CERTIFICATE_P12_PATH not set"
  exit 0
fi

# GoReleaser creates tar.gz archives before this script runs, so they contain
# unsigned binaries. Extract each archive, sign its executables, and repack.
found=0
for archive in dist/*darwin*.tar.gz; do
  [[ -f "$archive" ]] || continue
  found=1

  echo "Signing: $(basename "$archive")"
  tmpdir=$(mktemp -d)
  tar xzf "$archive" -C "$tmpdir"

  for binary in "$tmpdir"/*; do
    [[ -f "$binary" && -x "$binary" ]] || continue
    rcodesign sign \
      --p12-file "$APPLE_CERTIFICATE_P12_PATH" \
      --p12-password-file "$APPLE_CERTIFICATE_PASSWORD_PATH" \
      --code-signature-flags runtime \
      "$binary"
  done

  rm "$archive"
  tar czf "$archive" -C "$tmpdir" .
  rm -rf "$tmpdir"
  echo "Signed: $(basename "$archive")"
done

if [[ "$found" -eq 0 ]]; then
  echo "Warning: no macOS archives found in dist/"
  exit 0
fi

# Regenerate checksums to reflect the repacked archives.
(cd dist && sha256sum *.tar.gz *.zip *.deb *.rpm *.apk 2>/dev/null > checksums.txt)
echo "Checksums updated"
