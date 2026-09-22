#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

release_version="${1:?Usage: release-notes.sh vX.Y.Z}"
release_version="${release_version#v}"
changelog="$(cd "$(dirname "$0")/.." && pwd)/CHANGELOG.md"

# The maintained changelog describes the release without generated author
# mentions or GitHub's misleading "New Contributors" section on re-releases.
awk -v version="$release_version" '
  index($0, "## [" version "] - ") == 1 { found = 1; printing = 1; next }
  printing && /^## / { exit }
  printing {
    gsub(/\]\(README\.md/, "](https://github.com/zyno-io/sp2p/blob/v" version "/README.md")
    print
  }
  END { if (!found) exit 1 }
' "$changelog"
printf '\nFull changelog: https://github.com/zyno-io/sp2p/blob/v%s/CHANGELOG.md\n' "$release_version"
