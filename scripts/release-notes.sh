#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

release_version="${1:?Usage: release-notes.sh vX.Y.Z [link-tag]}"
release_version="${release_version#v}"
# Links point at the tag actually pushed (e.g. v0.7.6-server), which can
# differ from the changelog version.
link_tag="${2:-v$release_version}"
changelog="$(cd "$(dirname "$0")/.." && pwd)/CHANGELOG.md"

# The maintained changelog describes the release without generated author
# mentions or GitHub's misleading "New Contributors" section on re-releases.
awk -v version="$release_version" -v link_tag="$link_tag" '
  index($0, "## [" version "] - ") == 1 { found = 1; printing = 1; next }
  printing && /^## / { exit }
  printing {
    gsub(/\]\(README\.md/, "](https://github.com/zyno-io/sp2p/blob/" link_tag "/README.md")
    print
  }
  END { if (!found) exit 1 }
' "$changelog"
printf '\nFull changelog: https://github.com/zyno-io/sp2p/blob/%s/CHANGELOG.md\n' "$link_tag"
