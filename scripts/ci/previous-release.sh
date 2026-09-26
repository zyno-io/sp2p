#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Resolves the previous (or Nth-previous) plain vMAJOR.MINOR.PATCH release tag
# relative to the current ref, for cross-release compatibility testing.
#
# Usage: previous-release.sh [--nth N] [--remote NAME]
#
# Prints, suitable for appending to $GITHUB_OUTPUT:
#   tag=vX.Y.Z
#   sha=<commit sha>
#   version=X.Y.Z
#
# Resolution:
#   - Lists tags from the "origin" remote (by default) so this also works in
#     a shallow checkout, since it never depends on tag objects fetched
#     locally.
#   - Keeps only tags matching ^v[0-9]+\.[0-9]+\.[0-9]+$; scoped tags such as
#     v0.1.1-server are excluded.
#   - When $GITHUB_REF_NAME is itself a plain semver tag, only tags strictly
#     lower than it (by `sort -V`) are considered, so a release build never
#     resolves to itself or a newer release.
#   - A tag whose commit is the current HEAD is always skipped, even if it
#     would otherwise qualify (e.g. a no-op re-release tag pointing at the
#     same commit as an older tag).
#   - --nth (default 1) selects the Nth-highest qualifying tag: 1 is the
#     immediately previous release, 2 is the one before that, and so on.
set -euo pipefail

nth=1
remote=origin
while [ $# -gt 0 ]; do
  case "$1" in
    --nth)
      nth="${2:?--nth requires a value}"
      shift 2
      ;;
    --remote)
      remote="${2:?--remote requires a value}"
      shift 2
      ;;
    *)
      echo "previous-release.sh: unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ ! "$nth" =~ ^[0-9]+$ ]] || [ "$nth" -lt 1 ]; then
  echo "previous-release.sh: --nth must be a positive integer" >&2
  exit 1
fi

head_sha=$(git rev-parse HEAD)
current_ref="${GITHUB_REF_NAME:-}"

# name<TAB>sha for every plain vMAJOR.MINOR.PATCH tag on the remote. Prefer
# the peeled "^{}" SHA (the commit an annotated tag points to) over the tag
# object's own SHA; a lightweight tag has only the one, unpeeled line.
tag_shas=$(git ls-remote --tags "$remote" 'refs/tags/v*' | awk '
  {
    sha = $1; ref = $2
    sub(/^refs\/tags\//, "", ref)
    peeled = 0
    if (ref ~ /\^\{\}$/) { sub(/\^\{\}$/, "", ref); peeled = 1 }
    if (ref !~ /^v[0-9]+\.[0-9]+\.[0-9]+$/) next
    if (!(ref in seen) || peeled) seen[ref] = sha
  }
  END { for (name in seen) print name "\t" seen[name] }
')

if [ -z "$tag_shas" ]; then
  echo "previous-release.sh: no plain vMAJOR.MINOR.PATCH tags found on remote '$remote'" >&2
  exit 1
fi

sha_of() {
  printf '%s\n' "$tag_shas" | awk -F'\t' -v name="$1" '$1 == name { print $2; exit }'
}

candidates=()
while IFS= read -r name; do
  [ -z "$name" ] && continue
  if [[ "$current_ref" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    if [ "$name" = "$current_ref" ]; then
      continue
    fi
    lower=$(printf '%s\n%s\n' "$name" "$current_ref" | sort -V | head -n1)
    if [ "$lower" != "$name" ]; then
      continue
    fi
  fi
  if [ "$(sha_of "$name")" = "$head_sha" ]; then
    continue
  fi
  candidates+=("$name")
done < <(printf '%s\n' "$tag_shas" | cut -f1 | sort -V)

count=${#candidates[@]}
if [ "$count" -lt "$nth" ]; then
  echo "previous-release.sh: fewer than $nth qualifying release tag(s) found" >&2
  exit 1
fi

index=$((count - nth))
tag=${candidates[$index]}
sha=$(sha_of "$tag")
version=${tag#v}

echo "tag=$tag"
echo "sha=$sha"
echo "version=$version"
