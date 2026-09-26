#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Exercises previous-release.sh against a throwaway local git repository (with
# a local bare repo standing in for "origin") so its resolution logic is
# verified without touching the real repository or the network.
#
# Run directly: bash scripts/ci/previous-release_test.sh
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
resolve="$script_dir/previous-release.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

bare="$work/origin.git"
repo="$work/repo"

git init --quiet -b main --bare "$bare"
git init --quiet -b main "$repo"
cd "$repo"
git config user.email "test@example.com"
git config user.name "Test"
git remote add origin "$bare"

commit() {
  echo "$1" >>file.txt
  git add file.txt
  git commit --quiet -m "$1"
}

pass=0
fail=0
check() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "ok - $desc"
    pass=$((pass + 1))
  else
    echo "FAIL - $desc"
    echo "  expected: $(printf '%s' "$expected" | tr '\n' '|')"
    echo "  actual:   $(printf '%s' "$actual" | tr '\n' '|')"
    fail=$((fail + 1))
  fi
}

# History:
#   C1 v0.4.0
#   C2 v0.5.0
#   C3 v0.5.1-server        (scoped — must always be ignored)
#   C4 v0.5.5 AND v0.6.0    (two tags on the same commit, to exercise the
#                            "tag whose commit equals HEAD" exclusion)
#   C5 (untagged; simulates a post-release commit on a branch build)
commit "v0.4.0 work"
git tag v0.4.0
commit "v0.5.0 work"
git tag v0.5.0
commit "server-only work"
git tag v0.5.1-server
commit "v0.6.0 work"
git tag v0.5.5
git tag v0.6.0
commit "post-release work"

git push --quiet origin main
git push --quiet origin --tags

v040_sha=$(git rev-parse v0.4.0)
v050_sha=$(git rev-parse v0.5.0)
v060_sha=$(git rev-parse v0.6.0)

# HEAD untagged (a normal branch build): picks the latest qualifying release.
export GITHUB_REF_NAME="main"
out=$(bash "$resolve")
check "HEAD untagged picks the latest release" \
  "$(printf 'tag=v0.6.0\nsha=%s\nversion=0.6.0' "$v060_sha")" "$out"

# Scoped tags such as v0.5.1-server are never candidates, tagged or not.
check "scoped tags are ignored" "0" \
  "$(printf '%s\n' "$out" | grep -c 'v0\.5\.1-server' || true)"

# HEAD tagged at v0.6.0: the immediately previous release by version is
# v0.5.5, but it shares v0.6.0's commit, so it must be skipped in favor of
# v0.5.0 — this exercises both "tagged HEAD picks previous" and "a tag
# whose commit equals HEAD is skipped".
git checkout --quiet v0.6.0
export GITHUB_REF_NAME="v0.6.0"
out=$(bash "$resolve")
check "tagged HEAD picks the previous release, skipping a same-commit tag" \
  "$(printf 'tag=v0.5.0\nsha=%s\nversion=0.5.0' "$v050_sha")" "$out"

# --nth 2 from the same HEAD steps past v0.5.0 to v0.4.0, confirming ordering
# and the same-commit/scoped exclusions still apply beyond the first pick.
out=$(bash "$resolve" --nth 2)
check "--nth 2 selects the release before that" \
  "$(printf 'tag=v0.4.0\nsha=%s\nversion=0.4.0' "$v040_sha")" "$out"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
