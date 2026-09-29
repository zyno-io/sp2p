#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Exercises render.sh's argument validation and strict checksum-lookup
# semantics against synthetic, throwaway inputs — no network, no real
# assets. Run directly: bash scripts/packaging/render_test.sh
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
render="$script_dir/render.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

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
check_contains() {
  local desc="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "ok - $desc"
    pass=$((pass + 1))
  else
    echo "FAIL - $desc (expected to contain '$needle')"
    echo "  actual: $haystack"
    fail=$((fail + 1))
  fi
}

sha_n() { printf 'ab%062d' "$1"; } # deterministic, well-formed (and letter-containing) fake sha256

BASE="http://127.0.0.1:8765"

# ── Case 1: real ("./"-prefixed) release checksum format ────────────────
release_cs="$work/release-checksums.txt"
cat >"$release_cs" <<EOF
$(sha_n 1)  ./sp2p_darwin_arm64.tar.gz
$(sha_n 2)  ./sp2p_darwin_amd64.tar.gz
$(sha_n 3)  ./sp2p_linux_arm64.tar.gz
$(sha_n 4)  ./sp2p_linux_amd64.tar.gz
$(sha_n 5)  ./sp2p_windows_amd64.zip
$(sha_n 6)  ./sp2p_windows_arm64.zip
EOF

for ch in homebrew scoop aur chocolatey; do
  out="$work/release-$ch"
  if bash "$render" "$ch" 1.2.3 "$BASE" "$release_cs" "$out" >/dev/null 2>"$work/err"; then
    check "release format: $ch renders (exit 0)" "0" "0"
  else
    echo "FAIL - release format: $ch renders (exit 0)"; cat "$work/err"; fail=$((fail + 1))
  fi
done
check_contains "homebrew formula contains rendered URL" "$(cat "$work/release-homebrew/sp2p.rb")" "$BASE/sp2p_darwin_arm64.tar.gz"
check_contains "homebrew formula contains rendered sha" "$(cat "$work/release-homebrew/sp2p.rb")" "$(sha_n 1)"
check_contains "scoop manifest contains rendered URL" "$(cat "$work/release-scoop/sp2p.json")" "$BASE/sp2p_windows_amd64.zip"
check_contains "aur PKGBUILD contains rendered URL" "$(cat "$work/release-aur/PKGBUILD")" "$BASE/sp2p_linux_amd64.tar.gz"
check_contains "aur .SRCINFO contains rendered sha" "$(cat "$work/release-aur/.SRCINFO")" "$(sha_n 4)"
check_contains "chocolatey install script contains rendered URL" "$(cat "$work/release-chocolatey/tools/chocolateyInstall.ps1")" "$BASE/sp2p_windows_amd64.zip"

# ── Case 2: bare goreleaser-snapshot checksum format renders identically ──
bare_cs="$work/bare-checksums.txt"
sed 's#  \./#  #' "$release_cs" >"$bare_cs"
for ch in homebrew scoop aur chocolatey; do
  bash "$render" "$ch" 1.2.3 "$BASE" "$bare_cs" "$work/bare-$ch" >/dev/null 2>&1
  if diff -r "$work/release-$ch" "$work/bare-$ch" >/dev/null 2>&1; then
    check "bare checksum format: $ch identical to release format" "identical" "identical"
  else
    check "bare checksum format: $ch identical to release format" "identical" "different"
  fi
done

# ── Case 3: "*name" and "*./name" (binary-mode sha256sum) prefixes ──────
star_cs="$work/star-checksums.txt"
sed 's#  \./#  *./#' "$release_cs" >"$star_cs"
bash "$render" homebrew 1.2.3 "$BASE" "$star_cs" "$work/star-homebrew" >/dev/null 2>&1
if diff -r "$work/release-homebrew" "$work/star-homebrew" >/dev/null 2>&1; then
  check "'*./name' prefix: homebrew identical to release format" "identical" "identical"
else
  check "'*./name' prefix: homebrew identical to release format" "identical" "different"
fi

# ── Case 4: missing asset fails closed, writes nothing ──────────────────
missing_cs="$work/missing-checksums.txt"
grep -v windows_amd64 "$release_cs" >"$missing_cs"
out="$work/missing-scoop"
if bash "$render" scoop 1.2.3 "$BASE" "$missing_cs" "$out" >/dev/null 2>"$work/err"; then
  check "missing asset: scoop fails" "nonzero" "0"
else
  check "missing asset: scoop fails" "nonzero" "nonzero"
fi
check_contains "missing asset: error names the asset and expected count" "$(cat "$work/err")" "has 0 line(s) for sp2p_windows_amd64.zip (expected exactly 1)"
check "missing asset: outdir has no rendered files" "0" "$(find "$out" -type f 2>/dev/null | wc -l | tr -d ' ')"

# ── Case 5: duplicate checksum line ──────────────────────────────────────
dup_cs="$work/dup-checksums.txt"
{ cat "$release_cs"; echo "$(sha_n 9)  ./sp2p_windows_amd64.zip"; } >"$dup_cs"
bash "$render" scoop 1.2.3 "$BASE" "$dup_cs" "$work/dup-scoop" >/dev/null 2>"$work/err" && true
check_contains "duplicate checksum line: error reports 2 lines" "$(cat "$work/err")" "has 2 line(s) for sp2p_windows_amd64.zip"

# ── Case 6: malformed sha256 values ──────────────────────────────────────
upper_cs="$work/upper-checksums.txt"
sed "s/$(sha_n 5)/$(sha_n 5 | tr 'a-f' 'A-F')/" "$release_cs" >"$upper_cs"
bash "$render" scoop 1.2.3 "$BASE" "$upper_cs" "$work/upper-scoop" >/dev/null 2>"$work/err" && true
check_contains "uppercase hash: rejected" "$(cat "$work/err")" "invalid sha256 for sp2p_windows_amd64.zip"

short_cs="$work/short-checksums.txt"
sed "s/$(sha_n 5)/$(sha_n 5 | cut -c1-63)/" "$release_cs" >"$short_cs"
bash "$render" scoop 1.2.3 "$BASE" "$short_cs" "$work/short-scoop" >/dev/null 2>"$work/err" && true
check_contains "63-char hash: rejected" "$(cat "$work/err")" "invalid sha256 for sp2p_windows_amd64.zip"

# ── Case 7: CRLF checksums.txt — none of the lines match ────────────────
crlf_cs="$work/crlf-checksums.txt"
sed 's/$/\r/' "$release_cs" >"$crlf_cs"
bash "$render" scoop 1.2.3 "$BASE" "$crlf_cs" "$work/crlf-scoop" >/dev/null 2>"$work/err" && true
check_contains "CRLF checksums file: 0 lines match" "$(cat "$work/err")" "has 0 line(s) for sp2p_windows_amd64.zip"

# ── Case 8: decoy names still match exactly one ──────────────────────────
decoy_cs="$work/decoy-checksums.txt"
cat >"$decoy_cs" <<EOF
$(cat "$release_cs")
$(sha_n 10)  ./sp2p-server_1.2.3_windows_amd64.zip
$(sha_n 11)  ./xsp2p_windows_amd64.zip
$(sha_n 12)  ./sp2p_windows_amd64.zip.sig
EOF
if bash "$render" scoop 1.2.3 "$BASE" "$decoy_cs" "$work/decoy-scoop" >/dev/null 2>"$work/err"; then
  check "decoy asset names: still exactly one match" "0" "0"
else
  echo "FAIL - decoy asset names: still exactly one match"; cat "$work/err"; fail=$((fail + 1))
fi

# ── Case 9: bad arguments exit 2 ─────────────────────────────────────────
bad_arg() {
  local desc="$1"; shift
  if bash "$render" "$@" >/dev/null 2>/dev/null; then
    check "bad args: $desc" "2" "0"
  else
    check "bad args: $desc" "2" "$?"
  fi
}
bad_arg "wrong arg count" homebrew 1.2.3 "$BASE" "$release_cs"
bad_arg "unknown channel" snap 1.2.3 "$BASE" "$release_cs" "$work/x1"
bad_arg "version with only two components" homebrew 1.2 "$BASE" "$release_cs" "$work/x2"
bad_arg "version with 'v' prefix" homebrew v1.2.3 "$BASE" "$release_cs" "$work/x3"
bad_arg "baseURL with trailing slash" homebrew 1.2.3 "$BASE/" "$release_cs" "$work/x4"
bad_arg "baseURL with non-http(s) scheme" homebrew 1.2.3 "ftp://example.com" "$release_cs" "$work/x5"
bad_arg "baseURL containing a quote" homebrew 1.2.3 "$BASE/a'b" "$release_cs" "$work/x6"
bad_arg "missing checksums file" homebrew 1.2.3 "$BASE" "$work/does-not-exist.txt" "$work/x7"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
