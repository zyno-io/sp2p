#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Apply/verify/report netem WAN shaping on the "sp2p" netns's `lo` (see
# scripts/ci/netns.sh and docs/testing.md). Must run as root, after
# `netns.sh up`.
#
# Layout: a `prio` qdisc with 2 bands. Everything defaults to band 1:2, which
# carries the netem delay/loss for the chosen profile. Signaling TCP traffic
# (both directions, IPv4 and IPv6, matched by port) is filtered to band 1:1
# instead, which has no netem child qdisc — that's the bypass the `/health`
# latency check proves.
#
# Subcommands:
#   netem.sh apply <profile>   wan150 | wan150-cap | wan500
#   netem.sh verify             hard-fail unless the shaped RTT is in band
#   netem.sh stats               tc -s qdisc show dev lo (drops, packets, ...)
set -euo pipefail

NETNS=sp2p
IFACE=lo
SIGNAL_PORT="${SP2P_SIGNAL_PORT:-18090}"
GATEWAY=10.99.0.1

usage() {
  echo "usage: $0 {apply <profile>|verify|stats}" >&2
  echo "profiles: wan150, wan150-cap, wan500" >&2
  exit 1
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "netem.sh must run as root (use sudo)" >&2
    exit 1
  fi
}

in_ns() {
  ip netns exec "$NETNS" "$@"
}

# Deliberately no jitter on any profile: reordering on a loopback-delay qdisc
# causes spurious SCTP retransmits that have nothing to do with the WAN
# conditions we're trying to reproduce.
profile_netem_args() {
  case "$1" in
    wan150)     echo "delay 75ms loss 0.1% limit 100000" ;;
    wan150-cap) echo "delay 75ms loss 0.1% limit 100000 rate 100mbit" ;;
    wan500)     echo "delay 250ms limit 100000" ;;
    *) return 1 ;;
  esac
}

cmd_apply() {
  require_root
  local profile="${1:-}"
  [[ -n "$profile" ]] || usage
  local args
  args=$(profile_netem_args "$profile") || { echo "netem.sh: unknown profile '$profile'" >&2; usage; }

  # Idempotent: clear any qdisc already on lo before laying down a fresh one.
  in_ns tc qdisc del dev "$IFACE" root >/dev/null 2>&1 || true

  in_ns tc qdisc add dev "$IFACE" root handle 1: prio bands 2 \
    priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
  # shellcheck disable=SC2086
  in_ns tc qdisc add dev "$IFACE" parent 1:2 handle 20: netem $args

  # Signaling bypass: TCP traffic on the fixed test-server port skips netem
  # entirely (band 1:1 has no child qdisc, i.e. plain pfifo), in both
  # directions and both address families.
  in_ns tc filter add dev "$IFACE" parent 1:0 protocol ip prio 1 u32 \
    match ip protocol 6 0xff match ip sport "$SIGNAL_PORT" 0xffff flowid 1:1
  in_ns tc filter add dev "$IFACE" parent 1:0 protocol ip prio 1 u32 \
    match ip protocol 6 0xff match ip dport "$SIGNAL_PORT" 0xffff flowid 1:1
  in_ns tc filter add dev "$IFACE" parent 1:0 protocol ipv6 prio 1 u32 \
    match ip6 protocol 6 0xff match ip6 sport "$SIGNAL_PORT" 0xffff flowid 1:1
  in_ns tc filter add dev "$IFACE" parent 1:0 protocol ipv6 prio 1 u32 \
    match ip6 protocol 6 0xff match ip6 dport "$SIGNAL_PORT" 0xffff flowid 1:1

  echo "netem.sh: profile '$profile' applied to $NETNS/$IFACE ($args); signaling port $SIGNAL_PORT bypassed"
}

cmd_verify() {
  require_root
  # Preflight: hard-fail unless the shaped RTT is in the expected band, so a
  # broken qdisc (or none at all) never silently runs the suite unshaped.
  # Pinging our own dummy0 address from inside the namespace round-trips
  # over lo (a locally-owned destination is always delivered via lo), so it
  # picks up the netem delay in both directions.
  local out avg
  if ! out=$(in_ns ping -c 5 -q "$GATEWAY" 2>&1); then
    echo "netem.sh preflight FAILED: ping to $GATEWAY did not complete:" >&2
    echo "$out" >&2
    exit 1
  fi
  avg=$(echo "$out" | awk -F'/' '/= .*\/.*\/.*\// { split($0, parts, "= "); split(parts[2], nums, "/"); print nums[2] }')
  if [[ -z "$avg" ]]; then
    echo "netem.sh preflight FAILED: could not parse ping RTT from:" >&2
    echo "$out" >&2
    exit 1
  fi
  echo "netem.sh preflight: average RTT to $GATEWAY = ${avg} ms"
  if ! awk -v avg="$avg" 'BEGIN { exit !(avg >= 140 && avg <= 200) }'; then
    echo "netem.sh preflight FAILED: RTT ${avg}ms is outside the required 140-200ms band" \
         "— refusing to run the suite unshaped or mis-shaped" >&2
    exit 1
  fi
  echo "netem.sh preflight OK (${avg}ms in [140,200]ms)"
}

cmd_stats() {
  require_root
  in_ns tc -s qdisc show dev "$IFACE"
}

case "${1:-}" in
  apply) shift; cmd_apply "$@" ;;
  verify) cmd_verify ;;
  stats) cmd_stats ;;
  *) usage ;;
esac
