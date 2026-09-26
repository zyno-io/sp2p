#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Manage the "sp2p" Linux network namespace used by the netem CI job (see
# docs/testing.md). The namespace contains only `lo` and a `dummy0` at
# 10.99.0.1/24 — no route to the internet, so WebRTC ICE inside it is
# deterministic (host candidates only). `dummy0` exists so pion/Chromium have
# a non-loopback local address to put in host candidates; because the peer's
# candidate is also a local address of this same host, the kernel actually
# delivers that traffic over `lo` regardless, which is why netem.sh shapes
# `lo`, not `dummy0`.
#
# Subcommands:
#   netns.sh up                 create the namespace (needs root)
#   netns.sh down                delete it (needs root)
#   netns.sh exec -- <cmd...>    run <cmd...> inside the namespace as the
#                                 CALLING (non-root) user, not root — escalates
#                                 internally only for the `ip netns exec`/
#                                 `setpriv` step. Run this WITHOUT sudo; it
#                                 sudo's itself.
set -euo pipefail

NETNS=sp2p
DUMMY=dummy0
DUMMY_CIDR=10.99.0.1/24

usage() {
  echo "usage: $0 {up|down|exec -- <cmd...>}" >&2
  exit 1
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "netns.sh $1 must run as root (use sudo)" >&2
    exit 1
  fi
}

cmd_up() {
  require_root up
  if ip netns list | grep -qx "$NETNS"; then
    echo "netns.sh: namespace '$NETNS' already exists — run 'netns.sh down' first" >&2
    exit 1
  fi

  ip netns add "$NETNS"
  ip netns exec "$NETNS" ip link set lo up

  ip link add "$DUMMY" type dummy
  ip link set "$DUMMY" netns "$NETNS"
  # Disable IPv6 only on dummy0 so ::1 on lo keeps working (some tooling
  # assumes localhost has a working IPv6 loopback).
  ip netns exec "$NETNS" sysctl -qw "net.ipv6.conf.${DUMMY}.disable_ipv6=1"
  ip netns exec "$NETNS" ip addr add "$DUMMY_CIDR" dev "$DUMMY"
  ip netns exec "$NETNS" ip link set "$DUMMY" up

  # netem on lo distorts loss/delay if segments above 64 KB get offloaded
  # past the qdisc; keep lo at a normal MTU with GSO/TSO/GRO disabled.
  ip netns exec "$NETNS" ip link set lo mtu 1500
  ip netns exec "$NETNS" ethtool -K lo gso off tso off gro off

  echo "netns.sh: '$NETNS' up (lo, $DUMMY $DUMMY_CIDR)"
}

cmd_down() {
  require_root down
  if ! ip netns list | grep -qx "$NETNS"; then
    echo "netns.sh: namespace '$NETNS' does not exist, nothing to do"
    return 0
  fi
  ip netns delete "$NETNS"
  echo "netns.sh: '$NETNS' down"
}

cmd_exec() {
  if [[ "$(id -u)" -eq 0 ]]; then
    echo "netns.sh exec: run this without sudo — it escalates itself only for" \
         "the namespace attach, then drops back to your uid/gid" >&2
    exit 1
  fi
  if [[ "${1:-}" != "--" ]]; then
    usage
  fi
  shift
  if [[ $# -eq 0 ]]; then
    usage
  fi

  local uid gid
  uid=$(id -u)
  gid=$(id -g)

  # `ip netns exec` + `setpriv` need root, but the actual test process must
  # run as this (the runner) user, never root. sudo resets almost the whole
  # environment by default, so re-establish PATH/HOME plus the handful of
  # variables the build/test tooling relies on, sourced from *this*
  # (unprivileged, correctly-configured) shell — evaluated here, before sudo,
  # not after.
  local -a preserved_env=(PATH="$PATH" HOME="$HOME")
  local var
  for var in PLAYWRIGHT_BROWSERS_PATH GOCACHE GOPATH GOMODCACHE GOFLAGS \
             npm_config_cache CI SP2P_NETEM_PROFILE SP2P_PW_CLI_BIN \
             SP2P_PW_SERVER_BIN SP2P_PW_SKIP_WEB_BUILD GITHUB_STEP_SUMMARY \
             GITHUB_ENV GITHUB_OUTPUT GITHUB_WORKSPACE RUNNER_TEMP TMPDIR; do
    if [[ -n "${!var:-}" ]]; then
      preserved_env+=("$var=${!var}")
    fi
  done

  exec sudo ip netns exec "$NETNS" setpriv --reuid="$uid" --regid="$gid" --init-groups -- \
    env "${preserved_env[@]}" "$@"
}

case "${1:-}" in
  up) cmd_up ;;
  down) cmd_down ;;
  exec) shift; cmd_exec "$@" ;;
  *) usage ;;
esac
