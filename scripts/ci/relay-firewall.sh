#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Force WebRTC traffic inside the "sp2p" netns (see scripts/ci/netns.sh and
# docs/testing.md) through the TURN relay instead of a direct host-to-host
# UDP path, by firewalling everything except: signaling TCP, TURN/STUN
# control + relayed data UDP, and a fast DNS reject. Used by the relay CI job
# to prove that a "relay-only" transfer test actually went through TURN
# rather than silently falling back to a direct P2P path.
#
# Must run after `netns.sh up` (the "sp2p" namespace must already exist).
#
# Subcommands:
#   relay-firewall.sh apply [SIGNAL_PORTS]    install the firewall (root)
#   relay-firewall.sh verify [SIGNAL_PORTS]   check it's installed as expected
#   relay-firewall.sh clear                    remove chain + INPUT hook
#   relay-firewall.sh stats                    print packet/byte counters
#
# SIGNAL_PORTS is a comma-separated list of TCP ports (no spaces), default
# "18090,18091" — the test signaling server's ports, which must stay
# reachable so peers can exchange ICE candidates/SDP even though their
# direct UDP media path is blocked.
#
# Why signaling TCP uses `-m multiport --ports` (matches either source OR
# destination) instead of separate --sport/--dport rules: this is a
# stateless firewall (see the comment on the signaling rule below for why
# there's no conntrack), so it can't tell a "request" from a "reply" by
# direction alone. The signaling server's response to a client connected on
# port 18091 has *source* port 18091 but an ephemeral *destination* port on
# the way back. A dport-only rule would only ever match the outbound leg and
# would reject/drop the legitimate return traffic. `--ports` (unlike
# `--sports`/`--dports`) matches a packet if EITHER its source or its
# destination port is in the list, which is exactly the "either leg"
# behavior a client<->fixed-port-server exchange needs.
#
# Why the TURN/relay-data rules do NOT use that same "either side" matching
# for the relay port range specifically (this was a real bug found in
# review, not a design choice to imitate): a client's own local UDP socket
# never talks directly to a relay-range port at all — it only ever talks to
# the server's *control* port (TURN_PORT, 3478), which relays the encoded
# payload internally. The relay range (31000-31127) is used exclusively for
# genuine relay-socket-to-relay-socket traffic — e.g. two TURN allocations
# on the same testturnd process, one per peer, exchanging the actual relayed
# UDP payload directly with each other. If the relay-range rule matched
# "either side" the way the signaling rule does, a packet from a peer's own
# *host* candidate (ephemeral source port) straight to the OTHER peer's
# relay candidate address (destination port in 31000-31127) would also be
# allowed through — a mixed host<->relay ICE pair that lets one side skip
# relaying entirely, defeating the whole point of this firewall (proving
# BOTH sides actually relayed). So the relay-range rule below requires BOTH
# the source AND destination port to be in 31000-31127 (`--sport X:Y --dport
# X:Y` on one rule, not `-m multiport --ports X:Y`), which only ever matches
# genuine relay<->relay traffic; a mixed host<->relay pair now correctly
# falls through to the UDP DROP catch-all. TURN_PORT (3478) keeps the
# permissive "either side" multiport match, since a client's control-channel
# traffic to the server (ephemeral local port <-> the server's fixed 3478)
# is exactly the same client<->fixed-port-server shape as signaling.
#
# Why the relay port range (31000-31127) is deliberately kept BELOW the
# typical Linux ephemeral port range (32768-60999, see
# /proc/sys/net/ipv4/ip_local_port_range): so no host-candidate (kernel-
# assigned ephemeral) socket that a peer opens for a direct WebRTC path can
# ever land inside the relay range and be mistaken for one. `verify`
# double-checks this invariant against the namespace's actual
# ip_local_port_range rather than just assuming it.
set -euo pipefail

NETNS=sp2p
CHAIN=SP2P_RELAY
TURN_PORT=3478
RELAY_MIN_PORT=31000
RELAY_MAX_PORT=31127
DEFAULT_SIGNAL_PORTS="18090,18091"

usage() {
  echo "usage: $0 {apply [SIGNAL_PORTS]|verify [SIGNAL_PORTS]|clear|stats}" >&2
  echo "SIGNAL_PORTS: comma-separated TCP ports, no spaces (default: $DEFAULT_SIGNAL_PORTS)" >&2
  exit 1
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "relay-firewall.sh $1 must run as root (use sudo)" >&2
    exit 1
  fi
}

in_ns() {
  ip netns exec "$NETNS" "$@"
}

require_netns() {
  # `ip netns list` output varies by iproute2 version (plain name, or
  # "name (id: N)") — only ever match the first field (same as netns.sh).
  if ! ip netns list | awk '{print $1}' | grep -qx "$NETNS"; then
    echo "relay-firewall.sh: namespace '$NETNS' does not exist — run scripts/ci/netns.sh up first" >&2
    exit 1
  fi
}

# Validates SIGNAL_PORTS for apply/verify: comma-separated, each 1-65535, at
# most 13 ports total, and none may collide with TURN_PORT or the relay
# range. 13 is deliberate headroom under the iptables multiport module's
# hard limit of 15 port specs per rule for the signaling rule's own port
# list (the only rule that still uses multiport for a caller-supplied list —
# the TURN control rule is a single fixed port, and the relay-range rule
# uses plain --sport/--dport, not multiport at all).
validate_signal_ports() {
  local ports="$1"
  if [[ ! "$ports" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
    echo "relay-firewall.sh: invalid SIGNAL_PORTS '$ports' (expected comma-separated port numbers, no spaces)" >&2
    exit 1
  fi

  local -a port_arr
  IFS=',' read -r -a port_arr <<< "$ports"
  if (( ${#port_arr[@]} > 13 )); then
    echo "relay-firewall.sh: too many SIGNAL_PORTS (${#port_arr[@]}), at most 13 allowed" >&2
    exit 1
  fi

  local p
  for p in "${port_arr[@]}"; do
    if (( p < 1 || p > 65535 )); then
      echo "relay-firewall.sh: SIGNAL_PORTS port '$p' out of range 1-65535" >&2
      exit 1
    fi
    if (( p == TURN_PORT )); then
      echo "relay-firewall.sh: SIGNAL_PORTS port '$p' collides with TURN_PORT ($TURN_PORT)" >&2
      exit 1
    fi
    if (( p >= RELAY_MIN_PORT && p <= RELAY_MAX_PORT )); then
      echo "relay-firewall.sh: SIGNAL_PORTS port '$p' falls inside the relay port range ($RELAY_MIN_PORT-$RELAY_MAX_PORT)" >&2
      exit 1
    fi
  done
}

cmd_apply() {
  require_root apply
  require_netns

  local signal_ports="${1:-$DEFAULT_SIGNAL_PORTS}"
  validate_signal_ports "$signal_ports"

  # Idempotent: clear any previously-applied chain/hook before laying down a
  # fresh one (matches netem.sh's "... || true" idempotency pattern, just
  # via chain flush/delete instead of a qdisc delete).
  cmd_clear

  local ipt unreach
  for ipt in iptables ip6tables; do
    if [[ "$ipt" == "iptables" ]]; then
      unreach=icmp-port-unreachable
    else
      unreach=icmp6-port-unreachable
    fi

    in_ns "$ipt" -N "$CHAIN"

    # Signaling TCP, either leg (see the multiport rationale at the top of
    # this file). No conntrack/ESTABLISHED accept rule is used anywhere in
    # this chain: two peers running ICE connectivity checks against each
    # other must NOT be treated as "replies" to one another, or that would
    # make the direct UDP path this script exists to block work again.
    in_ns "$ipt" -A "$CHAIN" -p tcp -m multiport --ports "$signal_ports" -j ACCEPT

    # Allow outgoing TCP RSTs: a reset generated by our own REJECT rules
    # below re-enters the namespace via `lo` and hits INPUT (and this chain)
    # again. Without this exemption, the catch-all TCP REJECT further down
    # would reject the reset itself, and the sender would retransmit until
    # timeout instead of failing fast.
    in_ns "$ipt" -A "$CHAIN" -p tcp -m tcp --tcp-flags RST RST -j ACCEPT

    # TURN/STUN control traffic to/from the server's fixed port, either side
    # (same client<->fixed-port-server shape as signaling above).
    in_ns "$ipt" -A "$CHAIN" -p udp -m multiport --ports "$TURN_PORT" -j ACCEPT

    # Genuine relay<->relay data ONLY: both source AND destination must be
    # in the relay range. This is deliberately NOT an "either side" match
    # (see the rationale at the top of this file) — a client's own host
    # candidate reaching a peer's relay candidate directly (ephemeral source,
    # relay-range destination) must NOT match this rule, or a mixed
    # host<->relay ICE pair could connect without ever exercising both
    # peers' relays.
    in_ns "$ipt" -A "$CHAIN" -p udp -m udp \
      --sport "$RELAY_MIN_PORT:$RELAY_MAX_PORT" --dport "$RELAY_MIN_PORT:$RELAY_MAX_PORT" -j ACCEPT

    # Reject DNS fast instead of letting it silently hang on the DROP
    # catch-all below.
    in_ns "$ipt" -A "$CHAIN" -p udp -m udp --dport 53 -j REJECT --reject-with "$unreach"

    # Catch-all: drop all other UDP. This is what forces a direct
    # host-candidate WebRTC path to fail instead of connecting.
    in_ns "$ipt" -A "$CHAIN" -p udp -j DROP

    # Catch-all: reject all other TCP with a fast reset rather than a hang.
    in_ns "$ipt" -A "$CHAIN" -p tcp -j REJECT --reject-with tcp-reset

    # Hook the chain into INPUT, first rule, `lo` only — every destination
    # inside this namespace is a local address, so all namespace traffic
    # (both peers, the signaling server, TURN) is actually delivered over
    # `lo` regardless of which interface a candidate names (see
    # netns.sh/netem.sh for the same observation).
    in_ns "$ipt" -I INPUT 1 -i lo -j "$CHAIN"
  done

  echo "relay-firewall.sh: applied — signaling TCP $signal_ports allowed; TURN control UDP $TURN_PORT allowed; genuine relay<->relay UDP $RELAY_MIN_PORT-$RELAY_MAX_PORT allowed (both ends must be in range); all other direct UDP blocked (both address families)"
}

cmd_verify() {
  require_root verify
  require_netns

  local signal_ports="${1:-$DEFAULT_SIGNAL_PORTS}"
  validate_signal_ports "$signal_ports"

  local ipt unreach
  for ipt in iptables ip6tables; do
    if [[ "$ipt" == "iptables" ]]; then
      unreach=icmp-port-unreachable
    else
      unreach=icmp6-port-unreachable
    fi

    in_ns "$ipt" -C "$CHAIN" -p tcp -m multiport --ports "$signal_ports" -j ACCEPT || {
      echo "relay-firewall.sh verify FAILED: $ipt missing signaling TCP accept rule (ports $signal_ports)" >&2
      exit 1
    }
    in_ns "$ipt" -C "$CHAIN" -p tcp -m tcp --tcp-flags RST RST -j ACCEPT || {
      echo "relay-firewall.sh verify FAILED: $ipt missing TCP RST accept rule" >&2
      exit 1
    }
    in_ns "$ipt" -C "$CHAIN" -p udp -m multiport --ports "$TURN_PORT" -j ACCEPT || {
      echo "relay-firewall.sh verify FAILED: $ipt missing TURN control UDP accept rule" >&2
      exit 1
    }
    in_ns "$ipt" -C "$CHAIN" -p udp -m udp \
      --sport "$RELAY_MIN_PORT:$RELAY_MAX_PORT" --dport "$RELAY_MIN_PORT:$RELAY_MAX_PORT" -j ACCEPT || {
      echo "relay-firewall.sh verify FAILED: $ipt missing relay<->relay UDP accept rule (both ports in range)" >&2
      exit 1
    }
    in_ns "$ipt" -C "$CHAIN" -p udp -m udp --dport 53 -j REJECT --reject-with "$unreach" || {
      echo "relay-firewall.sh verify FAILED: $ipt missing DNS reject rule" >&2
      exit 1
    }
    in_ns "$ipt" -C "$CHAIN" -p udp -j DROP || {
      echo "relay-firewall.sh verify FAILED: $ipt missing catch-all UDP drop rule" >&2
      exit 1
    }
    in_ns "$ipt" -C "$CHAIN" -p tcp -j REJECT --reject-with tcp-reset || {
      echo "relay-firewall.sh verify FAILED: $ipt missing catch-all TCP reject rule" >&2
      exit 1
    }

    local rule_lines rule_count
    rule_lines=$(in_ns "$ipt" -S "$CHAIN" 2>&1) || {
      echo "relay-firewall.sh verify FAILED: $ipt chain $CHAIN does not exist (run 'apply' first)" >&2
      exit 1
    }
    rule_count=$(grep -c '^-A ' <<< "$rule_lines" || true)
    if [[ "$rule_count" -ne 7 ]]; then
      echo "relay-firewall.sh verify FAILED: $ipt chain $CHAIN has $rule_count rules, expected 7" >&2
      exit 1
    fi

    local input_hook
    input_hook=$(in_ns "$ipt" -S INPUT 2>/dev/null | sed -n '2p') || true
    if [[ "$input_hook" != "-A INPUT -i lo -j $CHAIN" ]]; then
      echo "relay-firewall.sh verify FAILED: $ipt INPUT hook is not '-A INPUT -i lo -j $CHAIN' (got: '$input_hook')" >&2
      exit 1
    fi
  done

  # Ephemeral port range must sit strictly above every protected port, so no
  # host-candidate (kernel-assigned) socket can ever land inside the relay
  # range or on TURN_PORT/a signal port and slip through as legitimate.
  local range low high
  range=$(in_ns cat /proc/sys/net/ipv4/ip_local_port_range) || true
  low=$(awk '{print $1}' <<< "$range")
  high=$(awk '{print $2}' <<< "$range")
  if [[ -z "$low" || -z "$high" ]]; then
    echo "relay-firewall.sh verify FAILED: could not parse ip_local_port_range ('$range')" >&2
    exit 1
  fi
  if (( low <= RELAY_MAX_PORT )); then
    echo "relay-firewall.sh verify FAILED: ephemeral port range starts at $low, which overlaps the relay range (<= $RELAY_MAX_PORT)" >&2
    exit 1
  fi
  if (( low <= TURN_PORT )); then
    echo "relay-firewall.sh verify FAILED: ephemeral port range starts at $low, which overlaps TURN_PORT ($TURN_PORT)" >&2
    exit 1
  fi
  local -a port_arr
  IFS=',' read -r -a port_arr <<< "$signal_ports"
  local p
  for p in "${port_arr[@]}"; do
    if (( low <= p )); then
      echo "relay-firewall.sh verify FAILED: ephemeral port range starts at $low, which overlaps signal port $p" >&2
      exit 1
    fi
  done

  echo "relay-firewall.sh verify OK"
}

cmd_clear() {
  require_root clear
  require_netns

  # netns.sh down deletes the whole namespace (and all its netfilter state)
  # between CI jobs, so this is really only needed for idempotent re-apply
  # and local iteration, not as mandatory CI teardown — CI's job steps
  # should still call it under `if: always()` for local-repro parity, but
  # this script doesn't need to assume it always will be.
  local ipt
  for ipt in iptables ip6tables; do
    while in_ns "$ipt" -D INPUT -i lo -j "$CHAIN" 2>/dev/null; do :; done
    in_ns "$ipt" -F "$CHAIN" 2>/dev/null || true
    in_ns "$ipt" -X "$CHAIN" 2>/dev/null || true
  done

  echo "relay-firewall.sh: cleared $CHAIN and its INPUT hook (both address families)"
}

cmd_stats() {
  require_root stats
  require_netns

  # -n: never resolve addresses. A non-zero DROP counter is visible evidence
  # that a direct path was attempted and blocked, without ever printing one.
  local ipt
  for ipt in iptables ip6tables; do
    echo "== $ipt -L $CHAIN -v -n -x --line-numbers =="
    in_ns "$ipt" -L "$CHAIN" -v -n -x --line-numbers
  done
}

case "${1:-}" in
  apply) shift; cmd_apply "$@" ;;
  verify) shift; cmd_verify "$@" ;;
  clear) cmd_clear ;;
  stats) cmd_stats ;;
  *) usage ;;
esac
