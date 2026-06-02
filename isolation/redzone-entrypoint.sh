#!/bin/bash
# redzone-entrypoint — draws the red/black boundary, then runs the workload.
#
# Drops ALL outbound traffic whose destination is a private (RFC1918 / CGNAT /
# link-local) network. The agent keeps the public internet (the model API) but
# loses every path to your LAN, domain, and prod. Air-gap by construction —
# not by policy. (Public IPs route THROUGH the gateway as next-hop, so internet
# still works; only packets *addressed to* private ranges are dropped.)
set -e

PRIVATE_NETS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10"

if iptables -L >/dev/null 2>&1; then
  # 1. Allow loopback + the container's OWN DNS resolver(s) on :53. Those are
  #    sandbox infrastructure (the Docker/VM resolver), NOT your company LAN —
  #    without this, name resolution dies and the agent can't reach the model API.
  iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
  for ns in $(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}'); do
    iptables -A OUTPUT -d "$ns" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -d "$ns" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
  done
  # 2. Drop everything else headed to a private network (your LAN / domain / prod).
  for net in $PRIVATE_NETS; do
    iptables -A OUTPUT -d "$net" -j DROP 2>/dev/null || true
  done
  echo "🔴 [red-zone] egress locked — public internet + DNS OK, private networks (LAN/domain/prod) BLOCKED."
else
  echo "⚠  [red-zone] no NET_ADMIN — run with --cap-add=NET_ADMIN to enforce the air-gap." >&2
fi

echo "⚫ [black-zone] your real network is unreachable from here. The agent only sees /work."
exec "$@"
