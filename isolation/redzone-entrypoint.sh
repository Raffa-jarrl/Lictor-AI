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
  for net in $PRIVATE_NETS; do
    iptables -A OUTPUT -d "$net" -j DROP 2>/dev/null || true
  done
  echo "🔴 [red-zone] egress locked — public internet OK, private networks (LAN/domain/prod) BLOCKED."
else
  echo "⚠  [red-zone] no NET_ADMIN — run with --cap-add=NET_ADMIN to enforce the air-gap." >&2
fi

echo "⚫ [black-zone] your real network is unreachable from here. The agent only sees /work."
exec "$@"
