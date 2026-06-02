#!/bin/bash
# run-redzone — launch the Lictor red-zone AI sandbox.
#
#   ./run-redzone.sh <project-dir> [-- <command...>]
#
# Runs <command> (default: a shell) inside the red zone:
#   - only <project-dir> is visible to the agent (mounted at /work)
#   - all egress to private networks (your LAN / domain / prod) is DROPPED
#   - the model API on the public internet still works
#
# This is the turnkey "off your real network" box the Isolation spec promises —
# in container form, shippable today (the VM/USB-OS form is the heavier roadmap).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

PROJECT="${1:?usage: run-redzone.sh <project-dir> [-- <command...>]}"; shift || true
[ "${1:-}" = "--" ] && shift || true
PROJECT_ABS="$(cd "$PROJECT" && pwd)"

echo "[run-redzone] building red-zone image…"
docker build -q -t lictor-redzone "$HERE" >/dev/null

echo "[run-redzone] launching — project=$PROJECT_ABS"
exec docker run --rm -it \
  --cap-add=NET_ADMIN \
  --dns 1.1.1.1 --dns 8.8.8.8 \
  --hostname lictor-redzone \
  -v "$PROJECT_ABS":/work \
  -w /work \
  lictor-redzone "${@:-bash}"
