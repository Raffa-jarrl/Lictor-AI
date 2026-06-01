#!/bin/bash
# scan-toggle — control Lictor scanning volume from one command.
#
# Built for ISP coordination: get them on the line, then flip scanning on/off
# so they can watch their alerts and tell you which mode is clean.
#
#   scan-toggle.sh off     fully silent — remove ALL Lictor cron, unload launchd, kill live scanners
#   scan-toggle.sh safe    ISP-SAFE only: GitHub-secret engine (GitHub API, not host scanning)
#                          + reply-monitor + morning-report. No host probing, no DNS floods.
#   scan-toggle.sh low     safe + LOW-VOLUME host probing (single-lane gentle-patrol, once daily)
#   scan-toggle.sh nightly safe + off-hours host probing (01/03/05h, ~1200 hosts/night)
#   scan-toggle.sh israel  safe + DNS-SAFE .il focus: passive crt.sh discovery + off-hours IL probe
#   scan-toggle.sh status  show what's enabled + what's running now
#
# PERMANENTLY EXCLUDED (the loud ones that drew the ISP):
#   - patrol-subdomain-takeover  (440k DNS lookups → "DNS infected" alarm)
#   - patrol-nuclei-cve / nuclei (vuln-scan → abuse reports)
#   - overnight-grinder.sh       (the */15 parallel swarm)
set -u
LIC="/Users/raffa/Lictor"
GHT='GH_TOKEN=$(cat /Users/raffa/.lictor/gh-token)'

# ── cron profiles (Gold + system crons are never touched) ──
read -r -d '' SAFE_BLOCK <<EOF || true
# ===== Lictor SAFE (ISP-safe: GitHub API + local only — no host/DNS scanning) =====
0 * * * * cd $LIC && $GHT /usr/bin/python3 scripts/lictor-hourly.py --per-hour 2 --max-per-day 24 >> /Users/raffa/.lictor/hourly.log 2>&1
0 */12 * * * cd $LIC && $GHT /usr/bin/python3 scripts/patrol-firebase.py --max 50 --max-age-days 365 >> /Users/raffa/.lictor/refresh.log 2>&1
30 */12 * * * cd $LIC && $GHT /usr/bin/python3 scripts/patrol-db-creds.py --max 30 --max-age-days 365 >> /Users/raffa/.lictor/refresh.log 2>&1
*/30 * * * * cd $LIC && /usr/bin/python3 scripts/reply-monitor.py >> /Users/raffa/.lictor/reply-monitor.log 2>&1
0 6 * * * cd $LIC && /usr/bin/python3 scripts/morning-report.py >> /Users/raffa/.lictor/morning-report.log 2>&1
# ===== end Lictor SAFE =====
EOF

read -r -d '' LOW_EXTRA <<EOF || true
# ===== Lictor LOW (single-lane throttled host probe, once daily — no takeover/swarm) =====
30 4 * * * cd $LIC && /bin/bash scripts/gentle-patrol.sh /Users/raffa/.lictor/bounty-corpus.txt 300 >> /Users/raffa/.lictor/gentle.log 2>&1
# ===== end Lictor LOW =====
EOF

read -r -d '' NIGHT_EXTRA <<EOF || true
# ===== Lictor NIGHTLY (off-hours host probe — 01:00/03:00/05:00 local, single-lane, gentle) =====
# Concentrated in the deep-night window: targets + NOCs asleep = fewest abuse reports.
# Each pass is idempotent (ledger-gated) so it advances to new hosts. ~1200 hosts/night.
0 1 * * * cd $LIC && /bin/bash scripts/gentle-patrol.sh /Users/raffa/.lictor/bounty-corpus.txt 400 >> /Users/raffa/.lictor/gentle.log 2>&1
0 3 * * * cd $LIC && /bin/bash scripts/gentle-patrol.sh /Users/raffa/.lictor/bounty-corpus.txt 400 >> /Users/raffa/.lictor/gentle.log 2>&1
0 5 * * * cd $LIC && /bin/bash scripts/gentle-patrol.sh /Users/raffa/.lictor/bounty-corpus.txt 400 >> /Users/raffa/.lictor/gentle.log 2>&1
# ===== end Lictor NIGHTLY =====
EOF

read -r -d '' ISRAEL_EXTRA <<EOF || true
# ===== Lictor ISRAEL (DNS-SAFE, .il-focused: passive crt.sh discovery + off-hours gentle probe) =====
# 00:30 — passive subdomain discovery for IL via crt.sh CT logs. ZERO DNS queries to targets,
#          NO brute-force, so it CANNOT trigger the ISP's DNS/NXDOMAIN alarm. Refreshes the surface.
30 0 * * * cd $LIC && /usr/bin/python3 scripts/passive-recon.py --apex /Users/raffa/.lictor/il-recon/il-apex.txt --out /Users/raffa/.lictor/il-recon/il-passive-subs.txt --sleep 5 >> /Users/raffa/.lictor/passive-il.log 2>&1
# 01:30 / 03:30 — gentle HEAD-first probe of the discovered IL surface (real hosts only, single-lane)
30 1 * * * cd $LIC && /bin/bash scripts/gentle-patrol.sh /Users/raffa/.lictor/il-recon/il-passive-subs.txt 500 >> /Users/raffa/.lictor/gentle-il.log 2>&1
30 3 * * * cd $LIC && /bin/bash scripts/gentle-patrol.sh /Users/raffa/.lictor/il-recon/il-passive-subs.txt 500 >> /Users/raffa/.lictor/gentle-il.log 2>&1
# ===== end Lictor ISRAEL =====
EOF

strip_lictor() { crontab -l 2>/dev/null | grep -vE "Lictor|\.lictor|Lictor SAFE|Lictor LOW"; }

kill_scanners() {
  pkill -9 -f "scripts/patrol-" 2>/dev/null
  pkill -9 -f overnight-grinder.sh 2>/dev/null
  pkill -9 -f "v3/scripts/scanners/scan-" 2>/dev/null
  for t in nuclei httpx subfinder dnsx; do pkill -9 -x $t 2>/dev/null; done
}

case "${1:-status}" in
  off)
    ( strip_lictor ) | crontab -
    for j in ai.lictor.globe-patrol ai.lictor.il-patrol; do launchctl bootout gui/$(id -u)/$j 2>/dev/null; done
    kill_scanners
    echo "[scan-toggle] OFF — all Lictor cron removed, launchd unloaded, scanners killed."
    ;;
  safe)
    ( strip_lictor; echo "$SAFE_BLOCK" ) | crontab -
    echo "[scan-toggle] SAFE — GitHub-secret engine + local jobs only. No host/DNS scanning."
    ;;
  low)
    ( strip_lictor; echo "$SAFE_BLOCK"; echo "$LOW_EXTRA" ) | crontab -
    echo "[scan-toggle] LOW — safe jobs + single-lane host probe (300 hosts/day). No takeover, no swarm."
    ;;
  nightly|offhours)
    ( strip_lictor; echo "$SAFE_BLOCK"; echo "$NIGHT_EXTRA" ) | crontab -
    echo "[scan-toggle] NIGHTLY — GitHub engine 24/7 + off-hours host probe (01/03/05h local, ~1200 hosts/night). No takeover, no swarm."
    ;;
  israel|il)
    ( strip_lictor; echo "$SAFE_BLOCK"; echo "$ISRAEL_EXTRA" ) | crontab -
    echo "[scan-toggle] ISRAEL — GitHub engine 24/7 + DNS-SAFE .il focus: passive crt.sh discovery (00:30) + off-hours gentle probe of the IL surface (01:30/03:30). No DNS brute-force, no takeover."
    ;;
  status)
    ;;
  *)
    echo "usage: scan-toggle.sh {off|safe|low|status}"; exit 1;;
esac

echo
echo "── cron (Lictor lines) ──"
crontab -l 2>/dev/null | grep -E "Lictor (SAFE|LOW)|lictor-hourly|patrol-firebase|patrol-db-creds|gentle-patrol|reply-monitor|morning-report" | sed 's/^/  /' || echo "  (none — fully off)"
echo "── scanners running now ──"
N=$(ps -eo args 2>/dev/null | grep -iE "nuclei|httpx|subfinder|dnsx|patrol-|scan-il|wave-coord|grinder|gentle-patrol" | grep -v grep | wc -l | tr -d ' ')
echo "  $N active"
echo "── subdomain-takeover (must always be 0) ──"
ps -eo args 2>/dev/null | grep -c "[p]atrol-subdomain-takeover" | sed 's/^/  /'
