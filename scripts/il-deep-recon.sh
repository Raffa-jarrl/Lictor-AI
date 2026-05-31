#!/bin/bash
# il-deep-recon — Israel external attack-surface mapping + deep validated scan.
#
# Turns our small IL host list into the full external surface, then runs the
# industry-standard detection stack over it. This is Pillar-3 (Patrol) work:
# an EXTERNAL SECURITY SCANNER, not an attack tool.
#
# ETHICS — non-negotiable, same discipline as every Lictor scanner:
#   • DETECTION ONLY. nuclei runs with intrusive/fuzz/DoS/brute templates
#     EXCLUDED. We observe whether an issue is PRESENT; we never exploit it.
#   • Rate-limited + capped concurrency — gentle on every host.
#   • subfinder is passive (cert-transparency / passive DNS) — barely touches
#     the targets.
#   • Draft-only: writes local ledgers. Sends nothing. Raffa reviews + Submits.
#   • Aggregate-only on any public surface; never name an affected party.
#
# Stages: apex → subfinder → dnsx(resolve) → httpx(alive) → nuclei(detect)
#         + dnsx(cname) → takeover candidates.
set -u
cd /Users/raffa/Lictor || exit 1
PY=/usr/bin/python3
DATE=$(date +%F)
OUT="$HOME/.lictor/il-recon"
mkdir -p "$OUT"
LOG="$OUT/recon-$DATE.log"
# trusted public resolver pool — spread DNS load so no single resolver (or any
# target's authoritative NS) is hammered. Created if absent.
[ -s "$OUT/resolvers.txt" ] || printf '1.1.1.1\n1.0.0.1\n8.8.8.8\n8.8.4.4\n9.9.9.9\n149.112.112.112\n208.67.222.222\n208.67.220.220\n' > "$OUT/resolvers.txt"
# severity gate (override with: SEV=medium,high,critical il-deep-recon.sh)
SEV="${SEV:-high,critical}"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

log "════════ il-deep-recon $DATE  sev=$SEV ════════"

# ── Stage 1: extract unique IL apex domains from the master ──
"$PY" - <<'PY' > "$OUT/il-apex.txt"
from pathlib import Path
hosts=[h.strip() for h in (Path.home()/".lictor"/"il-master.txt").read_text().splitlines() if h.strip()]
apex=set()
for h in hosts:
    p=h.split(".")
    if len(p)>=3 and p[-2] in ("co","org","gov","ac","net","muni","k12","idf"):
        apex.add(".".join(p[-3:]))
    elif len(p)>=2:
        apex.add(".".join(p[-2:]))
print("\n".join(sorted(apex)))
PY
log "apex domains: $(wc -l < "$OUT/il-apex.txt" | tr -d ' ')"

# ── Stage 2: subfinder — passive subdomain enumeration ──
log "subfinder enumerating (passive)…"
subfinder -dL "$OUT/il-apex.txt" -all -silent 2>>"$LOG" | sort -u > "$OUT/il-subs.txt"
# fold in the known master so we never lose a host
cat "$HOME/.lictor/il-master.txt" >> "$OUT/il-subs.txt"
sort -u "$OUT/il-subs.txt" -o "$OUT/il-subs.txt"
log "subdomains discovered: $(wc -l < "$OUT/il-subs.txt" | tr -d ' ')"

# ── Stage 3: dnsx — keep only the ones that resolve (rate-limited, spread) ──
# We resolve ONLY the real subdomains subfinder already found (never a guessed
# wordlist), via public recursive resolvers, capped at 150 q/s across 8
# resolvers — gentle, never a DNS flood against any authoritative nameserver.
log "dnsx resolving (rl=150, 8-resolver spread, no brute-force)…"
dnsx -l "$OUT/il-subs.txt" -silent -t 25 -rl 150 -r "$OUT/resolvers.txt" 2>>"$LOG" | sort -u > "$OUT/il-resolved.txt"
log "resolvable hosts: $(wc -l < "$OUT/il-resolved.txt" | tr -d ' ')"

# ── Stage 4: httpx — which are live web servers (1 req/host, rate-limited) ──
log "httpx probing live web hosts…"
httpx -l "$OUT/il-resolved.txt" -silent -rl 80 -timeout 8 \
      -json -o "$OUT/il-httpx-$DATE.jsonl" 2>>"$LOG"
# extract just the URLs for nuclei
"$PY" - "$OUT/il-httpx-$DATE.jsonl" <<'PY' > "$OUT/il-alive.txt"
import json,sys
seen=set()
for line in open(sys.argv[1]):
    try: u=json.loads(line).get("url")
    except: u=None
    if u and u not in seen: seen.add(u); print(u)
PY
log "live web hosts: $(wc -l < "$OUT/il-alive.txt" | tr -d ' ')"

# ── Stage 5: nuclei — DETECTION ONLY, intrusive templates excluded ──
log "nuclei detection scan (sev=$SEV, intrusive/fuzz/dos/brute EXCLUDED)…"
nuclei -l "$OUT/il-alive.txt" \
       -severity "$SEV" \
       -exclude-tags fuzz,dos,brute,intrusive \
       -rate-limit 60 -c 30 -timeout 8 -retries 1 \
       -jsonl -o "$OUT/il-nuclei-$DATE.jsonl" \
       -stats -stats-interval 60 2>>"$LOG"
NHITS=$( [ -f "$OUT/il-nuclei-$DATE.jsonl" ] && wc -l < "$OUT/il-nuclei-$DATE.jsonl" | tr -d ' ' || echo 0 )
log "nuclei findings: $NHITS  → $OUT/il-nuclei-$DATE.jsonl"

# ── Stage 6: takeover candidates — dnsx CNAME extraction ──
log "dnsx extracting CNAMEs for takeover review (rl=150, spread)…"
dnsx -l "$OUT/il-subs.txt" -silent -cname -resp -t 25 -rl 150 -r "$OUT/resolvers.txt" 2>>"$LOG" > "$OUT/il-cnames-$DATE.txt"
log "CNAME records: $(wc -l < "$OUT/il-cnames-$DATE.txt" | tr -d ' ')  → $OUT/il-cnames-$DATE.txt"

# ── Summary by severity ──
log "──────── SUMMARY ────────"
if [ -f "$OUT/il-nuclei-$DATE.jsonl" ]; then
  "$PY" - "$OUT/il-nuclei-$DATE.jsonl" <<'PY' | tee -a "$LOG"
import json,sys,collections
sev=collections.Counter(); names=collections.Counter()
for line in open(sys.argv[1]):
    try: d=json.loads(line)
    except: continue
    sev[d.get("info",{}).get("severity","?")]+=1
    names[d.get("template-id","?")]+=1
print("  by severity:", dict(sev))
print("  top templates:")
for t,c in names.most_common(12): print(f"    {c:>4}  {t}")
PY
fi
log "════════ done $DATE ════════"
