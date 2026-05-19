#!/usr/bin/env python3
"""
patrol-il — hunt vibe-coded Israeli (.co.il) sites and surface-scan them.

Discovery:
  1. Pull recent .co.il certs from crt.sh (last 90 days)
  2. Probe each for vibe-coding platform fingerprints (Vercel/Netlify/Lovable/Bolt/Render/Cloudflare Pages)
  3. Take first N

Scan: re-uses patrol-pilot scan functions (headers, exposed files, JS-bundle secrets, API probes).
"""
from __future__ import annotations
import argparse, json, re, sys, time, urllib.request, urllib.error, ssl
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent))
import importlib.util
spec = importlib.util.spec_from_file_location("pilot", Path(__file__).parent / "patrol-pilot.py")
pilot = importlib.util.module_from_spec(spec)
sys.modules["pilot"] = pilot
spec.loader.exec_module(pilot)

UA = "Lictor-Patrol-IL/0.1 (+https://lictorai.com/scan; raffa@lictor-ai.com)"
TIMEOUT = 8

VIBE_PLATFORM_HEADERS = {
    "server": ["vercel", "netlify", "cloudflare", "render"],
    "x-vercel-id": ["*"],
    "x-nf-request-id": ["*"],
    "x-powered-by": ["next.js", "express", "vercel"],
    "x-render-origin-server": ["*"],
}
VIBE_PLATFORM_BODY = [
    "lovable.dev", "lovable.app", "bolt.new", "v0.dev",
    "_next/static", "__NEXT_DATA__", "vercel-analytics",
    "supabase.co", "firebaseapp.com",
]

def crtsh_il(days=90, limit=2000):
    """Pull recent .co.il subjects from crt.sh."""
    url = "https://crt.sh/?q=.co.il&output=json"
    print(f"[+] crt.sh query: {url}", flush=True)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
    except Exception as e:
        print(f"[!] crt.sh fail: {e}", flush=True)
        return []
    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    hosts = set()
    for row in data:
        try:
            ts = datetime.fromisoformat(row.get("entry_timestamp", "").replace("Z","+00:00")).timestamp()
            if ts < cutoff: continue
        except Exception:
            continue
        for name in (row.get("name_value","") or "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(".co.il") and "@" not in name and " " not in name:
                hosts.add(name)
        if len(hosts) >= limit: break
    return sorted(hosts)

def probe(host):
    """Return ('vibe-platform-tag' or None, status, headers, body_snippet)."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
                headers = {k.lower(): v.lower() for k,v in r.headers.items()}
                body = r.read(80000)
                body_text = body.decode("utf-8","ignore").lower()
                tag = None
                for h, needles in VIBE_PLATFORM_HEADERS.items():
                    v = headers.get(h, "")
                    if v and (needles == ["*"] or any(n in v for n in needles)):
                        tag = f"hdr:{h}={v[:40]}"; break
                if not tag:
                    for needle in VIBE_PLATFORM_BODY:
                        if needle in body_text:
                            tag = f"body:{needle}"; break
                return (tag, r.status, headers, body)
        except Exception:
            continue
    return (None, 0, {}, b"")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=90)
    ap.add_argument("--max-discover", type=int, default=2000)
    ap.add_argument("--max-scan", type=int, default=100)
    ap.add_argument("--output", default=f"docs/launch/patrol-il-{datetime.now().strftime('%Y-%m-%d')}.md")
    ap.add_argument("--private", default=f"docs/launch/patrol-il-{datetime.now().strftime('%Y-%m-%d')}-private.md")
    args = ap.parse_args()

    print(f"[+] Discovering .co.il hosts from crt.sh (last {args.days}d)...", flush=True)
    hosts = crtsh_il(args.days, args.max_discover)
    # dedupe to apex+1 (drop deep subdomains beyond one level)
    seen = set(); shortlist = []
    for h in hosts:
        parts = h.split(".")
        if len(parts) > 4: continue  # skip foo.bar.baz.co.il
        if h in seen: continue
        seen.add(h); shortlist.append(h)
    print(f"[+] {len(shortlist)} candidate hosts; probing for vibe-platform fingerprints...", flush=True)

    vibe_targets = []
    for i, h in enumerate(shortlist):
        if len(vibe_targets) >= args.max_scan: break
        tag, status, headers, body = probe(h)
        marker = "🟢" if tag else "⚪"
        print(f"  [{i+1}/{len(shortlist)}] {h}  {marker} {tag or 'no-fp'} ({status})", flush=True)
        if tag:
            vibe_targets.append({"host": h, "platform": tag, "status": status})
        time.sleep(0.4)

    print(f"\n[+] {len(vibe_targets)} vibe-coded targets found. Scanning...", flush=True)

    results = []
    for i, t in enumerate(vibe_targets):
        homepage = f"https://{t['host']}/"
        print(f"  [scan {i+1}/{len(vibe_targets)}] {homepage}", end="", flush=True)
        try:
            r = pilot.scan_one({"full_name": t["host"], "homepage": homepage, "stargazers_count": 0,
                                "pushed_at": "", "platform": t["platform"]})
            results.append(r)
            crits = sum(1 for f in r.findings if f.severity in ("critical","high"))
            print(f"  grade={r.grade}  crit/high={crits}", flush=True)
        except Exception as e:
            print(f"  EXC: {e}", flush=True)
        time.sleep(2)

    n = pilot.render_report(results, args.output)
    print(f"\n[+] Wrote report → {args.output}  ({n} sites)")

    # Private summary
    crit_sites = [r for r in results if any(f.severity in ("critical","high") for f in r.findings)]
    md = [f"# Lictor Patrol IL — private triage ({datetime.now().strftime('%Y-%m-%d')})\n",
          f"**Discovered:** {len(shortlist)} hosts  |  **Vibe-coded:** {len(vibe_targets)}  |  **Scanned:** {len(results)}  |  **Crit/High findings:** {len(crit_sites)}\n",
          "## High-severity sites (private — do not paste publicly)\n",
          "| Host | Platform | Grade | Findings |", "|---|---|---|---|"]
    for r in sorted(crit_sites, key=lambda x: x.grade):
        finds = "; ".join(f"{f.severity}:{f.kind}" for f in r.findings if f.severity in ("critical","high"))
        md.append(f"| {r.repo} | {getattr(r,'platform','?')} | {r.grade} | {finds} |")
    Path(args.private).write_text("\n".join(md))
    print(f"[+] Private triage → {args.private}")

if __name__ == "__main__":
    main()
