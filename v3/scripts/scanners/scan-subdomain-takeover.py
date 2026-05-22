"""Subdomain-takeover scanner — finds dangling CNAMEs pointing to claimable cloud services.

Method:
1. For each host (or subdomain), do CNAME lookup
2. If CNAME points to a known takeover-vulnerable platform (heroku, vercel, github.io, etc.)
3. Fetch the actual URL and check for the platform's "this site doesn't exist" page
4. If we see the takeover-fingerprint string, this CNAME is claimable

Ethical: passive DNS + HTTP HEAD/GET. Never registers the dangling target. Just records
the fingerprint match.
"""
import socket, urllib.request, urllib.error, ssl, json, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-SubTakeover/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "subdomain-takeover-v2.jsonl"

# Provider-specific takeover fingerprints (when target points to provider but app is gone)
TAKEOVER_FINGERPRINTS = {
    "heroku": {
        "cname_suffix": ("herokuapp.com", "herokussl.com", "herokudns.com"),
        "fingerprints": [
            b"No such app",
            b"There&#x27;s nothing here, yet",
            b"herokucdn.com/error-pages/no-such-app.html",
        ],
    },
    "github-pages": {
        "cname_suffix": ("github.io",),
        "fingerprints": [
            b"There isn&#39;t a GitHub Pages site here",
            b"Site not found",
        ],
    },
    "vercel": {
        "cname_suffix": ("vercel-dns.com", "vercel.app"),
        "fingerprints": [b"DEPLOYMENT_NOT_FOUND", b"NOT_FOUND"],
    },
    "netlify": {
        "cname_suffix": ("netlify.app", "netlify.com"),
        "fingerprints": [b"Not Found - Request ID", b"netlify-cdp"],
    },
    "fastly": {
        "cname_suffix": ("fastly.net",),
        "fingerprints": [b"Fastly error: unknown domain"],
    },
    "shopify": {
        "cname_suffix": ("myshopify.com", "shops.myshopify.com"),
        "fingerprints": [b"Sorry, this shop is currently unavailable"],
    },
    "tumblr": {
        "cname_suffix": ("tumblr.com",),
        "fingerprints": [b"Whatever you were looking for doesn&#39;t currently exist"],
    },
    "wordpress": {
        "cname_suffix": ("wordpress.com",),
        "fingerprints": [b"Do you want to register"],
    },
    "azure-web": {
        "cname_suffix": ("azurewebsites.net",),
        "fingerprints": [b"404 Web Site not found"],
    },
    "azure-cloudapp": {
        "cname_suffix": ("cloudapp.net", "cloudapp.azure.com"),
        "fingerprints": [b"NoSuchBucket", b"Site does not exist"],
    },
    "aws-s3": {
        "cname_suffix": ("amazonaws.com",),
        "fingerprints": [b"NoSuchBucket"],
    },
    "ghost": {
        "cname_suffix": ("ghost.io",),
        "fingerprints": [b"The thing you were looking for is no longer here"],
    },
    "zendesk": {
        "cname_suffix": ("zendesk.com",),
        "fingerprints": [b"Help Center Closed"],
    },
    "readme-io": {
        "cname_suffix": ("readme.io",),
        "fingerprints": [b"Project doesn't exist"],
    },
    "intercom": {
        "cname_suffix": ("intercom.help", "custom.intercom.help"),
        "fingerprints": [b"Uh oh. That page doesn't exist"],
    },
}


def get_cname(host):
    """Return CNAME chain for host or None."""
    try:
        # socket doesn't directly support CNAME, use a subprocess host call
        import subprocess
        result = subprocess.run(["host", host], capture_output=True, text=True, timeout=5)
        out = result.stdout
        # parse "host is an alias for X"
        m = re.findall(r"alias for\s+([^\s]+)", out)
        return m
    except Exception:
        return None


def fetch_get(url, timeout=8):
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(5000)
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(5000)
        except: return e.code, b""
    except Exception:
        return None, b""


def check_takeover(host):
    cnames = get_cname(host)
    if not cnames: return None
    cname_str = " ".join(cnames).lower().rstrip('.')
    for provider, cfg in TAKEOVER_FINGERPRINTS.items():
        if any(cs in cname_str for cs in cfg["cname_suffix"]):
            # Fetch the host to see if takeover fingerprint appears
            for scheme in ("https", "http"):
                st, body = fetch_get(f"{scheme}://{host}/")
                if not body: continue
                for fp in cfg["fingerprints"]:
                    if fp in body:
                        return {
                            "type": "subdomain-takeover",
                            "host": host,
                            "cname": cname_str,
                            "provider": provider,
                            "fingerprint_matched": fp.decode("utf-8", "replace")[:80],
                            "scheme": scheme,
                            "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        }
    return None


import sys
with open(sys.argv[1]) as f:
    hosts = [l.strip() for l in f if l.strip()][:int(sys.argv[2]) if len(sys.argv) > 2 else 10000]
print(f"[+] Subdomain-takeover scan — {len(hosts)} hosts (CNAME lookup + provider fingerprint check)", flush=True)
print(f"[+] Detects dangling CNAMEs on {len(TAKEOVER_FINGERPRINTS)} cloud providers", flush=True)
print(f"[+] Ethical: NEVER registers/claims dangling targets — only records fingerprint match", flush=True)
all_findings = []
completed = 0
with ThreadPoolExecutor(max_workers=15) as pool:
    futures = {pool.submit(check_takeover, h): h for h in hosts}
    for fut in as_completed(futures):
        completed += 1
        if completed % 250 == 0:
            print(f"  [{completed}/{len(hosts)}] hosts checked, {len(all_findings)} takeovers", flush=True)
        try:
            r = fut.result(timeout=20)
            if r:
                all_findings.append(r)
                print(f"  🔴🔴 TAKEOVER  {r['host']}  → CNAME {r['cname']}  provider={r['provider']}  fp='{r['fingerprint_matched'][:60]}'", flush=True)
        except Exception:
            pass

print(f"\n[+] Subdomain-takeover scan complete: {len(all_findings)} claimable", flush=True)
if all_findings:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for fi in all_findings: f.write(json.dumps(fi) + "\n")
    print(f"[+] Wrote to {LEDGER}", flush=True)
