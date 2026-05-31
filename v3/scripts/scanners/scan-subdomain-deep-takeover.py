#!/usr/bin/env python3
"""scan-subdomain-deep-takeover.py — Full 4-step subdomain takeover hunt.

PIPELINE:
  Step 1: Enumerate subdomains via crt.sh certificate transparency logs
  Step 2: For each subdomain, look up CNAME / A record
  Step 3: For dangling CNAMEs, fingerprint the cloud provider's
          "this site doesn't exist" page → claimable
  Step 4: (manual) Validate impact — Lictor doesn't auto-claim
          dangling resources. We REPORT, we don't take over.

ETHICAL:
  - Public crt.sh data (already-published TLS certs)
  - Passive DNS lookup
  - HTTP GET to fingerprint provider error pages (public CDN responses)
  - NEVER registers/claims any dangling target
  - Even attempted takeover would be illegal without authorization
"""
import json, socket, urllib.request, urllib.error, time, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "LictorAI-EthicalScanner/0.4 (+https://lictor-ai.com/transparency)"
LEDGER = Path.home() / "Lictor/v3/ledgers/subdomain-takeover-deep.jsonl"

# Comprehensive fingerprint catalog (per can-i-take-over-xyz)
TAKEOVER_PROVIDERS = {
    "github.io":          [b"There isn't a GitHub Pages site here", b"For root URLs"],
    "herokuapp.com":      [b"No such app", b"no-such-app"],
    "herokudns.com":      [b"No such app"],
    "herokussl.com":      [b"No such app"],
    "vercel.app":         [b"The deployment could not be found"],
    "now.sh":             [b"The deployment could not be found"],
    "netlify.app":        [b"Not Found - Request ID:"],
    "netlify.com":        [b"Not Found - Request ID:"],
    "azurewebsites.net":  [b"Error 404 - Web app not found"],
    "cloudapp.azure.com": [b"404 Web Site not found"],
    "amazonaws.com":      [b"NoSuchBucket", b"The specified bucket does not exist"],
    "s3.amazonaws.com":   [b"NoSuchBucket"],
    "ghost.io":           [b"Domain error"],
    "tumblr.com":         [b"There's nothing here.", b"Whatever you were looking for"],
    "wordpress.com":      [b"Do you want to register"],
    "readthedocs.io":     [b"unknown to Read the Docs"],
    "surge.sh":           [b"project not found"],
    "tilda.cc":           [b"Please renew your subscription"],
    "fastly.net":         [b"Fastly error: unknown domain"],
    "pantheon.io":        [b"The gods are wise, but do not know"],
    "shopify.com":        [b"Sorry, this shop is currently unavailable"],
    "bigcartel.com":      [b"Oops! We could&#8217;t find that page"],
    "zendesk.com":        [b"Help Center Closed"],
    "uservoice.com":      [b"This UserVoice subdomain is currently available"],
    "wpengine.com":       [b"The site you were looking for couldn"],
    "fly.io":             [b"404 Not Found", b"Frankfurt", b"Render error"],
    "render.com":         [b"x-render-routing", b"Not Found"],
}


def crt_sh_subdomains(domain, timeout=20):
    """Pull subdomains from crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            data = json.loads(body)
            subs = set()
            for entry in data:
                names = (entry.get("name_value", "") or entry.get("common_name", ""))
                for n in names.split("\n"):
                    n = n.strip().lower()
                    if n.startswith("*."):
                        n = n[2:]
                    if n and "." in n and not n.startswith("//"):
                        subs.add(n)
            return list(subs)
    except Exception:
        return []


def get_cname(host, timeout=5):
    """DNS CNAME lookup. Returns target or None."""
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=1", "CNAME", host],
            capture_output=True, text=True, timeout=timeout
        )
        cname = result.stdout.strip().rstrip(".")
        return cname if cname else None
    except Exception:
        return None


def check_dangling_provider(cname):
    """Does this CNAME match a known takeover-vulnerable provider?"""
    cname_lower = cname.lower()
    for provider, _fingerprints in TAKEOVER_PROVIDERS.items():
        if cname_lower.endswith(provider) or provider in cname_lower:
            return provider
    return None


def fetch_and_fingerprint(host, provider, timeout=10):
    """Step 3: GET the host, check if response contains provider's
    'this site doesn't exist' fingerprint."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(8192)
                for fp in TAKEOVER_PROVIDERS.get(provider, []):
                    if fp in body:
                        return True, fp.decode("latin-1", "replace"), url
        except urllib.error.HTTPError as e:
            try:
                body = e.read(8192)
                for fp in TAKEOVER_PROVIDERS.get(provider, []):
                    if fp in body:
                        return True, fp.decode("latin-1", "replace"), url
            except:
                pass
        except Exception:
            continue
    return False, None, None


def process_subdomain(sub):
    """Full 4-step check on one subdomain."""
    cname = get_cname(sub)
    if not cname:
        return None
    provider = check_dangling_provider(cname)
    if not provider:
        return None
    # Step 3: fingerprint verification
    claimable, fp, url = fetch_and_fingerprint(sub, provider)
    if claimable:
        return {
            "subdomain": sub,
            "cname": cname,
            "provider": provider,
            "fingerprint_matched": fp,
            "url_checked": url,
            "tier": "POTENTIAL-CLAIMABLE",
            "severity": "HIGH-MAYBE-CRITICAL",
            "note": "Step 4 (impact validation — cookie scope, in-scope check) requires manual review",
            "discovered_at": datetime.now(timezone.utc).isoformat(),
        }
    # CNAME points to takeover provider but no fingerprint — could be live app
    return {
        "subdomain": sub,
        "cname": cname,
        "provider": provider,
        "claimable": False,
        "tier": "INFO",
        "note": "CNAME points to vulnerable provider but app appears live",
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: scan-subdomain-deep-takeover.py <corpus.txt> [limit]")
        sys.exit(1)
    corpus = Path(sys.argv[1])
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 999

    hosts = [l.strip() for l in corpus.read_text().splitlines() if l.strip()][:limit]
    print(f"[+] Deep subdomain takeover hunt — {len(hosts)} apex domains")
    print(f"[+] Pipeline: crt.sh enum → CNAME check → provider fingerprint")
    print(f"[+] Ledger: {LEDGER}")
    print()

    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    total_subs = 0
    findings = []

    with open(LEDGER, "a") as out:
        for i, host in enumerate(hosts, 1):
            print(f"  [{i:>3}/{len(hosts)}] {host}", end=" ", flush=True)
            # Strip scheme/path
            host = host.replace("https://","").replace("http://","").split("/")[0]
            # Extract just the apex (e.g. app.aave.com → aave.com)
            parts = host.split(".")
            if len(parts) >= 2:
                apex = ".".join(parts[-2:])
            else:
                apex = host

            subs = crt_sh_subdomains(apex)
            total_subs += len(subs)
            print(f"({len(subs)} subdomains)", end=" ", flush=True)

            if not subs:
                print("[no data]", flush=True)
                continue

            host_findings = 0
            with ThreadPoolExecutor(max_workers=20) as ex:
                futs = {ex.submit(process_subdomain, s): s for s in subs[:200]}  # cap per-host
                for fut in as_completed(futs):
                    try:
                        r = fut.result()
                        if r:
                            out.write(json.dumps(r) + "\n")
                            out.flush()
                            if r.get("tier") == "POTENTIAL-CLAIMABLE":
                                host_findings += 1
                                findings.append(r)
                    except Exception:
                        pass

            if host_findings > 0:
                print(f"🔴 {host_findings} CLAIMABLE!", flush=True)
            else:
                print(f"clean", flush=True)

            time.sleep(2)  # crt.sh rate-limit politeness

    print()
    print("=" * 70)
    print("DEEP SUBDOMAIN TAKEOVER SUMMARY")
    print("=" * 70)
    print(f"  Apex domains scanned: {len(hosts)}")
    print(f"  Subdomains enumerated: {total_subs}")
    print(f"  Potential claimable: {len(findings)}")
    if findings:
        print()
        print("🔴 CLAIMABLE FINDINGS — manual Step 4 needed:")
        for f in findings:
            print(f"  {f['subdomain']:<50} → {f['provider']} (fingerprint: {f['fingerprint_matched'][:50]})")
    print()
    print(f"[+] Ledger: {LEDGER}")


if __name__ == "__main__":
    main()
