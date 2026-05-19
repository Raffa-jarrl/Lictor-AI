#!/usr/bin/env python3
"""
patrol-subdomain-takeover — scanner #17.

Discovers dangling subdomain takeovers for bug-bounty companies.

What it does:
  1. For each bounty-program company, pull their public subdomains
     from crt.sh (Certificate Transparency logs)
  2. For each subdomain, resolve DNS — look for CNAMEs pointing at
     known-vulnerable provider patterns (S3, Heroku, GitHub Pages,
     Azure Cloud App, Fastly, Netlify, Vercel, Tumblr, Shopify, etc.)
  3. For each CNAME match, fetch the target URL and check for the
     provider's "not-claimed" fingerprint (e.g., "NoSuchBucket",
     "There isn't a GitHub Pages site here", etc.)
  4. Confirmed takeovers → bounty queue

Why this works for revenue:
  - Bounty programs explicitly accept subdomain takeovers
  - Payouts: $250-$5K per finding
  - Triage is usually fast (1-7 days)
  - Pattern coverage is well-known (https://github.com/EdOverflow/can-i-take-over-xyz)

Cron: 0 6 * * *  (daily, before bounty-hunter)
"""
from __future__ import annotations
import argparse, json, re, socket, subprocess, sys, time, urllib.request, urllib.error, ssl
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-SubdomainPatrol/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / ".lictor" / "subdomain-takeover-ledger.jsonl"
OUT_DIR = Path.home() / "Lictor" / "docs" / "launch"

# Fingerprints from can-i-take-over-xyz + manual additions.
# Each entry: (CNAME pattern → response pattern indicating not-claimed)
TAKEOVER_FINGERPRINTS = [
    {"provider": "AWS/S3",          "cname_rx": re.compile(r's3[.-].*?\.amazonaws\.com', re.I),  "body_rx": re.compile(r'(NoSuchBucket|The specified bucket does not exist)', re.I)},
    {"provider": "GitHub Pages",    "cname_rx": re.compile(r'github\.io',                  re.I), "body_rx": re.compile(r"There isn't a GitHub Pages site here|For root URLs", re.I)},
    {"provider": "Heroku",          "cname_rx": re.compile(r'herokuapp\.com|herokudns',   re.I),  "body_rx": re.compile(r"No such app|There's nothing here", re.I)},
    {"provider": "Fastly",          "cname_rx": re.compile(r'fastly\.net',                 re.I), "body_rx": re.compile(r"Fastly error: unknown domain", re.I)},
    {"provider": "Tumblr",          "cname_rx": re.compile(r'domains\.tumblr\.com',        re.I), "body_rx": re.compile(r"There's nothing here|Whatever you were looking for", re.I)},
    {"provider": "Shopify",         "cname_rx": re.compile(r'myshopify\.com',              re.I), "body_rx": re.compile(r"Sorry, this shop is currently unavailable", re.I)},
    {"provider": "Pantheon",        "cname_rx": re.compile(r'pantheonsite\.io|pantheon\.io', re.I), "body_rx": re.compile(r"The gods are wise|404 not found", re.I)},
    {"provider": "Tilda",           "cname_rx": re.compile(r'tilda\.ws',                   re.I), "body_rx": re.compile(r"Please renew your subscription", re.I)},
    {"provider": "Ghost",           "cname_rx": re.compile(r'ghost\.io',                   re.I), "body_rx": re.compile(r"The thing you were looking for is no longer here", re.I)},
    {"provider": "Statuspage",      "cname_rx": re.compile(r'statuspage\.io',              re.I), "body_rx": re.compile(r"You are being.*redirected.*statuspage", re.I)},
    {"provider": "Surge.sh",        "cname_rx": re.compile(r'surge\.sh',                   re.I), "body_rx": re.compile(r"project not found", re.I)},
    {"provider": "Unbounce",        "cname_rx": re.compile(r'unbouncepages\.com',          re.I), "body_rx": re.compile(r"The requested URL was not found", re.I)},
    {"provider": "HelpJuice",       "cname_rx": re.compile(r'helpjuice\.com',              re.I), "body_rx": re.compile(r"We could not find what you're looking for", re.I)},
    {"provider": "HelpScout",       "cname_rx": re.compile(r'helpscoutdocs\.com',          re.I), "body_rx": re.compile(r"No settings were found for this company", re.I)},
    {"provider": "Cargo",           "cname_rx": re.compile(r'cargocollective\.com',        re.I), "body_rx": re.compile(r"404 Not Found", re.I)},
    {"provider": "Webflow",         "cname_rx": re.compile(r'proxy.*?\.webflow\.com',      re.I), "body_rx": re.compile(r"The page you are looking for doesn't exist", re.I)},
    {"provider": "Acquia",          "cname_rx": re.compile(r'acquia-sites\.com',           re.I), "body_rx": re.compile(r"The site you are looking for could not be found", re.I)},
    {"provider": "Bitbucket",       "cname_rx": re.compile(r'bitbucket\.io',               re.I), "body_rx": re.compile(r"Repository not found", re.I)},
    {"provider": "Smartling",       "cname_rx": re.compile(r'smartling\.com',              re.I), "body_rx": re.compile(r"Domain is not configured", re.I)},
    {"provider": "Wordpress",       "cname_rx": re.compile(r'wordpress\.com',              re.I), "body_rx": re.compile(r"Do you want to register .*?\.wordpress\.com\?", re.I)},
    {"provider": "Vercel",          "cname_rx": re.compile(r'vercel-dns\.com|cname\.vercel-dns', re.I), "body_rx": re.compile(r"The deployment could not be found|404: NOT_FOUND.*?DEPLOYMENT_NOT_FOUND", re.I)},
    {"provider": "Netlify",         "cname_rx": re.compile(r'netlify\.app|netlify\.com',   re.I), "body_rx": re.compile(r"Not Found - Request ID:", re.I)},
]

# Domain seeds for bounty-program companies (apex + key subdomains)
BOUNTY_DOMAINS = [
    # Mid-tier — less coverage, faster triage
    "sentry.io", "posthog.com", "plaid.com", "figma.com", "notion.so",
    "linear.app", "cal.com", "documenso.com", "trigger.dev", "inngest.com",
    "anthropic.com", "openai.com", "langchain.com", "pinecone.io", "weaviate.io",
    "buildkite.com", "circleci.com", "datadoghq.com", "snyk.io", "supabase.com",
    "vercel.com", "netlify.com", "brex.com", "mercury.com", "ramp.com",
    # Higher-tier (more competition, but also bigger surface)
    "stripe.com", "shopify.com", "cloudflare.com", "atlassian.com", "discord.com",
    "hashicorp.com", "elastic.co", "mongodb.com", "twilio.com",
    "intercom.com", "zendesk.com", "okta.com", "auth0.com", "asana.com",
]


@dataclass
class Takeover:
    domain: str
    subdomain: str
    cname: str
    provider: str
    company: str
    confirmed_at: str
    body_snippet: str = ""


def crtsh_subdomains(domain: str, limit: int = 200) -> list[str]:
    """crt.sh (often flaky)."""
    try:
        req = urllib.request.Request(f"https://crt.sh/?q=%25.{domain}&output=json", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
    except Exception:
        return []
    hosts = set()
    for row in data:
        for name in (row.get("name_value", "") or "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(f".{domain}") and "@" not in name and " " not in name:
                hosts.add(name)
        if len(hosts) >= limit: break
    return sorted(hosts)


def hackertarget_subdomains(domain: str, limit: int = 200) -> list[str]:
    """hackertarget free tier (no key needed, ~100/day rate limit)."""
    try:
        req = urllib.request.Request(f"https://api.hackertarget.com/hostsearch/?q={domain}", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read().decode("utf-8", "replace")
    except Exception:
        return []
    hosts = set()
    for line in text.splitlines():
        if "," in line:
            host = line.split(",")[0].strip().lower()
            if host.endswith(f".{domain}") or host == domain:
                hosts.add(host)
        if len(hosts) >= limit: break
    return sorted(hosts)


def certspotter_subdomains(domain: str, limit: int = 200) -> list[str]:
    """Certspotter CT log API (free, no auth needed)."""
    try:
        req = urllib.request.Request(
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
            headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
    except Exception:
        return []
    hosts = set()
    for entry in data:
        for name in entry.get("dns_names", []):
            n = name.strip().lower().lstrip("*.")
            if n.endswith(f".{domain}") and "@" not in n:
                hosts.add(n)
        if len(hosts) >= limit: break
    return sorted(hosts)


def get_subdomains(domain: str, limit: int = 200) -> list[str]:
    """Try all 3 sources in parallel-ish, dedupe, return."""
    all_hosts = set()
    for fn, label in [(crtsh_subdomains, "crt.sh"),
                       (hackertarget_subdomains, "hackertarget"),
                       (certspotter_subdomains, "certspotter")]:
        try:
            hits = fn(domain, limit)
            if hits:
                all_hosts.update(hits)
                print(f"    {label}: {len(hits)}", flush=True)
            else:
                print(f"    {label}: 0", flush=True)
        except Exception as e:
            print(f"    {label}: err {e}", flush=True)
        time.sleep(0.5)
    return sorted(all_hosts)[:limit]


def resolve_cname(host: str) -> str:
    """Get the CNAME target for a hostname (1 query)."""
    try:
        import dns.resolver
        try:
            resp = dns.resolver.resolve(host, "CNAME", lifetime=5)
            return str(resp[0].target).rstrip(".")
        except Exception:
            return ""
    except ImportError:
        # Fallback: use `dig` if available
        try:
            out = subprocess.check_output(["dig", "+short", "CNAME", host], stderr=subprocess.DEVNULL, timeout=5)
            line = out.decode().strip().splitlines()[0] if out.strip() else ""
            return line.rstrip(".")
        except Exception:
            return ""


def fetch_body(host: str) -> str:
    """Fetch http(s)://host and return body snippet (1 request)."""
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}/", headers={"User-Agent": UA})
            ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                return r.read(20000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            try: return e.read(20000).decode("utf-8", "replace")
            except: pass
        except Exception:
            continue
    return ""


def load_ledger() -> set:
    if not LEDGER.exists(): return set()
    seen = set()
    for line in LEDGER.read_text().splitlines():
        if line.strip():
            try: seen.add(json.loads(line)["subdomain"])
            except: pass
    return seen


def append_ledger(t: Takeover):
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        f.write(json.dumps(asdict(t)) + "\n")


def check_one(host: str, company: str) -> Takeover | None:
    cname = resolve_cname(host)
    if not cname: return None
    for fp in TAKEOVER_FINGERPRINTS:
        if fp["cname_rx"].search(cname):
            # Found vulnerable-provider CNAME — fetch body to confirm
            body = fetch_body(host)
            if fp["body_rx"].search(body):
                return Takeover(
                    domain=host.split(".", 1)[1] if "." in host else host,
                    subdomain=host, cname=cname, provider=fp["provider"],
                    company=company,
                    confirmed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    body_snippet=body[:200].replace("\n", " "),
                )
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-domains", type=int, default=10, help="how many bounty domains to scan this run")
    ap.add_argument("--max-subs-per-domain", type=int, default=100)
    args = ap.parse_args()

    seen = load_ledger()
    print(f"[+] ledger: {len(seen)} prior subdomains scanned")

    targets = BOUNTY_DOMAINS[:args.max_domains]
    confirmed = []
    for ci, domain in enumerate(targets, 1):
        company = domain.replace(".com", "").replace(".io", "").replace(".so", "").replace(".app", "").replace(".dev", "").replace(".co", "")
        print(f"\n[{ci}/{len(targets)}] {domain} — pulling subdomains (3 sources)...", flush=True)
        subs = get_subdomains(domain, args.max_subs_per_domain)
        new_subs = [s for s in subs if s not in seen]
        print(f"  {len(subs)} total, {len(new_subs)} new (after ledger dedup)")
        if not new_subs: continue

        for si, sub in enumerate(new_subs[:args.max_subs_per_domain], 1):
            try:
                t = check_one(sub, company)
                seen.add(sub)
                if t:
                    print(f"  🔴🔴 TAKEOVER  {sub}  →  {t.cname}  ({t.provider})")
                    append_ledger(t)
                    confirmed.append(t)
                else:
                    pass  # too noisy to print each
            except Exception as e:
                pass
            time.sleep(0.15)  # be polite to DNS

        time.sleep(1.5)

    # Summary
    print(f"\n[+] scan complete: {len(confirmed)} NEW takeovers confirmed")
    if confirmed:
        out_path = OUT_DIR / f"takeovers-{datetime.now().strftime('%Y-%m-%d')}-private.md"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w") as f:
            f.write(f"# Subdomain takeovers — {datetime.now().strftime('%Y-%m-%d')}\n\n")
            f.write(f"**Confirmed:** {len(confirmed)}\n\n")
            f.write("| Subdomain | CNAME | Provider | Company |\n|---|---|---|---|\n")
            for t in confirmed:
                f.write(f"| `{t.subdomain}` | `{t.cname}` | **{t.provider}** | {t.company} |\n")
        print(f"    → {out_path}")


if __name__ == "__main__":
    main()
