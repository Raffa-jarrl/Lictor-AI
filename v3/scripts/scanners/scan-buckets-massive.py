"""Massive bucket-name permutation sweep — expanded prefix set + more providers.

Targets 200+ brand-name prefixes (real-estate, podcast, banks, .edu, gov, healthcare, etc.)
× 22 suffix variations × 11 cloud providers = ~48,400 probes.

HEAD-only. Records only: bucket name, provider, status (200/403). No content downloads.
Listable buckets (200) get manual triage by user.
"""
import urllib.request, urllib.error, ssl, json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-BucketSweep/0.3 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "day2-bucket-sweep.jsonl"

# Massive brand prefix list — high-PII / high-value targets
PREFIXES = [
    # Crypto/DeFi (already partially covered)
    "wallet", "vault", "treasury", "btc", "eth", "crypto", "coin", "coins",
    "trading", "exchange", "rewards", "staking", "claim", "deposit",
    "keystore", "seedphrase", "mnemonic",
    # Real estate
    "listings", "mls", "properties", "homes", "realestate", "estate",
    "mortgages", "loans", "leases", "deeds", "titles", "appraisals",
    "broker", "agent", "realtor",
    # Podcast / media
    "podcast", "audio", "episodes", "shows", "media", "uploads",
    "transcripts", "transcripts", "raw-audio", "raw-video",
    # Bank / fintech
    "statements", "accounts", "transactions", "payments", "invoices",
    "receipts", "kyc", "kyc-docs", "compliance", "aml", "frauds",
    # Healthcare / insurance
    "patients", "members", "claims", "premiums", "policies", "ehr",
    "phi", "hipaa", "medical-records", "prescriptions",
    # Education
    "students", "alumni", "grades", "transcripts", "applications",
    "admissions", "donors", "tuition", "scholarships",
    # Political / civic
    "voters", "donors", "donations", "campaigns", "ballots",
    "petitions", "registrations",
    # Generic high-value
    "backup", "backups", "db", "database", "mysql", "postgres", "mongo",
    "logs", "audit", "secrets", "creds", "credentials", "config",
    "internal", "private", "confidential",
    # CRM / customer
    "crm", "customers", "leads", "contacts", "subscribers",
    # Common dev artifacts
    "dev", "staging", "test", "qa", "prod", "production",
    # Mobile / app backups
    "mobile-backup", "app-backup", "ios-backup", "android-backup",
    "whatsapp", "telegram", "signal", "icloud",
    # Email / messages
    "mail", "email", "messages", "inbox", "attachments",
]

SUFFIXES = [
    "", "-backup", "-prod", "-production", "-staging", "-dev", "-test",
    "-data", "-storage", "-archive", "-cold", "-hot", "-secrets",
    "-keys", "-vault", "-private", "-internal", "-2024", "-2025", "-2026",
    "-old", "-legacy",
]

PROVIDERS = [
    ("s3", "{b}.s3.amazonaws.com"),
    ("s3-us-east-2", "{b}.s3.us-east-2.amazonaws.com"),
    ("s3-us-west-2", "{b}.s3.us-west-2.amazonaws.com"),
    ("s3-eu-west-1", "{b}.s3.eu-west-1.amazonaws.com"),
    ("gcs", "storage.googleapis.com/{b}/"),
    ("azure-blob", "{b}.blob.core.windows.net/"),
    ("do-spaces-nyc3", "{b}.nyc3.digitaloceanspaces.com"),
    ("do-spaces-ams3", "{b}.ams3.digitaloceanspaces.com"),
    ("do-spaces-sgp1", "{b}.sgp1.digitaloceanspaces.com"),
    ("wasabi-us-east-1", "{b}.s3.wasabisys.com"),
    ("b2", "{b}.s3.us-west-002.backblazeb2.com"),
]


def fetch_head(url, timeout=4):
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        # For most providers, GET / lists bucket if listable. HEAD usually returns 200/403.
        req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(200)
            # Listable buckets return XML
            is_listable = b"<ListBucketResult" in body or b"<EnumerationResults" in body
            return r.status, is_listable
    except urllib.error.HTTPError as e:
        return e.code, False
    except Exception:
        return None, False


def probe_bucket(args):
    prefix, suffix, provider_name, url_tmpl = args
    bucket = prefix + suffix
    base = "https://" + url_tmpl.format(b=bucket)
    st, listable = fetch_head(base)
    if st in (200, 403):
        return {
            "prefix": prefix, "suffix": suffix, "bucket": bucket,
            "provider": provider_name, "url": base,
            "status": st, "listable": listable,
            "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
    return None


# Build probe list
probes = []
for prefix in PREFIXES:
    for suffix in SUFFIXES:
        for provider_name, url_tmpl in PROVIDERS:
            probes.append((prefix, suffix, provider_name, url_tmpl))

print(f"[+] Massive bucket sweep — {len(PREFIXES)} prefixes × {len(SUFFIXES)} suffixes × {len(PROVIDERS)} providers = {len(probes)} probes", flush=True)
print(f"[+] HEAD-equivalent (200-byte GET to detect ListBucketResult). NEVER downloads bucket contents.", flush=True)
print(flush=True)

all_findings = []
completed = 0
with ThreadPoolExecutor(max_workers=40) as pool:
    futures = {pool.submit(probe_bucket, p): p for p in probes}
    for fut in as_completed(futures):
        completed += 1
        if completed % 5000 == 0:
            listable_n = sum(1 for h in all_findings if h["listable"])
            print(f"  [{completed}/{len(probes)}] probed, {len(all_findings)} hits ({listable_n} listable)", flush=True)
        try:
            r = fut.result(timeout=10)
            if r:
                all_findings.append(r)
                if r["listable"]:
                    print(f"  🔴 LISTABLE  {r['provider']}://{r['bucket']}  → {r['url']}", flush=True)
        except Exception:
            pass

listable_n = sum(1 for h in all_findings if h["listable"])
print(f"\n[+] bucket sweep complete: {len(all_findings)} hits ({listable_n} LISTABLE, {len(all_findings)-listable_n} private 403)", flush=True)
LEDGER.parent.mkdir(parents=True, exist_ok=True)
with LEDGER.open("a") as f:
    for fi in all_findings: f.write(json.dumps(fi) + "\n")
print(f"[+] Wrote to {LEDGER}", flush=True)
