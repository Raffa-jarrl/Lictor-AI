"""Day 3 bucket sweep — EDU + MENA + healthcare + insurance + airlines prefixes."""
import urllib.request, urllib.error, ssl, json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-BucketSweepD3/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "day3-bucket-sweep.jsonl"

# Day-3 specific prefixes (NEW, complement Day 2)
PREFIXES = [
    # EDU
    "students", "alumni", "grades", "transcripts", "applications", "admissions",
    "donors", "tuition", "scholarships", "courses", "lectures",
    "lms", "canvas", "moodle", "blackboard", "schoology", "powerschool",
    "edu", "school", "university", "college", "campus",
    # Healthcare
    "patients", "claims", "medical", "ehr", "phi", "hipaa", "rx",
    "prescriptions", "diagnoses", "lab-results", "imaging", "radiology",
    "telehealth", "healthplan",
    # Insurance
    "claims", "premiums", "policies", "underwriting", "actuarial",
    "auto-claims", "health-claims", "home-claims",
    # MENA (Arabic / regional)
    "uae", "ksa", "qatar", "kuwait", "bahrain", "oman", "lebanon", "jordan",
    "dubai", "abu-dhabi", "riyadh", "doha", "kuwait-city",
    "etisalat", "stc", "ooredoo", "zain", "batelco", "du",
    "alrajhi", "fab", "qnb", "adcb", "snb",
    # Airlines (massive PII)
    "passengers", "bookings", "reservations", "boarding", "manifest",
    "flights", "tickets", "loyalty", "miles", "frequent-flyer",
    "emirates", "etihad", "qatar-airways", "gulf-air",
    # AI / data infrastructure
    "training-data", "ai-data", "model-weights", "datasets",
    "embeddings", "checkpoints", "ml-prod", "ml-staging",
    # Software supply chain
    "build-artifacts", "ci-cd", "ci-cache", "deployer", "release",
    "signing-keys", "private-pkg", "internal-pkg",
]

SUFFIXES = [
    "", "-prod", "-production", "-staging", "-dev", "-test", "-qa",
    "-backup", "-data", "-storage", "-archive", "-private", "-internal",
    "-2024", "-2025", "-2026", "-leak", "-export",
]

PROVIDERS = [
    ("s3", "{b}.s3.amazonaws.com"),
    ("s3-us-east-2", "{b}.s3.us-east-2.amazonaws.com"),
    ("s3-eu-west-1", "{b}.s3.eu-west-1.amazonaws.com"),
    ("s3-ap-southeast-1", "{b}.s3.ap-southeast-1.amazonaws.com"),
    ("s3-me-south-1", "{b}.s3.me-south-1.amazonaws.com"),  # Bahrain region
    ("s3-me-central-1", "{b}.s3.me-central-1.amazonaws.com"),  # UAE region
    ("gcs", "storage.googleapis.com/{b}/"),
    ("azure-blob", "{b}.blob.core.windows.net/"),
    ("do-spaces-nyc3", "{b}.nyc3.digitaloceanspaces.com"),
    ("do-spaces-ams3", "{b}.ams3.digitaloceanspaces.com"),
    ("do-spaces-sgp1", "{b}.sgp1.digitaloceanspaces.com"),
    ("wasabi-us-east-1", "{b}.s3.wasabisys.com"),
]


def fetch(url, timeout=4):
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(200)
            is_listable = b"<ListBucketResult" in body or b"<EnumerationResults" in body
            return r.status, is_listable
    except urllib.error.HTTPError as e: return e.code, False
    except Exception: return None, False


def probe(args):
    prefix, suffix, provider_name, url_tmpl = args
    bucket = prefix + suffix
    base = "https://" + url_tmpl.format(b=bucket)
    st, listable = fetch(base)
    if st in (200, 403):
        return {"prefix": prefix, "suffix": suffix, "bucket": bucket,
                "provider": provider_name, "url": base, "status": st,
                "listable": listable,
                "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    return None


probes = [(p, s, pn, ut) for p in PREFIXES for s in SUFFIXES for pn, ut in PROVIDERS]
print(f"[+] Day 3 bucket sweep — {len(PREFIXES)} prefixes × {len(SUFFIXES)} suffixes × {len(PROVIDERS)} providers = {len(probes)} probes", flush=True)
all_findings = []
completed = 0
with ThreadPoolExecutor(max_workers=40) as pool:
    futures = {pool.submit(probe, p): p for p in probes}
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
print(f"\n[+] Day 3 bucket sweep complete: {len(all_findings)} hits ({listable_n} listable, {len(all_findings)-listable_n} private 403)", flush=True)
LEDGER.parent.mkdir(parents=True, exist_ok=True)
with LEDGER.open("a") as f:
    for fi in all_findings: f.write(json.dumps(fi) + "\n")
print(f"[+] Wrote to {LEDGER}", flush=True)
