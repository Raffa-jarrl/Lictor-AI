"""Google service-account JSON + Firebase admin key + GCP credential scanner.

Targets the distinctive shape of GCP service-account credential files:
  { "type": "service_account", "project_id": "...", "private_key": "-----BEGIN..." }

Ethical: HEAD + 200-byte GET on signature paths. NEVER extracts the private key —
only detects the SHAPE (presence of "type": "service_account" + "private_key" header).
The private key bytes themselves are NEVER logged or read past the first 200 bytes.
"""
import urllib.request, urllib.error, ssl, json, re, secrets, statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-GoogleSA/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "google-sa-candidates.jsonl"

# Candidate paths — common GCP/Firebase service-account locations
SA_PATHS = [
    # Generic credential filenames
    "/credentials.json", "/credential.json",
    "/service-account.json", "/service_account.json", "/sa.json",
    "/gcp-key.json", "/gcp-credentials.json", "/gcp.json",
    "/google-credentials.json", "/google-service-account.json",
    "/google-application-credentials.json", "/application_default_credentials.json",
    # Firebase admin SDK
    "/firebase-adminsdk.json", "/firebase-admin.json", "/firebase-key.json",
    "/firebase-service-account.json", "/serviceAccountKey.json",
    # Common GCP project paths
    "/keys/service-account.json", "/keys/gcp.json", "/keys/firebase.json",
    "/config/credentials.json", "/config/service-account.json",
    "/config/gcp.json", "/config/firebase.json",
    "/secrets/google.json", "/secrets/gcp.json", "/secrets/firebase.json",
    # IaC / deploy paths
    "/terraform/credentials.json", "/.gcloud/credentials.json",
    "/deploy/sa.json", "/build/sa.json",
    # GitHub Actions secrets that leaked
    "/.github/workflows/sa.json", "/.github/sa.json",
    # AWS credential equivalents (since user said AWS too)
    "/aws-credentials.json", "/aws-credentials", "/.aws/credentials",
    "/credentials", "/config", "/.boto",
]

# Signatures
GCP_SA_SIG = re.compile(rb'"type"\s*:\s*"service_account"', re.I)
GCP_PRIVKEY_SIG = re.compile(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----', re.I)
FIREBASE_SIG = re.compile(rb'"project_id"\s*:.*?"private_key_id"', re.I | re.S)
AWS_CRED_SIG = re.compile(rb'AKIA[0-9A-Z]{16}|aws_access_key_id|aws_secret_access_key', re.I)

HTML_CT_RX = re.compile(r"text/html|application/xhtml", re.I)


def fetch(url, method="GET", max_bytes=200, timeout=4):
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA}, method=method)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(max_bytes) if method != "HEAD" else b""
            return r.status, body, {k: v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        try: body = e.read(max_bytes) if method != "HEAD" else b""
        except: body = b""
        return e.code, body, {k: v for k, v in (e.headers.items() if e.headers else [])}
    except Exception:
        return None, None, None


def head_cl(url):
    st, _, hdr = fetch(url, method="HEAD")
    if st != 200 or not hdr: return None
    try: return int(hdr.get("Content-Length", "0"))
    except: return 0


def scan_host(host):
    findings = []
    base = f"https://{host}"
    # HEAD canaries
    nonce = secrets.token_hex(6)
    canary_cls = set()
    for c_path in [f"/__lictor_canary_{nonce}.json", f"/keys/__canary_{nonce}.json",
                   f"/config/__canary_{nonce}.json", f"/__canary_{nonce}"]:
        cl = head_cl(f"{base}{c_path}")
        if cl is not None and cl > 0:
            canary_cls.add(cl)

    raw_hits = []
    for path in SA_PATHS:
        st, body, hdr = fetch(f"{base}{path}", method="GET", max_bytes=200)
        if st != 200 or not body: continue
        ct = hdr.get("Content-Type", "?") if hdr else "?"
        if HTML_CT_RX.search(ct): continue
        body_len = len(body)
        if any(c > 0 and abs(body_len - c) / c < 0.05 for c in canary_cls): continue
        # Signature check on first 200 bytes
        sig_type = None
        if GCP_SA_SIG.search(body) or GCP_PRIVKEY_SIG.search(body):
            sig_type = "gcp-service-account"
        elif FIREBASE_SIG.search(body):
            sig_type = "firebase-admin"
        elif AWS_CRED_SIG.search(body):
            sig_type = "aws-credentials"
        if sig_type:
            raw_hits.append({"path": path, "ct": ct, "cl": body_len, "sig": sig_type})

    # Cluster dedup (4+ same body length = catch-all)
    if len(raw_hits) >= 4:
        cls = [h["cl"] for h in raw_hits]
        mean_cl = statistics.mean(cls)
        if mean_cl > 0:
            within = [h for h in raw_hits if abs(h["cl"] - mean_cl) / mean_cl < 0.05]
            if len(within) >= 4:
                print(f"  [drop-cluster]  {host}  {len(within)} sig-hits cluster — dropping", flush=True)
                raw_hits = []

    for h in raw_hits:
        print(f"  🔴 {h['sig'].upper()}  {host}{h['path']}  ct={h['ct']}  cl={h['cl']}", flush=True)
        findings.append({"type": h["sig"], "host": host, "path": h["path"],
                         "content_length": h["cl"], "content_type": h["ct"],
                         "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    return findings


import sys
with open(sys.argv[1]) as f:
    hosts = [l.strip() for l in f if l.strip()][:int(sys.argv[2]) if len(sys.argv) > 2 else 5000]
print(f"[+] google-SA + firebase + aws-cred file hunt — {len(hosts)} hosts × {len(SA_PATHS)} paths", flush=True)
print(f"[+] Signature detection ONLY — never extracts key material", flush=True)
all_findings = []
completed = 0
with ThreadPoolExecutor(max_workers=30) as pool:
    futures = {pool.submit(scan_host, h): h for h in hosts}
    for fut in as_completed(futures):
        completed += 1
        if completed % 250 == 0:
            print(f"  [{completed}/{len(hosts)}] hosts checked, {len(all_findings)} findings", flush=True)
        try:
            r = fut.result(timeout=25)
            if r: all_findings.extend(r)
        except Exception:
            pass
print(f"\n[+] google-SA hunt complete: {len(all_findings)} findings", flush=True)
if all_findings:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for fi in all_findings: f.write(json.dumps(fi) + "\n")
    print(f"[+] Wrote to {LEDGER}", flush=True)
