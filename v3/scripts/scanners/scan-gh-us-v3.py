"""GitHub Code Search v3 — high-signal patterns only, better FP rules.

v3 changes vs v2:
- DROPPED BEGIN PRIVATE KEY patterns (100% FP rate from test fixtures)
- FIXED filename regex to match paths starting without /
- ADDED Go _test.go convention + Jest __tests__/ convention
- ADDED 0xValue prefix check (real keys are 64 hex chars after 0x)
"""
import urllib.request, urllib.error, ssl, json, re, time
from pathlib import Path
from datetime import datetime, timezone

UA = "Lictor-v3-GHUS3/0.3 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "github-us-v3-secrets.jsonl"
TOKEN = (Path.home() / ".lictor" / "gh-token").read_text().strip()

HARDHAT_TEST_ADDRS = {
    "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1",
    "0xffcf8fdee72ac11b5c542428b35eef5769c409f0",
    "0x22d491bde2303f2f43325b2108d26f1eaba1e32b",
    "0xe11ba2b4d45eaed5996cd0823791e0c93114882d",
    "0xd03ea8624c8c5987235048901fb614fdca89b117",
}
BIP39_TEST_PATTERNS = [
    b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    b"test test test test test test test test test test test junk",
]
# FIXED regex — match path starting without slash too + Go convention + Jest convention
TEMPLATE_FILENAME_RE = re.compile(
    r"\.(example|sample|template|spec|test|fixture|mock|demo)(\.|$)|"
    r"(^|/)(test|tests|spec|specs|fixtures|mocks|examples|samples|"
    r"docs|archive|sample|sampleapp|devdocker|e2e|__tests__|__mocks__)/|"
    r"_test\.(go|py|rb|js|ts)$|"  # Go/Python/Ruby test files
    r"\.spec\.(js|ts|tsx|jsx|py)$",  # Spec test files
    re.I)

# Real-key signature: PRIVATE_KEY=0x followed by 64+ hex chars (real Ethereum private keys)
REAL_HEX_KEY_RE = re.compile(rb"PRIVATE_KEY\s*=\s*[\"\']?0x[0-9a-fA-F]{60,}")
# Real Stripe live key shape
REAL_STRIPE_LIVE_RE = re.compile(rb"sk_live_[A-Za-z0-9]{20,}")
# Real AWS key
REAL_AWS_RE = re.compile(rb"AKIA[0-9A-Z]{16}")
# Real Slack bot token
REAL_SLACK_RE = re.compile(rb"xoxb-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24}")

US_ORGS = [
    # Podcast
    "spotify", "wondery", "iheartmedia", "iheartradio", "npr", "PRX",
    "stitcher-app", "buzzsprout", "podbean", "transistorfm",
    # Real estate
    "zillowgroup", "zillow", "redfin", "realtor", "compass-com",
    "opendoor", "offerpad-com", "RocketCompanies", "RocketMortgage",
    "appfolio", "buildium", "yardi", "homelight", "lennar", "DRHorton",
    # Banks / Fintech
    "jpmorganchase", "BankOfAmerica", "wellsfargo", "citigroup", "citi",
    "USBank", "goldmansachs", "morganstanley", "schwab", "Fidelity",
    "ally", "capitalone", "americanexpress", "discover", "synchrony",
    "Robinhood", "robinhoodmarkets", "sofi", "SoFi", "chime",
    # Crypto-adjacent
    "circlefin", "paypal", "PayPal-Holdings", "stripe", "Block",
    # Political
    "actblue", "ngpvan", "civis", "civisanalytics", "i360-org",
    "winred", "rockthevote", "vote-org", "headcount",
    # Insurance
    "StateFarm", "geico", "allstate", "progressive-insurance",
    "libertymutual", "USAA", "Humana", "Aetna", "CignaCorp",
    "elevancehealth", "anthem", "kaiserpermanente", "UnitedHealthGroup",
    # Telecom
    "Verizon", "ATT", "tmobile", "T-Mobile", "comcast", "Charter",
    # Retail
    "walmartlabs", "Walmart", "amazon", "Costco", "Kroger", "target",
    "ebay",
    # Healthcare
    "AthenahealthInc", "cerner", "CVSHealth", "Walgreens",
]

# HIGH-SIGNAL patterns ONLY (env-var=value or specific token shapes)
PATTERNS = [
    'PRIVATE_KEY=0x filename:.env',
    'DEPLOYER_PRIVATE_KEY=0x filename:.env',
    'MNEMONIC=" filename:.env',
    'AKIA filename:.env',
    'ALCHEMY_API_KEY="alchemy filename:.env',
    'sk_live_ filename:.env',
    'DATABASE_URL="postgres://',
    'DATABASE_URL="mongodb://',
    'POSTGRES_PASSWORD="postgres filename:.env',
    'SLACK_BOT_TOKEN=xoxb',
    'STRIPE_SECRET_KEY=sk_live_',
    'AWS_SECRET_ACCESS_KEY=" filename:.env',
    'TWILIO_AUTH_TOKEN=" filename:.env',
]


def fetch(url, timeout=12):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Authorization": f"token {TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try: body = json.loads(e.read())
        except: body = {}
        return e.code, body
    except Exception: return None, {}

def fetch_raw(url, timeout=8, max_bytes=400):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(max_bytes)
    except: return b""

def is_template_file(path):
    return bool(TEMPLATE_FILENAME_RE.search(path))

def verify_real_secret(body):
    """Strict check: must have a real-key signature, not just the pattern."""
    body_lower = body.lower()
    # Drop if contains known test wallet or BIP39 test
    if any(addr.encode() in body_lower for addr in HARDHAT_TEST_ADDRS):
        return False, "hardhat-test-wallet"
    if any(pat in body for pat in BIP39_TEST_PATTERNS):
        return False, "bip39-test-mnemonic"
    # Look for genuine secret signatures
    if REAL_HEX_KEY_RE.search(body):
        # Make sure the hex isn't all 0s or all 1s
        m = REAL_HEX_KEY_RE.search(body)
        hex_part = m.group(0).decode("utf-8", "ignore").split("=")[-1].strip("'\" ").lstrip("0x")
        if len(set(hex_part.lower())) >= 4:  # not just '0000000000...' or 'ffffff...'
            return True, "real-eth-private-key"
    if REAL_STRIPE_LIVE_RE.search(body):
        return True, "real-stripe-live-key"
    if REAL_AWS_RE.search(body):
        return True, "real-aws-access-key"
    if REAL_SLACK_RE.search(body):
        return True, "real-slack-bot-token"
    # Detect empty template
    if b"=\n" in body or b'=""\n' in body or b"=''\n" in body:
        return False, "empty-template"
    return False, "no-real-secret-found"

def verify_finding(repo, path, default_branch="main"):
    if is_template_file(path):
        return False, "template-filename"
    for branch in (default_branch, "main", "master"):
        url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
        body = fetch_raw(url)
        if not body: continue
        return verify_real_secret(body)
    return False, "fetch-failed"

def search(query):
    url = "https://api.github.com/search/code?q=" + urllib.request.quote(query) + "&per_page=10"
    st, body = fetch(url)
    if st == 200:
        return st, body.get("total_count", 0), body.get("items", [])
    return st, 0, []


all_findings = []
total_queries = len(US_ORGS) * len(PATTERNS)
print(f"[+] GitHub US v3 — {len(US_ORGS)} orgs × {len(PATTERNS)} patterns = {total_queries} queries", flush=True)
print(f"[+] v3 HIGH-SIGNAL: dropped BEGIN-PRIVATE-KEY (FP class), kept env-var=value patterns", flush=True)
print(f"[+] Strict verify: real-key shape required (Ethereum/Stripe/AWS/Slack), not just pattern match", flush=True)
print(flush=True)

req_count = 0
for org in US_ORGS:
    for pat in PATTERNS:
        if req_count > 0 and req_count % 28 == 0:
            print(f"  [pause] rate-limit window, sleep 65s", flush=True)
            time.sleep(65)
        else:
            time.sleep(2.2)
        req_count += 1
        query = f"{pat} org:{org}"
        st, total, items = search(query)
        if st == 200 and total > 0:
            for item in items[:3]:
                repo = item.get("repository", {}).get("full_name", "?")
                path = item.get("path", "?")
                is_real, reason = verify_finding(repo, path, item.get("repository", {}).get("default_branch", "main"))
                if is_real:
                    print(f"  🔴🔴🔴 GENUINE  org={org}  {repo}/{path}  → {reason}  pat='{pat[:30]}'", flush=True)
                    all_findings.append({
                        "type": "verified-real-secret",
                        "org": org, "repo": repo, "path": path,
                        "pattern": pat, "verify_reason": reason,
                        "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    })

print(f"\n[+] gh-us-v3 complete: {len(all_findings)} GENUINE findings ({req_count} queries)", flush=True)
if all_findings:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for fi in all_findings: f.write(json.dumps(fi) + "\n")
    print(f"[+] Wrote to {LEDGER}", flush=True)
