"""Solana keypair file scanner.

Solana keypairs are JSON arrays of 64 integers (uint8 bytes of the secret key).
Format: [123,45,67,...] with exactly 64 integers.

Default Solana CLI keypair location: ~/.config/solana/id.json
Common exposed paths: /id.json, /keypair.json, /solana-keypair.json,
/validator-keypair.json, /phantom-export.json, etc.

Ethical: HEAD + 100-byte GET signature check only. NEVER reads enough to
reconstruct the secret key (64 ints = ~256-400 bytes; we limit to 100).
"""
import urllib.request, urllib.error, ssl, json, re, secrets, statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-SolanaHunt/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "solana-keypair-candidates.jsonl"

SOLANA_PATHS = [
    "/id.json",
    "/keypair.json", "/keypair-mainnet.json", "/keypair-devnet.json",
    "/solana-keypair.json", "/solana/id.json", "/solana/keypair.json",
    "/validator-keypair.json", "/vote-account-keypair.json",
    "/stake-account-keypair.json", "/withdrawer-keypair.json",
    "/phantom-export.json", "/phantom-wallet.json", "/phantom.json",
    "/solflare-export.json", "/sollet-export.json",
    "/.config/solana/id.json", "/.config/solana/cli/config.yml",
    "/wallet-keypair.json", "/deployer-keypair.json", "/deploy-keypair.json",
    "/program-keypair.json", "/upgrade-authority-keypair.json",
    "/mint-keypair.json", "/token-keypair.json",
    "/treasury-keypair.json", "/multisig-keypair.json",
    # Anchor framework defaults
    "/target/deploy/program-keypair.json",
    "/Anchor.toml",
    # SPL token paths
    "/spl-token/keypair.json", "/spl/keypair.json",
]

# Solana keypair signature: starts with [, followed by enough comma-separated
# small integers (0-255) to suggest a 64-byte secret key.
# We require at least 10 consecutive comma-separated 1-3 digit numbers in first 100 bytes.
SOLANA_KP_SIG = re.compile(rb'^\[\s*(\d{1,3}\s*,\s*){9,}\d{1,3}', re.S)
# Anchor.toml signature
ANCHOR_TOML_SIG = re.compile(rb'\[programs\.|provider\.cluster|anchor_version|wallet\s*=', re.I)
# Solana CLI config (YAML)
SOLANA_CLI_CFG_SIG = re.compile(rb'json_rpc_url|keypair_path|websocket_url', re.I)

HTML_CT_RX = re.compile(r"text/html|application/xhtml", re.I)


def fetch(url, method="GET", max_bytes=100, timeout=4):
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


def classify(path, body):
    if path.endswith("Anchor.toml") and ANCHOR_TOML_SIG.search(body):
        return ("anchor-config", "Anchor framework config exposed (deployer wallet referenced)")
    if path.endswith("config.yml") and SOLANA_CLI_CFG_SIG.search(body):
        return ("solana-cli-config", "Solana CLI config exposed (keypair_path leak)")
    if SOLANA_KP_SIG.search(body):
        return ("solana-keypair", "JSON-array keypair detected (likely 64-byte Solana secret key)")
    return (None, None)


def scan_host(host):
    findings = []
    base = f"https://{host}"
    nonce = secrets.token_hex(6)
    canary_cls = set()
    for c_path in [f"/__canary_{nonce}.json", f"/__canary_{nonce}.yml",
                   f"/solana/__canary_{nonce}.json", f"/__canary_{nonce}.toml"]:
        cl = head_cl(f"{base}{c_path}")
        if cl is not None and cl > 0:
            canary_cls.add(cl)

    raw_hits = []
    for path in SOLANA_PATHS:
        st, body, hdr = fetch(f"{base}{path}", method="GET", max_bytes=100)
        if st != 200 or not body: continue
        ct = hdr.get("Content-Type", "?") if hdr else "?"
        if HTML_CT_RX.search(ct): continue
        body_len = len(body)
        if any(c > 0 and abs(body_len - c) / c < 0.05 for c in canary_cls): continue
        sig_type, detail = classify(path, body)
        if sig_type:
            raw_hits.append({"path": path, "ct": ct, "cl": body_len,
                             "sig": sig_type, "detail": detail})

    if len(raw_hits) >= 4:
        cls = [h["cl"] for h in raw_hits]
        mean_cl = statistics.mean(cls)
        if mean_cl > 0:
            within = [h for h in raw_hits if abs(h["cl"] - mean_cl) / mean_cl < 0.05]
            if len(within) >= 4:
                print(f"  [drop-cluster]  {host}  {len(within)} sig-hits cluster — drop", flush=True)
                raw_hits = []

    for h in raw_hits:
        print(f"  🔴 {h['sig'].upper()}  {host}{h['path']}  → {h['detail']}", flush=True)
        findings.append({"type": h["sig"], "host": host, "path": h["path"],
                         "detail": h["detail"], "content_length": h["cl"],
                         "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    return findings


import sys
with open(sys.argv[1]) as f:
    hosts = [l.strip() for l in f if l.strip()][:int(sys.argv[2]) if len(sys.argv) > 2 else 5000]
print(f"[+] solana-keypair hunt — {len(hosts)} hosts × {len(SOLANA_PATHS)} paths (100B sig-only GET)", flush=True)
print(f"[+] Ethical: 100-byte limit insufficient to reconstruct 64-byte secret; signature shape only", flush=True)
all_findings = []
completed = 0
with ThreadPoolExecutor(max_workers=30) as pool:
    futures = {pool.submit(scan_host, h): h for h in hosts}
    for fut in as_completed(futures):
        completed += 1
        if completed % 200 == 0:
            print(f"  [{completed}/{len(hosts)}] hosts checked, {len(all_findings)} findings", flush=True)
        try:
            r = fut.result(timeout=25)
            if r: all_findings.extend(r)
        except Exception:
            pass
print(f"\n[+] solana-keypair hunt complete: {len(all_findings)} findings", flush=True)
if all_findings:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for fi in all_findings: f.write(json.dumps(fi) + "\n")
    print(f"[+] Wrote to {LEDGER}", flush=True)
