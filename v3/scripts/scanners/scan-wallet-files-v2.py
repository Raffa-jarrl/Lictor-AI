"""Wallet-file scanner v2 — HEAD-based canary, content-type sanity, dedup post-hoc.

v1 bug: canary was GET with max_bytes=1500 → canary_cl capped at 1500. Probe was
HEAD with full Content-Length header (e.g. 53695). Comparison
abs(53695 - 1500) / 1500 = 35.0 > 0.2 → catch-all not detected → mass FPs from
51job.com, 163.com, 1800contacts.com.

v2 fixes:
1) Canary uses HEAD too — compare Content-Length headers apples-to-apples
2) 5 diverse-shape canaries (.txt, .json, .key, .dat, deep-path) instead of 1
3) Drop findings where content-type is text/html (we expect json/octet-stream/plain)
4) Post-hoc dedup — if 4+ findings on same host within 5% of mean CL, drop ALL
5) Skip findings with CL < 64 (too small to be a real keystore/wallet)
"""
import urllib.request, urllib.error, ssl, json, re, secrets, statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-WalletHunt/0.2 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "wallet-exposure-candidates.v2.jsonl"

WALLET_PATHS_HEAD = [
    "/wallet.dat", "/wallets/wallet.dat", "/bitcoin/wallet.dat", "/.bitcoin/wallet.dat",
    "/wallet.json", "/keystore.json", "/keystore/wallet.json",
    "/eth-keystore.json", "/wallets/keystore.json",
    "/private.key", "/private-key.txt", "/eth-private-key.txt", "/btc-private-key.txt",
    "/keys/private.key", "/keys/eth.key", "/keys/btc.key", "/keys/wallet.key",
    "/mnemonic.txt", "/seed.txt", "/seed-phrase.txt", "/recovery-phrase.txt",
    "/12-words.txt", "/24-words.txt", "/bip39.txt",
    "/account.json", "/accounts.json", "/eth-account.json",
    "/MetaMaskWallet.json", "/metamask-wallet.json", "/metamask-vault.json",
    "/ledger-export.csv", "/ledger-live-export.json", "/trezor-export.json",
    "/descriptor.txt", "/wallet-descriptor.json",
    "/wallet-backup.zip", "/wallet-backup.tar.gz", "/wallet.bak",
    "/coins.json", "/funds.json", "/crypto-backup.json",
    "/treasury.json", "/multisig-keys.json", "/cold-storage.json",
    "/coinbase-keys.json", "/binance-api-keys.txt", "/exchange-api.json",
    "/.electrum/wallets/default_wallet", "/.electrum-ltc/wallets/default_wallet",
]

ENV_PATHS = [
    "/.env", "/.env.production", "/.env.local", "/.env.crypto",
    "/.env.wallet", "/.env.keys", "/.env.bitcoin", "/.env.ethereum",
]
CRYPTO_ENV_RX = re.compile(
    rb"^("
    rb"PRIVATE_KEY|PRIVATEKEY|PRIV_KEY|"
    rb"MNEMONIC|SEED_PHRASE|SEED|RECOVERY_PHRASE|"
    rb"ETH_PRIVATE_KEY|ETHEREUM_PRIVATE_KEY|"
    rb"BTC_PRIVATE_KEY|BITCOIN_PRIVATE_KEY|"
    rb"WALLET_PRIVATE_KEY|WALLET_KEY|WALLET_MNEMONIC|"
    rb"INFURA_PROJECT_ID|INFURA_API_KEY|ALCHEMY_API_KEY|"
    rb"MORALIS_API_KEY|QUICKNODE_API_KEY|"
    rb"COINBASE_API_KEY|BINANCE_API_KEY|BINANCE_SECRET|"
    rb"KRAKEN_API_KEY|KRAKEN_PRIVATE_KEY|KRAKEN_SECRET|"
    rb"OKX_API_KEY|OKX_SECRET|BYBIT_API_KEY|BYBIT_SECRET|"
    rb"DEPLOYER_PRIVATE_KEY|SIGNER_KEY|"
    rb"AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|"
    rb"GOOGLE_APPLICATION_CREDENTIALS|GCP_PRIVATE_KEY|GCP_SERVICE_ACCOUNT"
    rb")\s*=", re.M | re.I)

# Acceptable content-types for actual wallet/key files
EXPECTED_CTS = (
    "application/json", "application/octet-stream", "text/plain",
    "application/x-binary", "application/zip", "application/gzip",
    "application/x-tar", "text/csv", "application/x-pem-file",
)
# Drop if CT looks like HTML/web-page (catch-all serving SPA shell)
HTML_CT_RX = re.compile(r"text/html|application/xhtml", re.I)


def fetch(url, method="GET", max_bytes=500, timeout=4):
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
    """HEAD and return Content-Length header as int, 0 if missing."""
    st, _, hdr = fetch(url, method="HEAD")
    if st != 200 or not hdr: return None
    try:
        return int(hdr.get("Content-Length", "0"))
    except Exception:
        return 0


def scan_host(host):
    findings = []
    base = f"https://{host}"
    # 5 diverse-shape canaries — HEAD, compare CL
    canaries = []
    nonce = secrets.token_hex(6)
    for c_path in [
        f"/__lictor_canary_{nonce}.txt",
        f"/__lictor_canary_{nonce}.json",
        f"/__lictor_canary_{nonce}.key",
        f"/canary_{nonce}/wallet.dat",
        f"/non/existent/path/{nonce}",
    ]:
        cl = head_cl(f"{base}{c_path}")
        if cl is not None and cl > 0:
            canaries.append(cl)
    # Catch-all signature: any canary returned non-zero CL
    is_catchall = len(canaries) > 0
    canary_cls = set(canaries)

    # 1) Wallet files (HEAD only)
    raw_hits = []
    for path in WALLET_PATHS_HEAD:
        st, _, hdr = fetch(f"{base}{path}", method="HEAD")
        if st != 200: continue
        if not hdr: continue
        try: cl = int(hdr.get("Content-Length", "0"))
        except: cl = 0
        ct = hdr.get("Content-Type", "?")
        # Drop on HTML content-type (catch-all SPA)
        if HTML_CT_RX.search(ct):
            continue
        # Drop on canary CL match (within 5% of any canary CL)
        if is_catchall:
            matched = False
            for c_cl in canary_cls:
                if c_cl > 0 and abs(cl - c_cl) / c_cl < 0.05:
                    matched = True; break
            if matched: continue
        # Min size — real wallets/keystores are at least ~64 bytes
        if cl < 64: continue
        raw_hits.append({"path": path, "cl": cl, "ct": ct})

    # Post-hoc dedup: if 4+ hits, check if they cluster within 5% of mean CL
    # That's a strong catch-all signal even if canaries didn't fire
    if len(raw_hits) >= 4:
        cls = [h["cl"] for h in raw_hits]
        mean_cl = statistics.mean(cls)
        if mean_cl > 0:
            within = [h for h in raw_hits if abs(h["cl"] - mean_cl) / mean_cl < 0.05]
            if len(within) >= 4:
                # All cluster — almost certainly catch-all serving same content
                print(f"  [drop-cluster]  {host}  {len(within)} hits within 5% of mean CL={int(mean_cl)}", flush=True)
                raw_hits = []

    for h in raw_hits:
        print(f"  🔴 WALLET-FILE  {host}{h['path']}  size={h['cl']}  ct={h['ct']}", flush=True)
        findings.append({"type": "wallet-file", "host": host, "path": h["path"],
                         "content_length": h["cl"], "content_type": h["ct"],
                         "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})

    # 2) .env probes with crypto signature
    for path in ENV_PATHS:
        st, body, hdr = fetch(f"{base}{path}", method="GET", max_bytes=500)
        if st != 200 or not body: continue
        if b"<html" in body[:200].lower() or b"<!doctype" in body[:200].lower(): continue
        if hdr and HTML_CT_RX.search(hdr.get("Content-Type", "")): continue
        # Skip if body matches any canary CL
        body_len = len(body)
        if is_catchall:
            matched = any(c_cl > 0 and abs(body_len - c_cl) / c_cl < 0.05 for c_cl in canary_cls)
            if matched: continue
        m = CRYPTO_ENV_RX.search(body)
        if m:
            var_name = m.group(1).decode("utf-8", "replace")
            print(f"  🔴 CRYPTO-ENV  {host}{path}  contains {var_name}=[REDACTED]", flush=True)
            findings.append({"type": "crypto-env", "host": host, "path": path,
                             "env_var_detected": var_name, "content_length": body_len,
                             "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    return findings


import sys
with open(sys.argv[1]) as f:
    hosts = [l.strip() for l in f if l.strip()][:int(sys.argv[2]) if len(sys.argv) > 2 else 5000]
print(f"[+] wallet-file hunt v2 — {len(hosts)} hosts × {len(WALLET_PATHS_HEAD)} wallet paths (HEAD) + {len(ENV_PATHS)} .env (GET 500B)", flush=True)
print(f"[+] FP-resistant: HEAD-CL canary (5 diverse shapes) + text/html drop + 4+-cluster dedup", flush=True)
print(f"[+] Ethical: HEAD-only on wallet files (NEVER downloads). .env detection emits var-name only, NEVER value.", flush=True)
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
print(f"\n[+] wallet-hunt v2 complete: {len(all_findings)} findings", flush=True)
if all_findings:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for fi in all_findings: f.write(json.dumps(fi) + "\n")
    print(f"[+] Wrote to {LEDGER}", flush=True)
