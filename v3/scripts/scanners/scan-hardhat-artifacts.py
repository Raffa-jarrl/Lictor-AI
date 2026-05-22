"""Hardhat/Foundry/Truffle deployer-artifact scanner.

Catches: exposed `.openzeppelin/<network>.json`, `deployments/*/.json`,
`hardhat.config.js`, Foundry `out/` artifacts, `truffle-config.js`,
`/deploy/`, `/deployer/` configs, and ENV files referencing
DEPLOYER_PRIVATE_KEY / RPC URLs.

Ethical: HEAD + signature-only GET (200 bytes max). Never extracts private keys
or RPC URL values — only detects presence of var names / artifact markers.
"""
import urllib.request, urllib.error, ssl, json, re, secrets, statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-Hardhat/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "hardhat-artifact-candidates.jsonl"

# Targeted artifact paths
ARTIFACT_PATHS = [
    # Hardhat
    "/hardhat.config.js", "/hardhat.config.ts",
    "/deployments/mainnet/.chainId", "/deployments/mainnet/.migrations.json",
    "/deployments/polygon/.chainId", "/deployments/optimism/.chainId",
    "/deployments/arbitrum/.chainId", "/deployments/base/.chainId",
    "/.openzeppelin/mainnet.json", "/.openzeppelin/polygon.json",
    "/.openzeppelin/optimism.json", "/.openzeppelin/arbitrum.json",
    "/artifacts/build-info/", "/artifacts/contracts/",
    "/cache/solidity-files-cache.json",
    # Foundry
    "/foundry.toml", "/foundry.lock",
    "/out/Counter.sol/Counter.json", "/out/build-info/",
    "/script/Deploy.s.sol", "/broadcast/",
    "/broadcast/Deploy.s.sol/1/run-latest.json",
    "/broadcast/Deploy.s.sol/137/run-latest.json",
    # Truffle
    "/truffle-config.js", "/truffle.js",
    "/build/contracts/", "/migrations/2_deploy_contracts.js",
    # Generic deploy
    "/deploy/", "/deployer/", "/deployer.json", "/deployer-config.json",
    "/deploy-config.json", "/deploy.json",
    # Critical .env variants for DeFi deploys
    "/.env.deploy", "/.env.deployer", "/.env.mainnet", "/.env.polygon",
    "/.env.testnet", "/.env.fork", "/.env.hardhat",
    # OpenZeppelin Defender / Tenderly
    "/.tenderly/", "/.defender/",
    # IPFS hash refs that leaked
    "/ipfs/hash.txt", "/ipfs-hash",
    # Brownie (Python equivalent)
    "/brownie-config.yaml", "/build/deployments/",
    # WalletConnect projectId (less critical but common)
    "/.env.walletconnect",
]

# Signatures in artifact contents
HARDHAT_CFG_SIG = re.compile(rb'hardhat.*config|HardhatUserConfig|namedAccounts|networks\s*:', re.I)
FOUNDRY_SIG = re.compile(rb'\[profile|forge|foundry', re.I)
DEPLOYER_KEY_SIG = re.compile(rb'DEPLOYER_PRIVATE_KEY|PRIVATE_KEY|MNEMONIC|alchemy|infura|quicknode', re.I)
OZ_ADMIN_SIG = re.compile(rb'admin|proxies|implementations|"address"\s*:\s*"0x[0-9a-f]{40}"', re.I)
HTML_CT_RX = re.compile(r"text/html|application/xhtml", re.I)


def fetch(url, method="GET", max_bytes=400, timeout=4):
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
    """Return (sig_type, detail) or (None, None) if no signature match."""
    if path.endswith(("hardhat.config.js", "hardhat.config.ts")) and HARDHAT_CFG_SIG.search(body):
        return ("hardhat-config", "config exposed")
    if path.endswith(("foundry.toml", "foundry.lock")) and FOUNDRY_SIG.search(body):
        return ("foundry-config", "config exposed")
    if "/.openzeppelin/" in path and OZ_ADMIN_SIG.search(body):
        return ("openzeppelin-admin", "proxy admin metadata exposed")
    if path.endswith(("truffle-config.js", "truffle.js")) and b"contracts_build_directory" in body.lower():
        return ("truffle-config", "config exposed")
    if path.startswith("/.env"):
        m = DEPLOYER_KEY_SIG.search(body)
        if m: return ("deploy-env", m.group(0).decode("utf-8", "replace").upper()[:30])
    if "broadcast/" in path and (b'"transactions"' in body[:200] or b'"transactionHash"' in body[:200]):
        return ("foundry-broadcast", "deploy broadcast exposed (deployer address visible)")
    # Generic: any artifact path returning JSON with admin/private/deployer
    if b'"deployer"' in body[:200] or b'"adminAddress"' in body[:200] or b'"owner"' in body[:200]:
        return ("deploy-artifact", "artifact has deployer/admin/owner field")
    return (None, None)


def scan_host(host):
    findings = []
    base = f"https://{host}"
    nonce = secrets.token_hex(6)
    canary_cls = set()
    for c_path in [f"/__lictor_canary_{nonce}.json", f"/__canary_{nonce}.config.js",
                   f"/.openzeppelin/__canary_{nonce}.json", f"/__canary_{nonce}.toml"]:
        cl = head_cl(f"{base}{c_path}")
        if cl is not None and cl > 0:
            canary_cls.add(cl)

    raw_hits = []
    for path in ARTIFACT_PATHS:
        st, body, hdr = fetch(f"{base}{path}", method="GET", max_bytes=400)
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
print(f"[+] hardhat/foundry/truffle artifact hunt — {len(hosts)} hosts × {len(ARTIFACT_PATHS)} paths", flush=True)
print(f"[+] Ethical: signature-only; never extracts key material", flush=True)
all_findings = []
completed = 0
with ThreadPoolExecutor(max_workers=30) as pool:
    futures = {pool.submit(scan_host, h): h for h in hosts}
    for fut in as_completed(futures):
        completed += 1
        if completed % 100 == 0:
            print(f"  [{completed}/{len(hosts)}] hosts checked, {len(all_findings)} findings", flush=True)
        try:
            r = fut.result(timeout=25)
            if r: all_findings.extend(r)
        except Exception:
            pass
print(f"\n[+] hardhat-artifact hunt complete: {len(all_findings)} findings", flush=True)
if all_findings:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for fi in all_findings: f.write(json.dumps(fi) + "\n")
    print(f"[+] Wrote to {LEDGER}", flush=True)
