import urllib.request, ssl, sys, json, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-GitProbe/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "git-exposure-candidates.jsonl"
GIT_HEAD_RX = re.compile(rb"^ref:\s+refs/heads/[A-Za-z0-9_/.-]+\s*$")

def probe(host):
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    for scheme in ("https","http"):
        url = f"{scheme}://{host}/.git/HEAD"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=4, context=ctx) as r:
                body = r.read(120)
                # STRICT: body must look exactly like a git HEAD file
                if GIT_HEAD_RX.match(body.strip()):
                    # ALSO fetch /.git/config to confirm 
                    cfg_url = f"{scheme}://{host}/.git/config"
                    try:
                        with urllib.request.urlopen(urllib.request.Request(cfg_url, headers={"User-Agent": UA}), timeout=4, context=ctx) as r2:
                            cfg_body = r2.read(500).decode("utf-8", "replace")
                            if "[core]" in cfg_body or "[remote " in cfg_body:
                                print(f"  🔴 GIT-EXPOSED  {host}  HEAD={body.strip().decode('utf-8','replace')}", flush=True)
                                return {"host": host, "scheme": scheme,
                                        "git_head": body.strip().decode("utf-8","replace"),
                                        "git_config_excerpt": cfg_body[:300],
                                        "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
                    except Exception:
                        pass
                return None
        except Exception:
            continue
    return None

with open(sys.argv[1]) as f:
    hosts = [l.strip() for l in f if l.strip()][:int(sys.argv[2]) if len(sys.argv)>2 else 5000]
print(f"[+] git-exposure scan — {len(hosts)} hosts, single /.git/HEAD probe each", flush=True)
print(f"[+] strict signature: body must match ^ref:\\s+refs/heads/...", flush=True)
print(f"[+] confirmation: also fetch /.git/config and verify [core] or [remote ]", flush=True)
findings = []
completed = 0
with ThreadPoolExecutor(max_workers=40) as pool:
    futures = {pool.submit(probe, h): h for h in hosts}
    for fut in as_completed(futures):
        completed += 1
        if completed % 200 == 0:
            print(f"  [{completed}/{len(hosts)}] checked, {len(findings)} git exposures", flush=True)
        try:
            r = fut.result(timeout=15)
            if r: findings.append(r)
        except Exception:
            pass
print(f"\n[+] scan complete: {len(findings)} git-exposure findings", flush=True)
if findings:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for fi in findings:
            f.write(json.dumps(fi) + "\n")
    print(f"[+] Wrote to {LEDGER}", flush=True)
