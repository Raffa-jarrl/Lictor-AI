#!/usr/bin/env python3
"""
patrol-discord-webhook-leak — scanner #70 (grep.app variant).

Hunts hardcoded Discord webhook URLs in public GitHub code via grep.app's
public code search (no auth required). A leaked webhook lets an attacker:
  - Spam/deface the channel
  - Impersonate the bot to deliver phishing IN the channel (drain)
  - Spoof "security alerts" to social-engineer admins
  - @everyone to thousands of community members

Real-world: SushiSwap Discord drained $3M after webhook leak (2022); dozens
of NFT and DeFi Discords compromised by the same vector.

Strategy (passive, ethical):
  1. grep.app public search for the webhook URL pattern
  2. For each hit:
     - Extract the full webhook URL
     - Hash for dedup (we do NOT call the webhook)
     - Surface repo + path + redacted context
  3. Severity from repo signals + file kind

We never POST to the webhook. The webhook token never leaves the local ledger.

Usage:
  patrol-discord-webhook-leak.py
"""
from __future__ import annotations
import argparse, json, re, time, urllib.request, urllib.parse, hashlib
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-DiscordWebhookPatrol/0.2 (+https://lictor-ai.com)"

WEBHOOK_RX = re.compile(
    r'https?://(?:[a-z]+\.)?discord(?:app)?\.com/api/webhooks/(\d+)/([A-Za-z0-9_-]+)',
    re.IGNORECASE)

@dataclass
class WebhookFinding:
    repo: str
    file_path: str
    webhook_id: str
    webhook_hash: str   # SHA-256 prefix (dedup)
    context: str = ""   # redacted snippet
    severity: str = "INFO"
    notes: str = ""

def http_get(url: str, timeout: int = 15, max_retries: int = 3) -> bytes | None:
    """Polite HTTP GET with exponential backoff on 429 + 5s base delay."""
    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
        "Referer": "https://grep.app/",
    }
    backoff = 5
    for attempt in range(max_retries):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read(2_000_000)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = backoff * (2 ** attempt)
                print(f"[!] grep.app 429 (attempt {attempt+1}/{max_retries}) — sleeping {wait}s")
                time.sleep(wait)
                continue
            print(f"[!] http_get HTTPError {e.code}: {url[:60]}")
            return None
        except Exception as e:
            print(f"[!] http_get error: {e}")
            time.sleep(2)
            continue
    print(f"[!] http_get gave up after {max_retries} attempts")
    return None

def grepapp_search(query: str, page: int = 1) -> dict:
    """grep.app public search. Returns hits dict with 'hits' list."""
    url = (f"https://grep.app/api/search?"
           f"q={urllib.parse.quote(query)}&page={page}")
    body = http_get(url, timeout=20)
    if not body: return {}
    try:
        return json.loads(body)
    except Exception:
        return {}

def score_severity(repo: str, file_path: str) -> tuple[str, str]:
    pl = file_path.lower()
    # Test / sample / fixture → LOW
    if any(x in pl for x in ("test/", "tests/", "example/", "examples/",
                              "sample", "demo", "fixture", "mock", "spec/")):
        return "LOW", "appears to be a test/sample file"
    # CI / config / actively-shipped → HIGHER
    if any(x in pl for x in (".env", ".github/", "config", "secrets",
                              "deploy", "docker-compose", "k8s/")):
        return "HIGH", "leak in CI/config/deployment file"
    # Notebook / script / app code → MEDIUM
    if any(pl.endswith(x) for x in (".js", ".ts", ".py", ".rb", ".go",
                                     ".rs", ".java", ".php", ".sh",
                                     ".yml", ".yaml", ".json", ".env")):
        return "MEDIUM", "leak in active code/config"
    return "MEDIUM", "leak in unknown file kind"

def find_webhooks(max_pages: int = 5) -> list[WebhookFinding]:
    findings: list[WebhookFinding] = []
    seen_hashes: set[str] = set()
    query = "discord.com/api/webhooks/"
    for page in range(1, max_pages + 1):
        print(f"[+] grep.app search page {page}…")
        result = grepapp_search(query, page=page)
        hits = result.get("hits", {}).get("hits", [])
        if not hits:
            print(f"[!] no more results at page {page}")
            break
        print(f"  → {len(hits)} hits on page {page}")
        for h in hits:
            repo = h.get("repo", {}).get("raw", "?")
            path = h.get("path", {}).get("raw", "?")
            # grep.app returns "content" with the matched snippet + context
            content = h.get("content", {}).get("snippet", "") or ""
            # snippet has HTML tags — strip them
            content_text = re.sub(r'<[^>]+>', '', content)
            for m in WEBHOOK_RX.finditer(content_text):
                full_url = m.group(0)
                webhook_id = m.group(1)
                hashv = hashlib.sha256(full_url.encode()).hexdigest()[:16]
                if hashv in seen_hashes: continue
                seen_hashes.add(hashv)
                # Redact the token portion
                start = max(0, m.start() - 60)
                end = min(len(content_text), m.end() + 60)
                ctx_raw = content_text[start:end].replace("\n", " ").replace("\r", "")
                ctx = WEBHOOK_RX.sub(
                    lambda x: f"https://discord.com/api/webhooks/{x.group(1)}/REDACTED",
                    ctx_raw)[:240]
                sev, note = score_severity(repo, path)
                findings.append(WebhookFinding(
                    repo=repo,
                    file_path=path,
                    webhook_id=webhook_id,
                    webhook_hash=hashv,
                    context=ctx,
                    severity=sev,
                    notes=note))
        time.sleep(8)   # be MUCH more polite to grep.app (8s between pages)
    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-pages", type=int, default=5)
    ap.add_argument("--ledger",
                    default="/Users/raffa/Lictor/v3/ledgers/discord-webhook-leak.jsonl")
    args = ap.parse_args()

    print(f"[+] Discord-webhook-leak hunt via grep.app (max {args.max_pages} pages)")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)

    findings = find_webhooks(max_pages=args.max_pages)

    n_crit = n_high = n_med = n_low = 0
    with open(args.ledger, "a") as ledger:
        for f in findings:
            ledger.write(json.dumps(asdict(f)) + "\n")
            tag = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡",
                   "LOW":"⚪"}.get(f.severity, "?")
            print(f"  {tag} {f.repo}/{f.file_path}  "
                  f"webhook_id={f.webhook_id}  ({f.severity}) — {f.notes}")
            if f.severity == "CRITICAL": n_crit += 1
            elif f.severity == "HIGH": n_high += 1
            elif f.severity == "MEDIUM": n_med += 1
            else: n_low += 1
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high} MEDIUM={n_med} LOW={n_low}")
    print(f"[+] Note: webhook tokens REDACTED in ledger. To disclose, fetch from raw grep.app result.")
    print(f"[+] Disclose to: repo owner + Discord server admin (visible in channel info)")

if __name__ == "__main__":
    main()
