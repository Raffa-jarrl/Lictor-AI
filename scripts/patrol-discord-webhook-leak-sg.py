#!/usr/bin/env python3
"""
patrol-discord-webhook-leak-sg — Move 2: pivot from grep.app to Sourcegraph.

grep.app rate-limited us hard (429 even with exponential backoff). Pivot to
Sourcegraph's public code-search GraphQL endpoint, which is more lenient
and explicitly designed for programmatic queries.

Same scanner goal: hunt hardcoded Discord webhook URLs in public code,
flag for disclosure to repo owner + Discord server admin.

Usage:
  patrol-discord-webhook-leak-sg.py
"""
from __future__ import annotations
import argparse, json, re, time, urllib.request, urllib.parse, hashlib
from dataclasses import dataclass, asdict
from pathlib import Path

UA = "Lictor-DiscordWebhookPatrol-SG/0.1 (+https://lictor-ai.com)"

WEBHOOK_RX = re.compile(
    r'https?://(?:[a-z]+\.)?discord(?:app)?\.com/api/webhooks/(\d+)/([A-Za-z0-9_-]+)',
    re.IGNORECASE)

@dataclass
class WebhookFinding:
    repo: str
    file_path: str
    webhook_id: str
    webhook_hash: str
    context: str = ""
    severity: str = "INFO"
    notes: str = ""

def http_post_json(url: str, payload: dict, timeout: int = 20) -> dict | None:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={
        "User-Agent": UA,
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read(2_000_000))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            print("[!] sourcegraph 429 — sleeping 15s")
            time.sleep(15)
        else:
            print(f"[!] HTTPError {e.code}")
        return None
    except Exception as e:
        print(f"[!] http error: {e}")
        return None

def sg_stream_search(query: str) -> list[dict]:
    """
    Sourcegraph public search via REST stream endpoint.
    SSE events: filters, progress, matches, alert, done.
    We only care about 'matches' events — those contain the actual code hits.
    """
    url = (f"https://sourcegraph.com/.api/search/stream?"
           f"q={urllib.parse.quote(query)}"
           f"&display=200")
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/event-stream",
    })
    matches: list[dict] = []
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            buf = ""
            while True:
                chunk = r.read(64_000)
                if not chunk: break
                buf += chunk.decode("utf-8", "replace")
                while "\n\n" in buf:
                    event_block, buf = buf.split("\n\n", 1)
                    # Parse "event: <type>" + "data: <json>" lines
                    evt_type = None
                    data_lines = []
                    for line in event_block.split("\n"):
                        if line.startswith("event: "):
                            evt_type = line[7:].strip()
                        elif line.startswith("data: "):
                            data_lines.append(line[6:])
                    if evt_type != "matches" or not data_lines:
                        continue
                    try:
                        data = json.loads("\n".join(data_lines))
                    except Exception:
                        continue
                    # matches event payload is a list of match objects
                    if isinstance(data, list):
                        matches.extend(data)
                    elif isinstance(data, dict):
                        matches.append(data)
                    if len(matches) > 500: break
                if len(matches) > 500: break
    except Exception as e:
        print(f"[!] sourcegraph stream error: {e}")
    return matches

def score_severity(repo: str, file_path: str) -> tuple[str, str]:
    pl = file_path.lower()
    if any(x in pl for x in ("test/", "tests/", "example/", "examples/",
                              "sample", "demo", "fixture", "mock", "spec/")):
        return "LOW", "test/sample file"
    if any(x in pl for x in (".env", ".github/", "config", "secrets",
                              "deploy", "docker-compose", "k8s/", "terraform")):
        return "HIGH", "leak in CI/config/deployment file"
    return "MEDIUM", "leak in code/config"

def find_webhooks() -> list[WebhookFinding]:
    findings: list[WebhookFinding] = []
    seen_hashes: set[str] = set()
    # Sourcegraph query: match the webhook URL pattern across public code
    query = 'discord.com/api/webhooks/ count:200'
    print(f"[+] Sourcegraph stream search: {query}")
    raw = sg_stream_search(query)
    print(f"  → {len(raw)} raw events")
    for event in raw:
        # Sourcegraph match shapes: content (file match) or path (path match)
        if not isinstance(event, dict): continue
        if event.get("type") not in (None, "content", "path"): continue
        repo = event.get("repository", "?")
        path = event.get("path", "?")
        # 'content' matches have chunkMatches with full snippets
        chunk_matches = event.get("chunkMatches") or []
        line_matches = event.get("lineMatches") or []
        preview_text = ""
        for cm in chunk_matches:
            preview_text += cm.get("content", "") + "\n"
        for lm in line_matches:
            preview_text += lm.get("preview", "") + "\n"
        if not preview_text:
            continue
        for m in WEBHOOK_RX.finditer(preview_text):
            full_url = m.group(0)
            webhook_id = m.group(1)
            h = hashlib.sha256(full_url.encode()).hexdigest()[:16]
            if h in seen_hashes: continue
            seen_hashes.add(h)
            start = max(0, m.start() - 60)
            end = min(len(preview_text), m.end() + 60)
            ctx_raw = preview_text[start:end].replace("\n", " ").replace("\r", "")
            ctx = WEBHOOK_RX.sub(
                lambda x: f"https://discord.com/api/webhooks/{x.group(1)}/REDACTED",
                ctx_raw)[:240]
            sev, note = score_severity(repo, path)
            findings.append(WebhookFinding(
                repo=repo, file_path=path,
                webhook_id=webhook_id, webhook_hash=h,
                context=ctx, severity=sev, notes=note))
    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger",
                    default="/Users/raffa/Lictor/v3/ledgers/discord-webhook-leak-sg.jsonl")
    args = ap.parse_args()

    print(f"[+] Discord-webhook-leak via Sourcegraph (no auth)")
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)

    findings = find_webhooks()
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
    print(f"[+] Note: webhook tokens REDACTED. Disclose to repo owner + Discord server admin.")

if __name__ == "__main__":
    main()
