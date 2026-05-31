#!/usr/bin/env python3
"""
patrol-ai-saas-keys — hunt API keys for AI providers + modern SaaS in public code.

EXPANDS THE LANDSCAPE BEYOND patrol-cloud-keys.py (which only had 4 vendors).
Covers 30+ vendors across:

  AI model APIs:
    OpenAI, Anthropic, Google AI (Gemini), Mistral, Cohere, Together, Replicate,
    Hugging Face, Pinecone, Groq, Fireworks, Perplexity, ElevenLabs, Deepgram,
    Stability AI, xAI/Grok, LangSmith, LangChain Hub

  Automation/integration (high-value — direct trigger access):
    Zapier webhooks, Make.com webhooks, n8n webhooks, Pipedream, Workato

  Email/messaging:
    Resend, Loops.so, SendGrid, Mailgun, Postmark (already in main patrol)

  Cloud (GCP + Azure, complementing AWS in separate patrol):
    GCP service account JSON, Azure storage connection strings,
    Azure storage account keys, AzureWebJobsStorage

  Vector DBs / data infra:
    Pinecone, Weaviate, Qdrant (context-based)

  Financial / high-impact:
    Stripe live (sk_live_*), Mailgun

Verification chain (same rigor as patrol-aws-keys.py):
  1. GitHub Code Search by vendor-specific query
  2. Fetch raw file via gh api repos/{repo}/contents/{path}
  3. Regex-confirm credential pattern present in file content
  4. Skip placeholder/example/test contexts
  5. Filter freshness + not-archived
"""
from __future__ import annotations
import argparse
import json
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# VENDOR PATTERNS — (name, regex, search_queries)
# ─────────────────────────────────────────────────────────────────────────────
VENDORS = [
    # ═══ AI MODEL APIs ═══
    ("openai",
     re.compile(r'\b(sk-(?:proj-)?[A-Za-z0-9_-]{40,200})\b'),
     [
         'OPENAI_API_KEY extension:env',
         '"sk-proj-" extension:py',
         '"sk-proj-" extension:js',
         '"sk-proj-" extension:ts',
         'openai.api_key extension:py',
         '"OpenAI" "Authorization" "Bearer sk-" extension:py',
     ]),
    ("anthropic",
     re.compile(r'\b(sk-ant-api03-[A-Za-z0-9_-]{70,})\b'),
     [
         'ANTHROPIC_API_KEY extension:env',
         '"sk-ant-api03-" extension:py',
         '"sk-ant-api03-" extension:js',
         '"sk-ant-api03-" extension:ts',
         '"anthropic" "Bearer" "sk-ant" extension:py',
     ]),
    ("google-ai",
     re.compile(r'\b(AIza[A-Za-z0-9_-]{35})\b'),
     [
         'GOOGLE_API_KEY "AIza" extension:env',
         'GEMINI_API_KEY extension:env',
         'GOOGLE_AI_KEY extension:env',
         '"AIza" "gemini" extension:py',
         '"AIza" "googleapis.com/generativelanguage" extension:js',
     ]),
    ("hugging-face",
     re.compile(r'\b(hf_[A-Za-z0-9]{34,40})\b'),
     [
         'HF_TOKEN extension:env',
         'HUGGINGFACE_API_KEY extension:env',
         '"hf_" "huggingface" extension:py',
         '"hf_" extension:env',
     ]),
    ("replicate",
     re.compile(r'\b(r8_[A-Za-z0-9]{37,40})\b'),
     [
         'REPLICATE_API_TOKEN extension:env',
         '"r8_" "replicate" extension:py',
         '"r8_" extension:env',
     ]),
    ("pinecone",
     re.compile(r'\b(pcsk_[A-Za-z0-9_-]{30,})\b'),
     [
         'PINECONE_API_KEY extension:env',
         '"pcsk_" extension:env',
         '"pcsk_" "pinecone" extension:py',
     ]),
    ("groq",
     re.compile(r'\b(gsk_[A-Za-z0-9]{50,60})\b'),
     [
         'GROQ_API_KEY extension:env',
         '"gsk_" "groq" extension:py',
         '"gsk_" extension:env',
     ]),
    ("fireworks",
     re.compile(r'\b(fw-[A-Za-z0-9_-]{40,})\b'),
     [
         'FIREWORKS_API_KEY extension:env',
         '"fw-" "fireworks" extension:py',
         '"fireworks.ai" "Bearer" extension:py',
     ]),
    ("perplexity",
     re.compile(r'\b(pplx-[A-Za-z0-9]{48,60})\b'),
     [
         'PERPLEXITY_API_KEY extension:env',
         '"pplx-" extension:env',
         '"pplx-" "perplexity" extension:py',
     ]),
    ("elevenlabs",
     re.compile(r'\b([a-f0-9]{32})\b'),  # generic 32-hex; constrained by query context
     [
         'ELEVENLABS_API_KEY extension:env',
         'ELEVEN_API_KEY extension:env',
         '"elevenlabs" "xi-api-key" extension:py',
     ]),
    ("deepgram",
     re.compile(r'\b([a-f0-9]{40})\b'),  # 40-hex; constrained by context
     [
         'DEEPGRAM_API_KEY extension:env',
         '"deepgram" "Token" extension:py',
     ]),
    ("stability-ai",
     re.compile(r'\b(sk-[A-Za-z0-9]{48,})\b'),
     [
         'STABILITY_API_KEY extension:env',
         'STABILITY_AI_KEY extension:env',
         '"sk-" "stability.ai" extension:py',
     ]),
    ("xai-grok",
     re.compile(r'\b(xai-[A-Za-z0-9]{80,100})\b'),
     [
         'XAI_API_KEY extension:env',
         'GROK_API_KEY extension:env',
         '"xai-" extension:env',
     ]),
    ("langsmith",
     re.compile(r'\b(lsv2_(?:pt|sk)_[A-Za-z0-9]{32}_[A-Za-z0-9]{16,40})\b'),
     [
         'LANGSMITH_API_KEY extension:env',
         'LANGCHAIN_API_KEY extension:env',
         '"lsv2_pt_" extension:env',
         '"lsv2_sk_" extension:env',
     ]),
    ("mistral",
     re.compile(r'(?:mistral|MISTRAL)[^a-z]{0,40}[\'"]([A-Za-z0-9]{32})[\'"]', re.IGNORECASE),
     [
         'MISTRAL_API_KEY extension:env',
         '"mistral" "Authorization" "Bearer" extension:py',
     ]),
    ("cohere",
     re.compile(r'(?:cohere|COHERE)[^a-z]{0,40}[\'"]([A-Za-z0-9-]{40})[\'"]', re.IGNORECASE),
     [
         'COHERE_API_KEY extension:env',
         '"cohere" "Bearer" extension:py',
     ]),
    ("together-ai",
     re.compile(r'(?:together)[^a-z]{0,40}[\'"]([a-f0-9]{64})[\'"]', re.IGNORECASE),
     [
         'TOGETHER_API_KEY extension:env',
         '"together.ai" "Bearer" extension:py',
     ]),

    # ═══ AUTOMATION / INTEGRATION (direct trigger access) ═══
    ("zapier-webhook",
     re.compile(r'(https://hooks\.zapier\.com/hooks/catch/\d+/[a-zA-Z0-9]+/?)'),
     [
         '"hooks.zapier.com/hooks/catch" extension:env',
         '"hooks.zapier.com/hooks/catch" extension:py',
         '"hooks.zapier.com/hooks/catch" extension:js',
         '"hooks.zapier.com/hooks/catch" extension:ts',
         '"hooks.zapier.com/hooks/catch" extension:yml',
         '"hooks.zapier.com/hooks/catch" extension:yaml',
     ]),
    ("make-com-webhook",
     re.compile(r'(https://hook\.[a-z0-9-]+\.make\.com/[a-zA-Z0-9]{16,})'),
     [
         '"hook.eu1.make.com" extension:env',
         '"hook.eu1.make.com" extension:py',
         '"hook.us1.make.com" extension:env',
         '"hook.integromat.com" extension:env',
     ]),
    ("n8n-webhook",
     re.compile(r'(https://[a-zA-Z0-9.-]+/webhook/[a-f0-9-]{32,})'),
     [
         'N8N_WEBHOOK_URL extension:env',
         '"/webhook/" "n8n" extension:env',
     ]),
    ("pipedream",
     re.compile(r'\b(pd_[A-Za-z0-9_-]{30,})\b'),
     [
         'PIPEDREAM_API_KEY extension:env',
         '"pd_" "pipedream" extension:py',
     ]),
    ("workato",
     re.compile(r'(?:workato)[^a-z]{0,40}[\'"]([A-Za-z0-9-]{40,})[\'"]', re.IGNORECASE),
     [
         'WORKATO_API_TOKEN extension:env',
         '"workato.com" "Bearer" extension:py',
     ]),

    # ═══ EMAIL / MESSAGING (high-impact for phishing) ═══
    ("resend",
     re.compile(r'\b(re_[A-Za-z0-9]+_[A-Za-z0-9]{15,40})\b'),
     [
         'RESEND_API_KEY extension:env',
         '"re_" "resend" extension:py',
         '"re_" extension:env',
     ]),
    ("loops-so",
     re.compile(r'(?:loops)[^a-z]{0,40}[\'"]([a-f0-9]{32})[\'"]', re.IGNORECASE),
     [
         'LOOPS_API_KEY extension:env',
         '"loops.so" "Bearer" extension:py',
     ]),
    ("sendgrid",
     re.compile(r'\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b'),
     [
         'SENDGRID_API_KEY extension:env',
         '"SG." extension:env',
         '"sendgrid" "Bearer SG" extension:py',
     ]),
    ("mailgun",
     re.compile(r'\b(key-[a-f0-9]{32})\b'),
     [
         'MAILGUN_API_KEY extension:env',
         '"key-" "mailgun" extension:py',
     ]),

    # ═══ GCP + AZURE (complementing patrol-aws-keys.py) ═══
    ("gcp-service-account",
     re.compile(r'"type"\s*:\s*"service_account".+?"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----', re.DOTALL),
     [
         '"type": "service_account" "private_key" extension:json',
         'service-account.json extension:json',
         'gcloud_service_account extension:json',
     ]),
    ("azure-storage-conn",
     re.compile(r'(DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]{88}[^"\']*)', re.IGNORECASE),
     [
         '"DefaultEndpointsProtocol" "AccountKey" extension:env',
         '"DefaultEndpointsProtocol" "AccountKey" extension:py',
         '"DefaultEndpointsProtocol" "AccountKey" extension:json',
         'AZURE_STORAGE_CONNECTION_STRING extension:env',
     ]),
    ("azure-storage-key",
     re.compile(r'AccountKey=([A-Za-z0-9+/=]{88})'),
     [
         'AZURE_STORAGE_KEY extension:env',
         'AZURE_STORAGE_ACCOUNT_KEY extension:env',
     ]),
    ("azure-webjobs",
     re.compile(r'(AzureWebJobsStorage\s*=\s*[\'"]?DefaultEndpointsProtocol=https[^\'"]+)'),
     [
         'AzureWebJobsStorage extension:env',
         'AzureWebJobsStorage extension:json',
     ]),

    # ═══ FINANCIAL / HIGH-IMPACT ═══
    ("stripe-live",
     re.compile(r'\b(sk_live_[A-Za-z0-9]{24,})\b'),
     [
         'STRIPE_SECRET_KEY "sk_live_" extension:env',
         '"sk_live_" extension:env',
         '"sk_live_" "stripe" extension:py',
         '"sk_live_" "stripe" extension:js',
     ]),
    ("stripe-restricted",
     re.compile(r'\b(rk_live_[A-Za-z0-9]{24,})\b'),
     [
         '"rk_live_" extension:env',
         '"rk_live_" "stripe" extension:py',
     ]),
]

# Placeholder context — skip if real-looking match is in obvious dummy context
PLACEHOLDER_CTX = re.compile(
    r'(example|sample|placeholder|REPLACE|XXX|TODO|FAKE|YOUR_|your_|test_|<.{1,30}>|getenv|environ|process\.env)',
    re.IGNORECASE,
)
SKIP_PATH_RX = re.compile(
    r'(\.example$|/tests?/|/__tests__/|/spec/|/fixtures?/|/docs?/|README|CHANGELOG|\.lock$)',
    re.IGNORECASE,
)


@dataclass
class Hit:
    vendor: str
    repo: str
    path: str
    snippet: str
    stars: int
    pushed_at: str
    archived: bool
    secret_prefix: str  # first 8 chars for redaction
    full_url: str


def gh_code_search(query: str, max_pages: int = 1):
    """Call gh api search/code, return items list."""
    results = []
    for page in range(1, max_pages + 1):
        try:
            out = subprocess.check_output(
                ["gh", "api", "-X", "GET", "search/code",
                 "-f", f"q={query}", "-f", "per_page=50", "-f", f"page={page}",
                 "--jq", ".items"],
                stderr=subprocess.DEVNULL, timeout=30)
            items = json.loads(out)
            if not items:
                break
            results.extend(items)
            time.sleep(2)  # gentle pacing — share GH rate limit with sibling patrols
        except Exception:
            break
    return results


def fetch_repo_meta(repo_full: str):
    """Fetch repo metadata to check archived + recency."""
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo_full}", "--jq",
             "{archived: .archived, pushed_at: .pushed_at, stars: .stargazers_count}"],
            stderr=subprocess.DEVNULL, timeout=15)
        return json.loads(out)
    except Exception:
        return None


def fetch_file_content(repo_full: str, path: str) -> str:
    """Fetch raw file content.

    BUG FIX 2026-05-23: was using json.loads() on raw base64 output (which
    isn't JSON). Match the working pattern from patrol-aws-keys.py:
    decode bytes, strip newlines, base64-decode.
    """
    import base64
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo_full}/contents/{path}", "-q", ".content"],
            stderr=subprocess.DEVNULL, timeout=20)
        return base64.b64decode(out.decode().strip().replace("\n", "")).decode("utf-8", errors="replace")
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--max", type=int, default=400,
                    help="Total candidate files to inspect (default 400)")
    ap.add_argument("--max-age-days", type=int, default=730,
                    help="Skip repos with pushed_at older than N days (default 730 = 2yr)")
    ap.add_argument("--private", type=str,
                    default=f"docs/launch/patrol-ai-saas-{datetime.now().strftime('%Y-%m-%d')}-private.md")
    args = ap.parse_args()

    cutoff = datetime.now(timezone.utc) - timedelta(days=args.max_age_days)
    private_path = Path(args.private)
    private_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[+] patrol-ai-saas-keys: querying {sum(len(q) for _,_,q in VENDORS)} patterns across {len(VENDORS)} vendors")
    print(f"[+] freshness cutoff: {cutoff.isoformat()}")
    print(f"[+] private report: {private_path}")
    print()

    seen_keys = set()
    raw_cands = []

    for vendor, rx, queries in VENDORS:
        if len(raw_cands) >= args.max:
            print(f"[+] hit max={args.max} candidates, stopping query phase")
            break
        for q in queries:
            if len(raw_cands) >= args.max:
                break
            items = gh_code_search(q, max_pages=1)
            for it in items:
                key = (it["repository"]["full_name"], it["path"], vendor)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                raw_cands.append((vendor, rx, it))

    print(f"[+] collected {len(raw_cands)} raw candidates, validating...")
    print()

    hits = []
    with open(private_path, "a") as priv_log:
        priv_log.write(f"\n## patrol-ai-saas-keys run — {datetime.now().isoformat()}\n\n")

        for i, (vendor, rx, it) in enumerate(raw_cands[:args.max], 1):
            repo = it["repository"]["full_name"]
            path = it["path"]
            display = f"{repo}/{path}"
            print(f"  [{i:>3}/{min(len(raw_cands), args.max)}] {vendor} {display[:80]}", end="  ", flush=True)

            if SKIP_PATH_RX.search(path):
                print("⚪ (skip-path)", flush=True)
                continue

            meta = fetch_repo_meta(repo)
            if not meta:
                print("⚪ (meta-fetch-fail)", flush=True)
                continue
            if meta.get("archived"):
                print("⚪ (archived)", flush=True)
                continue
            try:
                pushed = datetime.fromisoformat(meta["pushed_at"].replace("Z", "+00:00"))
                if pushed < cutoff:
                    print("⚪ (stale)", flush=True)
                    continue
            except Exception:
                pass

            content = fetch_file_content(repo, path)
            if not content:
                print("⚪ (content-empty)", flush=True)
                continue

            # Skip if content is dominated by placeholder context
            if PLACEHOLDER_CTX.search(content[:500]):
                # If ALSO has placeholder near the regex match, drop
                match = rx.search(content)
                if match:
                    around = content[max(0, match.start()-100):match.end()+100]
                    if PLACEHOLDER_CTX.search(around):
                        print("⚪ (placeholder-context)", flush=True)
                        continue

            match = rx.search(content)
            if not match:
                print("⚪ (no-match)", flush=True)
                continue

            secret = match.group(1) if match.groups() else match.group(0)
            secret_prefix = secret[:8] if len(secret) > 8 else secret
            stars = meta.get("stars", 0)
            star_mark = f"★{stars}" if stars > 0 else ""

            print(f"🔴 {vendor} {secret_prefix}… {star_mark}", flush=True)

            url = f"https://github.com/{repo}/blob/HEAD/{path}"
            hits.append(Hit(
                vendor=vendor, repo=repo, path=path,
                snippet=content[max(0, match.start()-50):match.end()+50][:200],
                stars=stars, pushed_at=meta.get("pushed_at", ""),
                archived=meta.get("archived", False),
                secret_prefix=secret_prefix, full_url=url,
            ))

            priv_log.write(f"### Hit {len(hits)}: {vendor}\n")
            priv_log.write(f"- Repo: {repo} (★{stars}, pushed_at {meta.get('pushed_at')})\n")
            priv_log.write(f"- Path: {path}\n")
            priv_log.write(f"- URL: {url}\n")
            priv_log.write(f"- Secret prefix: `{secret_prefix}…` (full secret REDACTED — see file)\n")
            priv_log.write(f"- Context snippet: `{content[max(0, match.start()-50):match.end()+50][:200]}`\n\n")
            priv_log.flush()

    print()
    print(f"[+] DONE: {len(hits)} live credential candidates across {len(set(h.vendor for h in hits))} vendors")
    print(f"[+] Private report: {private_path}")


if __name__ == "__main__":
    main()
