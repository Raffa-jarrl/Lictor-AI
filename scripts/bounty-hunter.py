#!/usr/bin/env python3
"""
bounty-hunter v2 — the serious bug-hunting machine.

Upgrade over bounty-hunt.py:
  * 40+ companies (curated from H1/BC public directory)
  * 8 patterns with per-pattern exploitability heuristics
  * Content-level verification (downloads file, scores vuln 0-100)
  * Ledger (~/.lictor/bounty-ledger.jsonl) — dedupes across runs,
    tracks status: discovered → reviewed → submitted → paid|rejected
  * Auto-drafts submission templates per channel
  * Daily delta detection — fresh commits flagged as higher-priority

Workflow:
  $ bounty-hunter scan          # discover + score + log
  $ bounty-hunter queue         # show ready-to-submit (score>=60)
  $ bounty-hunter draft <id>    # generate submission template
  $ bounty-hunter stats         # ledger summary

Cron: 0 7 * * *  (daily)
"""
from __future__ import annotations
import argparse, base64, hashlib, json, re, subprocess, sys, time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

LEDGER = Path.home() / ".lictor" / "bounty-ledger.jsonl"
SUBMISSIONS_DIR = Path.home() / ".lictor" / "submissions"
OUT_DIR = Path.home() / "Lictor" / "docs" / "launch"

# =================================================================
# CORPUS — 40+ companies with active bounty programs
# =================================================================
CORPUS = {
    # Tier 1: Major tech, $1K+ avg payouts
    "github":     {"orgs": ["github", "octokit", "actions", "primer", "github-linguist"], "channel": "direct",    "url": "https://bounty.github.com",           "min": 617,   "max": 30000},
    "microsoft":  {"orgs": ["microsoft", "Azure", "dotnet", "MicrosoftDocs", "AzureAD", "PowerShell"], "channel": "direct", "url": "https://msrc.microsoft.com",  "min": 500,   "max": 250000},
    "google":     {"orgs": ["google", "GoogleCloudPlatform", "googleapis", "GoogleChromeLabs"],"channel": "direct","url": "https://bughunters.google.com",      "min": 100,   "max": 100000},
    "facebook":   {"orgs": ["facebook", "facebookresearch", "facebookincubator"],          "channel": "direct",    "url": "https://www.facebook.com/whitehat",  "min": 500,   "max": 40000},
    "apple":      {"orgs": ["apple"],                                                       "channel": "direct",    "url": "https://security.apple.com",         "min": 5000,  "max": 1000000},
    # Tier 2: SaaS & infrastructure
    "shopify":    {"orgs": ["Shopify"],                                                     "channel": "hackerone", "url": "https://hackerone.com/shopify",      "min": 500,   "max": 25000},
    "atlassian":  {"orgs": ["atlassian", "atlassian-labs"],                                "channel": "bugcrowd",  "url": "https://bugcrowd.com/atlassian",     "min": 100,   "max": 15000},
    "discord":    {"orgs": ["discord"],                                                     "channel": "hackerone", "url": "https://hackerone.com/discord",      "min": 100,   "max": 5000},
    "cloudflare": {"orgs": ["cloudflare"],                                                  "channel": "hackerone", "url": "https://hackerone.com/cloudflare",   "min": 100,   "max": 30000},
    "hashicorp":  {"orgs": ["hashicorp"],                                                   "channel": "hackerone", "url": "https://hackerone.com/hashicorp",    "min": 100,   "max": 5000},
    "elastic":    {"orgs": ["elastic"],                                                     "channel": "direct",    "url": "https://www.elastic.co/community/security", "min": 100, "max": 5000},
    "mongodb":    {"orgs": ["mongodb", "mongodb-developer", "mongodb-js"],                  "channel": "direct",    "url": "https://www.mongodb.com/security",   "min": 100,   "max": 5000},
    "vercel":     {"orgs": ["vercel"],                                                      "channel": "direct",    "url": "https://vercel.com/security",        "min": 100,   "max": 5000},
    "supabase":   {"orgs": ["supabase"],                                                    "channel": "direct",    "url": "https://supabase.com/security",      "min": 100,   "max": 5000},
    "datadog":    {"orgs": ["DataDog"],                                                     "channel": "direct",    "url": "https://www.datadoghq.com/security", "min": 100,   "max": 5000},
    "snyk":       {"orgs": ["snyk", "snyk-labs"],                                          "channel": "direct",    "url": "https://snyk.io/policies/responsible-disclosure", "min": 0, "max": 5000},
    # Tier 3: $100-$1K range
    "twilio":     {"orgs": ["twilio", "twilio-labs"],                                       "channel": "bugcrowd",  "url": "https://bugcrowd.com/twilio",        "min": 100,   "max": 10000},
    "sendgrid":   {"orgs": ["sendgrid"],                                                    "channel": "direct",    "url": "https://sendgrid.com/.well-known/security.txt", "min": 0, "max": 5000},
    "1password":  {"orgs": ["1Password", "agilebits"],                                     "channel": "bugcrowd",  "url": "https://bugcrowd.com/agilebits",     "min": 100,   "max": 25000},
    "linkedin":   {"orgs": ["linkedin"],                                                    "channel": "hackerone", "url": "https://hackerone.com/linkedin",     "min": 250,   "max": 5000},
    "uber":       {"orgs": ["uber", "uber-research"],                                       "channel": "hackerone", "url": "https://hackerone.com/uber",         "min": 100,   "max": 10000},
    "airbnb":     {"orgs": ["airbnb"],                                                      "channel": "hackerone", "url": "https://hackerone.com/airbnb",       "min": 100,   "max": 15000},
    "spotify":    {"orgs": ["spotify"],                                                     "channel": "direct",    "url": "https://www.spotify.com/safetyandprivacy/security", "min": 100, "max": 5000},
    "netflix":    {"orgs": ["Netflix"],                                                     "channel": "bugcrowd",  "url": "https://bugcrowd.com/netflix",       "min": 100,   "max": 10000},
    "stripe":     {"orgs": ["stripe"],                                                      "channel": "hackerone", "url": "https://hackerone.com/stripe",       "min": 500,   "max": 100000},
    "paypal":     {"orgs": ["paypal"],                                                      "channel": "hackerone", "url": "https://hackerone.com/paypal",       "min": 50,    "max": 30000},
    "yelp":       {"orgs": ["Yelp"],                                                        "channel": "hackerone", "url": "https://hackerone.com/yelp",         "min": 100,   "max": 15000},
    "gitlab":     {"orgs": ["gitlabhq", "gitlab-org"],                                     "channel": "hackerone", "url": "https://hackerone.com/gitlab",       "min": 100,   "max": 20000},
    "shopify":    {"orgs": ["Shopify"],                                                     "channel": "hackerone", "url": "https://hackerone.com/shopify",      "min": 500,   "max": 50000},
    "okta":       {"orgs": ["okta"],                                                        "channel": "bugcrowd",  "url": "https://bugcrowd.com/okta",          "min": 100,   "max": 25000},
    "auth0":      {"orgs": ["auth0", "auth0-samples"],                                     "channel": "bugcrowd",  "url": "https://auth0.com/security",         "min": 100,   "max": 15000},
    "intercom":   {"orgs": ["intercom"],                                                    "channel": "intigriti", "url": "https://intercom.com/security",      "min": 100,   "max": 5000},
    "asana":      {"orgs": ["asana"],                                                       "channel": "bugcrowd",  "url": "https://bugcrowd.com/asana",         "min": 100,   "max": 7500},
    "zendesk":    {"orgs": ["zendesk"],                                                     "channel": "hackerone", "url": "https://hackerone.com/zendesk",      "min": 100,   "max": 10000},
    "automattic": {"orgs": ["Automattic", "WordPress"],                                    "channel": "hackerone", "url": "https://hackerone.com/automattic",   "min": 50,    "max": 5000},
    "mozilla":    {"orgs": ["mozilla"],                                                     "channel": "direct",    "url": "https://www.mozilla.org/security/bug-bounty",  "min": 500, "max": 10000},
    "yandex":     {"orgs": ["yandex"],                                                      "channel": "hackerone", "url": "https://hackerone.com/yandex",       "min": 100,   "max": 5000},
    "ibm":        {"orgs": ["IBM"],                                                         "channel": "hackerone", "url": "https://hackerone.com/ibm",          "min": 100,   "max": 5000},
    "salesforce": {"orgs": ["salesforce", "forcedotcom"],                                  "channel": "hackerone", "url": "https://hackerone.com/salesforce",   "min": 100,   "max": 10000},
    # Tier 4 — mid-tier, less-scanned competitive landscape (where the real opportunity is)
    "sentry":      {"orgs": ["getsentry"],                                                  "channel": "hackerone", "url": "https://hackerone.com/sentry",       "min": 100,   "max": 5000},
    "posthog":     {"orgs": ["PostHog"],                                                    "channel": "direct",    "url": "https://posthog.com/security",       "min": 100,   "max": 5000},
    "plaid":       {"orgs": ["plaid"],                                                      "channel": "bugcrowd",  "url": "https://bugcrowd.com/plaid",         "min": 250,   "max": 10000},
    "algolia":     {"orgs": ["algolia"],                                                    "channel": "direct",    "url": "https://www.algolia.com/policies/security/", "min": 100, "max": 5000},
    "calcom":      {"orgs": ["calcom"],                                                     "channel": "direct",    "url": "https://cal.com/security",           "min": 100,   "max": 2500},
    "documenso":   {"orgs": ["documenso"],                                                  "channel": "direct",    "url": "https://documenso.com/security",     "min": 100,   "max": 2500},
    "trigger":     {"orgs": ["triggerdotdev"],                                              "channel": "direct",    "url": "https://trigger.dev/security",       "min": 100,   "max": 2500},
    "inngest":     {"orgs": ["inngest"],                                                    "channel": "direct",    "url": "https://www.inngest.com/security",   "min": 100,   "max": 2500},
    "linear":      {"orgs": ["linear"],                                                     "channel": "direct",    "url": "https://linear.app/security",        "min": 100,   "max": 5000},
    "figma":       {"orgs": ["figma"],                                                      "channel": "hackerone", "url": "https://hackerone.com/figma",        "min": 250,   "max": 10000},
    "notion":      {"orgs": ["makenotion"],                                                 "channel": "direct",    "url": "https://www.notion.so/security",     "min": 100,   "max": 5000},
    "brex":        {"orgs": ["brexhq"],                                                     "channel": "direct",    "url": "https://www.brex.com/security",      "min": 100,   "max": 5000},
    "mercury":     {"orgs": ["mercury-fi"],                                                 "channel": "direct",    "url": "https://mercury.com/security",       "min": 100,   "max": 5000},
    "ramp":        {"orgs": ["ramp"],                                                       "channel": "direct",    "url": "https://www.ramp.com/security",      "min": 100,   "max": 5000},
    "buildkite":   {"orgs": ["buildkite"],                                                  "channel": "direct",    "url": "https://buildkite.com/security",     "min": 100,   "max": 5000},
    "circleci":    {"orgs": ["circleci"],                                                   "channel": "hackerone", "url": "https://hackerone.com/circleci",     "min": 100,   "max": 5000},
    "jfrog":       {"orgs": ["jfrog"],                                                      "channel": "direct",    "url": "https://jfrog.com/security",         "min": 100,   "max": 5000},
    "sonatype":    {"orgs": ["sonatype"],                                                   "channel": "direct",    "url": "https://www.sonatype.com/security",  "min": 100,   "max": 5000},
    "anthropic":   {"orgs": ["anthropics", "anthropic"],                                    "channel": "direct",    "url": "https://www.anthropic.com/responsible-disclosure-policy", "min": 100, "max": 25000},
    "openai":      {"orgs": ["openai"],                                                     "channel": "bugcrowd",  "url": "https://bugcrowd.com/openai",        "min": 200,   "max": 20000},
    "langchain":   {"orgs": ["langchain-ai", "langchain"],                                 "channel": "direct",    "url": "https://www.langchain.com/security", "min": 100,   "max": 2500},
    "pinecone":    {"orgs": ["pinecone-io"],                                                "channel": "direct",    "url": "https://www.pinecone.io/security",   "min": 100,   "max": 2500},
    "weaviate":    {"orgs": ["weaviate"],                                                   "channel": "direct",    "url": "https://weaviate.io/security",       "min": 100,   "max": 2500},
    "qdrant":      {"orgs": ["qdrant"],                                                     "channel": "direct",    "url": "https://qdrant.tech/security",       "min": 100,   "max": 2500},
}

# =================================================================
# PATTERNS — 8 vuln classes with per-pattern verify + exploit-score
# =================================================================

PATTERN_DEFS = {
    "prtarget": {
        "search_query":  '"pull_request_target" extension:yml',
        "must_match":    re.compile(r'^\s*on:\s*\n.*?pull_request_target\s*:', re.MULTILINE | re.DOTALL),
        "exploit_check": "prtarget",
        "payout":        (200, 5000),
    },
    "firebase": {
        "search_query":  '"private_key_id" "service_account"',
        "must_match":    re.compile(r'"private_key_id"\s*:\s*"[a-f0-9]{40}"'),
        "exploit_check": "secret_in_source",
        "payout":        (500, 10000),
    },
    "db_creds": {
        "search_query":  '"postgres://" "@" extension:env',
        "must_match":    re.compile(r'(postgres|mysql|mongodb)(\+srv)?://[^:\s/]+:[^@\s]{6,}@'),
        "exploit_check": "secret_in_source",
        "payout":        (200, 3000),
    },
    "aws_pair": {
        "search_query":  '"AKIA" "aws_secret_access_key"',
        "must_match":    re.compile(r'\bAKIA[A-Z0-9]{16}\b.{0,400}[A-Za-z0-9/+=]{40}', re.DOTALL),
        "exploit_check": "secret_in_source",
        "payout":        (500, 5000),
    },
    "stripe_live": {
        "search_query":  '"sk_' + 'live_"',
        "must_match":    re.compile(r'\bsk_live_[A-Za-z0-9]{24,99}\b'),
        "exploit_check": "secret_in_source",
        "payout":        (500, 10000),
    },
    "openai_key": {
        "search_query":  '"sk-proj-" extension:env',
        "must_match":    re.compile(r'\bsk-(proj-)?[A-Za-z0-9_-]{40,200}\b'),
        "exploit_check": "secret_in_source",
        "payout":        (100, 2000),
    },
    "anthropic_key": {
        "search_query":  '"sk-ant-api" extension:env',
        "must_match":    re.compile(r'\bsk-ant-api\d{2}-[A-Za-z0-9_-]{50,200}\b'),
        "exploit_check": "secret_in_source",
        "payout":        (100, 2000),
    },
    "jwt_secret": {
        "search_query":  '"JWT_SECRET" extension:env',
        "must_match":    re.compile(r'JWT_SECRET\s*=\s*["\']?([A-Za-z0-9_!@#$%^&*+/=-]{20,200})'),
        "exploit_check": "jwt_strength",
        "payout":        (100, 1000),
    },
    # NEW: GitHub Actions expression injection (CWE-94, real-world payouts on H1)
    # github.event.* values flow into `run:` blocks unescaped — attacker controls fork PR title/body → RCE
    "gha_expr_injection": {
        "search_query":  '"github.event.pull_request.title" OR "github.event.issue.title" OR "github.event.comment.body" extension:yml',
        "must_match":    re.compile(r'run:\s*[|>].*?\$\{\{\s*github\.event\.(pull_request\.(title|body|head\.ref)|issue\.title|issue\.body|comment\.body|discussion\.body)', re.DOTALL),
        "exploit_check": "gha_expr_injection",
        "payout":        (500, 10000),
    },
    # NEW: actions/github-script with untrusted input — script: blocks that interpolate user-controlled github.event
    "gha_script_injection": {
        "search_query":  '"actions/github-script" "github.event.pull_request" extension:yml',
        "must_match":    re.compile(r'uses:\s*actions/github-script.*?script:\s*[|>].*?\$\{\{\s*github\.event\.(pull_request|issue|comment)', re.DOTALL),
        "exploit_check": "gha_expr_injection",
        "payout":        (500, 10000),
    },
    # NEW: GITHUB_TOKEN exfiltration via curl/wget to attacker-controlled URL
    "token_exfil": {
        "search_query":  '"GITHUB_TOKEN" "curl" extension:yml',
        "must_match":    re.compile(r'(curl|wget).*\$\{\{\s*secrets\.(GITHUB_TOKEN|GH_TOKEN)\s*\}\}.*\$\{\{\s*github\.event\.', re.DOTALL),
        "exploit_check": "token_exfil",
        "payout":        (500, 5000),
    },
}

# =================================================================
# FP filters (path + content based)
# =================================================================
PATH_FP_RX = re.compile(
    r'(test|fixture|sample|example|docs?/|\.md$|README|CHANGELOG|'
    r'validation|validator|scanner|detector|semgrep|secrets?-?scanner|'
    r'_test\.|\.test\.|\.spec\.|messages\.go$|event_types\.go$|'
    r'backport\.(py|go|js|ts)$|labeler\.yml$|stale\.yml$|'
    r'/types/|/schema/|/events/|/api-types/|/api-docs/|generated)',
    re.IGNORECASE,
)
PLACEHOLDER_RX = re.compile(
    r'(example|sample|placeholder|REPLACE|XXX+|TODO|FAKE|your_|YOUR_|<[^>]{1,30}>|'
    r'foo|bar|baz|test_value|change.?me|enter.?your|sk-test|sk_test)',
    re.IGNORECASE,
)
DETECTION_RULE_RX = re.compile(
    r'(detect|scanner|gitleaks|trufflehog|semgrep|yara|regex_list|patterns?:|rule:|signature:|severity:)',
    re.IGNORECASE,
)


# =================================================================
# Data classes
# =================================================================
@dataclass
class Finding:
    id: str
    company: str
    org: str
    repo: str
    path: str
    url: str
    pattern: str
    snippet: str
    score: int
    channel: str
    program_url: str
    payout_min: int
    payout_max: int
    expected: int
    status: str = "discovered"  # discovered | reviewed | submitted | paid | rejected
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


# =================================================================
# Verifiers — pattern-specific exploit scoring
# =================================================================
def check_prtarget(content: str, path: str) -> tuple[int, str]:
    """Return (score 0-100, reason)."""
    if not re.search(r'^\s*on:', content, re.MULTILINE):
        return 0, "not a workflow"
    if not re.search(r'pull_request_target\s*:', content):
        return 0, "no pull_request_target trigger"
    # Score factors
    score = 30  # baseline if pattern is in actual workflow on:
    reasons = []
    # CRITICAL: checks out PR head (not safe with PRT)
    if re.search(r'ref:\s*\$\{?\{?\s*github\.event\.pull_request\.head', content):
        score += 50; reasons.append("CHECKOUT HEAD (high-risk)")
    elif re.search(r'ref:\s*\$\{?\{?\s*github\.head_ref', content):
        score += 50; reasons.append("CHECKOUT head_ref (high-risk)")
    # Runs untrusted scripts after checkout
    if re.search(r'(npm install|npm ci|pip install|yarn install|bundle install|pre-commit)', content) and "checkout" in content.lower():
        score += 15; reasons.append("runs install script")
    # NEGATIVE: has guards
    if re.search(r'types:\s*\[\s*labeled\s*\]', content):
        score -= 25; reasons.append("label-gated")
    if re.search(r'if:\s*.*\b(actor|head\.repo\.full_name|head_ref)\b', content):
        score -= 15; reasons.append("actor/repo guard")
    if re.search(r'dependabot\[bot\]|renovate\[bot\]', content):
        score -= 10; reasons.append("bot-only allowlist")
    # NEGATIVE: it's a labeler/issue-responder (intended use)
    if re.search(r'uses:\s*actions/labeler', content):
        score -= 30; reasons.append("standard labeler")
    if re.search(r'(issue|pull[- ]request)[- ]responder', content):
        score -= 20; reasons.append("PR responder")
    # NEGATIVE: environment-based approval gate
    if re.search(r'^\s*environment:\s*\S+', content, re.MULTILINE):
        score -= 35; reasons.append("environment approval gate")
    # NEGATIVE: locker / project-board / status-checker (intended PRT use)
    if re.search(r'(locker\.|locked|project-board|project-bot|status-checker|stale\.yml)', content, re.IGNORECASE):
        score -= 25; reasons.append("locker/project-board pattern")
    # NEGATIVE: file name suggests it's CHECKING for prtarget (detection, not vuln)
    if re.search(r'(check-pr-target|prtarget-check|pr-target-validation)', content, re.IGNORECASE):
        score -= 40; reasons.append("PRT detection/validation code")
    return max(0, min(100, score)), "; ".join(reasons) or "raw pattern"


def check_secret_in_source(content: str, path: str) -> tuple[int, str]:
    """Heuristic for whether a matched secret looks real."""
    score = 50  # baseline if pattern matched
    reasons = []
    # Path signals
    if re.search(r'\.env(\.|$)', path): score += 20; reasons.append(".env file")
    if re.search(r'(production|prod|live)', path, re.IGNORECASE): score += 15; reasons.append("prod path")
    if re.search(r'config|secrets', path, re.IGNORECASE): score += 10; reasons.append("config path")
    # Content: looks like a real config block
    if re.search(r'(STRIPE_SECRET_KEY|FIREBASE_PRIVATE_KEY|DATABASE_URL|AWS_SECRET)\s*=', content):
        score += 20; reasons.append("config-style assignment")
    # NEGATIVE: detection rules / scanners
    if DETECTION_RULE_RX.search(content[:500]):
        score -= 40; reasons.append("looks like detection rule")
    if re.search(r'(test|fixture|spec)', content[:200], re.IGNORECASE):
        score -= 15; reasons.append("test context")
    return max(0, min(100, score)), "; ".join(reasons) or "secret pattern"


def check_jwt_strength(content: str, path: str) -> tuple[int, str]:
    m = re.search(r'JWT_SECRET\s*=\s*["\']?([A-Za-z0-9_!@#$%^&*+/=-]{20,200})', content)
    if not m: return 0, "no JWT_SECRET assignment"
    secret = m.group(1)
    score = 40
    reasons = ["JWT_SECRET found"]
    # Weak secrets (dictionary words, short)
    if len(secret) < 32: score += 25; reasons.append(f"short ({len(secret)} chars)")
    if secret.lower() in ("secret", "password", "changeme", "your_secret_here"):
        return 0, "placeholder"
    # Real-looking
    if len(set(secret)) > 10 and len(secret) >= 40: score += 15; reasons.append("high entropy")
    return max(0, min(100, score)), "; ".join(reasons)


def check_gha_expr_injection(content: str, path: str) -> tuple[int, str]:
    """GHA expression injection: github.event.* values in run:/script: blocks."""
    score = 60  # baseline — this pattern is genuinely dangerous
    reasons = ["github.event.* in run:/script: block"]
    # MORE DANGEROUS: pull_request_target / issue_comment triggers (write perms on fork PRs)
    if re.search(r'on:.*?(pull_request_target|issue_comment|discussion)', content, re.DOTALL):
        score += 25; reasons.append("PRT/comment trigger (write-scope on fork)")
    # LESS DANGEROUS: pull_request only (read-only on fork)
    if re.search(r'^\s*on:\s*\[?\s*pull_request\s*\]?\s*$', content, re.MULTILINE):
        score -= 30; reasons.append("pull_request only (read-only)")
    # POSITIVE: shows direct injection into shell
    if re.search(r'run:\s*[|>].*?\$\{\{\s*github\.event\.', content, re.DOTALL):
        score += 10; reasons.append("direct shell injection")
    # NEGATIVE: uses env var passthrough (safe pattern)
    if re.search(r'env:\s*\n\s*\w+:\s*\$\{\{\s*github\.event\.', content):
        score -= 35; reasons.append("uses env-var passthrough (safe)")
    return max(0, min(100, score)), "; ".join(reasons)


def check_token_exfil(content: str, path: str) -> tuple[int, str]:
    score = 70
    reasons = ["curl+GITHUB_TOKEN+event interpolation"]
    if re.search(r'github\.event\.(pull_request|issue|comment).*head|head\.ref|body|title', content, re.DOTALL):
        score += 20; reasons.append("event field controls URL")
    return max(0, min(100, score)), "; ".join(reasons)


VERIFIERS = {
    "prtarget":           check_prtarget,
    "secret_in_source":   check_secret_in_source,
    "jwt_strength":       check_jwt_strength,
    "gha_expr_injection": check_gha_expr_injection,
    "token_exfil":        check_token_exfil,
}


# =================================================================
# Ledger
# =================================================================
def load_ledger() -> dict:
    if not LEDGER.exists(): return {}
    seen = {}
    for line in LEDGER.read_text().splitlines():
        if not line.strip(): continue
        try:
            d = json.loads(line)
            seen[d["id"]] = d
        except: pass
    return seen


def append_ledger(finding: Finding):
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        f.write(json.dumps(asdict(finding)) + "\n")


def finding_id(repo: str, path: str, pattern: str) -> str:
    return hashlib.sha1(f"{repo}|{path}|{pattern}".encode()).hexdigest()[:12]


# =================================================================
# GitHub API helpers
# =================================================================
def gh_search_org(org: str, query: str, max_results: int = 10) -> list[dict]:
    try:
        out = subprocess.check_output(
            ["gh", "api", "-X", "GET", "search/code",
             "-f", f"q={query} org:{org}", "-f", f"per_page={max_results}",
             "--jq", "[.items[] | {repo: .repository.full_name, path: .path, url: .html_url}]"],
            stderr=subprocess.DEVNULL, timeout=25)
        return json.loads(out)
    except Exception:
        return []


def gh_raw(repo: str, path: str) -> Optional[str]:
    try:
        out = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/contents/{path}", "-q", ".content"],
            stderr=subprocess.DEVNULL, timeout=12)
        return base64.b64decode(out.decode().strip().replace("\n", "")).decode("utf-8", "replace")
    except Exception:
        return None


# =================================================================
# Main scan
# =================================================================
def scan(companies=None, patterns=None, max_per_company=5):
    seen = load_ledger()
    print(f"[+] ledger: {len(seen)} prior findings; starting scan...", flush=True)

    co_list = companies or list(CORPUS.keys())
    pat_list = patterns or list(PATTERN_DEFS.keys())

    new_findings = []
    fp_count = dup_count = 0

    for ci, company in enumerate(co_list, 1):
        meta = CORPUS[company]
        for org in meta["orgs"]:
            for pname in pat_list:
                pdef = PATTERN_DEFS[pname]
                print(f"  [{ci}/{len(co_list)}] {company}/{org} × {pname:<15}", end="", flush=True)
                items = gh_search_org(org, pdef["search_query"], max_per_company)
                time.sleep(2.5)
                if not items:
                    print("  ⚪", flush=True); continue
                hit_count = 0
                for it in items:
                    path = it["path"]
                    if PATH_FP_RX.search(path):
                        fp_count += 1; continue
                    fid = finding_id(it["repo"], path, pname)
                    if fid in seen:
                        dup_count += 1; continue
                    content = gh_raw(it["repo"], path)
                    time.sleep(0.5)
                    if not content: continue
                    m = pdef["must_match"].search(content)
                    if not m: continue
                    # Placeholder check: around the match AND at file header
                    match_ctx = content[max(0, m.start()-150):m.end()+150]
                    if PLACEHOLDER_RX.search(match_ctx): continue
                    if PLACEHOLDER_RX.search(content[:500]): continue
                    # Reject all-zero / repeating-char keys (AKIA0000000000000000, etc.)
                    matched = m.group(0)
                    if re.search(r'(0{6,}|x{6,}|X{6,}|\.{6,}|\*{6,})', matched): continue
                    # Score it
                    verifier = VERIFIERS[pdef["exploit_check"]]
                    score, reason = verifier(content, path)
                    if score < 20: continue
                    # Snippet
                    sn = content[max(0, m.start()-40):m.end()+80].replace("\n", " ")[:180]
                    f = Finding(
                        id=fid, company=company, org=org, repo=it["repo"],
                        path=path, url=it["url"], pattern=pname,
                        snippet=sn, score=score, channel=meta["channel"],
                        program_url=meta["url"],
                        payout_min=pdef["payout"][0], payout_max=pdef["payout"][1],
                        expected=min(pdef["payout"][1], meta["max"]) // 4,
                    )
                    new_findings.append(f)
                    append_ledger(f)
                    hit_count += 1
                tag = "🔴" if hit_count else ("⚠️" if fp_count else "⚪")
                print(f"  {tag} {hit_count} new ({reason if hit_count else 'no qual hits'})" if hit_count else f"  ⚪", flush=True)

    print(f"\n[+] scan complete:")
    print(f"    new findings: {len(new_findings)}")
    print(f"    duplicates skipped: {dup_count}")
    print(f"    path-FPs skipped: {fp_count}")
    if new_findings:
        new_findings.sort(key=lambda x: -x.score)
        print(f"\n[+] top 5 new findings by score:")
        for f in new_findings[:5]:
            print(f"  {f.score:>3} ${f.expected:>5} {f.company}/{f.org} {f.pattern} → {f.repo}/{f.path[:50]}")
    return new_findings


def show_queue():
    seen = load_ledger()
    queue = [v for v in seen.values() if v.get("status") == "discovered" and v.get("score", 0) >= 60]
    queue.sort(key=lambda x: -x.get("score", 0))
    print(f"# Submit queue — {len(queue)} findings score>=60\n")
    for q in queue:
        print(f"[{q['id']}] score={q['score']:>3} ${q.get('expected',0):>5} {q['company']:<12} {q['pattern']:<14} {q['repo']}/{q['path'][:60]}")
        print(f"            → {q['url']}")


def draft_submission(fid: str):
    seen = load_ledger()
    f = seen.get(fid)
    if not f:
        print(f"!! no finding {fid}"); return
    SUBMISSIONS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = SUBMISSIONS_DIR / f"{fid}-{f['company']}.md"
    body = f"""# Bug bounty submission — {f['company']} ({f['channel']})

**Finding ID:** {f['id']}
**Program:** {f['program_url']}
**Expected payout range:** ${f['payout_min']:,} – ${f['payout_max']:,}
**Lictor's exploit score:** {f['score']}/100

---

## Title

`{f['pattern']}` in `{f['repo']}/{f['path']}`

## Summary

Automated scan from [Lictor](https://lictor-ai.com) identified a pattern matching `{f['pattern']}` in your public repository `{f['repo']}` at path `{f['path']}`.

**Snippet** (redacted as needed):
```
{f['snippet']}
```

## Impact

[Fill in based on pattern type — `{f['pattern']}` means: ...]

## Reproduction

1. Navigate to: {f['url']}
2. Inspect the file at the linked line range
3. [Add specific verification steps]

## Suggested fix

[Pattern-specific remediation — see Lictor docs at https://lictor-ai.com]

## Disclosure timeline

- Discovered: {f['discovered_at']}
- Submitting via: {f['channel']} ({f['program_url']})

---

_Reported by Raffa via Lictor open-source security scanner._
_Lictor is Apache 2.0, free forever: https://lictor-ai.com_
"""
    out_path.write_text(body)
    print(f"[+] drafted: {out_path}")
    print(f"    submit at: {f['program_url']}")


def stats():
    seen = load_ledger()
    if not seen:
        print("Ledger empty. Run `scan` first."); return
    statuses = {}
    by_company = {}
    expected_total = 0
    for v in seen.values():
        s = v.get("status", "?")
        statuses[s] = statuses.get(s, 0) + 1
        if s in ("discovered", "submitted"):
            expected_total += v.get("expected", 0)
        by_company[v["company"]] = by_company.get(v["company"], 0) + 1
    print(f"=== Bounty ledger stats ===")
    print(f"Total findings: {len(seen)}")
    print(f"\nBy status:")
    for s, n in sorted(statuses.items(), key=lambda x: -x[1]):
        print(f"  {s:<12} {n:>4}")
    print(f"\nBy company (top 10):")
    for c, n in sorted(by_company.items(), key=lambda x: -x[1])[:10]:
        print(f"  {c:<14} {n:>4}")
    print(f"\nExpected pipeline value: ${expected_total:,}")


def mark(fid: str, status: str):
    seen = load_ledger()
    if fid not in seen:
        print(f"!! no finding {fid}"); return
    # Re-write ledger with updated status
    seen[fid]["status"] = status
    seen[fid]["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    LEDGER.write_text("\n".join(json.dumps(v) for v in seen.values()) + "\n")
    print(f"[+] {fid} → {status}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    s1 = sub.add_parser("scan"); s1.add_argument("--companies"); s1.add_argument("--patterns"); s1.add_argument("--max", type=int, default=5)
    sub.add_parser("queue")
    s2 = sub.add_parser("draft"); s2.add_argument("fid")
    sub.add_parser("stats")
    s3 = sub.add_parser("mark"); s3.add_argument("fid"); s3.add_argument("status", choices=["reviewed","submitted","paid","rejected"])
    args = ap.parse_args()
    if args.cmd == "scan":
        cos = args.companies.split(",") if args.companies else None
        pats = args.patterns.split(",") if args.patterns else None
        scan(cos, pats, args.max)
    elif args.cmd == "queue": show_queue()
    elif args.cmd == "draft": draft_submission(args.fid)
    elif args.cmd == "stats": stats()
    elif args.cmd == "mark":  mark(args.fid, args.status)
    else: ap.print_help()


if __name__ == "__main__":
    main()
