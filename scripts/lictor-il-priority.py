#!/usr/bin/env python3
"""
lictor-il-priority — IL-focused disclosure helpers.

Provides:
  - is_il_target(repo, url) — heuristic for Israeli ownership / .co.il deploy
  - sector_score(repo, url) — boost for fintech/health/gov/insurance
  - bilingual_body(class_name, base_body) — wrap English body with Hebrew preamble
  - log_il_disclosure(entry) — append to ~/.lictor/il-disclosures.jsonl

Used by lictor-hourly.py and patrol-il.py to prioritize Israeli targets.
These are our best potential customers — small dev shops + agencies who
build for IL businesses and need security tooling that speaks their market.
"""
from __future__ import annotations
import json, re
from pathlib import Path
from datetime import datetime, timezone

IL_LOG = Path.home() / ".lictor" / "il-disclosures.jsonl"

# Domain TLD signals
IL_TLD_RX = re.compile(r'\.(co|org|gov|ac|muni|net|k12)\.il(/|$|:)', re.IGNORECASE)

# Repo-owner / repo-name heuristics for Israeli authorship
IL_HEBREW_RX = re.compile(r'[֐-׿]')  # Hebrew Unicode block
IL_KEYWORDS_RX = re.compile(
    r'\b(israel|israeli|tel.?aviv|jerusalem|haifa|herzliya|petah.?tikva|netanya|'
    r'beersheva|raanana|rishon|ramat.?gan|kfar.?saba|hertzeliya|hebrew|ivrit)\b',
    re.IGNORECASE,
)

# High-stakes sector keywords (boost priority)
SECTOR_WEIGHTS = {
    # Fintech — money at stake
    r'\b(bank|fintech|payment|wallet|crypto|trading|invest|loan|credit|insur)\b': 10,
    # Health — PII + regulated
    r'\b(health|medic|clinic|hospital|pharma|telehealth|patient|kupat)\b': 9,
    # Gov / public sector — trust + scale
    r'\b(gov|municipal|misrad|knesset|btl|biton|mishtara)\b': 8,
    # E-commerce — real customers, real cards
    r'\b(shop|store|cart|checkout|ecommerce|marketplace)\b': 5,
    # SaaS B2B — likely paying customers
    r'\b(saas|platform|dashboard|crm|erp|hrtech)\b': 4,
}


def is_il_target(repo: str, url: str = "") -> bool:
    """True if we have strong signal this is an Israeli project."""
    if url and IL_TLD_RX.search(url):
        return True
    if IL_HEBREW_RX.search(repo):
        return True
    if IL_KEYWORDS_RX.search(repo):
        return True
    return False


def sector_score(repo: str, url: str = "") -> int:
    """Return the highest matching sector weight (0 if none)."""
    text = f"{repo} {url}".lower()
    best = 0
    for pattern, weight in SECTOR_WEIGHTS.items():
        if re.search(pattern, text):
            best = max(best, weight)
    return best


HEBREW_PREAMBLE = {
    "stripe": "שלום 👋\n\nסריקה אוטומטית של [Lictor](https://lictor-ai.com) זיהתה דפוס שנראה כמו **מפתח Stripe LIVE** (`sk_live_…`) בקוד הציבורי של הריפו. אם המפתח באמת פעיל — כל מי שקורא את הריפו יכול להוציא החזרים, לראות נתוני לקוחות, ולבצע העברות. ההמלצה: לרענן את המפתח מיד דרך Dashboard → Developers → API keys. הפרטים המלאים באנגלית למטה. תודה על העבודה החשובה. 🙏\n\n---\n\n",
    "firebase": "שלום 👋\n\nסריקה אוטומטית של [Lictor](https://lictor-ai.com) זיהתה מה שנראה כמו **קובץ service-account של Firebase / Google** בריפו הציבורי. אם זה אמיתי — המפתח נותן גישה מלאה לפרויקט GCP/Firebase עד שיבטלו אותו ידנית. הפרטים המלאים באנגלית למטה. תודה. 🙏\n\n---\n\n",
    "db-creds": "שלום 👋\n\nסריקה אוטומטית של [Lictor](https://lictor-ai.com) זיהתה מה שנראה כמו **מחרוזת חיבור למסד נתונים עם פרטי גישה אמיתיים** בקוד הציבורי. אם זה אמיתי — מי שיש לו גישה לאינטרנט יכול להתחבר ולקרוא/לכתוב. הפרטים באנגלית למטה. תודה. 🙏\n\n---\n\n",
    "prtarget": "שלום 👋\n\nסריקה אוטומטית של [Lictor](https://lictor-ai.com) זיהתה דפוס של `pull_request_target` ב־GitHub Actions שעלול להוות פרצת RCE קלאסית. תלוי בהגנות שלכם (label gates, dependabot only, וכו'). אנחנו וידאנו את הדפוס — לא את הניצול בפועל. הפרטים באנגלית למטה. תודה. 🙏\n\n---\n\n",
}


def bilingual_body(class_name: str, base_body: str) -> str:
    """Prepend Hebrew preamble for IL targets."""
    preamble = HEBREW_PREAMBLE.get(class_name, "")
    if not preamble:
        return base_body
    return preamble + base_body


def disclosure_priority(repo: str, url: str = "", stars: int = 0) -> int:
    """Combined priority score: sector + stars + IL boost."""
    score = 0
    if is_il_target(repo, url):
        score += 15  # IL targets always jump the queue
    score += sector_score(repo, url)
    # Modest star weight (we want help small projects too)
    if stars > 0:
        import math
        score += int(math.log10(stars + 1) * 3)
    return score


def log_il_disclosure(entry: dict):
    """Append IL-specific disclosure for transparency dashboard."""
    IL_LOG.parent.mkdir(exist_ok=True, parents=True)
    entry["logged_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with IL_LOG.open("a") as f:
        f.write(json.dumps(entry) + "\n")


# Self-test
if __name__ == "__main__":
    cases = [
        ("hellsecdev/orlysitbon.co.il", "https://orlysitbon.co.il", 0),
        ("shalev-osher/mazonhaosher.co.il", "https://mazonhaosher.co.il", 0),
        ("Brookeinternet/makeup-blog", "https://example.com", 0),
        ("kupat-cholim/patient-portal", "https://kupat.co.il", 5),
        ("israeli-fintech/payment-gw", "https://pay.co.il", 12),
    ]
    print(f"{'repo':<40} {'IL?':<5} {'sector':<7} {'priority':<8}")
    for repo, url, stars in cases:
        print(f"{repo:<40} {str(is_il_target(repo,url)):<5} "
              f"{sector_score(repo,url):<7} {disclosure_priority(repo,url,stars):<8}")
