#!/usr/bin/env python3
"""
email-monitor — runs every 15 min via cron. Scans inbox for replies to
our security disclosures and bounty submissions, classifies sentiment,
and either drafts a polite reply OR alerts the user (if upset).

Per safety rules:
  - NEVER auto-sends. Only creates Gmail drafts.
  - For upset/angry replies: logs to alert file, does NOT draft a reply.
    User reads the alert and decides how to respond.
  - For friendly/neutral replies: drafts a short acknowledgment.

Outputs:
  - Drafts saved via Gmail API (user reviews + sends manually)
  - ~/.lictor/email-alerts.log — angry/upset replies user should see
  - ~/.lictor/email-monitor.log — full run log

Cron: */15 * * * *
"""
from __future__ import annotations
import json, re, subprocess, sys, time, os
from pathlib import Path
from datetime import datetime, timezone

ALERT_LOG = Path.home() / ".lictor" / "email-alerts.log"
MONITOR_LOG = Path.home() / ".lictor" / "email-monitor.log"
STATE_FILE = Path.home() / ".lictor" / "email-monitor-state.json"

# Sentiment detection — keywords-based (simple but effective for sec disclosures)
UPSET_KEYWORDS = re.compile(
    r"\b("
    r"spam|slop|fuck|shit|stop|annoying|stupid|useless|waste|"
    r"unprofessional|inappropriate|do not contact|don't contact|"
    r"stop emailing|stop reporting|cease|desist|legal action|report you|"
    r"abuse|harass|automated.{0,20}garbage|ai.{0,10}slop|"
    r"terrible way|bad practice|wrong process|"
    r"go away|leave us alone|not interested|do not reply"
    r")\b",
    re.IGNORECASE,
)
FRIENDLY_KEYWORDS = re.compile(
    r"\b("
    r"thank you|thanks|appreciate|grateful|kind|nice|good catch|"
    r"helpful|merged|fixed|patched|rotated|resolved|will fix|"
    r"acknowledged|valid|confirmed|triaged|bounty|reward|"
    r"paid|payment|reward.{0,10}sent"
    r")\b",
    re.IGNORECASE,
)
TRIAGE_KEYWORDS = re.compile(
    r"\b("
    r"triaged|in review|under investigation|need more info|"
    r"can you provide|please share|more details|reproduce|"
    r"steps to reproduce|out of scope|duplicate|n/a|not applicable"
    r")\b",
    re.IGNORECASE,
)


def load_state():
    if STATE_FILE.exists():
        try: return json.loads(STATE_FILE.read_text())
        except: pass
    return {"processed_msg_ids": []}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state))


def log(msg):
    MONITOR_LOG.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with MONITOR_LOG.open("a") as f:
        f.write(f"[{ts}] {msg}\n")


def alert(msg):
    """High-priority alert visible to user."""
    ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with ALERT_LOG.open("a") as f:
        f.write(f"\n========================================\n")
        f.write(f"[{ts}] {msg}\n")


def classify_sentiment(body):
    """Returns ('upset' | 'friendly' | 'triage' | 'neutral', confidence_score)."""
    upset_hits = len(UPSET_KEYWORDS.findall(body or ""))
    friendly_hits = len(FRIENDLY_KEYWORDS.findall(body or ""))
    triage_hits = len(TRIAGE_KEYWORDS.findall(body or ""))
    if upset_hits >= 2 or (upset_hits >= 1 and friendly_hits == 0):
        return "upset", upset_hits
    if triage_hits >= 1:
        return "triage", triage_hits
    if friendly_hits >= 1:
        return "friendly", friendly_hits
    return "neutral", 0


# This script intentionally does NOT have Gmail API access (no oauth token).
# It runs as a cron-side classifier. Real implementation requires:
# - Gmail OAuth refresh token at ~/.lictor/gmail-token.json
# - googleapiclient.discovery for Gmail API calls
# For now, this is a stub that depends on a separate `gmail-sync.py`
# script (TODO) to populate ~/.lictor/inbox-cache.jsonl


CACHE = Path.home() / ".lictor" / "inbox-cache.jsonl"


def read_cached_inbox():
    """Read pre-fetched email cache (populated by gmail-sync.py or manual export)."""
    if not CACHE.exists():
        log("no inbox cache — run gmail-sync.py first")
        return []
    msgs = []
    for line in CACHE.read_text().splitlines():
        if line.strip():
            try: msgs.append(json.loads(line))
            except: pass
    return msgs


def main():
    state = load_state()
    seen = set(state.get("processed_msg_ids", []))

    msgs = read_cached_inbox()
    log(f"scanning {len(msgs)} cached messages ({len(seen)} prior)")

    new_count = 0
    for msg in msgs:
        mid = msg.get("id")
        if not mid or mid in seen: continue
        new_count += 1
        body = msg.get("plaintextBody", "") or msg.get("snippet", "")
        sender = msg.get("sender", "?")
        subject = msg.get("subject", "?")

        sentiment, score = classify_sentiment(body)

        if sentiment == "upset":
            alert(f"UPSET REPLY from {sender}\nSubject: {subject}\nMatching keywords score: {score}\nBody snippet:\n{body[:400]}\n\nDo NOT auto-reply. Read it and decide.")
            log(f"UPSET: {sender} on '{subject[:60]}' (score={score})")
        elif sentiment == "friendly":
            log(f"friendly: {sender} on '{subject[:60]}' (score={score}) — would draft thanks")
            # In a real Gmail-API impl, would create_draft here
        elif sentiment == "triage":
            log(f"triage: {sender} on '{subject[:60]}' (score={score}) — needs your attention")
            alert(f"TRIAGE REQUEST from {sender}\nSubject: {subject}\nBody snippet:\n{body[:400]}\n\nLikely needs you to provide more info.")
        else:
            log(f"neutral: {sender} on '{subject[:60]}'")
        seen.add(mid)

    state["processed_msg_ids"] = list(seen)[-500:]  # cap at last 500
    save_state(state)
    log(f"done. processed {new_count} new messages")


if __name__ == "__main__":
    main()
