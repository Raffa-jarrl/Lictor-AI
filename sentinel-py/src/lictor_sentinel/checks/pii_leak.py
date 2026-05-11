"""
PII-leak check (Python) — postflight. Mirrors @lictor/sentinel/src/checks/pii-leak.ts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Literal

from ..check_runner import PASS, Check, CheckResult
from ..types import Phase, Severity

PiiCategory = Literal[
    "email",
    "phone",
    "ssn",
    "credit-card",
    "iban",
    "ip-address",
    "postal-address",
    "driver-license",
]


@dataclass(frozen=True)
class PiiPattern:
    re: re.Pattern[str]
    category: PiiCategory
    severity: Severity
    description: str
    validate: Callable[[str], bool] | None = None


def luhn_valid(digits: str) -> bool:
    cleaned = re.sub(r"[^0-9]", "", digits)
    if not (13 <= len(cleaned) <= 19):
        return False
    s = 0
    alt = False
    for ch in reversed(cleaned):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        s += n
        alt = not alt
    return s % 10 == 0


PII_PATTERNS: list[PiiPattern] = [
    PiiPattern(re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"),
               "email", "medium", "Email address in model output."),
    PiiPattern(re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"),
               "ssn", "critical", "US Social Security Number (formatted)."),
    PiiPattern(re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
               "credit-card", "critical", "Credit card number (Luhn-validated).",
               validate=luhn_valid),
    PiiPattern(re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
               "iban", "critical", "Possible IBAN (International Bank Account Number)."),
    PiiPattern(re.compile(r"\(\d{3}\)\s*\d{3}[- ]\d{4}\b"),
               "phone", "medium", "US phone number with parenthesized area code."),
    PiiPattern(re.compile(r"\b\d{3}-\d{3}-\d{4}\b"),
               "phone", "medium", "US phone number (dashed format)."),
    PiiPattern(re.compile(r"\+1[ \-.]?\d{3}[ \-.]?\d{3}[ \-.]?\d{4}\b"),
               "phone", "medium", "US phone number with +1 international prefix."),
    PiiPattern(re.compile(r"\+(?:[2-9]\d{0,3})[ \-.]?\d{2,5}[ \-.]\d{2,5}(?:[ \-.]\d{2,5})?\b"),
               "phone", "medium", "International phone number with country code."),
    PiiPattern(re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"),
               "ip-address", "low", "IPv4 address in model output."),
    PiiPattern(re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
               "ip-address", "low", "IPv6 address (full form) in model output."),
    PiiPattern(re.compile(r"\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl)\.?,?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?,?\s+[A-Z]{2}\s+\d{5}(?:-\d{4})?\b"),
               "postal-address", "medium", "Formatted US street address with ZIP code."),
]


_SEVERITY_RANK: dict[Severity, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_severity(a: Severity, b: Severity) -> Severity:
    return a if _SEVERITY_RANK[a] >= _SEVERITY_RANK[b] else b


def _run(text: str, _phase: Phase) -> CheckResult:
    if not text:
        return PASS
    matches: list[tuple[str, Severity, str]] = []
    seen: set[str] = set()
    top: Severity = "info"

    for pat in PII_PATTERNS:
        for m in pat.re.finditer(text):
            if pat.validate is not None and not pat.validate(m.group(0)):
                continue
            matches.append((pat.category, pat.severity, pat.description))
            seen.add(pat.category)
            top = _max_severity(top, pat.severity)
            if len(matches) >= 10:
                break
        if len(matches) >= 10:
            break

    if not matches:
        return PASS

    cat_list = ", ".join(sorted(seen))
    title = f"PII leak — {len(matches)} match{'' if len(matches) == 1 else 'es'} in {len(seen)} categor{'y' if len(seen) == 1 else 'ies'} ({cat_list})"
    detail_lines = [f"  [{sev}] {cat}: {desc}" for cat, sev, desc in matches]
    detail = (
        "Pattern-based detection of PII in model output.\n"
        f"Matched {len(matches)} of {len(PII_PATTERNS)} catalog entries:\n\n"
        + "\n".join(detail_lines)
        + "\n\nThis is a rule-based detection. Credit-card matches are Luhn-validated. "
        "Treat severity as a prior, not a verdict."
    )
    return CheckResult(tripped=True, severity=top, title=title, detail=detail)


class _PiiLeakCheck:
    id = "pii-leak"

    def run(self, text: str, phase: Phase) -> CheckResult:
        return _run(text, phase)


pii_leak_check: Check = _PiiLeakCheck()  # type: ignore[assignment]
