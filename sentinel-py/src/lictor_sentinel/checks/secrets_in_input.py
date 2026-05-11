"""
Secrets-in-input check (Python) — preflight. Mirrors
@lictor/sentinel/src/checks/secrets-in-input.ts and lictor-core's
SECRET_PATTERNS in Rust.

When a pattern is added to one of those, mirror it here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..check_runner import PASS, Check, CheckResult
from ..types import Phase, Severity


@dataclass(frozen=True)
class SecretPattern:
    re: re.Pattern[str]
    label: str
    severity: Severity


SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(re.compile(r"AIza[A-Za-z0-9_\-]{35}"),                                                     "Google API key",                              "high"),
    SecretPattern(re.compile(r"sk-ant-api\d{2}-[A-Za-z0-9_\-]{40,}"),                                         "Anthropic API key",                           "critical"),
    SecretPattern(re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"),                                            "OpenAI API key (or similar sk- token)",       "critical"),
    SecretPattern(re.compile(r"sk_live_[A-Za-z0-9]{24,}"),                                                    "Stripe live secret key",                      "critical"),
    SecretPattern(re.compile(r"sk_test_[A-Za-z0-9]{24,}"),                                                    "Stripe test secret key (still leaks logic)",  "medium"),
    SecretPattern(re.compile(r"pk_live_[A-Za-z0-9]{24,}"),                                                    "Stripe live publishable key (informational)", "info"),
    SecretPattern(re.compile(r"ghp_[A-Za-z0-9]{36}"),                                                         "GitHub personal access token",                "critical"),
    SecretPattern(re.compile(r"ghs_[A-Za-z0-9]{36}"),                                                         "GitHub server token",                         "critical"),
    SecretPattern(re.compile(r"xox[abp]-[A-Za-z0-9\-]{10,}"),                                                 "Slack token",                                 "high"),
    SecretPattern(re.compile(r"AKIA[0-9A-Z]{16}"),                                                            "AWS access key ID",                           "high"),
    SecretPattern(re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----"),                              "Private key block",                           "critical"),
    SecretPattern(re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),               "JWT token (verify intended)",                 "low"),
    SecretPattern(re.compile(r"mongodb(?:\+srv)?://[^\s\"'<>]+"),                                             "MongoDB connection string",                   "critical"),
    SecretPattern(re.compile(r"postgres(?:ql)?://[^\s\"'<>]+"),                                               "PostgreSQL connection string",                "critical"),
    SecretPattern(re.compile(r"redis://[^\s\"'<>]+"),                                                         "Redis connection string",                     "high"),
]

_SEVERITY_RANK: dict[Severity, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_severity(a: Severity, b: Severity) -> Severity:
    return a if _SEVERITY_RANK[a] >= _SEVERITY_RANK[b] else b


def _run(text: str, _phase: Phase) -> CheckResult:
    if not text:
        return PASS
    seen: set[str] = set()
    matches: list[tuple[str, Severity]] = []
    top: Severity = "info"

    for pat in SECRET_PATTERNS:
        for m in pat.re.finditer(text):
            value = m.group(0)
            if value in seen:
                continue
            seen.add(value)
            matches.append((pat.label, pat.severity))
            top = _max_severity(top, pat.severity)
            if len(matches) >= 10:
                break
        if len(matches) >= 10:
            break

    if not matches:
        return PASS

    labels = "\n".join(f"  [{sev}] {lbl}" for lbl, sev in matches)
    title = (
        f"Secret in input: {matches[0][0]}"
        if len(matches) == 1
        else f"Secrets in input — {len(matches)} distinct credentials"
    )
    detail = (
        "Pattern-based detection of hardcoded credentials in the user's input.\n"
        "Sending these to the model leaks them to the AI provider (logged, "
        "potentially trained on, or visible to provider support staff).\n\n"
        f"Matched:\n{labels}\n\n"
        "Remediation: the secret should be redacted before the prompt is sent. "
        "With on_trip='block', the request is rejected entirely. "
        "With on_trip='log' (default), the event is recorded but the call proceeds — "
        "rotate the leaked credential."
    )
    return CheckResult(tripped=True, severity=top, title=title, detail=detail)


class _SecretsInInputCheck:
    id = "secrets-in-input"

    def run(self, text: str, phase: Phase) -> CheckResult:
        return _run(text, phase)


secrets_in_input_check: Check = _SecretsInInputCheck()  # type: ignore[assignment]
