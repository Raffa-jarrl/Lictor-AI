"""
Prompt-injection check (Python) — mirrors @lictor/sentinel's prompt-injection.

The pattern catalog is kept in lockstep with the TypeScript SDK. When the
TS catalog grows, add the equivalent Python regex here and update both
test suites. See @lictor/sentinel/src/checks/prompt-injection.ts for
authoring guidelines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from ..check_runner import PASS, Check, CheckResult
from ..types import Phase, Severity

Category = Literal[
    "direct-override",
    "authority-impersonation",
    "jailbreak",
    "system-prompt-extraction",
    "delimiter-injection",
    "goal-hijacking",
    "suspicious-encoding",
]


@dataclass(frozen=True)
class InjectionPattern:
    re: re.Pattern[str]
    category: Category
    severity: Severity
    description: str


def _p(pattern: str, category: Category, severity: Severity, description: str, flags: int = re.IGNORECASE) -> InjectionPattern:
    return InjectionPattern(re=re.compile(pattern, flags), category=category, severity=severity, description=description)


INJECTION_PATTERNS: list[InjectionPattern] = [
    # Direct override
    _p(r"\b(?:ignore|disregard|forget|skip)\s+(?:all\s+|the\s+|any\s+|every\s+|your\s+)?(?:previous|above|prior|earlier|preceding)\s+(?:instructions?|prompts?|commands?|rules?|directives?|guidelines?|messages?|context)\b",
       "direct-override", "high", "Tells the model to discard its prior instructions."),
    _p(r"\b(?:ignore|disregard|forget)\s+(?:everything|all)\s+(?:i\s+(?:said|wrote|told\s+you)|you\s+(?:were\s+)?told|above|that)\b",
       "direct-override", "high", "Tells the model to discard everything prior."),
    _p(r"\b(?:new|updated|revised|replacement)\s+(?:instructions?|prompts?|directives?|rules?|guidelines?)\s*:",
       "direct-override", "high", "Asserts replacement instructions."),
    _p(r"\bfrom\s+now\s+on\b[\s,:;]+(?:you|please)\s+(?:will|must|are|should|need\s+to|have\s+to)\b",
       "direct-override", "medium", "Resets the model's behaviour going forward."),
    _p(r"\b(?:your|the)\s+(?:real|actual|true|hidden|secret|new)\s+(?:task|goal|mission|objective|purpose|instructions?|prompt)\b",
       "goal-hijacking", "medium", "Reframes the model's task as the attacker's goal."),
    _p(r"\binstead\s+of\s+(?:doing\s+that|that|following|your\s+previous)[\s,]+(?:you\s+(?:should|will|must|need\s+to)|please)\b",
       "goal-hijacking", "medium", "Replaces the current task with the attacker's request."),

    # Authority impersonation
    _p(r"(?:^|\n|\.\s+)\s*(?:system|admin|administrator|root|developer)\s*:",
       "authority-impersonation", "high", "Mimics a system/admin role marker inside user input."),
    _p(r"\[\s*(?:system|admin|administrator|root|sudo|developer)\s*\]",
       "authority-impersonation", "high", "Square-bracketed system marker."),
    _p(r"\b(?:admin|administrator|root|sudo|developer)\s+(?:override|mode|access|privileges?|permissions?)\b",
       "authority-impersonation", "high", "Claims elevated authority over the model."),
    _p(r"\bdeveloper\s+mode\s+(?:enabled|on|activated|active)\b",
       "authority-impersonation", "high", "Classic 'developer mode' jailbreak claim."),
    _p(r"\b(?:bypass|override|disable|turn\s+off)\s+(?:your\s+|the\s+|all\s+)?(?:safety|safeguards?|filters?|guardrails?|restrictions?|limits?|safety\s+rules?|content\s+policy)\b",
       "authority-impersonation", "high", "Instructs the model to disable safety controls."),

    # Jailbreak personas
    _p(r"\bDAN\s+(?:mode|prompt)\b",
       "jailbreak", "high", "References the 'DAN' jailbreak persona."),
    _p(r"\bdo\s+anything\s+now\b",
       "jailbreak", "high", "DAN-style unrestricted-mode invocation."),
    _p(r"\b(?:act|pretend|behave|respond)\s+as\s+(?:if\s+you\s+(?:have\s+)?(?:no|don'?t\s+have)|an?\s+(?:evil|unrestricted|uncensored|jailbroken|amoral|unfiltered))\b",
       "jailbreak", "high", "Role-as-evil-AI persona setup."),
    _p(r"\b(?:pretend|imagine)\s+(?:you\s+(?:are|have))\s+(?:no\s+(?:ethics|morals|restrictions|rules)|been\s+jailbroken|free\s+from)\b",
       "jailbreak", "high", "Imagine-yourself-unrestricted persona setup."),
    _p(r"\b(?:evil|unrestricted|uncensored|jailbroken|unfiltered)\s+(?:AI|GPT|model|assistant|chatbot|version)\b",
       "jailbreak", "high", "References an 'evil/unrestricted' alter-ego."),
    _p(r"\byou\s+(?:can|may|will|are\s+allowed\s+to)\s+(?:now\s+)?(?:say|do|generate|produce|output)\s+(?:anything|whatever|any\s+content)\b",
       "jailbreak", "medium", "Asserts unrestricted output permission."),

    # System prompt extraction
    _p(r"\b(?:repeat|show|tell\s+me|print|reveal|output|display|share|reproduce)\s+(?:your\s+(?:system\s+)?|the\s+(?:system|initial|original|developer|previous)\s+)(?:prompt|instructions?|guidelines|rules|directives|message|messages)\b",
       "system-prompt-extraction", "medium", "Asks the model to repeat its system prompt."),
    _p(r"\bwhat\s+(?:were|are|is)\s+(?:your|the)\s+(?:previous|original|initial|first|system|developer)\s+(?:instructions?|prompts?|rules?|directives?|guidelines?)\b",
       "system-prompt-extraction", "medium", "Probes for the model's system prompt."),
    _p(r"\b(?:repeat|recite|state|print|show|output|dump|display)\s+(?:everything|all)\s+(?:above|before|prior|preceding|that\s+was\s+said|that\s+came\s+before)\b",
       "system-prompt-extraction", "medium", "Asks the model to dump its context window."),
    _p(r"\boutput\s+(?:your|the)\s+(?:initial|first|system)\s+(?:message|prompt|context)\s+verbatim\b",
       "system-prompt-extraction", "high", "Specifically requests verbatim system-prompt extraction."),
    _p(r"\btranslate\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)\s+(?:to|into)\b",
       "system-prompt-extraction", "medium", "Indirect extraction via translation."),
    _p(r"\b(?:base64|hex|rot13|encode|encrypt)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)\b",
       "system-prompt-extraction", "high", "Indirect extraction via encoding."),
    _p(r"\b(?:show|tell)\s+me\s+(?:the|what)\s+(?:rules|instructions?|guidelines|prompts?|directives|orders|constraints)\s+(?:you\s+(?:were\s+)?given|(?:that\s+)?(?:were|are)\s+given\s+to\s+you)\b",
       "system-prompt-extraction", "medium", "Asks the model what instructions it was given."),

    # Delimiter / model-token injection
    _p(r"<\|im_start\|>|<\|im_end\|>",
       "delimiter-injection", "critical", "ChatML turn-delimiter token in user input.", flags=0),
    _p(r"<\|start_header_id\|>|<\|end_header_id\|>|<\|eot_id\|>",
       "delimiter-injection", "critical", "Llama 3 turn-delimiter token in user input.", flags=0),
    _p(r"\[\s*/?\s*INST\s*\]",
       "delimiter-injection", "critical", "Llama [INST] / [/INST] turn-delimiter token.", flags=0),
    _p(r"<\/?\s*s\s*>",
       "delimiter-injection", "high", "BOS/EOS-style `<s>` / `</s>` token."),
    _p(r"(?:^|\n)\s*(?:Assistant|AI|Human|User)\s*:\s*(?:Sure|Okay|Of\s+course|Yes|Here)",
       "delimiter-injection", "high", "Fake conversation turn pre-filled with an affirmative reply."),

    # Suspicious encoding
    _p(r"[A-Za-z0-9+/]{80,}={0,2}",
       "suspicious-encoding", "medium", "Long base64-shaped string in input.", flags=0),
    _p(r"(?:\\x[0-9a-fA-F]{2}){8,}|(?:\\u[0-9a-fA-F]{4}){8,}",
       "suspicious-encoding", "medium", "Repeated hex/unicode escape sequences.", flags=0),
    _p(r"(?:[​-‏‪-‮⁠-⁯]){5,}",
       "suspicious-encoding", "medium", "Zero-width / direction-override character runs.", flags=0),
]


_SEVERITY_RANK: dict[Severity, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_severity(a: Severity, b: Severity) -> Severity:
    return a if _SEVERITY_RANK[a] >= _SEVERITY_RANK[b] else b


def _run(text: str, _phase: Phase) -> CheckResult:
    if not text:
        return PASS
    matches: list[tuple[str, str, Severity]] = []
    seen_cats: set[str] = set()
    top: Severity = "info"

    for pat in INJECTION_PATTERNS:
        if pat.re.search(text):
            matches.append((pat.category, pat.description, pat.severity))
            seen_cats.add(pat.category)
            top = _max_severity(top, pat.severity)
            if len(matches) >= 10:
                break

    if not matches:
        return PASS

    cat_list = ", ".join(sorted(seen_cats))
    title = f"Prompt injection — {len(matches)} pattern{'' if len(matches) == 1 else 's'} in {len(seen_cats)} categor{'y' if len(seen_cats) == 1 else 'ies'} ({cat_list})"
    detail_lines = [f"  [{sev}] {cat}: {desc}" for cat, desc, sev in matches]
    detail = (
        "Pattern-based detection of likely prompt injection in user input.\n"
        f"Matched {len(matches)} of {len(INJECTION_PATTERNS)} catalog entries:\n\n"
        + "\n".join(detail_lines)
        + "\n\nThis is a rule-based detection. False positives are possible if a legitimate prompt happens "
        "to use injection-shaped phrasing. False negatives are likely for novel attacks not yet in the catalog. "
        "Treat the severity as a prior, not a verdict."
    )
    return CheckResult(tripped=True, severity=top, title=title, detail=detail)


class _PromptInjectionCheck:
    id = "prompt-injection"

    def run(self, text: str, phase: Phase) -> CheckResult:
        return _run(text, phase)


prompt_injection_check: Check = _PromptInjectionCheck()  # type: ignore[assignment]
