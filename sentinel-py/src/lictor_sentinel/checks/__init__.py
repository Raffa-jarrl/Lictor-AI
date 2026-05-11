"""
Built-in check catalog (Python).

Mirrors @lictor/sentinel/src/checks/index.ts. Auto-registers all three
checks at module load — users who `from lictor_sentinel import wrap` get
the full catalog active by default.
"""

from __future__ import annotations

from ..check_runner import Check, register_check
from .pii_leak import pii_leak_check
from .prompt_injection import prompt_injection_check
from .secrets_in_input import secrets_in_input_check

__all__ = [
    "BUILTIN_CHECKS",
    "pii_leak_check",
    "prompt_injection_check",
    "secrets_in_input_check",
]

BUILTIN_CHECKS: list[Check] = [
    prompt_injection_check,
    pii_leak_check,
    secrets_in_input_check,
]

for _check in BUILTIN_CHECKS:
    register_check(_check)
