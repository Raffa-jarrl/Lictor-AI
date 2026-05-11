"""
lictor-sentinel — wraps OpenAI / Anthropic Python clients to block prompt
injection, data exfiltration, and unsafe AI behaviour.

Sister package to @lictor/sentinel (TypeScript). Same API surface, same
wire format to Guardian, same `IncidentEvent` shape.

See ../docs/specs/sentinel-api.md for the full contract.
"""

from .check_runner import (
    PASS,
    Check,
    CheckResult,
    get_check,
    register_check,
    registered_check_ids,
)
from .checks import BUILTIN_CHECKS  # side-effect: registers built-in checks
from .fingerprint import fingerprint
from .types import (
    SENTINEL_VERSION,
    CheckId,
    GuardianConfig,
    IncidentAction,
    IncidentEvent,
    IncidentModel,
    Phase,
    SentinelBlockedError,
    SentinelConfig,
    Severity,
    TripAction,
)
from .wrap import wrap

__all__ = [
    "BUILTIN_CHECKS",
    "Check",
    "CheckId",
    "CheckResult",
    "GuardianConfig",
    "IncidentAction",
    "IncidentEvent",
    "IncidentModel",
    "PASS",
    "Phase",
    "SENTINEL_VERSION",
    "SentinelBlockedError",
    "SentinelConfig",
    "Severity",
    "TripAction",
    "fingerprint",
    "get_check",
    "register_check",
    "registered_check_ids",
    "wrap",
]
