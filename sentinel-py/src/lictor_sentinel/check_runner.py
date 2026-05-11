"""
Check interface + registry — Python mirror of @lictor/sentinel's
src/check-runner.ts.

Each check implements run(text, phase) -> CheckResult. The registry is
keyed by CheckId; re-registering the same id replaces (used by tests).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol, runtime_checkable

from .types import CheckId, Phase, Severity


@dataclass(frozen=True)
class CheckResult:
    """Result from a single check run."""

    tripped: bool
    severity: Severity
    title: str
    detail: str


@runtime_checkable
class Check(Protocol):
    """A single Sentinel check."""

    id: CheckId

    def run(self, text: str, phase: Phase) -> CheckResult: ...


PASS = CheckResult(tripped=False, severity="info", title="", detail="")


# ─── Registry ────────────────────────────────────────────────────────────────

_REGISTRY: dict[CheckId, Check] = {}


def register_check(check: Check) -> None:
    """Register a check. Idempotent — re-registering replaces."""
    _REGISTRY[check.id] = check


def get_check(check_id: CheckId) -> Check | None:
    """Look up a check by id."""
    return _REGISTRY.get(check_id)


def registered_check_ids() -> list[CheckId]:
    """All currently registered check ids."""
    return list(_REGISTRY.keys())


def run_checks(
    text: str,
    check_ids: list[CheckId],
    phase: Phase,
) -> list[tuple[CheckId, CheckResult]]:
    """
    Run the given checks against text. Returns trips only.

    Failures inside a check (exceptions) are swallowed — Sentinel never
    blocks a user request because a check has a bug.
    """
    out: list[tuple[CheckId, CheckResult]] = []
    for cid in check_ids:
        check = _REGISTRY.get(cid)
        if check is None:
            continue
        try:
            result = check.run(text, phase)
            if result.tripped:
                out.append((cid, result))
        except Exception:
            # Drop — never block on a check bug.
            pass
    return out


def make_check(
    check_id: CheckId, run_fn: Callable[[str, Phase], CheckResult]
) -> Check:
    """Convenience: build a Check from a function + id."""

    class _AdHocCheck:
        id: CheckId = check_id

        def run(self, text: str, phase: Phase) -> CheckResult:
            return run_fn(text, phase)

    return _AdHocCheck()  # type: ignore[return-value]
