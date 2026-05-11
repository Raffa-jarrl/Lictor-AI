"""
Privacy-preserving fingerprint for telemetry.

Mirrors @lictor/sentinel's src/fingerprint.ts. SHA-256 of the first 4 KB
of the input/output, truncated to 16 hex characters. See
`docs/specs/wire-format.md` §4 for the privacy invariants.
"""

from __future__ import annotations

import hashlib

FINGERPRINT_BYTES = 4096
FINGERPRINT_HEX_LEN = 16


def fingerprint(text: str) -> str:
    """16 hex characters of sha256 over the first 4 KB of `text`."""
    truncated = text[:FINGERPRINT_BYTES].encode("utf-8", errors="replace")
    return hashlib.sha256(truncated).hexdigest()[:FINGERPRINT_HEX_LEN]
