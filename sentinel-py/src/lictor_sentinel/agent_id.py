"""Per-process random agent id. Stable for the lifetime of the process."""

from __future__ import annotations

import secrets

AGENT_ID = f"agent-{secrets.token_hex(4)}"
