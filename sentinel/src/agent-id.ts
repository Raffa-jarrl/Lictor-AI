/**
 * Per-process agent ID. Generated once at import time. Stable for the
 * lifetime of the Node process; randomized across restarts.
 *
 * Used by Guardian to correlate events from a single application instance
 * without identifying the user or shipping anything secret.
 */

import { randomBytes } from "node:crypto";

export const AGENT_ID = `agent-${randomBytes(4).toString("hex")}`;
