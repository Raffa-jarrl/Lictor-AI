/**
 * Stable agent identifier.
 *
 * Derives a per-process agent id so Guardian (and the local audit log) can
 * group actions by the agent/app instance that emitted them. Mirrors
 * @lictor/sentinel's agent-id so a single workstation running both products
 * reports a consistent id.
 */

import { createHash } from "node:crypto";
import { hostname } from "node:os";

export function agentId(): string {
  const sig = `${hostname()}:${process.pid}`;
  return createHash("sha256").update(sig).digest("hex").slice(0, 12);
}
