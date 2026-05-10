/**
 * Validation schema for the Sentinel → Guardian wire format.
 *
 * Single source of truth: `~/Lictor/docs/specs/wire-format.md`. Any change
 * here must update that spec in the same commit.
 */

import { z } from "zod";

export const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);

export const IncidentEventSchema = z.object({
  ts: z.string().datetime(),
  agentId: z.string().min(1).max(64),
  phase: z.enum(["preflight", "postflight"]),
  checkId: z.string().min(1).max(64),
  severity: SeveritySchema,
  title: z.string().min(1).max(200),
  detail: z.string().min(1).max(2000),
  model: z.object({
    provider: z.enum(["openai", "anthropic", "other"]),
    name: z.string().min(1).max(64),
  }),
  fingerprint: z.string().regex(/^[0-9a-f]{16}$/),
  action: z.enum(["logged", "blocked", "redacted"]),
  sentinelVersion: z.string().min(1).max(32),
});

export const EnvelopeSchema = z.object({
  envelope_version: z.literal("1"),
  sentinel_version: z.string().min(1).max(32),
  lictor_core_version: z.string().min(1).max(32),
  agent_id: z.string().min(1).max(64),
  sent_at: z.string().datetime(),
  events: z.array(IncidentEventSchema).min(1).max(100),
});

export type Envelope = z.infer<typeof EnvelopeSchema>;
export type IncidentEventWire = z.infer<typeof IncidentEventSchema>;
