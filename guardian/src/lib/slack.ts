/**
 * Slack webhook integration.
 *
 * One incoming-webhook URL per account. Fires on incidents at or above the
 * configured min_severity threshold. Best-effort — failures logged to
 * slack_integrations.last_error but never blocking ingest.
 */

import { db } from "./db";

type Sev = "critical" | "high" | "medium" | "low" | "info";

const SEVERITY_RANK: Record<Sev, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const SEVERITY_EMOJI: Record<Sev, string> = {
  critical: "🟥",
  high: "🟧",
  medium: "🟨",
  low: "🟦",
  info: "⬜",
};

export interface SlackPayload {
  text: string;
  blocks?: object[];
}

export interface SlackIncidentInput {
  ts: Date;
  phase: string;
  check_id: string;
  severity: Sev;
  title: string;
  model_provider: string | null;
  model_name: string | null;
  fingerprint: string;
  action: string;
  guardian_url: string;
  incident_id: string;
}

/** Build the Slack message payload for an incident. */
export function buildSlackPayload(i: SlackIncidentInput): SlackPayload {
  const emoji = SEVERITY_EMOJI[i.severity] ?? "❔";
  const link = `${i.guardian_url}/incidents/${i.incident_id}`;
  const text = `${emoji} *${i.severity.toUpperCase()}* — ${i.title}`;

  return {
    text,
    blocks: [
      {
        type: "section",
        text: { type: "mrkdwn", text: `${emoji} *${i.severity.toUpperCase()}* — ${i.title}` },
      },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `*${i.check_id}* · ${i.phase} · ${i.model_provider ?? "—"}/${i.model_name ?? "—"} · \`${i.fingerprint}\` · _${i.action}_`,
          },
        ],
      },
      {
        type: "actions",
        elements: [
          {
            type: "button",
            text: { type: "plain_text", text: "View in Guardian" },
            url: link,
          },
        ],
      },
    ],
  };
}

/** POST the payload to the webhook. Returns true on success. */
export async function postToSlack(webhookUrl: string, payload: SlackPayload): Promise<{ ok: boolean; error?: string }> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    const r = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    clearTimeout(t);
    if (!r.ok) {
      const body = await r.text();
      return { ok: false, error: `Slack ${r.status}: ${body.slice(0, 200)}` };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

/**
 * Look up the slack integration for an account, decide if the incident meets
 * the threshold, fire if so. Updates last_fired_at / last_error.
 *
 * Called from /api/ingest after the row lands. Never throws.
 */
export async function maybeFireSlackForIncident(
  accountId: string,
  incident: SlackIncidentInput,
): Promise<void> {
  try {
    const integration = await db()
      .selectFrom("slack_integrations")
      .selectAll()
      .where("account_id", "=", accountId)
      .where("enabled", "=", true)
      .executeTakeFirst();

    if (!integration) return;

    const minRank = SEVERITY_RANK[integration.min_severity as Sev];
    const evRank = SEVERITY_RANK[incident.severity];
    if (evRank < minRank) return;

    const payload = buildSlackPayload(incident);
    const result = await postToSlack(integration.webhook_url, payload);

    if (result.ok) {
      await db()
        .updateTable("slack_integrations")
        .set({ last_fired_at: new Date(), last_error: null, last_error_at: null })
        .where("id", "=", integration.id)
        .execute();
    } else {
      await db()
        .updateTable("slack_integrations")
        .set({ last_error: result.error ?? "unknown error", last_error_at: new Date() })
        .where("id", "=", integration.id)
        .execute();
    }
  } catch (e) {
    // Slack delivery must never block ingest. Log to stderr and move on.
    console.error("[slack] fire failed:", e);
  }
}
