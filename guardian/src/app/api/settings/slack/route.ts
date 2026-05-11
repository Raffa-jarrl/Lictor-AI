/**
 * POST /api/settings/slack — save / update the account's Slack webhook config.
 *
 * Validates the webhook URL shape; upserts the slack_integrations row;
 * records the change in audit_log; redirects back to /settings with a flash.
 */

import { NextResponse } from "next/server";
import { getSession } from "@/lib/auth";
import { db } from "@/lib/db";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

function redirectTo(url: URL, path: string): Response {
  return NextResponse.redirect(new URL(path, url.origin));
}

export async function POST(request: Request): Promise<Response> {
  const session = await getSession();
  if (!session) return redirectTo(new URL(request.url), "/");

  const data = await request.formData();
  const webhookUrl = (data.get("webhook_url") ?? "").toString().trim();
  const minSeverity = (data.get("min_severity") ?? "high").toString();
  const enabled = (data.get("enabled") ?? "true").toString() === "true";

  if (!/^https:\/\/hooks\.slack\.com\/services\/.+/.test(webhookUrl)) {
    const err = encodeURIComponent("Webhook URL must be a hooks.slack.com HTTPS URL.");
    return redirectTo(new URL(request.url), `/settings?err=${err}`);
  }
  if (!(VALID_SEVERITIES as readonly string[]).includes(minSeverity)) {
    const err = encodeURIComponent("Invalid min_severity.");
    return redirectTo(new URL(request.url), `/settings?err=${err}`);
  }

  await db()
    .insertInto("slack_integrations")
    .values({
      account_id: session.accountId,
      webhook_url: webhookUrl,
      min_severity: minSeverity as "critical" | "high" | "medium" | "low" | "info",
      enabled,
    })
    .onConflict((oc) =>
      oc.column("account_id").doUpdateSet({
        webhook_url: webhookUrl,
        min_severity: minSeverity as "critical" | "high" | "medium" | "low" | "info",
        enabled,
        updated_at: new Date(),
      }),
    )
    .execute();

  await db()
    .insertInto("audit_log")
    .values({
      account_id: session.accountId,
      actor_email: session.email,
      action: "slack.configure",
      target_id: null,
      metadata: { min_severity: minSeverity, enabled },
      ip: request.headers.get("x-forwarded-for") ?? null,
      user_agent: request.headers.get("user-agent") ?? null,
    })
    .execute();

  return redirectTo(new URL(request.url), "/settings?ok=slack");
}
