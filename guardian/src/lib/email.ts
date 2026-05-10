/**
 * Email delivery — Postmark in production, stdout in development.
 *
 * Dev mode: prints the magic link URL to stdout so the dev can click it
 * straight from their terminal. Production: real email via Postmark.
 *
 * Magic-link emails should be deliverable in <2 seconds and never blocked.
 * If Postmark is unreachable, we log loudly but don't throw — the user
 * can request another link.
 */

const POSTMARK_TOKEN_ENV = "POSTMARK_API_TOKEN";

export interface MagicLinkEmail {
  to: string;
  link: string;
}

export async function sendMagicLinkEmail(email: MagicLinkEmail): Promise<void> {
  const token = process.env[POSTMARK_TOKEN_ENV];

  if (!token) {
    // Dev mode: print to stdout. The dev clicks the link from terminal.
    // Preserve formatting + visibility so it's hard to miss.
    /* eslint-disable no-console */
    console.log("");
    console.log("┌─────────────────────────────────────────────────────────────────");
    console.log(`│ [Lictor dev] magic link for ${email.to}:`);
    console.log(`│   ${email.link}`);
    console.log("│ (set POSTMARK_API_TOKEN to send a real email instead)");
    console.log("└─────────────────────────────────────────────────────────────────");
    console.log("");
    /* eslint-enable no-console */
    return;
  }

  try {
    const r = await fetch("https://api.postmarkapp.com/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Postmark-Server-Token": token,
      },
      body: JSON.stringify({
        From: "no-reply@lictor.ai",
        To: email.to,
        Subject: "Your Lictor Guardian sign-in link",
        TextBody:
          `Click to sign in to Lictor Guardian:\n\n${email.link}\n\n` +
          `This link expires in 15 minutes. If you didn't request it, ignore this email.`,
        HtmlBody: magicLinkHtml(email.link),
        MessageStream: "outbound",
      }),
    });
    if (!r.ok) {
      console.error(`[Lictor email] Postmark returned ${r.status}: ${await r.text()}`);
    }
  } catch (e) {
    console.error("[Lictor email] Postmark request failed:", e);
  }
}

function magicLinkHtml(link: string): string {
  return `<!DOCTYPE html>
<html><body style="font-family: -apple-system, sans-serif; max-width: 480px; margin: 40px auto; color: #1A1A1A;">
<div style="font-family: 'Cormorant Garamond', Georgia, serif; font-size: 28px; font-weight: 700;">
  Lictor <span style="color: #C9A23B;">Guardian</span>
</div>
<p style="margin-top: 24px;">Click to sign in:</p>
<p>
  <a href="${link}" style="display: inline-block; padding: 12px 20px; background: #C9A23B; color: #0F1419; text-decoration: none; border-radius: 4px; font-weight: 600;">
    Sign in to Guardian
  </a>
</p>
<p style="color: #6E7780; font-size: 13px; margin-top: 32px;">
  This link expires in 15 minutes. If you didn't request it, ignore this email.
</p>
</body></html>`;
}
