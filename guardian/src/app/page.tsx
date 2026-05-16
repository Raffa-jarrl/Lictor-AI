/**
 * Guardian — landing / login page.
 *
 * Shows the brand + a "Sign in" form that posts to /api/auth/magic.
 * If a sign-in attempt failed (expired / invalid magic link), surfaces
 * a friendly error from the ?error= query string.
 */

import { redirect } from "next/navigation";
import { getSession } from "@/lib/auth";
import type { ReactElement } from "react";

export const dynamic = "force-dynamic";

interface PageProps {
  searchParams: Promise<{ error?: string; sent?: string }>;
}

const ERROR_MESSAGES: Record<string, string> = {
  invalid_link: "That sign-in link is invalid. Try again.",
  expired_or_invalid:
    "That sign-in link has expired or has already been used. Request a new one below.",
};

export default async function HomePage({ searchParams }: PageProps): Promise<ReactElement> {
  const session = await getSession();
  if (session) {
    redirect("/dashboard");
  }

  const params = await searchParams;
  const errorMessage =
    params.error && ERROR_MESSAGES[params.error] ? ERROR_MESSAGES[params.error] : null;

  return (
    <main
      style={{
        maxWidth: 480,
        margin: "0 auto",
        padding: "80px 24px",
        textAlign: "center",
      }}
    >
      <div
        style={{
          fontFamily: "'Cormorant Garamond', Georgia, serif",
          fontSize: 36,
          fontWeight: 700,
        }}
      >
        Lictor <span style={{ color: "#C9A23B" }}>Guardian</span>
      </div>
      <p style={{ color: "#6E7780", marginTop: 8 }}>
        AI security monitoring + compliance for teams.
      </p>

      <div
        style={{
          marginTop: 48,
          padding: 24,
          background: "#1A2028",
          borderRadius: 8,
        }}
      >
        <h2 style={{ marginTop: 0, fontSize: 16 }}>Sign in</h2>
        <p style={{ color: "#6E7780", fontSize: 13 }}>
          We&apos;ll email you a magic link. No password.
        </p>

        {errorMessage && (
          <div
            style={{
              margin: "12px 0",
              padding: "8px 12px",
              background: "rgba(192, 57, 43, 0.12)",
              border: "1px solid #C0392B",
              borderRadius: 4,
              color: "#E8E2D5",
              fontSize: 12,
              textAlign: "left",
            }}
          >
            {errorMessage}
          </div>
        )}

        <form action="/api/auth/magic" method="POST" style={{ marginTop: 16 }}>
          <input
            type="email"
            name="email"
            required
            placeholder="you@example.com"
            style={{
              width: "100%",
              padding: "10px 12px",
              background: "#0F1419",
              color: "#E8E2D5",
              border: "1px solid #2A323E",
              borderRadius: 4,
              fontSize: 14,
            }}
          />
          <button
            type="submit"
            style={{
              marginTop: 12,
              width: "100%",
              padding: "10px 12px",
              background: "#C9A23B",
              color: "#0F1419",
              border: "none",
              borderRadius: 4,
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            Send magic link
          </button>
        </form>
      </div>

      <div style={{ marginTop: 48, fontSize: 12, color: "#6E7780" }}>
        Built by Lictor AI.{" "}
        <a href="https://lictorai.com" style={{ color: "#C9A23B" }}>
          lictorai.com
        </a>
      </div>
    </main>
  );
}
