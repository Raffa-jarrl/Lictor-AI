import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = {
  title: "Lictor Guardian",
  description: "AI security monitoring + compliance for teams.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          fontFamily:
            "-apple-system, BlinkMacSystemFont, 'Inter', system-ui, sans-serif",
          background: "#0F1419",
          color: "#E8E2D5",
          minHeight: "100vh",
        }}
      >
        {children}
      </body>
    </html>
  );
}
