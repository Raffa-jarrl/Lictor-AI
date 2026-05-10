/**
 * Lictor Shield — content script.
 *
 * Tiny by design. Just two responsibilities:
 *   1. Detect AI-built site fingerprints in the page (cheap heuristic — exit
 *      fast on negative).
 *   2. Forward the page HTML + origin to the background service worker, which
 *      does all I/O and runs the WASM audit.
 *
 * No WASM is loaded here — content scripts can't easily import WASM, and
 * background can fetch any same/cross-origin URL with our manifest perms.
 */

import type { AuditRequest } from "./types.js";

const FINGERPRINTS: RegExp[] = [
  /__NEXT_DATA__/,                       // Next.js SSR data
  /\/_next\/static\//,                   // Next.js bundles
  /supabase-js/i,                        // Supabase client
  /firebase-app/i,                       // Firebase
  /openai\.com\/v1/i,                    // OpenAI API
  /api\.anthropic\.com/i,                // Anthropic API
  /\bclaude-(?:opus|sonnet|haiku)/i,     // Claude model identifiers
  /\bgpt-(?:4|3\.5|4o|5)/i,              // OpenAI model identifiers
  /vite\/dist/i,                         // Vite
  /\/_app-router-/i,                     // Next.js app router
  /\bcreate-react-app/i,                 // CRA
];

function looksLikeAiBuiltSite(): boolean {
  const html = document.documentElement.outerHTML;
  return FINGERPRINTS.some((re) => re.test(html));
}

(async function main() {
  // Don't audit chrome:// pages, file://, etc.
  if (location.protocol !== "https:" && location.protocol !== "http:") return;
  if (!looksLikeAiBuiltSite()) return;

  const msg: AuditRequest = {
    type: "audit-request",
    origin: location.origin,
    landingHtml: document.documentElement.outerHTML,
  };

  try {
    await chrome.runtime.sendMessage(msg);
  } catch (e) {
    console.error("[Lictor Shield] failed to dispatch audit:", e);
  }
})();
