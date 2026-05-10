/**
 * Lictor Shield — content script.
 *
 * Runs in every tab. Responsibilities (target):
 *   1. Detect AI-built site fingerprints (Next.js, Vite, Supabase, OpenAI/Anthropic SDKs)
 *   2. Load lictor-core WASM (lazy, only when fingerprint matches)
 *   3. Run static checks against page HTML / JS
 *   4. Watch DOM for AI-agent surfaces reading sensitive data (localStorage,
 *      cookies, form contents) and ship-to-network patterns
 *   5. Forward findings to background.ts for badge + alarm UI
 *
 * Status: stub. Detection heuristic + message passing scaffolded; real audit
 * pipeline lands in Phase 1 once WASM bundle is wired.
 */

interface Finding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  detail: string;
  where_found: string;
  remediation: string;
}

/**
 * Quick heuristic: does this page look like an AI-built site we should audit?
 * Cheap synchronous checks only — we exit fast on negative.
 */
function looksLikeAiBuiltSite(): boolean {
  const html = document.documentElement.outerHTML;

  const fingerprints = [
    /__NEXT_DATA__/,                       // Next.js
    /\/_next\/static\//,                   // Next.js bundles
    /supabase-js/i,                        // Supabase client
    /firebase-app/i,                       // Firebase
    /openai\.com\/v1/i,                    // OpenAI API
    /api\.anthropic\.com/i,                // Anthropic API
    /\bclaude-(?:opus|sonnet|haiku)/i,     // Claude model identifiers
    /\bgpt-(?:4|3\.5|4o|5)/i,              // OpenAI model identifiers
    /vite\/dist/i,                         // Vite
    /<script[^>]*type="module"/i,          // ESM (modern build)
  ];

  return fingerprints.some((re) => re.test(html));
}

/**
 * Run the audit pipeline. Returns findings for this page.
 *
 * STUB: real impl will load `lictor-core` WASM and dispatch to its checks.
 */
async function runAudit(): Promise<Finding[]> {
  // TODO(Phase 1): import('../wasm/lictor_core.js') and run real checks.
  // For now, emit one INFO finding so the toolchain end-to-end works.
  return [
    {
      severity: 'info',
      category: 'general',
      title: 'AI-built site detected (audit stub)',
      detail: 'Lictor Shield is wired but checks are not yet ported.',
      where_found: location.origin,
      remediation: 'Real checks ship in Phase 1.',
    },
  ];
}

(async function main() {
  if (!looksLikeAiBuiltSite()) return;

  const findings = await runAudit();
  chrome.runtime.sendMessage({
    type: 'audit-result',
    origin: location.origin,
    findings,
  });
})().catch((e) => console.error('[Lictor Shield] content script failed:', e));
