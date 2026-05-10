/**
 * The audit engine that runs in the background service worker.
 *
 * Loads `lictor-core` WASM, then orchestrates the full audit:
 *   1. Static scan of the landing HTML (for secrets / Supabase URLs / AI-agent fingerprints)
 *   2. Fetch first 8 same-host JS bundles, scan each for secrets
 *   3. Probe sensitive-file paths (/.env, /.git/config, etc.)
 *   4. Probe Supabase / Firebase URLs found in haystack
 *   5. Probe common /api/* paths for unauth data exposure
 *   6. Probe /admin etc. paths for client-side-only auth gates
 *   7. Probe a few /api/* paths for CORS posture
 *
 * All HTTP is done by the service worker (which has cross-origin permissions
 * via `host_permissions: <all_urls>`). WASM does only pattern matching.
 */

import type { Finding, WrappedFindings, Severity } from "./types.js";

// The WASM module ships pre-built into dist/wasm/. Loaded lazily on first audit.
type Wasm = typeof import("../wasm/lictor_core.js");

let wasmReady: Promise<Wasm> | null = null;

async function loadWasm(): Promise<Wasm> {
  if (!wasmReady) {
    wasmReady = (async () => {
      const url = chrome.runtime.getURL("wasm/lictor_core.js");
      const mod = (await import(url)) as Wasm;
      const wasmUrl = chrome.runtime.getURL("wasm/lictor_core_bg.wasm");
      // wasm-pack with --target web exports a default init() that accepts a
      // URL string. The bundled .d.ts uses a wider type; pass through.
      await (mod.default as (input: string) => Promise<unknown>)(wasmUrl);
      return mod;
    })();
  }
  return wasmReady;
}

interface FetchedResource {
  url: string;
  status: number;
  contentType: string;
  bodyText: string;
  bodyBytes: Uint8Array;
}

/** Polite fetch with timeout. Returns a resource record or null on failure. */
async function fetchResource(url: string, timeoutMs = 12000): Promise<FetchedResource | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    const r = await fetch(url, { signal: ctrl.signal, credentials: "omit" });
    clearTimeout(t);
    const buf = new Uint8Array(await r.arrayBuffer());
    return {
      url,
      status: r.status,
      contentType: r.headers.get("content-type") || "",
      bodyText: new TextDecoder("utf-8", { fatal: false }).decode(buf),
      bodyBytes: buf,
    };
  } catch {
    return null;
  }
}

async function fetchHeaders(url: string, timeoutMs = 8000): Promise<Headers | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    const r = await fetch(url, { signal: ctrl.signal, method: "GET", credentials: "omit" });
    clearTimeout(t);
    return r.headers;
  } catch {
    return null;
  }
}

function toFindings(jsValue: unknown): Finding[] {
  if (!jsValue || typeof jsValue !== "object") return [];
  const wrapped = jsValue as WrappedFindings;
  return Array.isArray(wrapped.findings) ? wrapped.findings : [];
}

/** Minimal 1-req/sec/host throttler so we don't hammer anyone's app. */
class HostThrottle {
  private last = new Map<string, number>();
  async wait(host: string, gapMs = 1000): Promise<void> {
    const prev = this.last.get(host) ?? 0;
    const now = Date.now();
    const sleep = prev + gapMs - now;
    if (sleep > 0) await new Promise((r) => setTimeout(r, sleep));
    this.last.set(host, Date.now());
  }
}

/** Run a full audit against `origin`. Returns an aggregated finding list. */
export async function audit(origin: string, landingHtml: string): Promise<Finding[]> {
  const wasm = await loadWasm();
  const findings: Finding[] = [];
  const throttle = new HostThrottle();

  const baseUrl = new URL(origin);
  const baseHost = baseUrl.host;

  // 1. Static HTML scan — secrets + AI agent + login surface
  findings.push(...toFindings(wasm.analyze_secrets(landingHtml, origin, "page HTML")));
  findings.push(...toFindings(wasm.analyze_ai_agent(landingHtml, origin)));

  const loginSurface = wasm.classify_login_surface(landingHtml);
  let haystack = landingHtml;

  // 2. Same-host JS bundles — fetch and scan
  const scriptSrcs = extractScriptSrcs(landingHtml, 8);
  for (const src of scriptSrcs) {
    const full = resolveUrl(baseUrl, src);
    if (!full) continue;
    if (full.host !== baseHost) continue;
    await throttle.wait(full.host);
    const r = await fetchResource(full.toString());
    if (!r || r.status !== 200 || !r.bodyText) continue;
    haystack += "\n" + r.bodyText;
    findings.push(...toFindings(wasm.analyze_secrets(r.bodyText, full.toString(), "JS bundle")));
  }

  // 3. Sensitive file probes
  for (const path of (wasm.sensitive_file_probes() as unknown as string[])) {
    const full = `${baseUrl.protocol}//${baseHost}${path}`;
    await throttle.wait(baseHost);
    const r = await fetchResource(full);
    if (r && r.status === 200 && r.bodyBytes.length > 30) {
      findings.push(...toFindings(wasm.analyze_exposed_file(path, full, r.bodyBytes.length)));
      // Also scan the leaked file for secrets.
      findings.push(...toFindings(wasm.analyze_secrets(r.bodyText, full, ".env file")));
    }
  }

  // 4. Supabase + Firebase probes
  for (const sb of wasm.extract_supabase_hosts(haystack) as unknown as string[]) {
    const rest = `${sb}/rest/v1/`;
    await throttle.wait(new URL(sb).host);
    const r = await fetchResource(rest);
    if (!r) continue;
    const cls = wasm.classify_supabase_probe(r.status, r.bodyBytes);
    if (cls === "schema_open") {
      findings.push(...toFindings(wasm.finding_supabase_schema_open(sb, rest)));
    } else if (cls === "auth_enforced") {
      findings.push(...toFindings(wasm.finding_supabase_auth_enforced(sb, rest, r.status)));
    }
  }

  for (const fb of wasm.extract_firebase_hosts(haystack) as unknown as string[]) {
    const probe = `${fb}/.json`;
    await throttle.wait(new URL(fb).host);
    const r = await fetchResource(probe);
    if (r && r.status === 200 && r.bodyBytes.length > 5) {
      const isNull = r.bodyText.trim() === "null";
      if (!isNull) findings.push(...toFindings(wasm.finding_firebase_open(fb, probe)));
    }
  }

  // 5. Unauth API path probes
  for (const path of wasm.database_api_paths() as unknown as string[]) {
    const full = `${baseUrl.protocol}//${baseHost}${path}`;
    await throttle.wait(baseHost);
    const r = await fetchResource(full);
    if (!r) continue;
    findings.push(...toFindings(wasm.analyze_unauth_api(path, full, r.status, r.contentType, r.bodyBytes)));
  }

  // 6. Admin path probes (only if a login surface was detected)
  if (loginSurface === "present") {
    for (const path of wasm.admin_probes() as unknown as string[]) {
      const full = `${baseUrl.protocol}//${baseHost}${path}`;
      await throttle.wait(baseHost);
      const r = await fetchResource(full);
      if (r && r.status === 200) {
        findings.push(...toFindings(wasm.finding_admin_path_open(path, full)));
      }
    }
  } else {
    findings.push(...toFindings(wasm.finding_no_login_surface(origin)));
  }

  // 7. CORS posture probes
  for (const path of wasm.cors_api_paths() as unknown as string[]) {
    const full = `${baseUrl.protocol}//${baseHost}${path}`;
    await throttle.wait(baseHost);
    const headers = await fetchHeaders(full);
    if (!headers) continue;
    const aca = headers.get("access-control-allow-origin") || "";
    const acc = headers.get("access-control-allow-credentials") || "";
    // We don't get status from fetchHeaders separately; rough use of 200 here is fine — the browser only returns headers on a successful response.
    const cls = wasm.classify_cors(200, aca, acc);
    if (cls === "star_with_credentials") {
      findings.push(...toFindings(wasm.finding_cors_misconfigured(path, full)));
    } else if (cls === "star_only") {
      findings.push(...toFindings(wasm.finding_cors_origin_star(path, full)));
    }
  }

  return findings;
}

function extractScriptSrcs(html: string, max: number): string[] {
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    out.push(m[1]);
    if (out.length >= max) break;
  }
  return out;
}

function resolveUrl(base: URL, src: string): URL | null {
  try {
    if (src.startsWith("//")) return new URL(`${base.protocol}${src}`);
    return new URL(src, base);
  } catch {
    return null;
  }
}

/** Pure helper for callers that want to display top severity. */
export function topSeverity(findings: Finding[]): Severity {
  const ranks: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  return findings.reduce<Severity>(
    (acc, f) => (ranks[f.severity] > ranks[acc] ? f.severity : acc),
    "info",
  );
}
