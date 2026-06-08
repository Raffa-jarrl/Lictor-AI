// Cloudflare Pages Function — POST /api/scan  (passive public scanner)
// Logic lives in functions/_lib/scan-core.mjs. Same-origin; optional WAITLIST KV
// is reused for per-IP rate limiting and (opt-in) anonymous research telemetry.
import { runScan, ScanError, buildTelemetry } from "../_lib/scan-core.mjs";

const J = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "POST, GET, OPTIONS",
      "access-control-allow-headers": "content-type",
    },
  });

export const onRequestOptions = () => J({ ok: true });
export const onRequestGet = () => J({ ok: true, service: "lictor-scan", live: true });

export const onRequestPost = async (ctx) => {
  let url, consent = false;
  try {
    const body = await ctx.request.json().catch(() => ({}));
    url = body && body.url;
    consent = !!(body && body.consent === true);
  } catch { /* fallthrough → validation error */ }
  const ip = ctx.request.headers.get("cf-connecting-ip") || "anon";
  try {
    const result = await runScan(url, ctx.env, ip);
    // Opt-in, anonymous research telemetry. Fire-and-forget via waitUntil so it
    // never delays the response or breaks the scan if KV is unavailable. The
    // record carries only finding TYPES + severities + grade — never the URL,
    // host, IP, or any value from the scanned site (see buildTelemetry).
    if (consent && ctx.env && ctx.env.WAITLIST) {
      const rec = buildTelemetry(result);
      ctx.waitUntil(
        ctx.env.WAITLIST.put(`tel:${rec.at}:${crypto.randomUUID().slice(0, 8)}`, JSON.stringify(rec), { metadata: { grade: rec.grade } }).catch(() => {}),
      );
    }
    return J(result, 200);
  } catch (e) {
    const status = e instanceof ScanError ? e.status : 500;
    return J({ error: e.message || "Scan failed.", status }, status);
  }
};
