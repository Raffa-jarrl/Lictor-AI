// Cloudflare Pages Function — POST /api/scan  (passive public scanner)
// Logic lives in functions/_lib/scan-core.mjs. Same-origin; optional WAITLIST KV
// is reused for per-IP rate limiting.
import { runScan, ScanError } from "../_lib/scan-core.mjs";

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
  let url;
  try {
    const body = await ctx.request.json().catch(() => ({}));
    url = body && body.url;
  } catch { /* fallthrough → validation error */ }
  const ip = ctx.request.headers.get("cf-connecting-ip") || "anon";
  try {
    const result = await runScan(url, ctx.env, ip);
    return J(result, 200);
  } catch (e) {
    const status = e instanceof ScanError ? e.status : 500;
    return J({ error: e.message || "Scan failed.", status }, status);
  }
};
