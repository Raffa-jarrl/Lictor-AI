// waitlist-core — self-hosted waitlist capture logic (runtime-agnostic ESM).
// Used by the Cloudflare Pages Function (functions/api/waitlist.js) and unit-tested
// directly by scripts/test-waitlist-fn.mjs. No third-party dependency.
//
// Storage: a KV namespace bound as env.WAITLIST. Each signup is one key
//   wl:<product>:<email>  ->  JSON record
// Admin read: GET /api/waitlist?token=<ADMIN_TOKEN>[&product=isolation-os]

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const PRODUCTS = new Set(["isolation-os", "sentry", "lictor", "patrol"]);

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

function wantsJson(request) {
  const a = (request.headers.get("accept") || "").toLowerCase();
  return a.includes("application/json") || request.headers.get("x-requested-with") === "fetch";
}

// only allow same-site absolute paths — blocks open-redirects (//evil, https://evil)
function safeRedirect(path) {
  if (typeof path === "string" && path.startsWith("/") && !path.startsWith("//")) return path;
  return "/";
}

async function parseBody(request) {
  const ctype = (request.headers.get("content-type") || "").toLowerCase();
  if (ctype.includes("application/json")) {
    const b = await request.json().catch(() => ({}));
    return {
      email: b.email, product: b.metadata__product ?? b.product,
      use_case: b.metadata__use_case ?? b.use_case, redirect: b.redirect,
    };
  }
  if (ctype.includes("application/x-www-form-urlencoded")) {
    const p = new URLSearchParams(await request.text());
    return {
      email: p.get("email"), product: p.get("metadata__product"),
      use_case: p.get("metadata__use_case"), redirect: p.get("redirect"),
    };
  }
  try {
    const f = await request.formData();
    return {
      email: f.get("email"), product: f.get("metadata__product"),
      use_case: f.get("metadata__use_case"), redirect: f.get("redirect"),
    };
  } catch { return {}; }
}

export async function handlePost(request, env) {
  let fields;
  try { fields = await parseBody(request); }
  catch { return json({ ok: false, error: "bad_request" }, 400); }

  let email = (fields.email || "").toString().trim().toLowerCase();
  let product = (fields.product || "").toString();
  const use_case = (fields.use_case || "").toString().slice(0, 60);
  const redirect = safeRedirect((fields.redirect || "/").toString());

  if (!EMAIL_RE.test(email)) {
    return wantsJson(request)
      ? json({ ok: false, error: "invalid_email" }, 422)
      : Response.redirect(new URL(redirect + "?subscribed=err", request.url).toString(), 303);
  }
  if (!PRODUCTS.has(product)) product = "lictor";

  const record = {
    email, product, use_case,
    ts: new Date().toISOString(),
    ref: (request.headers.get("referer") || "").slice(0, 200),
    ua: (request.headers.get("user-agent") || "").slice(0, 160),
    country: request.headers.get("cf-ipcountry") || "",
  };

  // Fail loud if storage isn't bound — never silently drop a signup in production.
  if (!env || !env.WAITLIST) {
    return json({ ok: false, error: "storage_unavailable" }, 503);
  }
  await env.WAITLIST.put(`wl:${product}:${email}`, JSON.stringify(record), {
    metadata: { product, ts: record.ts },
  });

  return wantsJson(request)
    ? json({ ok: true, email, product })
    : Response.redirect(new URL(redirect + "?subscribed=1", request.url).toString(), 303);
}

export async function handleGet(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get("token") || "";
  if (!env || !env.ADMIN_TOKEN || token !== env.ADMIN_TOKEN) {
    return json({ ok: false, error: "unauthorized" }, 401);
  }
  const product = url.searchParams.get("product");
  const prefix = product ? `wl:${product}:` : "wl:";
  const list = env.WAITLIST ? await env.WAITLIST.list({ prefix, limit: 1000 }) : { keys: [] };
  return json({ ok: true, count: list.keys.length, keys: list.keys.map((k) => k.name) });
}
