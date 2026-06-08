// Lictor Scan — core logic for the public passive scanner (Cloudflare Pages Function).
//
// Design goals (match Lictor's ethical-disclosure rules):
//   • PASSIVE + signature-only — HEAD / Range:bytes=0-0, never read credential bodies.
//   • Identifiable — every request carries a LictorScan UA pointing at /scan.
//   • Bounded — one origin, ~9 short requests, 6s timeout each, run in parallel.
//   • SSRF-guarded — reject private / loopback / link-local / metadata hosts.
//   • Rate-limited per IP (KV) so it can't be turned into an attack tool.
//
// Returns a plain-English scorecard: { url, host, grade, score, findings[], scannedAt }.

export class ScanError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}

const UA = "LictorScan/1.0 (+https://lictor-ai.com/scan)";
const TIMEOUT_MS = 6000;
const RL_MAX = 8;          // scans per IP per window
const RL_WINDOW_S = 3600;  // 1 hour

// ── URL validation + SSRF guard ──────────────────────────────────────────────
const PRIVATE_V4 = [
  /^0\./, /^10\./, /^127\./, /^169\.254\./, /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // CGNAT 100.64/10
];
function isProbablyPrivateHost(host) {
  let h = host.toLowerCase().replace(/\.$/, "");                 // strip trailing dot (localhost.)
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);  // unwrap IPv6 brackets — the old fc/fd test never matched
  if (h === "localhost" || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".lan")) return true;
  if (!h.includes(":") && !h.includes(".")) return true;        // bare hostname / decimal-int IP, no public TLD
  // IPv6 — loopback, unspecified, ULA (fc00::/7), link-local (fe80::/10), IPv4-mapped
  if (h.includes(":")) {
    if (h === "::1" || h === "::") return true;
    if (/^0*:(0*:)*0*1$/.test(h)) return true;                  // expanded ::1
    if (/^f[cd]/.test(h)) return true;                          // ULA
    if (/^fe[89ab]/.test(h)) return true;                       // link-local
    if (h.includes("::ffff:")) {                                // IPv4-mapped (dotted OR hex hextets) — classic SSRF bypass
      const t = h.split("::ffff:")[1] || "";
      let v4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(t) ? t : null;
      const hx = t.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);  // URL parser normalizes a.b.c.d → hex hextets
      if (!v4 && hx) { const a = parseInt(hx[1], 16), b = parseInt(hx[2], 16); v4 = `${(a >> 8) & 255}.${a & 255}.${(b >> 8) & 255}.${b & 255}`; }
      if (!v4) return true;                                     // unparseable mapped form — fail safe
      if (v4 === "0.0.0.0" || v4 === "169.254.169.254" || PRIVATE_V4.some((re) => re.test(v4))) return true;
    }
    return false;
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) {                       // IPv4 literal
    if (h === "0.0.0.0" || h === "169.254.169.254") return true;
    if (PRIVATE_V4.some((re) => re.test(h))) return true;
  }
  return false;
}

export function normalizeTarget(input) {
  if (!input || typeof input !== "string") throw new ScanError("Enter a URL to scan.");
  let raw = input.trim();
  if (raw.length > 2000) throw new ScanError("That URL is too long.");
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw; // default to https
  let u;
  try { u = new URL(raw); } catch { throw new ScanError("That doesn't look like a valid URL."); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new ScanError("Only http/https URLs can be scanned.");
  if (isProbablyPrivateHost(u.hostname)) throw new ScanError("That host looks private or internal — Lictor only scans public sites.");
  u.hash = "";
  return u;
}

// ── rate limit (KV optional; degrades to no-op locally) ──────────────────────
async function checkRateLimit(env, ip) {
  const kv = env && env.WAITLIST;
  if (!kv || !ip) return;
  const bucket = Math.floor(nowSec() / RL_WINDOW_S);
  const key = `rl:scan:${ip}:${bucket}`;
  const cur = parseInt((await kv.get(key)) || "0", 10);
  if (cur >= RL_MAX) throw new ScanError("You've hit the scan limit (8/hour). Try the open-source CLI for unlimited scans.", 429);
  await kv.put(key, String(cur + 1), { expirationTtl: RL_WINDOW_S + 60 });
}
function nowSec() { return Math.floor(Date.now() / 1000); }

// ── timed fetch ──────────────────────────────────────────────────────────────
async function tfetch(url, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, {
      redirect: "manual",
      signal: ctrl.signal,
      headers: { "User-Agent": UA, "Accept": "*/*", ...(opts.headers || {}) },
      method: opts.method || "GET",
      cf: { cacheTtl: 0 },
    });
  } finally { clearTimeout(t); }
}

// ── the checks ───────────────────────────────────────────────────────────────
const SENSITIVE_PATHS = ["/.env", "/.git/config", "/.git/HEAD", "/config.json", "/.DS_Store", "/backup.sql", "/.aws/credentials"];

async function probePath(origin, path) {
  // signature-only: minimal Range GET, never read the body
  try {
    const r = await tfetch(origin + path, { headers: { Range: "bytes=0-0" } });
    return { path, status: r.status, ctype: (r.headers.get("content-type") || "").toLowerCase(), len: r.headers.get("content-length") };
  } catch { return { path, status: 0 }; }
}

export async function runScan(input, env, ip) {
  const u = normalizeTarget(input);
  await checkRateLimit(env, ip);
  const origin = u.origin;
  const findings = [];

  // Fetch the root first (gentler — don't burst the origin; bail early if unreachable).
  const rootRes = await tfetch(origin + "/").catch(() => null);
  if (!rootRes) {
    throw new ScanError(`Couldn't reach ${u.host}. Is it online and public?`, 502);
  }
  // canary — does the server 200 on a path that cannot exist? if so, ignore exposed-file 200s.
  const canary = `/lictor-canary-${Math.random().toString(36).slice(2, 12)}`;
  const [httpRes, canaryRes, ...fileRes] = await Promise.all([
    u.protocol === "https:" ? tfetch("http://" + u.host + "/").catch(() => null) : Promise.resolve(null),
    probePath(origin, canary),
    ...SENSITIVE_PATHS.map((p) => probePath(origin, p)),
  ]);

  // 1) HTTPS + redirect
  if (u.protocol === "https:") {
    findings.push(pass("https", "Served over HTTPS", "Traffic to your site is encrypted."));
    if (httpRes && httpRes.status >= 200 && httpRes.status < 300) {
      findings.push(f("http-no-redirect", "medium", "Plain HTTP is not redirected to HTTPS",
        "Visiting the http:// version returns content instead of redirecting to https://.",
        "Add a 301 redirect from http→https (most hosts do this with one setting)."));
    }
  } else {
    findings.push(f("no-https", "high", "Site is served over plain HTTP",
      "Traffic isn't encrypted — anyone on the network can read it.",
      "Enable HTTPS (free via Cloudflare/Let's Encrypt) and redirect http→https."));
  }

  // 2) security headers (from the root response)
  const H = (n) => (rootRes.headers.get(n) || "");
  const csp = H("content-security-policy");
  if (!H("strict-transport-security")) findings.push(f("hsts", "medium", "No HSTS header",
    "Browsers aren't told to always use HTTPS, leaving a downgrade window.",
    "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`."));
  if (!csp) findings.push(f("csp", "medium", "No Content-Security-Policy",
    "Nothing constrains what scripts/resources can load — your main defense against injected scripts (XSS) is off.",
    "Add a Content-Security-Policy header (start in report-only mode)."));
  if (!H("x-content-type-options")) findings.push(f("nosniff", "low", "No X-Content-Type-Options",
    "Browsers may guess (sniff) content types, which can enable some attacks.", "Send `X-Content-Type-Options: nosniff`."));
  if (!H("x-frame-options") && !/frame-ancestors/i.test(csp)) findings.push(f("clickjacking", "low", "No clickjacking protection",
    "Your site can be embedded in a hidden iframe on another site (clickjacking).",
    "Send `X-Frame-Options: DENY` or a CSP `frame-ancestors 'none'`."));
  if (!H("referrer-policy")) findings.push(info("referrer", "No Referrer-Policy", "Full URLs may leak to third parties via the Referer header.", "Send `Referrer-Policy: strict-origin-when-cross-origin`."));
  const server = H("server");
  if (server && /\d/.test(server)) findings.push(info("server-banner", "Server version disclosed", `The Server header reveals “${server}”, which helps attackers target known bugs.`, "Strip or genericize the Server header."));

  // 3) cookies
  const setCookie = rootRes.headers.get("set-cookie") || "";
  if (setCookie) {
    if (!/;\s*secure/i.test(setCookie) || !/;\s*httponly/i.test(setCookie)) {
      findings.push(f("cookie-flags", "medium", "Cookie missing Secure/HttpOnly",
        "A cookie is set without the Secure and/or HttpOnly flags — it can be stolen over HTTP or by injected scripts.",
        "Add `Secure; HttpOnly; SameSite=Lax` to your session cookies."));
    }
  }

  // 4) exposed files (signature-only, with canary guard)
  const serverLies = canaryRes.status >= 200 && canaryRes.status < 300; // 200s on a nonexistent path
  for (const r of fileRes) {
    const looksReal = r.status >= 200 && r.status < 300 && !serverLies && !(r.ctype || "").includes("text/html");
    if (looksReal) {
      findings.push(f("exposed-" + r.path.replace(/[^a-z]/gi, ""), "critical",
        `Sensitive file is publicly readable: ${r.path}`,
        `\`${r.path}\` returns ${r.status} (${r.ctype || "unknown type"}) — this often contains secrets or source.`,
        `Block ${r.path} at the web server / move it out of the web root and rotate anything it exposed.`));
    }
  }

  // pass rows so the report isn't all-negative
  if (!findings.some((x) => x.id === "csp")) findings.push(pass("csp-ok", "Content-Security-Policy present", "Good — script/resource loading is constrained."));
  if (!fileRes.some((r) => r.status >= 200 && r.status < 300)) findings.push(pass("no-exposed", "No common exposed files", "None of the usual leaky files (.env, .git, backups) were reachable."));

  const score = scoreOf(findings);
  return {
    url: u.href, host: u.host, grade: gradeOf(score), score,
    findings: sortFindings(findings),
    note: "Passive, non-intrusive surface check (headers, HTTPS, exposed files). For a deep audit of your code, run the open-source CLI: `cargo install lictor-cli && lictor audit " + u.host + "`.",
    scannedAt: new Date().toISOString(),
  };
}

// ── helpers ──────────────────────────────────────────────────────────────────
function f(id, severity, title, detail, fix) { return { id, severity, title, detail, fix }; }
function info(id, title, detail, fix) { return { id, severity: "info", title, detail, fix }; }
function pass(id, title, detail) { return { id, severity: "pass", title, detail }; }
const WEIGHT = { critical: 32, high: 18, medium: 10, low: 4, info: 0, pass: 0 };
const ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, pass: 5 };
function scoreOf(fs) { return Math.max(0, 100 - fs.reduce((s, x) => s + (WEIGHT[x.severity] || 0), 0)); }
function gradeOf(s) { return s >= 92 ? "A" : s >= 80 ? "B" : s >= 65 ? "C" : s >= 45 ? "D" : "F"; }
function sortFindings(fs) { return fs.slice().sort((a, b) => (ORDER[a.severity] - ORDER[b.severity])); }
