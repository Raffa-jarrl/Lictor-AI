// Unit + live test for the /api/scan core. Run: node scripts/test-scan-fn.mjs
import { normalizeTarget, runScan, ScanError } from "../landing/functions/_lib/scan-core.mjs";

let pass = 0, fail = 0;
const ok = (n, c) => (c ? pass++ : (fail++, console.log("  ✗", n)));
const throws = (n, fn) => { try { fn(); fail++; console.log("  ✗", n, "(no throw)"); } catch (e) { e instanceof ScanError ? pass++ : (fail++, console.log("  ✗", n, "(wrong err)", e.message)); } };

console.log("— normalizeTarget —");
ok("adds https", normalizeTarget("example.com").href === "https://example.com/");
ok("keeps https + path", normalizeTarget("https://x.com/a/b").pathname === "/a/b");
ok("strips hash", normalizeTarget("https://x.com/#y").hash === "");
throws("reject localhost", () => normalizeTarget("http://localhost"));
throws("reject 10.x", () => normalizeTarget("http://10.0.0.5"));
throws("reject 127.x", () => normalizeTarget("http://127.0.0.1"));
throws("reject 192.168", () => normalizeTarget("http://192.168.1.1"));
throws("reject 172.16", () => normalizeTarget("http://172.16.0.1"));
throws("reject metadata", () => normalizeTarget("http://169.254.169.254/latest/meta-data"));
throws("reject .local", () => normalizeTarget("https://printer.local"));
throws("reject bare host", () => normalizeTarget("http://intranet"));
throws("reject ftp", () => normalizeTarget("ftp://x.com"));
throws("reject empty", () => normalizeTarget(""));
console.log(`unit: ${pass} pass, ${fail} fail`);

// live network scans (Node 18+ global fetch). Targets are safe/public.
if (typeof fetch === "function") {
  for (const t of ["https://example.com", "https://lictor-ai.com"]) {
    try {
      const r = await runScan(t, {}, "test-ip");
      console.log(`live ${t} → grade ${r.grade} (${r.score}/100), ${r.findings.length} findings: ` +
        r.findings.slice(0, 4).map((f) => `${f.severity}:${f.id}`).join(", "));
    } catch (e) { console.log(`live ${t} → ERROR ${e.message}`); }
  }
} else { console.log("(no global fetch — skipping live scan; Node 18+ required)"); }

process.exit(fail ? 1 : 0);
