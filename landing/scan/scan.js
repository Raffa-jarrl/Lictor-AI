// Lictor Scan — client. Posts to the same-origin /api/scan Pages Function and
// renders the scorecard inline. Passive, non-intrusive surface check.
(() => {
  const form = document.getElementById("scan-form");
  if (!form) return;
  const input = document.getElementById("scan-url");

  const SEV = {
    critical: { c: "#ff6b5e", b: "#C0392B", bg: "rgba(192,57,43,.12)", label: "CRITICAL" },
    high:     { c: "#E8A33D", b: "#9a6a18", bg: "rgba(214,137,16,.12)", label: "HIGH" },
    medium:   { c: "#E8A33D", b: "#B8860B", bg: "rgba(184,134,11,.12)", label: "MEDIUM" },
    low:      { c: "#9bb0c7", b: "#3C4658", bg: "rgba(120,140,170,.12)", label: "LOW" },
    info:     { c: "#8E887B", b: "#3a3a3a", bg: "rgba(110,119,128,.12)", label: "INFO" },
    pass:     { c: "#6fcaa0", b: "#3D7C5E", bg: "rgba(61,124,94,.14)", label: "PASS" },
  };
  const GRADE_C = { A: "#6fcaa0", B: "#9ccf6f", C: "#E8A33D", D: "#e0863c", F: "#ff6b5e" };
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]));

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = (input?.value || "").trim();
    if (!url) return;
    // opt-in, anonymous research telemetry (default off; never sends your URL)
    const consent = !!document.getElementById("scan-consent")?.checked;
    render(`<div class="scan-card scan-card--busy"><div class="scan-spin"></div><p>Scanning <strong>${esc(url)}</strong>… passive surface check, ~10&nbsp;seconds.</p></div>`);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, consent }),
      });
      const data = await res.json();
      if (!res.ok) { renderError(data.error || "Scan failed.", url); return; }
      renderResult(data);
    } catch (_) {
      renderError("Couldn't reach the scanner. Try again in a moment, or run it locally.", url);
    }
  });

  function renderResult(d) {
    const gc = GRADE_C[d.grade] || "#E8A33D";
    const rows = (d.findings || []).map((x) => {
      const s = SEV[x.severity] || SEV.info;
      return `<li class="scan-finding">
        <span class="scan-badge" style="color:${s.c};border-color:${s.b};background:${s.bg}">${s.label}</span>
        <div><div class="scan-finding__t">${esc(x.title)}</div>
        ${x.detail ? `<div class="scan-finding__d">${esc(x.detail)}</div>` : ""}
        ${x.fix ? `<div class="scan-finding__f">→ ${esc(x.fix)}</div>` : ""}</div></li>`;
    }).join("");
    const counts = (d.findings || []).reduce((a, x) => ((a[x.severity] = (a[x.severity] || 0) + 1), a), {});
    const summary = ["critical", "high", "medium", "low"].filter((k) => counts[k]).map((k) => `${counts[k]} ${k}`).join(" · ") || "no issues found";
    render(`<div class="scan-card">
      <div class="scan-card__head">
        <div class="scan-grade" style="color:${gc};border-color:${gc}">${esc(d.grade)}</div>
        <div><div class="scan-card__host">${esc(d.host)}</div>
          <div class="scan-card__score">Score ${esc(d.score)}/100 · ${esc(summary)}</div></div>
      </div>
      <ul class="scan-findings">${rows}</ul>
      <p class="scan-card__note">${esc(d.note || "")}</p>
    </div>`);
  }

  function renderError(msg, url) {
    render(`<div class="scan-card scan-card--err">
      <p><strong>${esc(msg)}</strong></p>
      <p class="scan-card__note">Run the same scan locally, unlimited:
      <code>cargo install lictor-cli &amp;&amp; lictor audit ${esc(url)}</code></p>
    </div>`);
  }

  function render(html) {
    let box = document.getElementById("scan-result");
    if (!box) {
      box = document.createElement("div");
      box.id = "scan-result";
      form.parentNode.insertBefore(box, form.nextSibling);
    }
    box.innerHTML = html;
    box.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
})();
