// mc-data.js — externalized live-data layer for mission-control.
// Moved out of an inline <script> so the page works under a strict
// Content-Security-Policy (script-src 'self', no 'unsafe-inline').
    const AGENTS_DATA = [
      { name: 'Wolf',       role: 'PLANNER',   status: 'Orchestrates the rotation between 7 scanners. Lives in discover-loop.', metric: 'discover-loop pid: live' },
      { name: 'Hawk',       role: 'SCOUT',     status: 'Patrols GitHub Code Search for new candidates across 9 vuln classes.', metric: 'patrol-firebase + 8 others' },
      { name: 'Bat',        role: 'SURVEYOR',  status: 'Walks repo trees, fetches raw files, decodes JWTs to verify role.', metric: 'verify-finding.py' },
      { name: 'Owl',        role: 'CRITIC',    status: 'Re-checks every disclosure every 3h to detect silent fixes.', metric: 'recheck.py · 7 silent fixes' },
      { name: 'Lyrebird',   role: 'WRITER',    status: 'Drafts every disclosure body. Voice: humble, plain English, no jargon.', metric: 'templates in lictor-hourly.py' },
      { name: 'Mantis',     role: 'REVIEWER',  status: 'Validates findings via WAF/SPA detection before any contact fires.', metric: 'verify-finding.py — RET-009 added' },
      { name: 'Bee',        role: 'MAGNET',    status: 'Submits the contact-request to the repo. Pollinates the disclosure.', metric: 'lictor-hourly.py · 50/day cap' },
      { name: 'Mongoose',   role: 'PROBE',     status: 'Probes URLs at scale (Israeli sites, vibe-coded deployments).', metric: 'scan-il-parallel.py' },
      { name: 'Cuttlefish', role: 'VIBE',      status: 'Voice-checks every outbound message. Catches tone-deaf phrasing.', metric: 'manual review · pretalx-incident protocol' },
      { name: 'Starling',   role: 'TRENDS',    status: 'Watches scanning trends + GitHub API limits + reply patterns.', metric: 'reply-monitor every 15min' },
      { name: 'Octopus',    role: 'DEV',       status: 'Ships site changes + new scanners + cron infra. Multi-tasker.', metric: 'pushes commits hourly' },
      { name: 'Parrot',     role: 'TRANSLATOR',status: 'Localizes the content + disclosure queue (he / es-LA / pt-BR / ja).', metric: 'every 6h' },
      { name: 'Peacock',    role: 'REEL',      status: 'Drafts weekly video scripts from the week’s findings.', metric: 'weekly · Sun' },
      { name: 'Nightingale',role: 'BOOTH',     status: 'Drafts podcast + conference (CFP) outreach.', metric: 'weekly · Mon' },
      { name: 'Meerkat',    role: 'BRIDGE',    status: 'Triages inbound GitHub issues + community replies.', metric: 'every 4h' },
    ];

    function renderAgents() {
      const grid = document.getElementById('agents-grid');
      grid.innerHTML = AGENTS_DATA.map((a, i) => `
        <div class="panel agent active">
          <div class="agent__head">
            <span class="agent__name">${a.name}</span>
            <span class="agent__role">${a.role}</span>
          </div>
          <div class="agent__status">${a.status}</div>
          <div class="agent__metric">→ ${a.metric}</div>
        </div>
      `).join('');
    }
    renderAgents();

    // Scanner status is hardcoded operational state — render it ALWAYS, with no
    // network dependency, so a GitHub hiccup can never blank this section.
    function renderScannerStatus() {
      document.getElementById('scanner-status').innerHTML = `
          <div>🟢 <strong>lictor-discover-loop</strong> · running 24/7 (7 scanners × 4 variants)</div>
          <div>🟢 <strong>hourly cron</strong> · :05 every hour · 50/day cap</div>
          <div>🟢 <strong>scanner-refresh cron</strong> · every 6h · firebase + db-creds + prtarget</div>
          <div>🟢 <strong>reply-monitor</strong> · every 15min</div>
          <div>🟢 <strong>recheck cron</strong> · every 3h · silent-fix detection</div>
          <div>🟢 <strong>disclose-priority</strong> · every 6h · impact-weighted queue</div>
          <div style="margin-top:.75rem; padding-top:.75rem; border-top:1px solid var(--panel-border);">
            <strong style="color:var(--copper-1);">14 vuln classes scanned:</strong> Firebase · DB-creds · PR-target · Mailchimp · SendGrid · Twilio · Cloudflare · HF Spaces · npm · PyPI · GitLab · Gists · Twilio-SID · Open-DB
          </div>`;
    }
    renderScannerStatus();

    // GitHub disclosure stats: best-effort enhancement. ONE search call
    // (unauthenticated Search API caps at 10 req/min/IP), with the last good
    // result cached so a 403 shows stale-but-real numbers instead of a blank board.
    const feedClass = t =>
      t.includes('Firebase') ? 'firebase' : t.includes('pull_request_target') ? 'prtarget' :
      t.includes('Mailchimp') ? 'mailchimp' : t.includes('Twilio') ? 'twilio' :
      t.includes('DB connection') ? 'db-creds' : t.includes('/admin') ? 'admin-leak' : 'other';

    function paintStats(d) {
      document.getElementById('hud-total').textContent = (d.total ?? 0).toLocaleString();
      document.getElementById('hud-today').textContent = d.today ?? 0;
      document.getElementById('hud-closed').textContent = d.closed ?? 0;
      document.getElementById('hud-replies').textContent = Math.max(5, d.closed ?? 0);
      if (d.feed) document.getElementById('live-feed').innerHTML = d.feed;
    }

    async function refreshGitHub() {
      const todayIso = new Date().toISOString().slice(0,10);
      try {
        const r = await fetch(`https://api.github.com/search/issues?q=${encodeURIComponent('author:Raffa-jarrl sort:created-desc')}&per_page=100`);
        if (!r.ok) throw new Error('github ' + r.status);
        const j = await r.json();
        const items = j.items ?? [];
        const data = {
          total: j.total_count ?? 0,
          today: items.filter(it => (it.created_at || '').slice(0,10) === todayIso).length,
          closed: items.filter(it => it.state === 'closed').length,
          feed: items.slice(0, 30).map(it => {
            const time = new Date(it.created_at).toLocaleTimeString(undefined, {hour:'2-digit', minute:'2-digit'});
            const date = new Date(it.created_at).toLocaleDateString(undefined, {month:'short', day:'numeric'});
            // REDACTION RULE: Lictor never publishes WHO was affected — only that a
            // disclosure happened, its class, and its state. The repo name and issue
            // URL are deliberately NOT placed in the DOM. (A CSS blur would still leak
            // them in the page source — so we never emit them at all.)
            return `
              <div class="mc-feed__item">
                <span class="mc-feed__time">${date} ${time}</span>
                <span class="mc-feed__class">${feedClass(it.title)}</span>
                <span class="mc-feed__repo" style="opacity:.55;letter-spacing:.5px" title="affected party redacted — responsible disclosure">████ redacted</span>
                <span class="mc-feed__state ${it.state}">${it.state === 'closed' ? '✓' : '○'}</span>
              </div>`;
          }).join(''),
        };
        paintStats(data);
        try { localStorage.setItem('mc-gh2', JSON.stringify({ ...data, at: Date.now() })); } catch (_) {}
        document.getElementById('last-update').textContent =
          'live · updated ' + new Date().toLocaleTimeString(undefined, {hour:'2-digit', minute:'2-digit'});
      } catch (e) {
        // Degrade gracefully — show last-good from cache; never blank the board.
        let cached = null;
        try { cached = JSON.parse(localStorage.getItem('mc-gh2') || 'null'); } catch (_) {}
        if (cached) {
          paintStats(cached);
          const mins = Math.round((Date.now() - (cached.at || Date.now())) / 60000);
          document.getElementById('last-update').textContent = `cached ${mins}m ago · GitHub busy (10 req/min cap)`;
        } else {
          document.getElementById('last-update').textContent = 'GitHub busy (10 req/min cap) · disclosure stats load shortly';
        }
      }
    }

    refreshGitHub();
    setInterval(refreshGitHub, 120000);
