// cf-stats.js — externalized Cloudflare site-traffic panel for /transparency.
// Moved out of an inline <script> so the page works under a strict
// Content-Security-Policy (script-src 'self', no 'unsafe-inline').
    (async function() {
      const container = document.getElementById('cf-stats-container');
      try {
        const data = await fetch('/static/cf-stats.json?cache=' + Date.now()).then(r => r.json());
        if (data._status === 'not-configured') {
          container.innerHTML = `<p class="text-caption">
            Site-traffic integration is configured but Cloudflare API token isn't installed yet.
            Once it lands, this panel shows live request counts + top referrers + top pages —
            same data as our internal dashboard.
          </p>`;
          return;
        }
        const zones = data.zones || {};
        const html = [];
        for (const [name, z] of Object.entries(zones)) {
          if (z._error) {
            html.push(`<div class="shell-card"><h3>${name}</h3><p class="text-muted">${z._error}</p></div>`);
            continue;
          }
          html.push(`
            <div style="background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:1.5rem;margin-bottom:1.5rem;">
              <h3 style="margin:0 0 1rem;font-family:'Cormorant Garamond',serif;font-size:1.5rem;color:var(--text);">
                <span class="text-accent">${name}</span>
              </h3>
              <div class="shell-grid shell-grid--3" style="margin-bottom:1.5rem;">
                <div class="shell-card shell-card--stat"><div class="shell-stat__num">${(z.requests || 0).toLocaleString()}</div><div class="shell-stat__label">total requests</div></div>
                <div class="shell-card shell-card--stat"><div class="shell-stat__num">${(z.unique_visitors || 0).toLocaleString()}</div><div class="shell-stat__label">unique visitors</div></div>
                <div class="shell-card shell-card--stat"><div class="shell-stat__num">${(z.page_views || 0).toLocaleString()}</div><div class="shell-stat__label">page views</div></div>
              </div>

              <div class="shell-grid shell-grid--2">
                <div>
                  <h4 style="font-family:'JetBrains Mono',monospace;font-size:.8rem;letter-spacing:.1em;color:var(--accent);text-transform:uppercase;margin:0 0 .75rem;">Top referrers</h4>
                  ${(z.top_referrers || []).slice(0,6).map(r => `
                    <div style="display:flex;justify-content:space-between;padding:.4rem 0;border-bottom:1px solid var(--border);font-size:.9rem;">
                      <span style="color:var(--text);">${r.referer || '(direct)'}</span>
                      <span style="font-family:'JetBrains Mono',monospace;color:var(--text-muted);">${r.count.toLocaleString()}</span>
                    </div>
                  `).join('') || '<p class="text-meta">no data yet</p>'}
                </div>
                <div>
                  <h4 style="font-family:'JetBrains Mono',monospace;font-size:.8rem;letter-spacing:.1em;color:var(--accent);text-transform:uppercase;margin:0 0 .75rem;">Top pages</h4>
                  ${(z.top_pages || []).slice(0,6).map(p => `
                    <div style="display:flex;justify-content:space-between;padding:.4rem 0;border-bottom:1px solid var(--border);font-size:.9rem;">
                      <span style="color:var(--text);font-family:'JetBrains Mono',monospace;">${p.path}</span>
                      <span style="font-family:'JetBrains Mono',monospace;color:var(--text-muted);">${p.count.toLocaleString()}</span>
                    </div>
                  `).join('') || '<p class="text-meta">no data yet</p>'}
                </div>
              </div>
            </div>
          `);
        }
        container.innerHTML = html.join('') + `<p style="text-align:center;color:var(--text-muted);font-size:.75rem;margin-top:1rem;">fetched ${new Date(data.fetched_at).toLocaleString()}</p>`;
      } catch (e) {
        container.innerHTML = `<p class="text-caption">Cloudflare stats not available yet. <a href="https://github.com/Raffa-jarrl/Lictor-AI/blob/main/scripts/cf-stats-fetch.py" class="link">setup instructions</a></p>`;
      }
    })();
