// changelog.js — externalized live GitHub commit feed for /changelog.
// Moved out of an inline <script> so the page works under a strict
// Content-Security-Policy (script-src 'self', no 'unsafe-inline').
  (async function() {
    const list = document.getElementById('changelog-list');
    const ts   = document.getElementById('commits-timestamp');

    try {
      const resp = await fetch('https://api.github.com/repos/Raffa-jarrl/Lictor-AI/commits?per_page=40');
      if (!resp.ok) throw new Error('GitHub API ' + resp.status);
      const commits = await resp.json();
      list.innerHTML = '';

      for (const c of commits) {
        const sha = (c.sha || '').slice(0, 7);
        const url = c.html_url;
        const msg = c.commit.message || '';
        const [title, ...rest] = msg.split('\n');
        // Filter the Co-Authored-By trailer for cleaner display
        const body = rest.join('\n').replace(/\n*Co-Authored-By:.*$/s, '').trim();
        const author = c.commit.author?.name || 'Raffa';
        const dateObj = new Date(c.commit.author?.date);
        const dateStr = dateObj.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) +
                        ' · ' + dateObj.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });

        const div = document.createElement('div');
        div.className = 'commit';
        div.innerHTML = `
          <div class="commit__head">
            <h3 class="commit__title">${escapeHtml(title)}</h3>
            <span class="commit__meta">${dateStr} · <a href="${url}" class="commit__sha">${sha}</a></span>
          </div>
          ${body ? `<p class="commit__body">${escapeHtml(body)}</p>` : ''}
        `;
        list.appendChild(div);
      }

      const now = new Date().toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', timeZoneName: 'short' });
      ts.textContent = `fetched ${now} · ${commits.length} commits`;
    } catch (err) {
      list.innerHTML = `<div class="changelog-empty">GitHub API rate-limited — try again in 60s, or <a href="https://github.com/Raffa-jarrl/Lictor-AI/commits/main" class="link">view directly on GitHub</a>.</div>`;
      ts.textContent = 'fetch failed';
    }

    function escapeHtml(s) {
      return s.replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
    }
  })();
