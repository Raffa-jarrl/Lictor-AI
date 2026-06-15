// gh-stats.js — externalized GitHub issue/PR counters for /transparency.
// Moved out of an inline <script> so the page works under a strict
// Content-Security-Policy (script-src 'self', no 'unsafe-inline').
  (async function() {
    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = typeof val === 'number' ? val.toLocaleString() : val;
    };
    const todayIso = new Date().toISOString().slice(0,10);
    try {
      const q = (state, extra='') => `https://api.github.com/search/issues?q=author:Raffa-jarrl${extra ? '+' + encodeURIComponent(extra) : ''}+${state ? 'state:' + state : ''}&per_page=1`;
      // 4 lightweight queries in parallel
      const [allRes, openRes, closedRes, todayRes] = await Promise.all([
        fetch(`https://api.github.com/search/issues?q=${encodeURIComponent('author:Raffa-jarrl')}&per_page=1`),
        fetch(`https://api.github.com/search/issues?q=${encodeURIComponent('author:Raffa-jarrl state:open')}&per_page=1`),
        fetch(`https://api.github.com/search/issues?q=${encodeURIComponent('author:Raffa-jarrl state:closed')}&per_page=1`),
        fetch(`https://api.github.com/search/issues?q=${encodeURIComponent('author:Raffa-jarrl created:>=' + todayIso)}&per_page=1`),
      ]);
      const [all, open, closed, today] = await Promise.all([allRes.json(), openRes.json(), closedRes.json(), todayRes.json()]);
      setVal('stat-total', all.total_count ?? 0);
      setVal('stat-open',  open.total_count ?? 0);
      setVal('stat-closed', closed.total_count ?? 0);
      setVal('stat-today', today.total_count ?? 0);
      const ts = new Date().toLocaleTimeString(undefined, {hour:'2-digit', minute:'2-digit', timeZoneName:'short'});
      const tsEl = document.getElementById('stats-timestamp');
      if (tsEl) tsEl.textContent = `fetched ${ts}`;
    } catch (e) {
      ['stat-total','stat-open','stat-closed','stat-today'].forEach(id => setVal(id, '—'));
      const tsEl = document.getElementById('stats-timestamp');
      if (tsEl) tsEl.textContent = 'GitHub rate-limited — try again in 60s';
    }
  })();
