// Lictor Scan — client-side form handler.
//
// Today (pre-Jul 6, 2026): the public Scan Worker is not yet deployed. The
// form falls back to "save your URL, we'll email you the scorecard the day
// the engine goes live" — a Buttondown-backed list distinct from Beacon.
//
// After Jul 6: the form POSTs to https://scan-api.lictor.ai/scan and polls
// /scan/<id> for completion, then redirects to /scan/<id> for the scorecard.

(() => {
  const form = document.getElementById('scan-form');
  if (!form) return;

  // Feature flag: flip to true the day the Worker ships.
  const SCAN_API_LIVE = false;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = document.getElementById('scan-url');
    const url = (input?.value || '').trim();
    if (!url) return;

    if (!SCAN_API_LIVE) {
      // Pre-launch: collect interest. Buttondown form-post under the hood.
      try {
        await fetch('https://buttondown.com/api/emails/embed-subscribe/lictor-ai', {
          method: 'POST',
          mode: 'no-cors',
          body: new URLSearchParams({
            email: prompt('What\'s your email? We\'ll send your scorecard the day Scan goes live (Jul 6).\n\nIf you don\'t want to share an email, just close this dialog — and you can still try the open-source CLI:\n\n  cargo install lictor-cli && lictor audit ' + url) || '',
            'metadata__url': url,
            'metadata__source': 'scan-pre-launch',
            embed: '1',
          }),
        });
        showMessage('You\'re on the list. We\'ll scan your URL the day Scan goes live and email you the scorecard. No spam — single email per launch milestone. To scan now: run `cargo install lictor-cli && lictor audit ' + url + '`.');
      } catch (err) {
        showMessage('Couldn\'t reach the waitlist — please try again, or install the open-source CLI: `cargo install lictor-cli && lictor audit ' + url + '`.');
      }
      return;
    }

    // Post-launch flow.
    showMessage('Scanning… this takes about 30 seconds.');
    try {
      const res = await fetch('https://scan-api.lictor.ai/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const { scan_id } = await res.json();
      pollForResult(scan_id);
    } catch (err) {
      showMessage('Scanner is currently overloaded. Please try again in a minute, or run the same scan locally with `lictor audit ' + url + '`.');
    }
  });

  function pollForResult(scanId) {
    let tries = 0;
    const interval = setInterval(async () => {
      tries++;
      if (tries > 30) { clearInterval(interval); showMessage('Scan took too long; we\'ll email you when it\'s done.'); return; }
      try {
        const r = await fetch(`https://scan-api.lictor.ai/scan/${scanId}`);
        if (r.status === 200) {
          clearInterval(interval);
          window.location.href = `/scan/${scanId}`;
        }
      } catch (_) {}
    }, 2000);
  }

  function showMessage(text) {
    const existing = document.querySelector('.scan-form__msg');
    if (existing) existing.remove();
    const div = document.createElement('div');
    div.className = 'scan-form__msg';
    div.style.cssText = 'max-width:580px;margin:1rem auto;padding:1rem 1.25rem;background:var(--surface);border:1px solid var(--accent);border-radius:8px;color:var(--text);font-size:0.95rem;line-height:1.5;';
    div.textContent = text;
    form.parentNode.insertBefore(div, form.nextSibling);
  }
})();
