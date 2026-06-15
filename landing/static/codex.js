/* codex.js — portable Codex layer with the homepage's animated feel: gold aurora in the
   page background + each da-Vinci hero accent enriched (golden spiral + self-drawing
   strokes + an orbiting amber spotlight) + safe progressive scroll-reveals. Motion-safe;
   reveals never permanently hide content. External / CSP-clean, no dependencies. */
(function () {
  var NS = 'http://www.w3.org/2000/svg';

  // ambient gold aurora layered into the body background (behind everything, fixed)
  try {
    var bs = getComputedStyle(document.body);
    var ex = (bs.backgroundImage && bs.backgroundImage !== 'none') ? ', ' + bs.backgroundImage : '';
    document.body.style.backgroundImage =
      'radial-gradient(58% 50% at 16% 20%, rgba(232,163,61,.10), transparent 70%), ' +
      'radial-gradient(46% 46% at 86% 82%, rgba(232,163,61,.06), transparent 72%)' + ex;
    document.body.style.backgroundAttachment = 'fixed';
  } catch (e) {}

  document.documentElement.classList.add('codex-js');  // enables codex styling (animations still gated by @media reduced-motion)

  // enrich every da-Vinci hero accent: uniform pathLength (so strokes self-draw),
  // a golden-ratio spiral, and an orbiting spotlight sibling behind it.
  [].forEach.call(document.querySelectorAll('.codex-geo'), function (geo) {
    [].forEach.call(geo.querySelectorAll('.ink, .spiral'), function (s) {
      if (!s.getAttribute('pathLength')) s.setAttribute('pathLength', '1');
    });
    if (!geo.querySelector('.spiral')) {
      var vb = (geo.getAttribute('viewBox') || '0 0 320 320').split(/\s+/).map(Number);
      var cx = (vb[2] || 320) / 2, cy = (vb[3] || 320) / 2, PHI = 1.6180339887, max = Math.min(cx, cy) * 0.95, pts = [], r, t;
      for (t = 0; t <= 7 * Math.PI; t += 0.13) {
        r = 1.6 * Math.pow(PHI, t / (Math.PI / 2));
        if (r > max) break;
        pts.push((pts.length ? 'L' : 'M') + (cx + r * Math.cos(t)).toFixed(1) + ' ' + (cy - r * Math.sin(t)).toFixed(1));
      }
      var sp = document.createElementNS(NS, 'path');
      sp.setAttribute('class', 'spiral'); sp.setAttribute('pathLength', '1'); sp.setAttribute('d', pts.join(' '));
      geo.appendChild(sp);
    }
    var hero = geo.parentElement;
    if (hero && !hero.querySelector('.codex-glow')) {
      if (getComputedStyle(hero).position === 'static') hero.style.position = 'relative';
      var glow = document.createElement('div');
      glow.className = 'codex-glow'; glow.setAttribute('aria-hidden', 'true');
      hero.insertBefore(glow, hero.firstChild);
    }
  });

  // scroll-reveals — motion only; failsafe so nothing stays hidden
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || !('IntersectionObserver' in window)) return;
  var els = [].slice.call(document.querySelectorAll('[data-reveal]'));
  if (!els.length) return;
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add('codex-in'); io.unobserve(e.target); } });
  }, { rootMargin: '0px 0px -8% 0px', threshold: 0.04 });
  els.forEach(function (el) { io.observe(el); });
  setTimeout(function () { els.forEach(function (el) { el.classList.add('codex-in'); }); }, 3500);
})();
