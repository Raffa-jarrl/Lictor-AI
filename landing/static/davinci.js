/* davinci.js — Lictor Codex: draws a golden-ratio spiral + φ margin-notes into the
   hero construction SVG, and tilts the hero in 3D toward the cursor. Motion-safe:
   inert under prefers-reduced-motion or on touch / coarse pointers. External file
   (CSP-compliant); no dependencies. */
(function () {
  var NS = 'http://www.w3.org/2000/svg';
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)');
  var geo = document.querySelector('.hero__geo');

  // 1. Golden logarithmic spiral drawn into the existing 560×560 construction SVG.
  if (geo && !geo.querySelector('.spiral')) {
    var cx = 280, cy = 280, PHI = 1.6180339887, pts = [], r, x, y;
    for (var t = 0; t <= 7.4 * Math.PI; t += 0.12) {     // r grows by φ each quarter-turn
      r = 2.0 * Math.pow(PHI, t / (Math.PI / 2));
      if (r > 252) break;
      x = cx + r * Math.cos(t);
      y = cy - r * Math.sin(t);
      pts.push((pts.length ? 'L' : 'M') + x.toFixed(1) + ' ' + y.toFixed(1));
    }
    var sp = document.createElementNS(NS, 'path');
    sp.setAttribute('d', pts.join(' '));
    sp.setAttribute('class', 'spiral');
    sp.setAttribute('pathLength', '1');
    geo.appendChild(sp);

    var lab = document.createElementNS(NS, 'text');           // φ
    lab.setAttribute('x', '296'); lab.setAttribute('y', '272');
    lab.setAttribute('class', 'codex-label'); lab.textContent = 'φ';
    geo.appendChild(lab);
    var note = document.createElementNS(NS, 'text');          // 1.618 · sectio aurea
    note.setAttribute('x', '298'); note.setAttribute('y', '290');
    note.setAttribute('class', 'codex-note'); note.textContent = '1.618 · sectio aurea';
    geo.appendChild(note);
  }

  // 2. 3D mouse-tilt — desktop pointers only, motion on.
  var grid = document.querySelector('.hero__grid');
  var hero = document.querySelector('.hero');
  if (!grid || !hero || reduce.matches || !window.matchMedia('(pointer:fine)').matches) return;
  var MAX = 6, queued = false, tx = 0, ty = 0;
  function apply() { queued = false; grid.style.setProperty('--tx', tx.toFixed(2) + 'deg'); grid.style.setProperty('--ty', ty.toFixed(2) + 'deg'); }
  function queue() { if (!queued) { queued = true; requestAnimationFrame(apply); } }
  hero.addEventListener('mousemove', function (e) {
    var b = hero.getBoundingClientRect();
    tx = ((e.clientX - b.left) / b.width - 0.5) * MAX * 2;     // rotateY ← horizontal
    ty = -((e.clientY - b.top) / b.height - 0.5) * MAX * 2;    // rotateX ← vertical (inverted)
    queue();
  }, { passive: true });
  hero.addEventListener('mouseleave', function () { tx = 0; ty = 0; queue(); });
})();
