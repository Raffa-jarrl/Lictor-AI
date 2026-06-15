/* premium.js — subtle hero-aurora parallax. Motion-safe: disabled under
   prefers-reduced-motion. Sets --par (scrollY in px) on .hero; premium.css maps it.
   rAF-throttled, passive scroll listener — zero layout cost. */
(function () {
  var hero = document.querySelector('.hero');
  if (!hero) return;
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)');
  var ticking = false;
  function apply() {
    ticking = false;
    if (reduce.matches) { hero.style.removeProperty('--par'); return; }
    /* clamp to the hero's range — past it the hero is off-screen anyway */
    hero.style.setProperty('--par', Math.min(window.scrollY, 800) + 'px');
  }
  function onScroll() { if (!ticking) { ticking = true; requestAnimationFrame(apply); } }
  window.addEventListener('scroll', onScroll, { passive: true });
  if (reduce.addEventListener) reduce.addEventListener('change', apply);
  apply();
})();
