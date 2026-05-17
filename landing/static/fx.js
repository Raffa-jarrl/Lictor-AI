/* ============================================================
   Lictor FX — motion controller (vanilla, ~3KB)
   ============================================================
   - Scroll-reveal via IntersectionObserver
   - Count-up for [data-count] numbers
   - Cursor-tracked glow position for .fx-glow
   - Nav blur intensifier on scroll
   - Cleans up on prefers-reduced-motion
============================================================ */
(() => {
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* -------- Nav blur on scroll -------- */
  const nav = document.querySelector('header.nav, .nav');
  if (nav) {
    const onScroll = () => nav.classList.toggle('fx-scrolled', window.scrollY > 20);
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }

  if (reduce) return;

  /* -------- Scroll reveal -------- */
  const reveals = document.querySelectorAll('.fx-reveal');
  if (reveals.length && 'IntersectionObserver' in window) {
    const io = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) {
          e.target.classList.add('fx-in');
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
    reveals.forEach((el, i) => {
      if (!el.style.getPropertyValue('--fx-delay')) {
        el.style.setProperty('--fx-delay', `${Math.min(i * 0.06, 0.6)}s`);
      }
      io.observe(el);
    });
  }

  /* -------- Count-up numbers -------- */
  const counters = document.querySelectorAll('[data-count]');
  const animate = (el) => {
    const target = parseFloat(el.dataset.count);
    const suffix = el.dataset.suffix || '';
    const prefix = el.dataset.prefix || '';
    const duration = 1400;
    const start = performance.now();
    const isInt = Number.isInteger(target);
    const step = (now) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      const val = target * eased;
      el.textContent = prefix + (isInt ? Math.round(val).toLocaleString() : val.toFixed(1)) + suffix;
      if (t < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  };
  if (counters.length && 'IntersectionObserver' in window) {
    const cio = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) { animate(e.target); cio.unobserve(e.target); }
      });
    }, { threshold: 0.5 });
    counters.forEach((el) => cio.observe(el));
  }

  /* -------- Cursor-tracked glow -------- */
  document.querySelectorAll('.fx-glow').forEach((el) => {
    el.addEventListener('pointermove', (e) => {
      const r = el.getBoundingClientRect();
      el.style.setProperty('--mx', `${e.clientX - r.left}px`);
      el.style.setProperty('--my', `${e.clientY - r.top}px`);
    });
  });

  /* -------- Duplicate marquee tracks so they loop seamlessly -------- */
  document.querySelectorAll('.fx-marquee__track').forEach((track) => {
    track.innerHTML += track.innerHTML; // double for seamless scroll
  });
})();
