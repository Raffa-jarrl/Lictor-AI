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
  // Safety net: no matter what happens with the FX layer below,
  // every fx-reveal element WILL show within 2s. Never leave content hidden.
  setTimeout(() => {
    document.querySelectorAll('.fx-reveal:not(.fx-in)').forEach((el) => {
      el.classList.add('fx-in');
    });
  }, 1800);

  // Mark <html> ready → CSS now applies the hidden-pre-reveal state.
  // If this script never runs, the CSS keeps everything visible.
  document.documentElement.classList.add('fx-ready');

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

  /* -------- Cursor spotlight (global) -------- */
  const spot = document.createElement('div');
  spot.className = 'fx-spotlight';
  document.body.appendChild(spot);
  let rafSpot = null;
  document.addEventListener('pointermove', (e) => {
    if (rafSpot) return;
    rafSpot = requestAnimationFrame(() => {
      spot.style.setProperty('--cx', `${e.clientX}px`);
      spot.style.setProperty('--cy', `${e.clientY}px`);
      rafSpot = null;
    });
  });

  /* -------- 3D parallax tilt on hero logo -------- */
  document.querySelectorAll('.fx-parallax').forEach((el) => {
    const layer = el.querySelector('.fx-parallax__layer') || el.querySelector('img');
    if (!layer) return;
    let raf = null;
    const center = () => {
      const r = el.getBoundingClientRect();
      return { x: r.left + r.width / 2, y: r.top + r.height / 2, w: r.width, h: r.height };
    };
    document.addEventListener('pointermove', (e) => {
      if (raf) return;
      raf = requestAnimationFrame(() => {
        const c = center();
        const dx = (e.clientX - c.x) / c.w;
        const dy = (e.clientY - c.y) / c.h;
        const max = 22; // deeper tilt
        const rx = (-dy * max).toFixed(2);
        const ry = (dx * max).toFixed(2);
        // Kill idle animation while user is interacting, swap for direct transform
        layer.style.animation = 'none';
        layer.style.transform = `rotateX(${rx}deg) rotateY(${ry}deg) translateZ(40px) scale(1.04)`;
        raf = null;
      });
    });
    el.addEventListener('pointerleave', () => {
      layer.style.transform = '';
      // Resume ambient idle tilt after a beat
      setTimeout(() => { layer.style.animation = ''; }, 200);
    });
  });

  /* -------- Magnetic buttons (pull toward cursor) -------- */
  document.querySelectorAll('.fx-magnetic').forEach((el) => {
    el.addEventListener('pointermove', (e) => {
      const r = el.getBoundingClientRect();
      const dx = (e.clientX - (r.left + r.width / 2)) * 0.15;
      const dy = (e.clientY - (r.top + r.height / 2)) * 0.15;
      el.style.transform = `translate(${dx}px, ${dy}px)`;
    });
    el.addEventListener('pointerleave', () => {
      el.style.transform = 'translate(0, 0)';
    });
  });

  /* -------- Particle field (canvas) -------- */
  const canvas = document.createElement('canvas');
  canvas.className = 'fx-particles';
  document.body.appendChild(canvas);
  const ctx = canvas.getContext('2d');
  let W = 0, H = 0, dpr = window.devicePixelRatio || 1;
  const particles = [];
  const PCOUNT = window.innerWidth < 760 ? 28 : 64;

  const resize = () => {
    W = window.innerWidth; H = window.innerHeight;
    canvas.width = W * dpr; canvas.height = H * dpr;
    canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  };
  resize();
  window.addEventListener('resize', resize);

  for (let i = 0; i < PCOUNT; i++) {
    particles.push({
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.25,
      vy: (Math.random() - 0.5) * 0.25,
      r: Math.random() * 1.6 + 0.4,
      a: Math.random() * 0.4 + 0.2,
    });
  }

  const tick = () => {
    ctx.clearRect(0, 0, W, H);
    // particles
    for (const p of particles) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(196, 136, 90, ${p.a})`;
      ctx.fill();
    }
    // connect nearby
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const a = particles[i], b = particles[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const d2 = dx * dx + dy * dy;
        if (d2 < 14000) {
          const alpha = (1 - d2 / 14000) * 0.12;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = `rgba(196, 136, 90, ${alpha})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(tick);
  };
  tick();
})();
