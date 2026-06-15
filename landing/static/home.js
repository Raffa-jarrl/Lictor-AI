// home.js — externalized home-page scripts (GitHub star magnet + motion layer).
// Moved out of inline <script> blocks in index.html so the page works under a
// strict Content-Security-Policy (script-src 'self', no 'unsafe-inline').
// Everything here is pure progressive enhancement: the page is fully usable
// without it.

// ── (1) Star magnet — fetch live count + supporters wall ────────────────────
(function () {
  function run() {
    (async function () {
      try {
        const repo = await fetch(
          "https://api.github.com/repos/Raffa-jarrl/Lictor-AI"
        ).then((r) => r.json());
        const stars = repo.stargazers_count || 0;
        // Dynamic target: 100 → 250 → 1000 once we hit each milestone
        const target =
          stars >= 1000 ? 10000 : stars >= 250 ? 1000 : stars >= 100 ? 250 : 100;
        const cur = document.getElementById("stars-current");
        if (cur) cur.textContent = stars.toLocaleString();
        const ft = document.getElementById("founders-target");
        if (ft) ft.textContent = target.toLocaleString();
        const ft2 = document.getElementById("founders-target-2");
        if (ft2) ft2.textContent = target.toLocaleString();
        // Dynamic tier headline
        const h = document.getElementById("star-headline");
        if (h) {
          if (stars >= 1000)
            h.innerHTML = `<span class="fx-gradient-text">${stars.toLocaleString()}</span> people back Lictor. Add your star.`;
          else if (stars >= 250) h.innerHTML = `Almost a thousand. Push us over.`;
          else if (stars >= 100)
            h.innerHTML = `Help us reach <span class="fx-gradient-text">250</span>.`;
        }
        const pct = Math.max(1, Math.min(100, (stars / target) * 100));
        const prog = document.getElementById("stars-progress");
        if (prog) prog.style.width = pct + "%";
        // Update button text to feel personal
        const btn = document.getElementById("star-cta-text");
        if (btn && stars > 0) {
          btn.textContent = `Star — be #${stars + 1}`;
        }
      } catch (e) {
        const cur = document.getElementById("stars-current");
        if (cur) cur.textContent = "—";
      }

      // Wall of stargazers
      try {
        const gazers = await fetch(
          "https://api.github.com/repos/Raffa-jarrl/Lictor-AI/stargazers?per_page=100"
        ).then((r) => r.json());
        const wall = document.getElementById("supporters-wall");
        if (!wall) return;
        if (gazers.length === 0) {
          wall.innerHTML =
            '<span class="wall__empty">No supporters yet — be the first</span>';
        } else {
          wall.innerHTML = gazers
            .map(
              (u) => `
          <a href="${u.html_url}" target="_blank" rel="noopener" title="@${u.login}">
            <img src="${u.avatar_url}&s=48" width="36" height="36" alt="" loading="lazy" />
          </a>
        `
            )
            .join("");
        }
      } catch (e) {}
    })();
  }
  if (document.readyState !== "loading") run();
  else document.addEventListener("DOMContentLoaded", run);
})();

// ── (2) Motion layer — short, once; disabled under prefers-reduced-motion ───
(function () {
  function run() {
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    // (a) scroll-settle reveals — skip anything already on screen (no flicker)
    var sel =
      ".shead,.inst,.step,.dplate,.suite-block,.crew__item,.why__item," +
      ".faq details,.founder,.cta,.star-block,.wall-block,.iso-frame," +
      ".wedge-frame,.codewrap,.pillars-foot,.crew__more";
    var io = new IntersectionObserver(
      function (es) {
        es.forEach(function (e) {
          if (!e.isIntersecting) return;
          var el = e.target;
          var sibs = [].filter.call(el.parentElement.children, function (c) {
            return c.classList.contains("reveal");
          });
          el.style.transitionDelay =
            Math.min(Math.max(sibs.indexOf(el), 0) * 70, 350) + "ms";
          el.classList.add("in");
          io.unobserve(el);
        });
      },
      { rootMargin: "0px 0px -8% 0px" }
    );
    document.querySelectorAll(sel).forEach(function (el) {
      if (el.getBoundingClientRect().top < innerHeight * 0.9) {
        // above the fold: visible immediately; still let title rules draw
        requestAnimationFrame(function () {
          requestAnimationFrame(function () {
            el.classList.add("in");
          });
        });
        return;
      }
      el.classList.add("reveal");
      io.observe(el);
    });

    // (b) hero terminal: type the command, then findings appear line by line
    var term = document.querySelector(".hero-term");
    if (!term) return;
    var lines = term.querySelectorAll(".tl");
    var cmd = document.getElementById("term-cmd");
    if (!cmd || lines.length < 7) return;
    term.classList.add("term-anim");
    var full = cmd.textContent;
    cmd.textContent = "";
    var caret = document.createElement("span");
    caret.className = "term-caret";
    cmd.after(caret);
    function show(i) {
      if (lines[i]) lines[i].classList.add("on");
    }
    setTimeout(function () {
      show(0);
    }, 250);
    // cue the hand: hero kicker sketches first, the trust bar after the command
    var hk = document.querySelector(".hero__copy .kicker");
    if (hk)
      setTimeout(function () {
        hk.classList.add("in");
      }, 150);
    var tb = document.querySelector(".trustbar");
    if (tb)
      setTimeout(function () {
        tb.classList.add("in");
      }, 1700);
    setTimeout(function () {
      show(1);
      var k = 0;
      var t = setInterval(function () {
        cmd.textContent = full.slice(0, ++k);
        if (k >= full.length) {
          clearInterval(t);
          setTimeout(function () {
            caret.remove();
            [2, 3, 4, 5].forEach(function (li, j) {
              setTimeout(function () {
                show(li);
              }, 320 * j);
            });
            setTimeout(function () {
              show(6);
            }, 320 * 4 + 300);
          }, 380);
        }
      }, 34);
    }, 650);
  }
  if (document.readyState !== "loading") run();
  else document.addEventListener("DOMContentLoaded", run);
})();
