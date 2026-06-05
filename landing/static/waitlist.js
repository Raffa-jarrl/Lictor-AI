// Progressive enhancement for self-hosted waitlist forms (action="/api/waitlist").
// Works without JS too: a plain POST redirects back with ?subscribed=1 and we show
// the same thank-you on load.
(function () {
  function thankYou(el) {
    var msg = document.createElement("div");
    msg.className = "waitlist-thanks";
    msg.setAttribute("role", "status");
    msg.textContent = "✓ You’re on the list. We’ll email you when your build is ready.";
    msg.style.cssText =
      "max-width:460px;margin:0 auto;padding:1rem 1.25rem;border:1px solid var(--accent,#E8A33D);" +
      "border-radius:10px;color:var(--text,#ece3d6);background:rgba(232, 163, 61,.09);font-weight:600;text-align:center;";
    el.replaceWith(msg);
  }
  function wire(form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var data = {};
      new FormData(form).forEach(function (v, k) { data[k] = v; });
      var btn = form.querySelector('button[type="submit"]') || form.querySelector("button");
      var label = btn ? btn.textContent : "";
      if (btn) { btn.disabled = true; btn.textContent = "Adding…"; }
      fetch(form.getAttribute("action") || "/api/waitlist", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(data),
      })
        .then(function (r) { return r.json().catch(function () { return { ok: r.ok }; }); })
        .then(function (res) {
          if (res && res.ok) { thankYou(form); }
          else {
            if (btn) { btn.disabled = false; btn.textContent = label; }
            alert(res && res.error === "invalid_email"
              ? "Please enter a valid email address."
              : "Something went wrong — please try again.");
          }
        })
        .catch(function () {
          if (btn) { btn.disabled = false; btn.textContent = label; }
          alert("Network error — please try again.");
        });
    });
  }
  function init() {
    var forms = document.querySelectorAll('form[action="/api/waitlist"]');
    Array.prototype.forEach.call(forms, wire);
    if (/[?&]subscribed=1(?:&|$)/.test(location.search) && forms.length) thankYou(forms[0]);
  }
  if (document.readyState !== "loading") init();
  else document.addEventListener("DOMContentLoaded", init);
})();
