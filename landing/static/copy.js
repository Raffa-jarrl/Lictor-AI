// copy.js — externalized "copy to clipboard" wiring for code blocks.
// Replaces inline onclick="navigator.clipboard.writeText(...)" handlers so pages
// work under a strict Content-Security-Policy (script-src 'self', no 'unsafe-inline').
//
// Markup contract:
//   <pre>…code…</pre><button class="js-copy" data-done="✓ copied">copy</button>
// The button copies either its [data-copy] attribute (explicit text) or, if
// absent, the .innerText of its previousElementSibling (the <pre>).
(function () {
  function flash(btn, doneLabel) {
    var original = btn.textContent;
    btn.textContent = doneLabel || "✓ copied";
    setTimeout(function () {
      btn.textContent = original;
    }, 2000);
  }
  function copyText(btn) {
    if (btn.hasAttribute("data-copy")) return btn.getAttribute("data-copy");
    var prev = btn.previousElementSibling;
    return prev ? prev.innerText : "";
  }
  function wire(btn) {
    btn.addEventListener("click", function () {
      var text = copyText(btn);
      var done = btn.getAttribute("data-done") || "✓ copied";
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(
          function () { flash(btn, done); },
          function () {}
        );
      }
    });
  }
  function init() {
    var btns = document.querySelectorAll(".js-copy");
    Array.prototype.forEach.call(btns, wire);
  }
  if (document.readyState !== "loading") init();
  else document.addEventListener("DOMContentLoaded", init);
})();
