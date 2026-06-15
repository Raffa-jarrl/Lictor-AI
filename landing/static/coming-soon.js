// coming-soon.js — externalized from an inline <script> so the page works under
// a strict Content-Security-Policy (script-src 'self', no 'unsafe-inline').
// Shows the matching "when" block based on the ?from= query param.
(function () {
  function init() {
    var from = new URLSearchParams(location.search).get("from");
    var valid = ["in-the-wild", "transparency", "crew"];
    var id = valid.indexOf(from) !== -1 ? "when-" + from : "when-default";
    var el = document.getElementById(id);
    if (el) el.hidden = false;
  }
  if (document.readyState !== "loading") init();
  else document.addEventListener("DOMContentLoaded", init);
})();
