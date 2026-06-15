// buttondown.js — externalized Buttondown embed-popup wiring.
// Replaces the inline onsubmit="window.open(...)" attribute so the page works
// under a strict Content-Security-Policy (script-src 'self', no 'unsafe-inline').
//
// Progressive enhancement: the form has target="popupwindow" and a real
// action="https://buttondown.com/api/emails/embed-subscribe/lictor-ai", so it
// still submits and subscribes WITHOUT JavaScript. This script only pre-opens
// the named popup window so the Buttondown confirmation lands in a popup rather
// than navigating the whole page.
(function () {
  function wire(form) {
    form.addEventListener("submit", function () {
      window.open("https://buttondown.com/lictor-ai", "popupwindow");
    });
  }
  function init() {
    var forms = document.querySelectorAll(
      'form[action^="https://buttondown.com/"]'
    );
    Array.prototype.forEach.call(forms, wire);
  }
  if (document.readyState !== "loading") init();
  else document.addEventListener("DOMContentLoaded", init);
})();
