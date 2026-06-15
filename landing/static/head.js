// head.js — runs synchronously in <head> to flag that JS is enabled, so CSS can
// progressively enhance (e.g. hide animation targets until they reveal). Kept as
// an external file so the page needs no inline <script> under a strict CSP.
document.documentElement.classList.add("js");
