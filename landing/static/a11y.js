/* Lictor — standalone accessibility controller.
   For pages that don't load fx.js (which already bundles this identical module).
   Injects the panel, persists choices, respects the OS reduce-motion preference.
   The FAB guard makes it a no-op if fx.js already added the panel. */
(function () {
  var root = document.documentElement, KEY = 'lictor-a11y', saved = {};
  try { saved = JSON.parse(localStorage.getItem(KEY) || '{}'); } catch (e) {}
  var prefersReduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function apply() {
    root.classList.remove('a11y-motion', 'a11y-nomotion');
    if (saved.motion === true) root.classList.add('a11y-motion');
    else if (saved.motion === false) root.classList.add('a11y-nomotion');
    root.classList.toggle('a11y-contrast', !!saved.contrast);
    root.classList.toggle('a11y-large', !!saved.large);
  }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(saved)); } catch (e) {} }
  function motionOn() { return saved.motion === true ? true : saved.motion === false ? false : !prefersReduce; }
  apply();

  function row(id, label, on) {
    return '<div class="a11y-row"><label for="' + id + '">' + label + '</label>' +
      '<input type="checkbox" role="switch" id="' + id + '" class="a11y-switch"' + (on ? ' checked' : '') + '></div>';
  }
  function build() {
    if (document.querySelector('.a11y-fab')) return;   // fx.js may have already built it
    var fab = document.createElement('button');
    fab.className = 'a11y-fab'; fab.type = 'button';
    fab.setAttribute('aria-label', 'Accessibility options');
    fab.setAttribute('aria-expanded', 'false'); fab.setAttribute('aria-controls', 'a11y-panel');
    fab.innerHTML = '<span aria-hidden="true">&#9855;</span>';
    var panel = document.createElement('div');
    panel.id = 'a11y-panel'; panel.className = 'a11y-panel';
    panel.setAttribute('role', 'dialog'); panel.setAttribute('aria-label', 'Accessibility options');
    panel.setAttribute('aria-hidden', 'true');
    panel.innerHTML = '<h2 class="a11y-title">Accessibility</h2>' +
      row('a11y-t-motion', 'Animations', motionOn()) +
      row('a11y-t-contrast', 'High contrast', !!saved.contrast) +
      row('a11y-t-large', 'Larger text', !!saved.large) +
      '<p class="a11y-note">Saved on this device. The hero animation follows your system &ldquo;reduce motion&rdquo; setting unless you change it here.</p>';
    document.body.appendChild(fab); document.body.appendChild(panel);
    function open(o) { panel.setAttribute('aria-hidden', o ? 'false' : 'true'); fab.setAttribute('aria-expanded', o ? 'true' : 'false'); if (o) { var f = panel.querySelector('input'); if (f) f.focus(); } }
    fab.addEventListener('click', function () { open(panel.getAttribute('aria-hidden') === 'true'); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') open(false); });
    document.addEventListener('click', function (e) { if (panel.getAttribute('aria-hidden') === 'false' && !panel.contains(e.target) && !fab.contains(e.target)) open(false); });
    function bind(id, fn) { var el = document.getElementById(id); if (el) el.addEventListener('change', function () { fn(el.checked); apply(); save(); }); }
    bind('a11y-t-motion', function (on) { saved.motion = on; });
    bind('a11y-t-contrast', function (on) { saved.contrast = on; });
    bind('a11y-t-large', function (on) { saved.large = on; });
  }
  if (document.body) build(); else document.addEventListener('DOMContentLoaded', build);
})();
