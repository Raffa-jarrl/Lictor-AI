/* codex3d.js — the "da-Vinci study": a real 3D gold-wireframe Lictor shield rendered
   in Three.js (r128, global THREE from cdnjs). Construction-edge wireframe + faint
   translucent body for volume + embossed checkmark + orbiting compass rings. Slow
   rotation, mouse-reactive tilt. Falls back silently to the 2D SVG codex when WebGL
   is unavailable, on touch/small screens, or under prefers-reduced-motion. */
(function () {
  if (!window.THREE) return;                                            // three didn't load → keep SVG codex
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  if (window.innerWidth < 1024) return;                                 // mobile keeps the simple hero
  var hero = document.querySelector('.hero');
  if (!hero) return;
  try { var probe = document.createElement('canvas');
        if (!(probe.getContext('webgl') || probe.getContext('experimental-webgl'))) return;
  } catch (e) { return; }

  var GOLD = 0xE8A33D;
  var canvas = document.createElement('canvas');
  canvas.id = 'codex3d';
  canvas.setAttribute('aria-hidden', 'true');
  canvas.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;z-index:0;pointer-events:none;';
  hero.insertBefore(canvas, hero.firstChild);

  var renderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true, antialias: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  var scene = new THREE.Scene();
  var camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
  camera.position.set(0, 0, 6);

  var root = new THREE.Group();
  root.position.set(1.3, -0.25, 0);                                     // right-biased centerpiece
  root.scale.setScalar(1.18);
  scene.add(root);

  // ── heater-shield silhouette → extruded with a bevel ──
  var shape = new THREE.Shape();
  shape.moveTo(-1.0, 1.3);
  shape.lineTo(1.0, 1.3);
  shape.bezierCurveTo(1.06, 0.4, 0.85, -0.55, 0.0, -1.72);
  shape.bezierCurveTo(-0.85, -0.55, -1.06, 0.4, -1.0, 1.3);
  var geo = new THREE.ExtrudeGeometry(shape, {
    depth: 0.34, bevelEnabled: true, bevelThickness: 0.07, bevelSize: 0.07,
    bevelSegments: 2, steps: 1, curveSegments: 28
  });
  geo.center();

  var shield = new THREE.Group();
  shield.add(new THREE.Mesh(geo, new THREE.MeshBasicMaterial(            // faint body = volume
    { color: GOLD, transparent: true, opacity: 0.055, side: THREE.DoubleSide, depthWrite: false })));
  shield.add(new THREE.LineSegments(new THREE.EdgesGeometry(geo, 18),    // gold construction edges
    new THREE.LineBasicMaterial({ color: GOLD, transparent: true, opacity: 0.82 })));
  var ghost = new THREE.LineSegments(new THREE.EdgesGeometry(geo, 18),   // faint "sketch redraw" offset
    new THREE.LineBasicMaterial({ color: GOLD, transparent: true, opacity: 0.16 }));
  ghost.scale.set(1.05, 1.05, 1.05);
  shield.add(ghost);
  // embossed Lictor checkmark on the front face
  shield.add(new THREE.Mesh(
    new THREE.TubeGeometry(new THREE.CatmullRomCurve3([
      new THREE.Vector3(-0.40, 0.04, 0.20), new THREE.Vector3(-0.08, -0.30, 0.20), new THREE.Vector3(0.48, 0.55, 0.20)
    ]), 28, 0.035, 8, false),
    new THREE.MeshBasicMaterial({ color: GOLD, transparent: true, opacity: 0.9 })));
  root.add(shield);

  // ── da-Vinci compass rings (golden-ratio radii), slowly counter-rotating ──
  var rings = new THREE.Group();
  root.add(rings);
  function ring(r, op, rx, ry) {
    var m = new THREE.Mesh(new THREE.TorusGeometry(r, 0.012, 6, 140),
      new THREE.MeshBasicMaterial({ color: GOLD, transparent: true, opacity: op }));
    m.rotation.x = rx; m.rotation.y = ry; rings.add(m);
  }
  ring(2.62, 0.14, 0.45, 0);
  ring(2.00, 0.20, 1.25, 0.35);
  ring(1.50, 0.30, 0, 0);

  // ── interaction + resize ──
  var mx = 0, my = 0, tmx = 0, tmy = 0;
  window.addEventListener('mousemove', function (e) {
    var b = hero.getBoundingClientRect();
    if (e.clientY > b.bottom) return;
    tmx = (e.clientX - b.left) / b.width - 0.5;
    tmy = (e.clientY - b.top) / b.height - 0.5;
  }, { passive: true });
  function resize() {
    var b = hero.getBoundingClientRect();
    renderer.setSize(b.width, b.height, false);
    camera.aspect = b.width / b.height; camera.updateProjectionMatrix();
  }
  window.addEventListener('resize', resize); resize();

  // 3D object is now the centerpiece → retire the flat 2D SVG codex
  var svg = hero.querySelector('.hero__geo'); if (svg) svg.style.display = 'none';

  var t = 0;
  (function loop() {
    requestAnimationFrame(loop);
    t += 0.01;
    mx += (tmx - mx) * 0.05; my += (tmy - my) * 0.05;
    shield.rotation.y = Math.sin(t * 0.28) * 0.6;                        // gentle 3D turn — always reads as a shield, never a thin edge-on line
    root.rotation.y = mx * 0.55;                                        // tilt toward cursor
    root.rotation.x = my * 0.4 + Math.sin(t * 0.5) * 0.05;             // + gentle breathing
    rings.rotation.y -= 0.0026; rings.rotation.x += 0.0013;
    renderer.render(scene, camera);
  })();
})();
