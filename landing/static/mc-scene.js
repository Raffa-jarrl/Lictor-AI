// mc-scene.js — externalized Three.js background scene for mission-control.
// Moved out of an inline <script> so the page works under a strict
// Content-Security-Policy (script-src 'self' + the cdnjs three.js origin,
// no 'unsafe-inline'). Depends on the global THREE loaded from cdnjs before
// this file. Pure visual enhancement.
    const canvas = document.getElementById('scene-bg');
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x050608, 0.008);

    const camera = new THREE.PerspectiveCamera(50, window.innerWidth / window.innerHeight, 0.1, 1000);
    camera.position.set(0, 6, 22);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x050608, 1);

    // === Ambient + spotlight ===
    scene.add(new THREE.AmbientLight(0xffffff, 0.25));
    const keyLight = new THREE.PointLight(0xc4885a, 1.2, 60);
    keyLight.position.set(8, 12, 8);
    scene.add(keyLight);
    const fillLight = new THREE.PointLight(0x4a6fa8, 0.4, 40);
    fillLight.position.set(-10, 6, 10);
    scene.add(fillLight);

    // === Floor grid (the "mission control room") ===
    const gridGeom = new THREE.PlaneGeometry(60, 60, 30, 30);
    const gridMat = new THREE.ShaderMaterial({
      uniforms: { time: { value: 0 } },
      vertexShader: `
        varying vec2 vUv;
        void main() {
          vUv = uv;
          gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
        }
      `,
      fragmentShader: `
        uniform float time;
        varying vec2 vUv;
        void main() {
          vec2 grid = abs(fract(vUv * 30.0 - 0.5) - 0.5) / fwidth(vUv * 30.0);
          float line = min(grid.x, grid.y);
          float alpha = 1.0 - min(line, 1.0);
          float dist = length(vUv - 0.5) * 2.0;
          float falloff = 1.0 - smoothstep(0.3, 0.95, dist);
          vec3 color = mix(vec3(0.77, 0.53, 0.35), vec3(0.4, 0.3, 0.2), dist);
          gl_FragColor = vec4(color, alpha * falloff * 0.7);
        }
      `,
      transparent: true,
      side: THREE.DoubleSide,
    });
    const grid = new THREE.Mesh(gridGeom, gridMat);
    grid.rotation.x = -Math.PI / 2;
    grid.position.y = -3;
    scene.add(grid);

    // === Central shield (the Lictor mark, abstracted) ===
    const shieldGeom = new THREE.OctahedronGeometry(1.2, 0);
    const shieldMat = new THREE.MeshPhongMaterial({
      color: 0xc4885a,
      emissive: 0x4a2a14,
      shininess: 80,
      flatShading: true,
      transparent: true, opacity: 0.85,
    });
    const shield = new THREE.Mesh(shieldGeom, shieldMat);
    shield.position.y = 1;
    scene.add(shield);

    // Wireframe overlay for the shield
    const shieldWire = new THREE.LineSegments(
      new THREE.EdgesGeometry(shieldGeom),
      new THREE.LineBasicMaterial({ color: 0xf4dcc4, transparent: true, opacity: 0.6 })
    );
    shieldWire.position.copy(shield.position);
    scene.add(shieldWire);

    // === 11 agent orbs orbiting the center (one per agent) ===
    const AGENTS = [
      { name: 'Wolf',       role: 'Planner' },
      { name: 'Hawk',       role: 'Scout' },
      { name: 'Bat',        role: 'Surveyor' },
      { name: 'Owl',        role: 'Critic / Recheck' },
      { name: 'Lyrebird',   role: 'Writer' },
      { name: 'Mantis',     role: 'Reviewer' },
      { name: 'Bee',        role: 'Magnet (Disclose)' },
      { name: 'Mongoose',   role: 'Probe (URL scan)' },
      { name: 'Cuttlefish', role: 'Vibe (Voice check)' },
      { name: 'Starling',   role: 'Trends' },
      { name: 'Octopus',    role: 'Dev / Multitool' },
      { name: 'Parrot',     role: 'Translator' },
      { name: 'Peacock',    role: 'Reel' },
      { name: 'Nightingale',role: 'Booth' },
      { name: 'Meerkat',    role: 'Bridge' },
    ];
    const orbs = [];
    AGENTS.forEach((agent, i) => {
      const angle = (i / AGENTS.length) * Math.PI * 2;
      const radius = 6;
      const orbGeom = new THREE.SphereGeometry(0.25, 16, 16);
      const orbMat = new THREE.MeshPhongMaterial({
        color: 0xc4885a, emissive: 0x6a3b1a, shininess: 60,
      });
      const orb = new THREE.Mesh(orbGeom, orbMat);
      orb.position.set(Math.cos(angle) * radius, 1 + Math.sin(i * 0.7) * 0.5, Math.sin(angle) * radius);
      orb.userData = { angle, radius, speed: 0.0005 + (i % 3) * 0.0002, baseY: orb.position.y };
      scene.add(orb);
      orbs.push(orb);

      // Connection line from shield to orb
      const lineGeom = new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(0, 1, 0),
        orb.position.clone(),
      ]);
      const lineMat = new THREE.LineBasicMaterial({ color: 0xc4885a, transparent: true, opacity: 0.15 });
      const line = new THREE.Line(lineGeom, lineMat);
      orb.userData.line = line;
      scene.add(line);
    });

    // === Animation loop ===
    let t = 0;
    function animate() {
      requestAnimationFrame(animate);
      t += 0.01;
      gridMat.uniforms.time.value = t;
      shield.rotation.x = t * 0.3;
      shield.rotation.y = t * 0.5;
      shieldWire.rotation.copy(shield.rotation);
      shield.position.y = 1 + Math.sin(t * 1.2) * 0.15;
      shieldWire.position.y = shield.position.y;

      orbs.forEach(orb => {
        orb.userData.angle += orb.userData.speed;
        const a = orb.userData.angle;
        orb.position.x = Math.cos(a) * orb.userData.radius;
        orb.position.z = Math.sin(a) * orb.userData.radius;
        orb.position.y = orb.userData.baseY + Math.sin(t * 1.5 + a) * 0.2;
        // Update connection line
        const pts = new Float32Array([0, 1, 0, orb.position.x, orb.position.y, orb.position.z]);
        orb.userData.line.geometry.setAttribute('position', new THREE.BufferAttribute(pts, 3));
        orb.userData.line.geometry.attributes.position.needsUpdate = true;
      });

      // Slow camera orbit
      const camRadius = 22;
      camera.position.x = Math.sin(t * 0.05) * camRadius;
      camera.position.z = Math.cos(t * 0.05) * camRadius;
      camera.position.y = 6 + Math.sin(t * 0.1) * 0.5;
      camera.lookAt(0, 1, 0);

      renderer.render(scene, camera);
    }
    animate();

    window.addEventListener('resize', () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    });
