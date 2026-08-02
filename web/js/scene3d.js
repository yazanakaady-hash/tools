import * as THREE from "three";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";

let renderer, scene, camera, controls, root, raf;
const state = { nodes: [], meshes: [], raycaster: new THREE.Raycaster(), mouse: new THREE.Vector2() };

const COLORS = {
  root: 0x3d8bfd,
  section: 0x64748b,
  dll: 0x7c5cff,
  api: 0x94a3b8,
  dangerous: 0xff3b5c,
  ioc: 0xf5a524,
};

export function initScene(canvas) {
  if (renderer) return;
  const w = canvas.clientWidth || canvas.parentElement.clientWidth;
  const h = canvas.clientHeight || 500;

  renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  renderer.setSize(w, h, false);

  scene = new THREE.Scene();
  camera = new THREE.PerspectiveCamera(50, w / h, 0.1, 2000);
  camera.position.set(0, 40, 180);

  controls = new OrbitControls(camera, canvas);
  controls.enableDamping = true;
  controls.dampingFactor = 0.06;

  const amb = new THREE.AmbientLight(0x9db7ff, 0.55);
  scene.add(amb);
  const dir = new THREE.DirectionalLight(0xffffff, 0.85);
  dir.position.set(40, 80, 30);
  scene.add(dir);

  // floor grid
  const grid = new THREE.GridHelper(240, 24, 0x1e2a3d, 0x121a28);
  grid.position.y = -40;
  scene.add(grid);

  root = new THREE.Group();
  scene.add(root);

  const tip = document.getElementById("nodeTip");
  canvas.addEventListener("pointermove", (ev) => {
    const rect = canvas.getBoundingClientRect();
    state.mouse.x = ((ev.clientX - rect.left) / rect.width) * 2 - 1;
    state.mouse.y = -((ev.clientY - rect.top) / rect.height) * 2 + 1;
    state.raycaster.setFromCamera(state.mouse, camera);
    const hits = state.raycaster.intersectObjects(state.meshes, false);
    if (hits.length) {
      const u = hits[0].object.userData;
      tip.classList.remove("hidden");
      tip.style.left = `${ev.clientX - rect.left + 12}px`;
      tip.style.top = `${ev.clientY - rect.top + 12}px`;
      tip.innerHTML = `<strong>${esc(u.label)}</strong><br/>${esc(u.group)} · risk ${u.risk}<br/>${esc(u.detail || "")}`;
      canvas.style.cursor = "pointer";
    } else {
      tip.classList.add("hidden");
      canvas.style.cursor = "grab";
    }
  });

  window.addEventListener("resize", () => {
    if (!renderer) return;
    const ww = canvas.clientWidth;
    const hh = canvas.clientHeight;
    camera.aspect = ww / hh;
    camera.updateProjectionMatrix();
    renderer.setSize(ww, hh, false);
  });

  const tick = () => {
    raf = requestAnimationFrame(tick);
    // gentle spin of dangerous nodes
    for (const m of state.meshes) {
      if (m.userData.group === "dangerous") {
        m.rotation.y += 0.02;
        const s = 1 + Math.sin(performance.now() / 250 + m.id) * 0.08;
        m.scale.setScalar(s);
      }
    }
    controls.update();
    renderer.render(scene, camera);
  };
  tick();
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
export function renderGraph(graph) {
  if (!root) return;
  // clear
  while (root.children.length) root.remove(root.children[0]);
  state.meshes = [];
  state.nodes = graph.nodes || [];

  const byId = Object.fromEntries(state.nodes.map((n) => [n.id, n]));
  const pos = {};

  for (const n of state.nodes) {
    const geo = new THREE.SphereGeometry(Math.max(1.6, n.size * 0.55), 20, 20);
    const color = COLORS[n.group] || 0x8899aa;
    const mat = new THREE.MeshStandardMaterial({
      color,
      emissive: n.group === "dangerous" ? 0x550015 : 0x000000,
      emissiveIntensity: n.group === "dangerous" ? 0.65 : 0,
      metalness: 0.2,
      roughness: 0.35,
    });
    const mesh = new THREE.Mesh(geo, mat);
    const x = n.x ?? 0;
    const y = n.y ?? 0;
    const z = n.z ?? 0;
    mesh.position.set(x, y, z);
    mesh.userData = n;
    root.add(mesh);
    state.meshes.push(mesh);
    pos[n.id] = mesh.position;
  }

  const lineMat = new THREE.LineBasicMaterial({ color: 0x2a3b55, transparent: true, opacity: 0.55 });
  for (const e of graph.edges || []) {
    const a = pos[e.source];
    const b = pos[e.target];
    if (!a || !b) continue;
    const g = new THREE.BufferGeometry().setFromPoints([a.clone(), b.clone()]);
    root.add(new THREE.Line(g, lineMat));
  }
}
