// APT115 CODEX ARCANUM — Cheatsheet: chrome de la UI
// Sidebar/tema/atajos de teclado, timers del header y el orbe decorativo.

import { $, $in } from './util.js';
import { toggleIntel } from './intel.js';
import { openCustomModal, closeCustomModal } from './custom.js';
import { toggleFav } from './favs.js';
import { doSearch } from './search.js';

export function toggleShortcuts() {
  $('shortcutPanel').classList.toggle('on');
}

// Drawer del sidebar en móvil (off-canvas). En desktop el sidebar es fijo;
// en pantallas chicas se abre/cierra con la hamburguesa del header + backdrop.
export function toggleSidebarDrawer() {
  document.body.classList.toggle('sb-drawer-open');
}
export function closeSidebarDrawer() {
  document.body.classList.remove('sb-drawer-open');
}

export function toggleSidebar() {
  const sb = $('sidebar');
  const btn = $('sbCollapseBtn');
  const hist = $('histPanel');
  sb.classList.toggle('collapsed');
  const col = sb.classList.contains('collapsed');
  if (btn) btn.textContent = col ? '›' : '‹';
  if (btn) btn.title = col ? 'Expand sidebar' : 'Collapse sidebar';
  // Keep histPanel aligned
  if (hist && hist.classList.contains('on')) {
    hist.style.left = col ? '44px' : 'var(--sidebar-w)';
  }
  localStorage.setItem('cs_sbCollapsed', col ? '1' : '0');
}

// ─── THEME ───────────────────────────────────────────────
export function initTheme() {
  const saved = localStorage.getItem('cs_theme');
  if (saved === 'light') {
    document.body.classList.add('light-mode');
    const btn = $('themeToggleBtn');
    if (btn) btn.innerHTML = '☀️ LIGHT';
  }
}

export function toggleTheme() {
  const isLight = document.body.classList.toggle('light-mode');
  const btn = $('themeToggleBtn');
  if (btn) btn.innerHTML = isLight ? '☀️ LIGHT' : '🌙 DARK';
  localStorage.setItem('cs_theme', isLight ? 'light' : 'dark');
}

// ─── KEYBOARD SHORTCUTS ────────────────────────────────────
/** Handler único de teclado. Llamar una vez desde el init. */
export function wireKeyboard() {
  document.addEventListener('keydown', e => {
    const inInput = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName);

    // Ctrl+K — focus search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      const si = $in('searchInput');
      si.focus(); si.select(); return;
    }
    // Ctrl+/ — toggle shortcuts panel
    if ((e.ctrlKey || e.metaKey) && e.key === '/') {
      e.preventDefault(); toggleShortcuts(); return;
    }
    // Ctrl+B — toggle sidebar
    if ((e.ctrlKey || e.metaKey) && e.key === 'b') {
      e.preventDefault(); toggleSidebar(); return;
    }
    // Ctrl+I — toggle Intel panel
    if ((e.ctrlKey || e.metaKey) && e.key === 'i' && !inInput) {
      e.preventDefault(); toggleIntel(); return;
    }
    // Ctrl+→ / Ctrl+← — section nav
    if ((e.ctrlKey) && (e.key === 'ArrowRight' || e.key === 'ArrowLeft')) {
      e.preventDefault();
      const items = /** @type {HTMLElement[]} */ (Array.from(document.querySelectorAll('.si')));
      const cur = items.findIndex(x => x.classList.contains('on'));
      const next = e.key === 'ArrowRight' ? Math.min(cur + 1, items.length - 1) : Math.max(cur - 1, 0);
      if (items[next]) items[next].click(); return;
    }
    // Ctrl+Shift+A — add command
    if (e.ctrlKey && e.shiftKey && e.key === 'A') {
      e.preventDefault(); openCustomModal(); return;
    }
    // Ctrl+Shift+F — toggle favorites
    if (e.ctrlKey && e.shiftKey && e.key === 'F') {
      e.preventDefault(); toggleFav(); return;
    }
    // Escape — clear search / close panels
    if (e.key === 'Escape') {
      closeCustomModal();
      ['shortcutPanel', 'intelPanel', 'favPanel', 'histPanel', 'notesPanel'].forEach(pid => {
        const p = $(pid);
        if (p) p.classList.remove('on');
      });
      const si = $in('searchInput');
      if (si.value) { si.value = ''; doSearch(''); return; }
    }
  });
}

// ─── TIMERS DEL HEADER ─────────────────────────────────────
export function initTimers() {
  // Session timer
  const sessionStart = Date.now();
  setInterval(() => {
    const s = Math.floor((Date.now() - sessionStart) / 1000);
    const h = String(Math.floor(s / 3600)).padStart(2, '0');
    const m = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
    const sec = String(s % 60).padStart(2, '0');
    const el = $('sessionTimer');
    if (el) el.textContent = h === '00' ? `⏱ ${m}:${sec}` : `⏱ ${h}:${m}:${sec}`;
  }, 1000);
  // Cyber clock
  setInterval(() => {
    const now = new Date();
    const hh = String(now.getHours()).padStart(2, '0');
    const mm = String(now.getMinutes()).padStart(2, '0');
    const ss = String(now.getSeconds()).padStart(2, '0');
    const el = $('cyberClock');
    if (el) el.textContent = `${hh}:${mm}:${ss}`;
  }, 1000);
}

// ─── JUMP TO TOP ────────────────────────────────────────
export function wireJumpTop() {
  const main = /** @type {HTMLElement} */ (document.querySelector('.main'));
  main.addEventListener('scroll', () => {
    const btn = $('jumpTop');
    if (btn) btn.classList.toggle('on', main.scrollTop > 300);
  });
}

// ─── THREE.JS HOLOGRAPHIC ORB ────────────────────────────
// Decorativo. Solo corre si hay un THREE global (hoy no se vendoriza:
// queda como no-op, igual que en el app.js original).
export function initOrb() {
  const THREE = /** @type {any} */ (window).THREE;
  const canvas = /** @type {HTMLCanvasElement} */ (document.getElementById('threejs-orb'));
  if (!canvas || typeof THREE === 'undefined') return;

  const W = 44, H = 44;
  canvas.width = W; canvas.height = H;

  const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
  renderer.setSize(W, H);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setClearColor(0x000000, 0);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(60, 1, 0.1, 100);
  camera.position.z = 2.2;

  const geo = new THREE.IcosahedronGeometry(0.75, 2);
  const mat = new THREE.MeshBasicMaterial({ color: 0x9141ac, wireframe: true, transparent: true, opacity: 0.7 });
  const sphere = new THREE.Mesh(geo, mat);
  scene.add(sphere);

  const innerGeo = new THREE.SphereGeometry(0.45, 16, 16);
  const innerMat = new THREE.MeshBasicMaterial({ color: 0xc471ed, wireframe: true, transparent: true, opacity: 0.4 });
  const inner = new THREE.Mesh(innerGeo, innerMat);
  scene.add(inner);

  const ringGeo = new THREE.TorusGeometry(0.85, 0.02, 8, 60);
  const ringMat = new THREE.MeshBasicMaterial({ color: 0xff6b9d, transparent: true, opacity: 0.6 });
  const ring = new THREE.Mesh(ringGeo, ringMat);
  ring.rotation.x = Math.PI / 2.5;
  scene.add(ring);

  let t = 0;
  function animate() {
    requestAnimationFrame(animate);
    t += 0.016;
    sphere.rotation.y = t * 0.6;
    sphere.rotation.x = t * 0.2;
    inner.rotation.y = -t * 0.9;
    inner.rotation.z = t * 0.3;
    ring.rotation.z = t * 0.4;
    mat.opacity = 0.5 + Math.sin(t * 2) * 0.2;
    innerMat.opacity = 0.3 + Math.cos(t * 1.5) * 0.15;
    renderer.render(scene, camera);
  }
  animate();
}
