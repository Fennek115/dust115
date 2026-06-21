// APT115 CODEX ARCANUM — Barra de navegación inferior (solo móvil).
// Capa fina sobre los handlers existentes: cada tab abre un destino/panel y nunca
// deja dos paneles abiertos a la vez (evita el solape que hacía la UI inusable en
// el teléfono). El estado "activo" se sincroniza observando las clases del DOM, así
// también se actualiza cuando un panel se cierra con su botón Close ✕ o con Esc.

import { $, $in } from './util.js';
import { toggleSidebarDrawer, closeSidebarDrawer } from './ui.js';
import { toggleFav } from './favs.js';
import { toggleIntel } from './intel.js';
import { toggleNotesPanel } from './notes.js';

// destino → (estado actual abierto?, toggle)
const PANELS = {
  favs: { el: 'favPanel', toggle: toggleFav },
  intel: { el: 'intelPanel', toggle: toggleIntel },
  notes: { el: 'notesPanel', toggle: toggleNotesPanel },
};

function isOpen(dest) {
  if (dest === 'menu') return document.body.classList.contains('sb-drawer-open');
  const p = PANELS[dest];
  return !!(p && $(p.el)?.classList.contains('on'));
}

/** Cierra todo lo que no sea `keep` (drawer + paneles), para no solapar. */
function closeOthers(keep) {
  if (keep !== 'menu') closeSidebarDrawer();
  Object.entries(PANELS).forEach(([dest, p]) => {
    if (dest === keep) return;
    const el = $(p.el);
    if (el?.classList.contains('on')) p.toggle();
  });
}

/** Handler de cada tab de la bottom nav. @param {string} dest */
export function mobileNav(dest) {
  if (dest === 'search') {
    closeOthers(null);
    const main = /** @type {HTMLElement} */ (document.querySelector('.main'));
    main?.scrollTo({ top: 0, behavior: 'smooth' });
    const si = $in('searchInput');
    si?.focus();
    si?.select();
    syncMobileNav();
    return;
  }
  closeOthers(dest);
  // Toca el mismo tab = toggle (los demás ya quedaron cerrados por closeOthers).
  if (dest === 'menu') toggleSidebarDrawer();
  else if (PANELS[dest]) PANELS[dest].toggle();
  syncMobileNav();
}

/** Marca `.on` en el tab cuyo destino está abierto. */
export function syncMobileNav() {
  const nav = $('mBottomNav');
  if (!nav) return;
  nav.querySelectorAll('.m-nav-btn').forEach((btn) => {
    const dest = /** @type {HTMLElement} */ (btn).dataset.dest;
    btn.classList.toggle('on', !!dest && dest !== 'search' && isOpen(dest));
  });
}

/** Arranca el observer de estado y hace un sync inicial. Llamar una vez en el init. */
export function wireMobileNav() {
  syncMobileNav();
  if (typeof MutationObserver === 'undefined') return;
  const targets = ['favPanel', 'intelPanel', 'notesPanel']
    .map((id) => $(id))
    .filter(Boolean);
  const obs = new MutationObserver(syncMobileNav);
  // Cambios de clase en body (sb-drawer-open) y en cada panel (.on).
  obs.observe(document.body, { attributes: true, attributeFilter: ['class'] });
  targets.forEach((el) => obs.observe(/** @type {Node} */ (el), { attributes: true, attributeFilter: ['class'] }));
}
