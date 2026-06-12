// APT115 CODEX ARCANUM — Cheatsheet: favoritos (panel + toggle por fila + export)

import { D } from './data.js';
import { $, $$, escHtml } from './util.js';
import { sub, gv } from './vars.js';
import { favorites, notes, customCmds, saveFavorites, clearFavoritesState } from './state.js';

/**
 * Marca/desmarca favorito desde una fila. `desc` viene del onclick inline
 * (no se usa, se conserva la firma por los callers generados).
 * @param {string} id @param {string} desc @param {HTMLElement} btn
 */
export function toggleFavItem(id, desc, btn) {
  favorites[id] = !favorites[id];
  if (!favorites[id]) delete favorites[id];
  saveFavorites();
  btn.classList.toggle('on');
  const row = $('row_' + id);
  if (row) row.classList.toggle('fav-row', !!favorites[id]);
  updateFavCount();
  renderFavList();
}

export function updateFavCount() {
  $('favCount').textContent = String(Object.keys(favorites).length);
}

export function toggleFav() {
  const p = $('favPanel');
  p.classList.toggle('on');
  if (p.classList.contains('on')) renderFavList();
}

/** Resuelve un id de favorito a su comando (dataset o custom). @param {string} id */
function resolveFav(id) {
  if (id.startsWith('custom_')) {
    const cmd = customCmds.find(c => c.id === id.slice('custom_'.length));
    if (!cmd) return null;
    return { name: cmd.name, body: cmd.body, label: 'My Commands' };
  }
  const parts = id.replace('c_', '').split('_');
  const sec = D.find(x => x.id === parts[0]);
  const cmd = sec?.groups[parseInt(parts[1])]?.c[parseInt(parts[2])];
  if (!sec || !cmd) return null;
  return { name: cmd[0], body: cmd[1], label: sec.label };
}

export function renderFavList() {
  const fl = $('favList');
  const keys = Object.keys(favorites);
  if (!keys.length) { fl.innerHTML = '<div class="empty"><div class="empty-icon">⭐</div>No favorites yet.</div>'; return; }
  let h = '';
  keys.forEach(id => {
    const fav = resolveFav(id);
    if (!fav) return;
    h += `<div class="row fav-row" style="margin-bottom:6px">
      <div class="ri">
        <div class="rd">${escHtml(fav.name)} <span style="color:var(--text3);font-size:10px">${escHtml(fav.label)}</span></div>
        <div class="rc" id="favrc_${id}">${escHtml(sub(fav.body))}</div>
      </div>
      <div class="row-actions">
        <button class="cp" onclick="copyText('favrc_${id}',this)">Copy</button>
        <button class="fav-btn on" onclick="removeFav('${id}')">★</button>
      </div>
    </div>`;
  });
  fl.innerHTML = h;
}

/** @param {string} id */
export function removeFav(id) {
  delete favorites[id];
  saveFavorites();
  // Update fav button in main content if visible
  const row = $('row_' + id);
  if (row) {
    row.classList.remove('fav-row');
    const fb = row.querySelector('.fav-btn');
    if (fb) fb.classList.remove('on');
  }
  updateFavCount();
  renderFavList();
}

export function clearAllFavs() {
  clearFavoritesState();
  $$('.fav-btn.on').forEach(b => b.classList.remove('on'));
  $$('.fav-row').forEach(r => r.classList.remove('fav-row'));
  updateFavCount();
  renderFavList();
}

/** Descarga los favoritos como .txt con variables sustituidas + notas. */
export function exportFavs() {
  const keys = Object.keys(favorites);
  if (!keys.length) { alert('No favorites to export!'); return; }
  let txt = '# APT115 CODEX ARCANUM — Exported Favorites\n# Generated: ' + new Date().toLocaleString() + '\n\n';
  const v = gv();
  txt += '# Variables:\n';
  Object.entries(v).forEach(([k, val]) => { txt += `# ${k} = ${val}\n`; });
  txt += '\n';
  keys.forEach(id => {
    const fav = resolveFav(id);
    if (!fav) return;
    txt += `\n## [${fav.label}] ${fav.name}\n`;
    txt += sub(fav.body) + '\n';
    if (notes[id]) txt += `# Note: ${notes[id]}\n`;
  });
  const blob = new Blob([txt], { type: 'text/plain' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = 'favorites_' + new Date().toISOString().slice(0, 10) + '.txt';
  a.click();
}
