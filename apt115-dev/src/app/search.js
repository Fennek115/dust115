// APT115 CODEX ARCANUM — Cheatsheet: búsqueda global + refresco de comandos

import { D } from './data.js';
import { $, $in, escHtml, mkId, renderTags } from './util.js';
import { sub } from './vars.js';
import { favorites, notes, customCmds } from './state.js';

/** Cablea el input de búsqueda (debounce 200 ms). Llamar una vez desde el init. */
export function wireSearch() {
  let searchTimeout = 0;
  const si = $in('searchInput');
  si.addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => doSearch(si.value.trim()), 200);
  });
}

/** Busca en dataset + comandos custom; muestra resultados sobre las secciones. @param {string} q */
export function doSearch(q) {
  const sr = $('searchResults');
  const secs = $('sections');
  if (!q) {
    sr.classList.remove('on'); sr.innerHTML = '';
    secs.style.display = ''; return;
  }
  secs.style.display = 'none';
  sr.classList.add('on');
  const ql = q.toLowerCase();
  /** @type {{ s: import('./data.js').Section, g: import('./data.js').CmdGroup, gi: number, cmd: import('./data.js').CmdTuple, ci: number }[]} */
  const results = [];
  D.forEach(s => {
    s.groups.forEach((g, gi) => {
      g.c.forEach((cmd, ci) => {
        if ((cmd[0] + ' ' + cmd[1]).toLowerCase().includes(ql))
          results.push({ s, g, gi, cmd, ci });
      });
    });
  });

  // Also search user-defined custom commands
  const customResults = customCmds.filter(c =>
    (c.name + ' ' + c.body).toLowerCase().includes(ql));

  // Safe highlight: escape raw string first, then wrap match
  /** @param {string} raw */
  function hl(raw) {
    const escaped = escHtml(raw);
    const safeQ = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`(${safeQ})`, 'gi');
    return escaped.replace(re, '<span class="hl">$1</span>');
  }

  const totalResults = results.length + customResults.length;
  let h = `<div class="sr-count">Found <span>${totalResults}</span> result${totalResults !== 1 ? 's' : ''} for "<b>${escHtml(q)}</b>"</div>`;
  if (!totalResults) h += '<div class="empty"><div class="empty-icon">🔍</div>No commands match.</div>';
  results.forEach(({ s, g, gi, cmd, ci }) => {
    const id = mkId(s.id, gi, ci);
    const isFav = favorites[id]; const hasNote = notes[id];
    h += `<div class="row${isFav ? ' fav-row' : ''}">
      <div class="ri">
        <div class="rd">${hl(cmd[0])} <span style="color:var(--text3);font-size:10px">${s.icon || ''} ${escHtml(s.label)} › ${escHtml(g.t)}</span> ${renderTags(cmd[2] || [])}</div>
        <div class="rc" id="sr_${id}">${hl(sub(cmd[1]))}</div>
        ${hasNote ? `<div class="note-display">📝 ${escHtml(notes[id])}</div>` : ''}
      </div>
      <div class="row-actions">
        <button class="cp" onclick="copyText('sr_${id}',this)">Copy</button>
        <button class="fav-btn${isFav ? ' on' : ''}" onclick="toggleFavItem('${id}','${escHtml(cmd[0]).replace(/'/g, "\\'")}',this)">★</button>
      </div>
    </div>`;
  });
  customResults.forEach(cmd => {
    const cid = 'custom_' + cmd.id;
    const isFav = favorites[cid]; const hasNote = notes[cid];
    h += `<div class="row${isFav ? ' fav-row' : ''}">
      <div class="ri">
        <div class="rd">${hl(cmd.name)} <span class="custom-badge">CUSTOM</span> ${renderTags(cmd.tags || [])}</div>
        <div class="rc" id="sr_${cid}">${hl(sub(cmd.body))}</div>
        ${hasNote ? `<div class="note-display">📝 ${escHtml(notes[cid])}</div>` : ''}
      </div>
      <div class="row-actions">
        <button class="cp" onclick="copyText('sr_${cid}',this)">Copy</button>
        <button class="fav-btn${isFav ? ' on' : ''}" onclick="toggleFavItem('${cid}','${escHtml(cmd.name).replace(/'/g, "\\'")}',this)">★</button>
      </div>
    </div>`;
  });
  sr.innerHTML = h;
}

/** Re-sustituye las variables en todas las filas visibles del dataset (tras editar la barra). */
export function refreshAllCmds() {
  document.querySelectorAll('.rc').forEach(el => {
    const id = el.id;
    if (!id || !id.startsWith('c_')) return;
    const parts = id.replace('c_', '').split('_');
    const sec = D.find(x => x.id === parts[0]);
    if (!sec) return;
    const cmd = sec.groups[parseInt(parts[1])]?.c[parseInt(parts[2])];
    if (!cmd) return;
    el.textContent = sub(cmd[1]);
  });
  const q = $in('searchInput').value.trim();
  if (q) doSearch(q);
}
