// APT115 CODEX ARCANUM — Cheatsheet: render del sidebar, secciones y filas
// + checklist (done) con sus barras de progreso y export de sección a .txt.

import { D } from './data.js';
import { $, $$, $in, escHtml, mkId, renderTags, getTagBorderClass } from './util.js';
import { sub } from './vars.js';
import { favorites, notes, doneItems, activeNotes, saveDoneItems } from './state.js';

/**
 * Fila de comando (HTML string). Los botones llaman handlers por nombre global
 * (onclick inline) — index.js los cuelga de window.
 * @param {import('./data.js').CmdTuple} cmd @param {string} secId @param {number} gi @param {number} ci
 */
export function renderRow(cmd, secId, gi, ci) {
  const [desc, raw, tags] = [cmd[0], cmd[1], cmd[2] || []];
  const id = mkId(secId, gi, ci);
  const isFav = favorites[id] || false;
  const hasNote = notes[id] && notes[id].trim();
  const isDone = doneItems[id] || false;
  const borderCls = isFav ? ' fav-row' : getTagBorderClass(tags);
  return `<div class="row${borderCls}${isDone ? ' done-row' : ''}" id="row_${id}">
    <div class="ri">
      <div class="rd">${escHtml(desc)} ${renderTags(tags)}</div>
      <div class="rc" id="${id}">${escHtml(sub(raw))}</div>
      ${hasNote ? `<div class="note-display">📝 ${escHtml(notes[id])}</div>` : ''}
      ${activeNotes[id] ? `<textarea class="note-area" id="note_${id}" placeholder="Add note..." onblur="saveNote('${id}')">${escHtml(notes[id] || '')}</textarea>` : ''}
    </div>
    <div class="row-actions">
      <button class="cp" onclick="doCopy(this,'${id}')">Copy</button>
      <button class="cp-1l" onclick="do1Liner(this,'${id}')" title="Copy as one-liner (newlines → semicolons)">1-line</button>
      <button class="fav-btn${isFav ? ' on' : ''}" onclick="toggleFavItem('${id}','${escHtml(desc).replace(/'/g, "\\'")}',this)" title="Favorite">★</button>
      <button class="note-btn${hasNote ? ' has-note' : ''}" onclick="toggleNote('${id}')" title="Note">📝</button>
      <button class="done-btn${isDone ? ' on' : ''}" onclick="toggleDone('${id}')" title="Mark done">✔</button>
    </div>
  </div>`;
}

export function buildSidebar() {
  const sb = $('sidebar');
  /** @type {Record<string, import('./data.js').Section[]>} */
  const groups = {};
  D.forEach(s => { if (!groups[s.group]) groups[s.group] = []; groups[s.group].push(s); });
  let h = '';
  Object.entries(groups).forEach(([g, items]) => {
    h += `<div class="sg">${g}</div>`;
    items.forEach(s => {
      const total = s.groups.reduce((a, g) => a + g.c.length, 0);
      h += `<div class="si${D[0].id === s.id ? ' on' : ''}" data-id="${s.id}" title="${s.label}">
        <span class="si-icon">${s.icon || ''}</span>
        <span class="si-label">${s.label}</span>
        <span class="cnt">${total}</span>
      </div>
      <div class="si-prog"><div class="si-prog-bar" id="siprog_${s.id}"></div></div>`;
    });
  });
  // Insert after sb-top
  sb.querySelector('.sb-top').insertAdjacentHTML('afterend', h);
  $$('.si', sb).forEach(el => {
    el.onclick = () => {
      $$('.si').forEach(x => x.classList.remove('on'));
      $$('.sec').forEach(x => x.classList.remove('on'));
      el.classList.add('on');
      $('s-' + el.dataset.id).classList.add('on');
      $('searchResults').classList.remove('on');
      $in('searchInput').value = '';
    };
  });
}

/** Cuerpo de una sección (header + grupos colapsables + filas). @param {import('./data.js').Section} s */
function sectionInnerHtml(s) {
  const totalCmds = s.groups.reduce((a, g) => a + g.c.length, 0);
  let html = `<div class="sec-hdr">
    <div class="sec-title">${s.icon || ''} ${s.label}</div>
    <span class="sec-cmds-badge">${totalCmds} commands</span>
    <button class="sec-export" onclick="exportSection('${s.id}')">↓ Export</button>
  </div>`;
  s.groups.forEach((g, gi) => {
    const grpId = `grp_${s.id}_${gi}`;
    html += `<div class="grp" id="${grpId}">
      <div class="grp-title" onclick="toggleGrp('${grpId}')">
        ${escHtml(g.t)} <span style="color:var(--text3);font-weight:400;text-transform:none;letter-spacing:0">(${g.c.length})</span>
        <span class="collapse-icon">▾</span>
      </div>
      <div class="grp-progress"><div class="grp-progress-bar" id="prg_${grpId}"></div></div>
      <div class="grp-body" id="body_${grpId}">`;
    g.c.forEach((cmd, ci) => { html += renderRow(cmd, s.id, gi, ci); });
    html += '</div></div>';
  });
  return html;
}

export function buildSections() {
  const cont = $('sections');
  let html = '';
  D.forEach((s, si) => {
    html += `<div id="s-${s.id}" class="sec${si === 0 ? ' on' : ''}">` + sectionInnerHtml(s) + '</div>';
  });
  cont.innerHTML = html;
  updateAllProgressBars();
}

/** Re-renderiza una sección en el lugar (helper de consola; sin llamadores en la UI). @param {string} secId */
export function refreshSection(secId) {
  const secData = D.find(x => x.id === secId);
  if (!secData) return;
  const el = $('s-' + secId);
  if (!el) return;
  el.innerHTML = sectionInnerHtml(secData);
  updateAllProgressBars();
}

// ─── DONE / CHECKLIST ────────────────────────────────────
/** @param {string} id */
export function toggleDone(id) {
  const row = $('row_' + id);
  const btn = row?.querySelector('.done-btn');
  if (doneItems[id]) {
    delete doneItems[id];
    row?.classList.remove('done-row');
    btn?.classList.remove('on');
  } else {
    doneItems[id] = true;
    row?.classList.add('done-row');
    btn?.classList.add('on');
  }
  saveDoneItems();
  updateAllProgressBars();
}

// ─── COLLAPSIBLE GROUPS ──────────────────────────────────
/** @param {string} grpId */
export function toggleGrp(grpId) {
  const title = document.querySelector(`#${grpId} .grp-title`);
  const body = $('body_' + grpId);
  if (!body) return;
  const collapsed = body.classList.toggle('collapsed');
  title?.classList.toggle('collapsed', collapsed);
}

// ─── PROGRESS BARS ───────────────────────────────────────
export function updateAllProgressBars() {
  D.forEach((s) => {
    let secDone = 0, secTotal = 0;
    s.groups.forEach((g, gi) => {
      const grpId = `grp_${s.id}_${gi}`;
      const bar = $('prg_' + grpId);
      const total = g.c.length;
      const done = g.c.filter((_, ci) => doneItems[mkId(s.id, gi, ci)]).length;
      if (bar) bar.style.width = total ? (done / total * 100) + '%' : '0%';
      secDone += done; secTotal += total;
    });
    // Update sidebar progress bar
    const sb = $('siprog_' + s.id);
    if (sb) sb.style.width = secTotal ? (secDone / secTotal * 100) + '%' : '0%';
  });
  const totalDone = Object.keys(doneItems).length;
  const totalCmds = D.reduce((a, s) => a + s.groups.reduce((b, g) => b + g.c.length, 0), 0);
  const el = $('globalProgress');
  if (el) el.textContent = `✔ ${totalDone}/${totalCmds}`;
}

// ─── EXPORT SECTION ──────────────────────────────────────
/** Descarga la sección como .txt con las variables ya sustituidas. @param {string} secId */
export function exportSection(secId) {
  const s = D.find(x => x.id === secId);
  if (!s) return;
  let txt = `# ${s.label} — APT115 CODEX ARCANUM\n# Exported: ${new Date().toLocaleString()}\n\n`;
  s.groups.forEach(g => {
    txt += `\n## ${g.t}\n`;
    g.c.forEach(cmd => {
      txt += `\n### ${cmd[0]}\n${sub(cmd[1])}\n`;
    });
  });
  const blob = new Blob([txt], { type: 'text/plain' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = `${secId}_${new Date().toISOString().slice(0, 10)}.txt`;
  a.click();
}
