// APT115 CODEX ARCANUM — Cheatsheet: comandos custom del usuario
// Sección "My Commands" + modal de alta/edición. Persisten en cs_custom.

import { $, $in, escHtml, renderTags } from './util.js';
import { sub } from './vars.js';
import { favorites, notes, customCmds, saveCustomCmds, setCustomCmds } from './state.js';

const TAG_IDS = ['crit', 'high', 'med', 'osep', 'new'];

const CAT_NAMES = {
  custom: 'My Commands', recon: 'Recon', web: 'Web Attacks', api: 'API Attacks',
  shells: 'Shells', lpe: 'Linux PrivEsc', wpe: 'Windows PrivEsc', adrecon: 'AD Recon',
  adatk: 'AD Attacks', adlat: 'AD Lateral', adpst: 'Persistence', evasion: 'Evasion / OPSEC',
  inject: 'Injection', c2: 'C2 Frameworks', tunnel: 'Tunneling', transfer: 'File Transfer',
  crack: 'Hash Cracking', misc: 'Misc / Snippets'
};

/** Abre el modal; con editId precarga el comando a editar. @param {string} [editId] */
export function openCustomModal(editId) {
  const m = $('customModal');
  $in('editingId').value = editId || '';
  $('modalTitleText').textContent = editId ? 'Edit Command' : 'Add Custom Command';
  if (editId) {
    const cmd = customCmds.find(c => c.id === editId);
    if (cmd) {
      $in('cmdName').value = cmd.name;
      $in('cmdCategory').value = cmd.category || 'custom';
      $in('cmdBody').value = cmd.body;
      TAG_IDS.forEach(t => {
        $in('t_' + t).checked = (cmd.tags || []).includes(t);
      });
    }
  } else {
    $in('cmdName').value = '';
    $in('cmdCategory').value = 'custom';
    $in('cmdBody').value = '';
    TAG_IDS.forEach(t => { $in('t_' + t).checked = false; });
  }
  m.classList.add('on');
  setTimeout(() => $in('cmdName').focus(), 100);
}

export function closeCustomModal() {
  $('customModal').classList.remove('on');
}

/** Cierra el modal al clickear el fondo. Llamar una vez desde el init. */
export function wireCustomModal() {
  const m = $('customModal');
  m.addEventListener('click', e => {
    if (e.target === m) closeCustomModal();
  });
}

export function saveCustomCommand() {
  const name = $in('cmdName').value.trim();
  const body = $in('cmdBody').value.trim();
  if (!name) { $in('cmdName').focus(); return; }
  if (!body) { $in('cmdBody').focus(); return; }
  const tags = TAG_IDS.filter(t => $in('t_' + t).checked);
  const category = $in('cmdCategory').value;
  const editId = $in('editingId').value;
  if (editId) {
    const idx = customCmds.findIndex(c => c.id === editId);
    if (idx > -1) customCmds[idx] = { ...customCmds[idx], name, body, category, tags };
  } else {
    customCmds.push({ id: 'cust_' + Date.now(), name, body, category, tags, createdAt: new Date().toISOString() });
  }
  saveCustomCmds();
  closeCustomModal();
  rebuildCustomSection();
  updateCustomCount();
}

/** @param {string} id */
export function deleteCustomCmd(id) {
  if (!confirm('Delete this custom command?')) return;
  setCustomCmds(customCmds.filter(c => c.id !== id));
  rebuildCustomSection();
  updateCustomCount();
}

/** @param {import('./state.js').CustomCmd} cmd */
function renderCustomRow(cmd) {
  const isFav = favorites['custom_' + cmd.id];
  const hasNote = notes['custom_' + cmd.id] && notes['custom_' + cmd.id].trim();
  const subbed = sub(cmd.body);
  return `<div class="row${isFav ? ' fav-row' : ''}" id="crow_${cmd.id}">
    <div class="ri">
      <div class="rd">${escHtml(cmd.name)} <span class="custom-badge">CUSTOM</span> ${renderTags(cmd.tags || [])}</div>
      <div class="rc" id="custom_${cmd.id}">${escHtml(subbed)}</div>
      ${hasNote ? `<div class="note-display">📝 ${escHtml(notes['custom_' + cmd.id])}</div>` : ''}
    </div>
    <div class="row-actions">
      <button class="cp" onclick="doCopyCustom(this,'custom_${cmd.id}')">Copy</button>
      <button class="fav-btn${isFav ? ' on' : ''}" onclick="toggleFavItem('custom_${cmd.id}','${escHtml(cmd.name)}',this)" title="Favorite">★</button>
      <button class="edit-btn" onclick="openCustomModal('${cmd.id}')" title="Edit">✏</button>
      <button class="del-btn" onclick="deleteCustomCmd('${cmd.id}')" title="Delete">🗑</button>
    </div>
  </div>`;
}

export function rebuildCustomSection() {
  const el = $('s-custom');
  if (!el) return;
  let html = `<div class="sec-hdr"><div class="sec-title">⚙ My Commands</div></div>
  <div style="margin-bottom:12px">
    <button class="hdr-btn custom-btn" onclick="openCustomModal()" style="font-size:11px;padding:5px 12px">➕ Add New Command</button>
  </div>`;
  if (!customCmds.length) {
    html += '<div class="empty"><div class="empty-icon">⚙</div>No custom commands yet.<br>Click "Add Command" in the header to create one.</div>';
  } else {
    // Group by category
    /** @type {Record<string, import('./state.js').CustomCmd[]>} */
    const cats = {};
    customCmds.forEach(c => {
      const k = c.category || 'custom';
      if (!cats[k]) cats[k] = [];
      cats[k].push(c);
    });
    Object.entries(cats).forEach(([cat, cmds]) => {
      html += `<div class="grp"><div class="grp-title">${CAT_NAMES[cat] || cat} <span style="color:var(--text3);font-weight:400;text-transform:none;letter-spacing:0">(${cmds.length})</span></div>`;
      cmds.forEach(cmd => { html += renderCustomRow(cmd); });
      html += '</div>';
    });
  }
  el.innerHTML = html;
  updateCustomCount();
}

export function buildCustomSection() {
  const cont = $('sections');
  const div = document.createElement('div');
  div.id = 's-custom';
  div.className = 'sec';
  cont.appendChild(div);
  rebuildCustomSection();
}

export function addCustomSidebarItem() {
  const sb = $('sidebar');
  const sg = document.createElement('div');
  sg.className = 'sg';
  sg.textContent = 'Custom';
  const si = document.createElement('div');
  si.className = 'si';
  si.dataset.id = 'custom';
  si.innerHTML = '⚙ My Commands <span class="cnt" id="customCount">0</span>';
  sb.appendChild(sg);
  sb.appendChild(si);
  si.onclick = () => {
    document.querySelectorAll('.si').forEach(x => x.classList.remove('on'));
    document.querySelectorAll('.sec').forEach(x => x.classList.remove('on'));
    si.classList.add('on');
    $('s-custom').classList.add('on');
    $('searchResults').classList.remove('on');
    $in('searchInput').value = '';
  };
}

export function updateCustomCount() {
  const el = $('customCount');
  if (el) el.textContent = String(customCmds.length);
}

/** Re-sustituye las variables en las filas custom visibles. */
export function refreshCustomCmds() {
  document.querySelectorAll('[id^="custom_cust_"]').forEach(el => {
    const cmdId = el.id.replace('custom_', '');
    const cmd = customCmds.find(c => c.id === cmdId);
    if (cmd) el.textContent = sub(cmd.body);
  });
}
