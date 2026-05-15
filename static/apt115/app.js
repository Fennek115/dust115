// APT115 CODEX ARCANUM — Core Logic
// solve et coagula

const D = [...CORE_DATA, ...MITRE_DATA, ...INTEL_DATA];

// ═══════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════
let favorites = JSON.parse(localStorage.getItem('cs_favs') || '{}');
let notes = JSON.parse(localStorage.getItem('cs_notes') || '{}');
let copyHistory = JSON.parse(localStorage.getItem('cs_hist') || '[]');
let doneItems = JSON.parse(localStorage.getItem('cs_done') || '{}');
let activeNotes = {};

function gv() {
  return {
    LHOST: document.getElementById('lhost').value,
    RHOST: document.getElementById('rhost').value,
    LPORT: document.getElementById('lport').value,
    RPORT: document.getElementById('rport').value,
    DOMAIN: document.getElementById('domain').value,
    DC: document.getElementById('dc').value,
    USER: document.getElementById('user').value,
    PASS: document.getElementById('pass').value,
    HASH: document.getElementById('hash').value,
    URL: document.getElementById('url').value,
  };
}

function sub(s) {
  const v = gv();
  return s.replace(/\{(\w+)\}/g, (m, k) => v[k] !== undefined ? v[k] : m);
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function mkId(secId, gi, ci) { return `c_${secId}_${gi}_${ci}`; }

function renderTags(tags) {
  if (!tags || !tags.length) return '';
  return tags.map(t => {
    if (t === 'crit') return '<span class="tag tag-crit">CRITICAL</span>';
    if (t === 'high') return '<span class="tag tag-high">HIGH</span>';
    if (t === 'med') return '<span class="tag tag-med">MEDIUM</span>';
    if (t === 'osep') return '<span class="tag tag-osep">OSEP</span>';
    if (t === 'new') return '<span class="tag tag-new">NEW</span>';
    return '';
  }).join('');
}

function getTagBorderClass(tags) {
  if (!tags || !tags.length) return '';
  if (tags.includes('crit')) return ' tag-crit-row';
  if (tags.includes('high')) return ' tag-high-row';
  if (tags.includes('osep')) return ' tag-osep-row';
  if (tags.includes('med')) return ' tag-med-row';
  return '';
}

function renderRow(cmd, secId, gi, ci) {
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
      <button class="fav-btn${isFav ? ' on' : ''}" onclick="toggleFavItem('${id}','${escHtml(desc).replace(/'/g,"\\'")}',this)" title="Favorite">★</button>
      <button class="note-btn${hasNote ? ' has-note' : ''}" onclick="toggleNote('${id}')" title="Note">📝</button>
      <button class="done-btn${isDone ? ' on' : ''}" onclick="toggleDone('${id}')" title="Mark done">✔</button>
    </div>
  </div>`;
}

function buildSidebar() {
  const sb = document.getElementById('sidebar');
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
  sb.querySelectorAll('.si').forEach(el => {
    el.onclick = () => {
      document.querySelectorAll('.si').forEach(x => x.classList.remove('on'));
      document.querySelectorAll('.sec').forEach(x => x.classList.remove('on'));
      el.classList.add('on');
      document.getElementById('s-' + el.dataset.id).classList.add('on');
      document.getElementById('searchResults').classList.remove('on');
      document.getElementById('searchInput').value = '';
    };
  });
}

function buildSections() {
  const cont = document.getElementById('sections');
  let html = '';
  D.forEach((s, si) => {
    const totalCmds = s.groups.reduce((a,g)=>a+g.c.length,0);
    html += `<div id="s-${s.id}" class="sec${si === 0 ? ' on' : ''}">`;
    html += `<div class="sec-hdr">
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
    html += '</div>';
  });
  cont.innerHTML = html;
  updateAllProgressBars();
}

function refreshSection(secId) {
  const secData = D.find(x => x.id === secId);
  if (!secData) return;
  const el = document.getElementById('s-' + secId);
  if (!el) return;
  const totalCmds = secData.groups.reduce((a,g)=>a+g.c.length,0);
  let html = `<div class="sec-hdr">
    <div class="sec-title">${secData.icon||''} ${secData.label}</div>
    <span class="sec-cmds-badge">${totalCmds} cmds</span>
    <button class="sec-export" onclick="exportSection('${secData.id}')">↓ Export</button>
  </div>`;
  secData.groups.forEach((g, gi) => {
    const grpId = `grp_${secData.id}_${gi}`;
    html += `<div class="grp" id="${grpId}">
      <div class="grp-title" onclick="toggleGrp('${grpId}')">
        ${escHtml(g.t)} <span style="color:var(--text3);font-weight:400;text-transform:none;letter-spacing:0">(${g.c.length})</span>
        <span class="collapse-icon">▾</span>
      </div>
      <div class="grp-progress"><div class="grp-progress-bar" id="prg_${grpId}"></div></div>
      <div class="grp-body" id="body_${grpId}">`;
    g.c.forEach((cmd, ci) => { html += renderRow(cmd, secData.id, gi, ci); });
    html += '</div></div>';
  });
  el.innerHTML = html;
  updateAllProgressBars();
}

function showToast(msg) {
  const t = document.getElementById('copyToast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(t._tid);
  t._tid = setTimeout(() => t.classList.remove('show'), 1800);
}

function copyToClipboard(text) {
  try { navigator.clipboard.writeText(text); return; } catch(e) {}
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  document.execCommand('copy'); document.body.removeChild(ta);
}

function doCopy(btn, id) {
  const el = document.getElementById(id);
  if (!el) return;
  const txt = el.textContent;
  copyToClipboard(txt);
  btn.textContent = '✓';
  btn.classList.add('ok');
  setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('ok'); }, 1500);
  showToast('✓ Copied to clipboard');
  const ts = new Date().toLocaleTimeString();
  copyHistory.unshift({ t: ts, c: txt.slice(0, 120) + (txt.length > 120 ? '…' : '') });
  if (copyHistory.length > 20) copyHistory.pop();
  localStorage.setItem('cs_hist', JSON.stringify(copyHistory));
  renderHistory();
}

function do1Liner(btn, id) {
  const el = document.getElementById(id);
  if (!el) return;
  const txt = el.textContent
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'))
    .join(' ; ');
  copyToClipboard(txt);
  btn.textContent = '✓';
  btn.classList.add('ok');
  setTimeout(() => { btn.textContent = '1-line'; btn.classList.remove('ok'); }, 1500);
  showToast('✓ Copied as 1-liner');
}

function toggleFavItem(id, desc, btn) {
  favorites[id] = !favorites[id];
  if (!favorites[id]) delete favorites[id];
  localStorage.setItem('cs_favs', JSON.stringify(favorites));
  btn.classList.toggle('on');
  const row = document.getElementById('row_' + id);
  if (row) row.classList.toggle('fav-row', !!favorites[id]);
  updateFavCount();
  renderFavList();
}

function updateFavCount() {
  document.getElementById('favCount').textContent = Object.keys(favorites).length;
}

function toggleFav() {
  const p = document.getElementById('favPanel');
  p.classList.toggle('on');
  if (p.classList.contains('on')) renderFavList();
}

function renderFavList() {
  const fl = document.getElementById('favList');
  const keys = Object.keys(favorites);
  if (!keys.length) { fl.innerHTML = '<div class="empty"><div class="empty-icon">⭐</div>No favorites yet.</div>'; return; }
  let h = '';
  keys.forEach(id => {
    const parts = id.replace('c_','').split('_');
    const secId = parts[0]; const gi = parseInt(parts[1]); const ci = parseInt(parts[2]);
    const sec = D.find(x => x.id === secId);
    if (!sec || !sec.groups[gi] || !sec.groups[gi].c[ci]) return;
    const cmd = sec.groups[gi].c[ci];
    h += `<div class="row fav-row" style="margin-bottom:6px">
      <div class="ri">
        <div class="rd">${escHtml(cmd[0])} <span style="color:var(--text3);font-size:10px">${sec.label}</span></div>
        <div class="rc">${escHtml(sub(cmd[1]))}</div>
      </div>
      <div class="row-actions">
        <button class="cp" onclick="doCopy(this,'fav_c_${id}');document.getElementById('fav_c_${id}').textContent=document.getElementById('${id}').textContent" style="display:none">-</button>
        <button class="cp" onclick="copyText('${id}')">Copy</button>
        <button class="fav-btn on" onclick="removeFav('${id}')">★</button>
      </div>
    </div>`;
  });
  fl.innerHTML = h;
}

function copyText(id, btn) {
  const el = document.getElementById(id);
  if (!el) return;
  copyToClipboard(el.textContent);
  showToast('✓ Copied to clipboard');
  if (btn) { btn.textContent = '✓'; btn.classList.add('ok'); setTimeout(()=>{btn.textContent='Copy';btn.classList.remove('ok');},1500); }
}

function doCopyCustom(btn, id) {
  const el = document.getElementById(id);
  if (!el) return;
  const txt = el.textContent;
  copyToClipboard(txt);
  btn.textContent = '✓';
  btn.classList.add('ok');
  setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('ok'); }, 1500);
  showToast('✓ Copied to clipboard');
  const ts = new Date().toLocaleTimeString();
  copyHistory.unshift({ t: ts, c: txt.slice(0, 120) + (txt.length > 120 ? '…' : '') });
  if (copyHistory.length > 20) copyHistory.pop();
  localStorage.setItem('cs_hist', JSON.stringify(copyHistory));
  renderHistory();
}

function removeFav(id) {
  delete favorites[id];
  localStorage.setItem('cs_favs', JSON.stringify(favorites));
  // Update fav button in main content if visible
  const row = document.getElementById('row_' + id);
  if (row) {
    row.classList.remove('fav-row');
    const fb = row.querySelector('.fav-btn');
    if (fb) fb.classList.remove('on');
  }
  updateFavCount();
  renderFavList();
}

function clearAllFavs() {
  favorites = {};
  localStorage.setItem('cs_favs', JSON.stringify(favorites));
  document.querySelectorAll('.fav-btn.on').forEach(b => b.classList.remove('on'));
  document.querySelectorAll('.fav-row').forEach(r => r.classList.remove('fav-row'));
  updateFavCount();
  renderFavList();
}

function toggleNote(id) {
  if (activeNotes[id]) {
    delete activeNotes[id];
  } else {
    activeNotes[id] = true;
  }
  // Re-render just that row
  D.forEach(s => {
    s.groups.forEach((g, gi) => {
      g.c.forEach((cmd, ci) => {
        const rid = mkId(s.id, gi, ci);
        if (rid === id) {
          const row = document.getElementById('row_' + id);
          if (row) row.outerHTML = renderRow(cmd, s.id, gi, ci);
          if (activeNotes[id]) {
            setTimeout(() => { const ta = document.getElementById('note_' + id); if(ta) ta.focus(); }, 50);
          }
        }
      });
    });
  });
}

function saveNote(id) {
  const ta = document.getElementById('note_' + id);
  if (!ta) return;
  const val = ta.value.trim();
  if (val) notes[id] = val; else delete notes[id];
  localStorage.setItem('cs_notes', JSON.stringify(notes));
  delete activeNotes[id];
  D.forEach(s => {
    s.groups.forEach((g, gi) => {
      g.c.forEach((cmd, ci) => {
        if (mkId(s.id, gi, ci) === id) {
          const row = document.getElementById('row_' + id);
          if (row) row.outerHTML = renderRow(cmd, s.id, gi, ci);
        }
      });
    });
  });
}

function toggleHistory() {
  const p = document.getElementById('histPanel');
  p.classList.toggle('on');
  if (p.classList.contains('on')) renderHistory();
}

function toggleShortcuts() {
  document.getElementById('shortcutPanel').classList.toggle('on');
}

// ─── DONE / CHECKLIST ────────────────────────────────────
function toggleDone(id) {
  const row = document.getElementById('row_' + id);
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
  localStorage.setItem('cs_done', JSON.stringify(doneItems));
  updateAllProgressBars();
}

// ─── COLLAPSIBLE GROUPS ──────────────────────────────────
function toggleGrp(grpId) {
  const title = document.querySelector(`#${grpId} .grp-title`);
  const body = document.getElementById('body_' + grpId);
  if (!body) return;
  const collapsed = body.classList.toggle('collapsed');
  title?.classList.toggle('collapsed', collapsed);
}

// ─── PROGRESS BARS ───────────────────────────────────────
function updateAllProgressBars() {
  D.forEach((s) => {
    let secDone = 0, secTotal = 0;
    s.groups.forEach((g, gi) => {
      const grpId = `grp_${s.id}_${gi}`;
      const bar = document.getElementById('prg_' + grpId);
      const total = g.c.length;
      const done = g.c.filter((_, ci) => doneItems[mkId(s.id, gi, ci)]).length;
      if (bar) bar.style.width = total ? (done / total * 100) + '%' : '0%';
      secDone += done; secTotal += total;
    });
    // Update sidebar progress bar
    const sb = document.getElementById('siprog_' + s.id);
    if (sb) sb.style.width = secTotal ? (secDone / secTotal * 100) + '%' : '0%';
  });
  const totalDone = Object.keys(doneItems).length;
  const totalCmds = D.reduce((a, s) => a + s.groups.reduce((b, g) => b + g.c.length, 0), 0);
  const el = document.getElementById('globalProgress');
  if (el) el.textContent = `✔ ${totalDone}/${totalCmds}`;
}

// ─── EXPORT SECTION ──────────────────────────────────────
function exportSection(secId) {
  const s = D.find(x => x.id === secId);
  if (!s) return;
  const v = gv();
  let txt = `# ${s.label} — APT115 CODEX ARCANUM\n# Exported: ${new Date().toLocaleString()}\n\n`;
  s.groups.forEach(g => {
    txt += `\n## ${g.t}\n`;
    g.c.forEach(cmd => {
      txt += `\n### ${cmd[0]}\n${sub(cmd[1])}\n`;
    });
  });
  const blob = new Blob([txt], {type:'text/plain'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = `${secId}_${new Date().toISOString().slice(0,10)}.txt`;
  a.click();
}

function renderHistory() {
  const hl = document.getElementById('histList');
  if (!copyHistory.length) { hl.innerHTML = '<div style="color:var(--text3);font-size:11px">No history yet.</div>'; return; }
  hl.innerHTML = copyHistory.map(h => `<div class="hist-item"><span class="hist-time">${h.t}</span><span style="flex:1;font-size:11px;color:var(--code)">${escHtml(h.c)}</span></div>`).join('');
}

function clearHistory() {
  copyHistory = [];
  localStorage.setItem('cs_hist', JSON.stringify(copyHistory));
  renderHistory();
}

function exportFavs() {
  const keys = Object.keys(favorites);
  if (!keys.length) { alert('No favorites to export!'); return; }
  let txt = '# APT115 CODEX ARCANUM — Exported Favorites\n# Generated: ' + new Date().toLocaleString() + '\n\n';
  const v = gv();
  txt += '# Variables:\n';
  Object.entries(v).forEach(([k,val]) => { txt += `# ${k} = ${val}\n`; });
  txt += '\n';
  keys.forEach(id => {
    const parts = id.replace('c_','').split('_');
    const sec = D.find(x => x.id === parts[0]);
    if (!sec) return;
    const cmd = sec.groups[parseInt(parts[1])]?.c[parseInt(parts[2])];
    if (!cmd) return;
    txt += `\n## [${sec.label}] ${cmd[0]}\n`;
    txt += sub(cmd[1]) + '\n';
    if (notes[id]) txt += `# Note: ${notes[id]}\n`;
  });
  const blob = new Blob([txt], {type:'text/plain'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = 'favorites_' + new Date().toISOString().slice(0,10) + '.txt';
  a.click();
}

// ─── SEARCH ──────────────────────────────────────────────
let searchTimeout;
document.getElementById('searchInput').addEventListener('input', function() {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => doSearch(this.value.trim()), 200);
});

function doSearch(q) {
  const sr = document.getElementById('searchResults');
  const secs = document.getElementById('sections');
  if (!q) {
    sr.classList.remove('on'); sr.innerHTML = '';
    secs.style.display = ''; return;
  }
  secs.style.display = 'none';
  sr.classList.add('on');
  const ql = q.toLowerCase();
  const results = [];
  D.forEach(s => {
    s.groups.forEach((g, gi) => {
      g.c.forEach((cmd, ci) => {
        if ((cmd[0] + ' ' + cmd[1]).toLowerCase().includes(ql))
          results.push({s, g, gi, cmd, ci});
      });
    });
  });

  // Safe highlight: escape raw string first, then wrap match
  function hl(raw) {
    const escaped = escHtml(raw);
    const safeQ = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`(${safeQ})`, 'gi');
    return escaped.replace(re, '<span class="hl">$1</span>');
  }

  let h = `<div class="sr-count">Found <span>${results.length}</span> result${results.length !== 1 ? 's' : ''} for "<b>${escHtml(q)}</b>"</div>`;
  if (!results.length) h += '<div class="empty"><div class="empty-icon">🔍</div>No commands match.</div>';
  results.forEach(({s, g, gi, cmd, ci}) => {
    const id = mkId(s.id, gi, ci);
    const isFav = favorites[id]; const hasNote = notes[id];
    h += `<div class="row${isFav ? ' fav-row' : ''}">
      <div class="ri">
        <div class="rd">${hl(cmd[0])} <span style="color:var(--text3);font-size:10px">${s.icon||''} ${escHtml(s.label)} › ${escHtml(g.t)}</span> ${renderTags(cmd[2]||[])}</div>
        <div class="rc" id="sr_${id}">${hl(sub(cmd[1]))}</div>
        ${hasNote ? `<div class="note-display">📝 ${escHtml(notes[id])}</div>` : ''}
      </div>
      <div class="row-actions">
        <button class="cp" onclick="copyText('sr_${id}',this)">Copy</button>
        <button class="fav-btn${isFav ? ' on' : ''}" onclick="toggleFavItem('${id}','${escHtml(cmd[0]).replace(/'/g,"\\'")}',this)">★</button>
      </div>
    </div>`;
  });
  sr.innerHTML = h;
}

// ─── VARS DEFAULTS ─────────────────────────────────────────
const VARS_DEFAULTS = {lhost:'10.10.14.1',rhost:'10.10.10.10',lport:'4444',rport:'9001',domain:'corp.local',dc:'192.168.1.10',user:'john',pass:'Password123',hash:'NTLM_HASH_HERE',url:'http://10.10.10.10'};

function resetVars() {
  Object.entries(VARS_DEFAULTS).forEach(([id, val]) => {
    const el = document.getElementById(id);
    if (el) { el.value = val; el.classList.remove('modified'); }
  });
  refreshAllCmds();
}

function toggleVarsBar() {
  const bar = document.getElementById('varsBar');
  const col = document.getElementById('varsCollapsedBar');
  const btn = document.getElementById('varToggleBtn');
  const isOpen = !bar.classList.contains('collapsed');
  bar.classList.toggle('collapsed', isOpen);
  col.classList.toggle('on', isOpen);
  if (btn) btn.textContent = isOpen ? '▼ Show' : '▲ Hide';
  localStorage.setItem('cs_varsOpen', isOpen ? '0' : '1');
}

function toggleSidebar() {
  const sb = document.getElementById('sidebar');
  const btn = document.getElementById('sbCollapseBtn');
  const hist = document.getElementById('histPanel');
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

// ─── KEYBOARD SHORTCUTS ────────────────────────────────────
// Single unified keydown handler (fix: was duplicated)
document.addEventListener('keydown', e => {
  const inInput = ['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName);

  // Ctrl+K — focus search
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    const si = document.getElementById('searchInput');
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
    const items = Array.from(document.querySelectorAll('.si'));
    const cur = items.findIndex(x => x.classList.contains('on'));
    const next = e.key === 'ArrowRight' ? Math.min(cur+1, items.length-1) : Math.max(cur-1, 0);
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
    document.getElementById('shortcutPanel').classList.remove('on');
    document.getElementById('intelPanel').classList.remove('on');
    const si = document.getElementById('searchInput');
    if (si.value) { si.value = ''; doSearch(''); return; }
  }
});

// ─── VARS UPDATE ─────────────────────────────────────────
function refreshAllCmds() {
  document.querySelectorAll('.rc').forEach(el => {
    const id = el.id;
    if (!id || !id.startsWith('c_')) return;
    const parts = id.replace('c_','').split('_');
    const sec = D.find(x => x.id === parts[0]);
    if (!sec) return;
    const cmd = sec.groups[parseInt(parts[1])]?.c[parseInt(parts[2])];
    if (!cmd) return;
    el.textContent = sub(cmd[1]);
  });
  const q = document.getElementById('searchInput').value.trim();
  if (q) doSearch(q);
}

document.querySelectorAll('.vi').forEach(i => {
  const def = VARS_DEFAULTS[i.id] || '';
  i.addEventListener('input', () => {
    i.classList.toggle('modified', i.value !== def);
    refreshAllCmds();
  });
});
// ─── CUSTOM COMMANDS ──────────────────────────────────────
// customCmds = [{id, name, body, category, tags, createdAt}]
let customCmds = JSON.parse(localStorage.getItem('cs_custom') || '[]');

function openCustomModal(editId) {
  const m = document.getElementById('customModal');
  document.getElementById('editingId').value = editId || '';
  document.getElementById('modalTitleText').textContent = editId ? 'Edit Command' : 'Add Custom Command';
  if (editId) {
    const cmd = customCmds.find(c => c.id === editId);
    if (cmd) {
      document.getElementById('cmdName').value = cmd.name;
      document.getElementById('cmdCategory').value = cmd.category || 'custom';
      document.getElementById('cmdBody').value = cmd.body;
      ['crit','high','med','osep','new'].forEach(t => {
        document.getElementById('t_'+t).checked = (cmd.tags || []).includes(t);
      });
    }
  } else {
    document.getElementById('cmdName').value = '';
    document.getElementById('cmdCategory').value = 'custom';
    document.getElementById('cmdBody').value = '';
    ['crit','high','med','osep','new'].forEach(t => document.getElementById('t_'+t).checked = false);
  }
  m.classList.add('on');
  setTimeout(() => document.getElementById('cmdName').focus(), 100);
}

function closeCustomModal() {
  document.getElementById('customModal').classList.remove('on');
}

document.getElementById('customModal').addEventListener('click', function(e) {
  if (e.target === this) closeCustomModal();
});

function saveCustomCommand() {
  const name = document.getElementById('cmdName').value.trim();
  const body = document.getElementById('cmdBody').value.trim();
  if (!name) { document.getElementById('cmdName').focus(); return; }
  if (!body) { document.getElementById('cmdBody').focus(); return; }
  const tags = ['crit','high','med','osep','new'].filter(t => document.getElementById('t_'+t).checked);
  const category = document.getElementById('cmdCategory').value;
  const editId = document.getElementById('editingId').value;
  if (editId) {
    const idx = customCmds.findIndex(c => c.id === editId);
    if (idx > -1) customCmds[idx] = {...customCmds[idx], name, body, category, tags};
  } else {
    customCmds.push({ id: 'cust_' + Date.now(), name, body, category, tags, createdAt: new Date().toISOString() });
  }
  localStorage.setItem('cs_custom', JSON.stringify(customCmds));
  closeCustomModal();
  rebuildCustomSection();
  updateCustomCount();
}

function deleteCustomCmd(id) {
  if (!confirm('Delete this custom command?')) return;
  customCmds = customCmds.filter(c => c.id !== id);
  localStorage.setItem('cs_custom', JSON.stringify(customCmds));
  rebuildCustomSection();
  updateCustomCount();
}

function renderCustomRow(cmd) {
  const isFav = favorites['custom_' + cmd.id];
  const hasNote = notes['custom_' + cmd.id] && notes['custom_' + cmd.id].trim();
  const subbed = sub(cmd.body);
  const tags = (cmd.tags || []).map(t => {
    if (t==='crit') return '<span class="tag tag-crit">CRITICAL</span>';
    if (t==='high') return '<span class="tag tag-high">HIGH</span>';
    if (t==='med') return '<span class="tag tag-med">MEDIUM</span>';
    if (t==='osep') return '<span class="tag tag-osep">OSEP</span>';
    if (t==='new') return '<span class="tag tag-new">NEW</span>';
    return '';
  }).join('');
  const catLabel = document.getElementById('cmdCategory') ? '' : '';
  return `<div class="row${isFav ? ' fav-row' : ''}" id="crow_${cmd.id}">
    <div class="ri">
      <div class="rd">${escHtml(cmd.name)} <span class="custom-badge">CUSTOM</span> ${tags}</div>
      <div class="rc" id="custom_${cmd.id}">${escHtml(subbed)}</div>
      ${hasNote ? `<div class="note-display">📝 ${escHtml(notes['custom_'+cmd.id])}</div>` : ''}
    </div>
    <div class="row-actions">
      <button class="cp" onclick="doCopyCustom(this,'custom_${cmd.id}')">Copy</button>
      <button class="fav-btn${isFav ? ' on' : ''}" onclick="toggleFavItem('custom_${cmd.id}','${escHtml(cmd.name)}',this)" title="Favorite">★</button>
      <button class="edit-btn" onclick="openCustomModal('${cmd.id}')" title="Edit">✏</button>
      <button class="del-btn" onclick="deleteCustomCmd('${cmd.id}')" title="Delete">🗑</button>
    </div>
  </div>`;
}


function rebuildCustomSection() {
  const el = document.getElementById('s-custom');
  if (!el) return;
  let html = `<div class="sec-hdr"><div class="sec-title">⚙ My Commands</div></div>
  <div style="margin-bottom:12px">
    <button class="hdr-btn custom-btn" onclick="openCustomModal()" style="font-size:11px;padding:5px 12px">➕ Add New Command</button>
  </div>`;
  if (!customCmds.length) {
    html += '<div class="empty"><div class="empty-icon">⚙</div>No custom commands yet.<br>Click "Add Command" in the header to create one.</div>';
  } else {
    // Group by category
    const cats = {};
    customCmds.forEach(c => {
      const k = c.category || 'custom';
      if (!cats[k]) cats[k] = [];
      cats[k].push(c);
    });
    const catNames = {
      custom:'My Commands', recon:'Recon', web:'Web Attacks', api:'API Attacks',
      shells:'Shells', lpe:'Linux PrivEsc', wpe:'Windows PrivEsc', adrecon:'AD Recon',
      adatk:'AD Attacks', adlat:'AD Lateral', adpst:'Persistence', evasion:'Evasion / OPSEC',
      inject:'Injection', c2:'C2 Frameworks', tunnel:'Tunneling', transfer:'File Transfer',
      crack:'Hash Cracking', misc:'Misc / Snippets'
    };
    Object.entries(cats).forEach(([cat, cmds]) => {
      html += `<div class="grp"><div class="grp-title">${catNames[cat] || cat} <span style="color:var(--text3);font-weight:400;text-transform:none;letter-spacing:0">(${cmds.length})</span></div>`;
      cmds.forEach(cmd => { html += renderCustomRow(cmd); });
      html += '</div>';
    });
  }
  el.innerHTML = html;
  updateCustomCount();
}

function buildCustomSection() {
  const cont = document.getElementById('sections');
  const div = document.createElement('div');
  div.id = 's-custom';
  div.className = 'sec';
  cont.appendChild(div);
  rebuildCustomSection();
}

function addCustomSidebarItem() {
  const sb = document.getElementById('sidebar');
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
    document.getElementById('s-custom').classList.add('on');
    document.getElementById('searchResults').classList.remove('on');
    document.getElementById('searchInput').value = '';
  };
}

function updateCustomCount() {
  const el = document.getElementById('customCount');
  if (el) el.textContent = customCmds.length;
}

function refreshCustomCmds() {
  document.querySelectorAll('[id^="custom_cust_"]').forEach(el => {
    const cmdId = el.id.replace('custom_', '');
    const cmd = customCmds.find(c => c.id === cmdId);
    if (cmd) el.textContent = sub(cmd.body);
  });
}

// ─── TARGET INTEL PANEL ───────────────────────────────────
let intelData = JSON.parse(localStorage.getItem('cs_intel') || '{"name":"","scope":"","obj":"","notes":"","creds":[],"flags":[],"pivots":[]}');

function toggleIntel() {
  const p = document.getElementById('intelPanel');
  p.classList.toggle('on');
  if (p.classList.contains('on')) loadIntelUI();
}

function loadIntelUI() {
  document.getElementById('intel-name').value  = intelData.name  || '';
  document.getElementById('intel-scope').value = intelData.scope || '';
  document.getElementById('intel-obj').value   = intelData.obj   || '';
  document.getElementById('intel-notes').value = intelData.notes || '';
  renderIntelItems('creds');
  renderIntelItems('flags');
  renderIntelItems('pivots');
}

function saveIntel() {
  intelData.name  = document.getElementById('intel-name').value;
  intelData.scope = document.getElementById('intel-scope').value;
  intelData.obj   = document.getElementById('intel-obj').value;
  intelData.notes = document.getElementById('intel-notes').value;
  localStorage.setItem('cs_intel', JSON.stringify(intelData));
}

function addIntelItem(type) {
  const inp = document.getElementById('intel' + type.charAt(0).toUpperCase() + type.slice(1) + 'Input');
  if (!inp) return;
  const val = inp.value.trim();
  if (!val) return;
  if (!intelData[type]) intelData[type] = [];
  intelData[type].push(val);
  inp.value = '';
  localStorage.setItem('cs_intel', JSON.stringify(intelData));
  renderIntelItems(type);
}

function removeIntelItem(type, idx) {
  intelData[type].splice(idx, 1);
  localStorage.setItem('cs_intel', JSON.stringify(intelData));
  renderIntelItems(type);
}

function renderIntelItems(type) {
  const listId = 'intel' + type.charAt(0).toUpperCase() + type.slice(1) + 'List';
  const el = document.getElementById(listId);
  if (!el) return;
  const items = intelData[type] || [];
  if (!items.length) { el.innerHTML = ''; return; }
  el.innerHTML = items.map((item, i) =>
    `<div class="intel-loot-item${type==='flags'?' flag-item':''}">
      <span>${escHtml(item)}</span>
      <span class="intel-loot-del" onclick="removeIntelItem('${type}',${i})" title="Remove">✕</span>
    </div>`
  ).join('');
}

function clearIntel() {
  if (!confirm('Clear all Intel data for this engagement?')) return;
  intelData = {name:'',scope:'',obj:'',notes:'',creds:[],flags:[],pivots:[]};
  localStorage.setItem('cs_intel', JSON.stringify(intelData));
  loadIntelUI();
}

function exportIntel() {
  const d = intelData;
  let out = `=== TARGET INTEL — ${d.name || 'Unnamed Engagement'} ===\n`;
  out += `Exported: ${new Date().toLocaleString()}\n\n`;
  if (d.scope)  out += `[TARGET SCOPE]\n${d.scope}\n\n`;
  if (d.obj)    out += `[CURRENT OBJECTIVE]\n${d.obj}\n\n`;
  if (d.creds?.length)  out += `[FOUND CREDENTIALS]\n${d.creds.map(c=>'  '+c).join('\n')}\n\n`;
  if (d.flags?.length)  out += `[CAPTURED FLAGS]\n${d.flags.map(f=>'  '+f).join('\n')}\n\n`;
  if (d.pivots?.length) out += `[PIVOT POINTS / SHELLS]\n${d.pivots.map(p=>'  '+p).join('\n')}\n\n`;
  if (d.notes)  out += `[QUICK NOTES]\n${d.notes}\n`;
  const a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(out);
  a.download = (d.name || 'engagement') + '_intel.txt';
  a.click();
}

// ─── INIT ─────────────────────────────────────────────────
buildSidebar();
buildSections();
buildCustomSection();
addCustomSidebarItem();
updateFavCount();
renderHistory();
updateAllProgressBars();

// Restore persistent UI state
if (localStorage.getItem('cs_sbCollapsed') === '1') toggleSidebar();
if (localStorage.getItem('cs_varsOpen') === '0') toggleVarsBar();

// Patch vars refresh for custom commands
document.querySelectorAll('.vi').forEach(i => {
  i.addEventListener('input', refreshCustomCmds);
});


// ─── THEME TOGGLE ────────────────────────────────────────
(function(){
  const saved = localStorage.getItem('cs_theme');
  if(saved === 'light'){
    document.body.classList.add('light-mode');
    const btn = document.getElementById('themeToggleBtn');
    if(btn) btn.innerHTML = '☀️ LIGHT';
  }
})();

function toggleTheme(){
  const isLight = document.body.classList.toggle('light-mode');
  const btn = document.getElementById('themeToggleBtn');
  if(btn) btn.innerHTML = isLight ? '☀️ LIGHT' : '🌙 DARK';
  localStorage.setItem('cs_theme', isLight ? 'light' : 'dark');
}

// ─── NOTES PANEL ─────────────────────────────────────────
let notesData = JSON.parse(localStorage.getItem('cs_notes_panel') || '[]');

function toggleNotesPanel() {
  const p = document.getElementById('notesPanel');
  p.classList.toggle('on');
  if (p.classList.contains('on')) renderNotes();
}

function addNote() {
  const note = {
    id: 'n_' + Date.now(),
    title: '',
    body: '',
    ts: new Date().toLocaleString()
  };
  notesData.unshift(note);
  saveNotesData();
  renderNotes();
  // Focus title of new note
  setTimeout(() => {
    const el = document.getElementById('nt_' + note.id);
    if (el) el.focus();
  }, 50);
}

function deleteNote(id) {
  notesData = notesData.filter(n => n.id !== id);
  saveNotesData();
  renderNotes();
}

function updateNoteTitle(id, val) {
  const n = notesData.find(n => n.id === id);
  if (n) { n.title = val; n.ts = new Date().toLocaleString(); saveNotesData(); }
}

function updateNoteBody(id, val) {
  const n = notesData.find(n => n.id === id);
  if (n) { n.body = val; n.ts = new Date().toLocaleString(); saveNotesData(); }
}

function saveNotesData() {
  localStorage.setItem('cs_notes_panel', JSON.stringify(notesData));
  const el = document.getElementById('notesCount');
  if (el) el.textContent = notesData.length;
}

function renderNotes() {
  const list = document.getElementById('notesList');
  if (!list) return;
  if (!notesData.length) {
    list.innerHTML = '<div class="notes-empty"><div class="notes-empty-icon">📓</div>Koi note nahi hai abhi.<br><span style="font-size:11px;opacity:.6">+ New Note se banao</span></div>';
    return;
  }
  list.innerHTML = notesData.map(n => `
    <div class="note-card" id="nc_${n.id}">
      <div class="note-card-top">
        <input class="note-card-title" id="nt_${n.id}"
          placeholder="Note ka title..."
          oninput="updateNoteTitle('${n.id}', this.value)">
        <button class="note-card-del" onclick="deleteNote('${n.id}')" title="Delete note">✕</button>
      </div>
      <textarea class="note-card-body" id="nb_${n.id}"
        placeholder="Yahan apne notes likho..."
        oninput="updateNoteBody('${n.id}', this.value)"></textarea>
      <div class="note-card-ts">🕐 ${n.ts}</div>
    </div>
  `).join('');
  // Set input/textarea values via JS to avoid HTML entity double-escaping
  notesData.forEach(n => {
    const ti = document.getElementById('nt_' + n.id);
    const tb = document.getElementById('nb_' + n.id);
    if (ti) ti.value = n.title;
    if (tb) tb.value = n.body;
  });
  // Update count badge
  const el = document.getElementById('notesCount');
  if (el) el.textContent = notesData.length;
}

// Init count on load
(function(){ 
  const el = document.getElementById('notesCount');
  if (el) el.textContent = notesData.length;
})();

// ─── SESSION TIMER ─────────────────────────────────────
const sessionStart = Date.now();
setInterval(() => {
  const s = Math.floor((Date.now() - sessionStart) / 1000);
  const h = String(Math.floor(s/3600)).padStart(2,'0');
  const m = String(Math.floor((s%3600)/60)).padStart(2,'0');
  const sec = String(s%60).padStart(2,'0');
  const el = document.getElementById('sessionTimer');
  if (el) el.textContent = h==='00' ? `⏱ ${m}:${sec}` : `⏱ ${h}:${m}:${sec}`;
}, 1000);

// ─── JUMP TO TOP ────────────────────────────────────────
document.querySelector('.main').addEventListener('scroll', function() {
  const btn = document.getElementById('jumpTop');
  if (btn) btn.classList.toggle('on', this.scrollTop > 300);
});
// ─── CYBER CLOCK ───────────────────────────────────────
setInterval(() => {
  const now = new Date();
  const hh = String(now.getHours()).padStart(2,'0');
  const mm = String(now.getMinutes()).padStart(2,'0');
  const ss = String(now.getSeconds()).padStart(2,'0');
  const el = document.getElementById('cyberClock');
  if (el) el.textContent = `${hh}:${mm}:${ss}`;
}, 1000);

// ─── THREE.JS HOLOGRAPHIC ORB ────────────────────────────
(function() {
  const canvas = document.getElementById('threejs-orb');
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
})();
