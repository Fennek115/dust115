// APT115 CODEX ARCANUM — Cheatsheet: panel Target Intel
// Scratchpad del engagement: alcance, objetivo, creds/flags/pivots y notas.

import { $, $in, escHtml } from './util.js';
import { intelData, saveIntelData, resetIntelState } from './state.js';

export function toggleIntel() {
  const p = $('intelPanel');
  p.classList.toggle('on');
  if (p.classList.contains('on')) loadIntelUI();
}

export function loadIntelUI() {
  $in('intel-name').value = intelData.name || '';
  $in('intel-scope').value = intelData.scope || '';
  $in('intel-obj').value = intelData.obj || '';
  $in('intel-notes').value = intelData.notes || '';
  renderIntelItems('creds');
  renderIntelItems('flags');
  renderIntelItems('pivots');
}

export function saveIntel() {
  intelData.name = $in('intel-name').value;
  intelData.scope = $in('intel-scope').value;
  intelData.obj = $in('intel-obj').value;
  intelData.notes = $in('intel-notes').value;
  saveIntelData();
}

/** @param {'creds' | 'flags' | 'pivots'} type */
export function addIntelItem(type) {
  const inp = $in('intel' + type.charAt(0).toUpperCase() + type.slice(1) + 'Input');
  if (!inp) return;
  const val = inp.value.trim();
  if (!val) return;
  if (!intelData[type]) intelData[type] = [];
  intelData[type].push(val);
  inp.value = '';
  saveIntelData();
  renderIntelItems(type);
}

/** @param {'creds' | 'flags' | 'pivots'} type @param {number} idx */
export function removeIntelItem(type, idx) {
  intelData[type].splice(idx, 1);
  saveIntelData();
  renderIntelItems(type);
}

/** @param {'creds' | 'flags' | 'pivots'} type */
export function renderIntelItems(type) {
  const listId = 'intel' + type.charAt(0).toUpperCase() + type.slice(1) + 'List';
  const el = $(listId);
  if (!el) return;
  const items = intelData[type] || [];
  if (!items.length) { el.innerHTML = ''; return; }
  el.innerHTML = items.map((item, i) =>
    `<div class="intel-loot-item${type === 'flags' ? ' flag-item' : ''}">
      <span>${escHtml(item)}</span>
      <span class="intel-loot-del" onclick="removeIntelItem('${type}',${i})" title="Remove">✕</span>
    </div>`
  ).join('');
}

export function clearIntel() {
  if (!confirm('Clear all Intel data for this engagement?')) return;
  resetIntelState();
  loadIntelUI();
}

export function exportIntel() {
  const d = intelData;
  let out = `=== TARGET INTEL — ${d.name || 'Unnamed Engagement'} ===\n`;
  out += `Exported: ${new Date().toLocaleString()}\n\n`;
  if (d.scope) out += `[TARGET SCOPE]\n${d.scope}\n\n`;
  if (d.obj) out += `[CURRENT OBJECTIVE]\n${d.obj}\n\n`;
  if (d.creds?.length) out += `[FOUND CREDENTIALS]\n${d.creds.map(c => '  ' + c).join('\n')}\n\n`;
  if (d.flags?.length) out += `[CAPTURED FLAGS]\n${d.flags.map(f => '  ' + f).join('\n')}\n\n`;
  if (d.pivots?.length) out += `[PIVOT POINTS / SHELLS]\n${d.pivots.map(p => '  ' + p).join('\n')}\n\n`;
  if (d.notes) out += `[QUICK NOTES]\n${d.notes}\n`;
  const a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(out);
  a.download = (d.name || 'engagement') + '_intel.txt';
  a.click();
}
