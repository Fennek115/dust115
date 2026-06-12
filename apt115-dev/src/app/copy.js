// APT115 CODEX ARCANUM — Cheatsheet: copiado al clipboard + historial

import { $, escHtml, showToast, copyToClipboard } from './util.js';
import { copyHistory, pushCopyHistory, clearCopyHistoryState } from './state.js';

/** Copy con feedback en el botón + registro en historial. @param {HTMLElement} btn @param {string} id */
export function doCopy(btn, id) {
  const el = $(id);
  if (!el) return;
  const txt = el.textContent;
  copyToClipboard(txt);
  btn.textContent = '✓';
  btn.classList.add('ok');
  setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('ok'); }, 1500);
  showToast('✓ Copied to clipboard');
  pushCopyHistory(txt);
  renderHistory();
}

/** Mismo flujo que doCopy; nombre aparte para las filas custom. */
export const doCopyCustom = doCopy;

/** Copia colapsando líneas a `;` (descarta comentarios #). @param {HTMLElement} btn @param {string} id */
export function do1Liner(btn, id) {
  const el = $(id);
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

/** Copy simple sin historial (paneles de favoritos/búsqueda). @param {string} id @param {HTMLElement} [btn] */
export function copyText(id, btn) {
  const el = $(id);
  if (!el) return;
  copyToClipboard(el.textContent);
  showToast('✓ Copied to clipboard');
  if (btn) { btn.textContent = '✓'; btn.classList.add('ok'); setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('ok'); }, 1500); }
}

export function toggleHistory() {
  const p = $('histPanel');
  p.classList.toggle('on');
  if (p.classList.contains('on')) renderHistory();
}

export function renderHistory() {
  const hl = $('histList');
  if (!copyHistory.length) { hl.innerHTML = '<div style="color:var(--text3);font-size:11px">No history yet.</div>'; return; }
  hl.innerHTML = copyHistory.map(h => `<div class="hist-item"><span class="hist-time">${h.t}</span><span style="flex:1;font-size:11px;color:var(--code)">${escHtml(h.c)}</span></div>`).join('');
}

export function clearHistory() {
  clearCopyHistoryState();
  renderHistory();
}
