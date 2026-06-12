// APT115 CODEX ARCANUM — Cheatsheet: variables de engagement
// Los comandos del dataset llevan placeholders {LHOST}/{RHOST}/… que se
// sustituyen con los inputs de la barra de variables (persistidos en cs_vars).

import { $, $in } from './util.js';

/** Defaults de la barra (id de input → valor). */
export const VARS_DEFAULTS = {
  lhost: '10.10.14.1', rhost: '10.10.10.10', lport: '4444', rport: '9001',
  domain: 'corp.local', dc: '192.168.1.10', user: 'john', pass: 'Password123',
  hash: 'NTLM_HASH_HERE', url: 'http://10.10.10.10',
};

/** Valores actuales de las variables, por placeholder. @returns {Record<string, string>} */
export function gv() {
  return {
    LHOST: $in('lhost').value,
    RHOST: $in('rhost').value,
    LPORT: $in('lport').value,
    RPORT: $in('rport').value,
    DOMAIN: $in('domain').value,
    DC: $in('dc').value,
    USER: $in('user').value,
    PASS: $in('pass').value,
    HASH: $in('hash').value,
    URL: $in('url').value,
  };
}

/** Sustituye los {PLACEHOLDER} de un comando por las variables actuales. @param {string} s */
export function sub(s) {
  const v = gv();
  return s.replace(/\{(\w+)\}/g, (m, k) => v[k] !== undefined ? v[k] : m);
}

export function saveVars() {
  /** @type {Record<string, string>} */
  const out = {};
  Object.keys(VARS_DEFAULTS).forEach(id => {
    const el = $in(id);
    if (el) out[id] = el.value;
  });
  localStorage.setItem('cs_vars', JSON.stringify(out));
}

export function restoreVars() {
  const saved = JSON.parse(localStorage.getItem('cs_vars') || 'null');
  if (!saved) return;
  Object.entries(saved).forEach(([id, val]) => {
    const el = $in(id);
    if (el) { el.value = String(val); el.classList.toggle('modified', val !== (VARS_DEFAULTS[id] || '')); }
  });
}

/** Vuelve a defaults y persiste. El refresco de los comandos lo envuelve index.js. */
export function resetVars() {
  Object.entries(VARS_DEFAULTS).forEach(([id, val]) => {
    const el = $in(id);
    if (el) { el.value = val; el.classList.remove('modified'); }
  });
  saveVars();
}

export function toggleVarsBar() {
  const bar = $('varsBar');
  const col = $('varsCollapsedBar');
  const btn = $('varToggleBtn');
  const isOpen = !bar.classList.contains('collapsed');
  bar.classList.toggle('collapsed', isOpen);
  col.classList.toggle('on', isOpen);
  if (btn) btn.textContent = isOpen ? '▼ Show' : '▲ Hide';
  localStorage.setItem('cs_varsOpen', isOpen ? '0' : '1');
}
