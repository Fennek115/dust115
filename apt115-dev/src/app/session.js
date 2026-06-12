// APT115 CODEX ARCANUM — Cheatsheet: export/import de sesión
// Todo el estado vive en estas claves de localStorage. Un export/import
// las empaqueta a un solo .json para respaldar o cambiar de sesión.

import { showToast } from './util.js';

const SESSION_KEYS = ['cs_favs', 'cs_notes', 'cs_hist', 'cs_done', 'cs_vars',
  'cs_varsOpen', 'cs_sbCollapsed', 'cs_custom', 'cs_intel', 'cs_theme', 'cs_notes_panel'];

export function exportSession() {
  /** @type {Record<string, string>} */
  const data = {};
  SESSION_KEYS.forEach(k => {
    const v = localStorage.getItem(k);
    if (v !== null) data[k] = v;
  });
  const payload = {
    _app: 'APT115 CODEX ARCANUM',
    _type: 'session',
    _version: 1,
    _exported: new Date().toISOString(),
    data
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'apt115_session_' + new Date().toISOString().slice(0, 10) + '.json';
  a.click();
  URL.revokeObjectURL(a.href);
  showToast('✓ Session exported');
}

/** Restaura una sesión desde el file input (onchange inline). @param {HTMLInputElement} input */
export function importSession(input) {
  const file = input.files && input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function (e) {
    let payload;
    try { payload = JSON.parse(/** @type {string} */(e.target.result)); }
    catch (err) { alert('Archivo inválido: no es un JSON legible.'); input.value = ''; return; }
    if (!payload || payload._type !== 'session' || !payload.data) {
      alert('Este archivo no es una sesión de APT115.'); input.value = ''; return;
    }
    const count = Object.keys(payload.data).length;
    const ok = confirm(
      'Importar esta sesión SOBREESCRIBE tu estado actual\n' +
      '(favoritos, notas, comandos custom, Target Intel, etc.).\n\n' +
      'Exportada: ' + (payload._exported || 'desconocido') + '\n' +
      'Claves a restaurar: ' + count + '\n\n' +
      '¿Continuar?'
    );
    if (!ok) { input.value = ''; return; }
    // Reemplazo limpio: setea las claves del archivo, borra las que no estén
    SESSION_KEYS.forEach(k => {
      if (payload.data[k] !== undefined) localStorage.setItem(k, payload.data[k]);
      else localStorage.removeItem(k);
    });
    input.value = '';
    location.reload();
  };
  reader.readAsText(file);
}
