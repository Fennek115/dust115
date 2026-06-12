// APT115 CODEX ARCANUM — Cheatsheet: estado persistente (localStorage)
// Único dueño de las claves cs_* de estado: el resto de los módulos lee estos
// bindings (live bindings ESM) y muta a través de los helpers de acá. Las
// reasignaciones (clear/set) DEBEN pasar por este módulo: un import no puede
// reasignar el binding desde afuera.

/**
 * @typedef {{ id: string, name: string, body: string, category?: string, tags?: string[], createdAt?: string }} CustomCmd
 * @typedef {{ name: string, scope: string, obj: string, notes: string, creds: string[], flags: string[], pivots: string[] }} IntelData
 * @typedef {{ id: string, title: string, body: string, ts: string }} NoteCard
 * @typedef {{ t: string, c: string }} HistEntry  Entrada del historial de copiado: hora + comando truncado.
 */

/** @param {string} key @param {any} fallback */
function read(key, fallback) {
  return JSON.parse(localStorage.getItem(key) || JSON.stringify(fallback));
}

const EMPTY_INTEL = { name: '', scope: '', obj: '', notes: '', creds: [], flags: [], pivots: [] };

/** Favoritos por id de comando. @type {Record<string, boolean>} */
export let favorites = read('cs_favs', {});
/** Nota adjunta por id de comando. @type {Record<string, string>} */
export let notes = read('cs_notes', {});
/** Historial de copiado (máx. 20). @type {HistEntry[]} */
export let copyHistory = read('cs_hist', []);
/** Checklist de comandos hechos. @type {Record<string, boolean>} */
export let doneItems = read('cs_done', {});
/** Editores de nota abiertos (transitorio, no persiste). @type {Record<string, boolean>} */
export const activeNotes = {};
/** Comandos definidos por el usuario. @type {CustomCmd[]} */
export let customCmds = read('cs_custom', []);
/** Panel Target Intel. @type {IntelData} */
export let intelData = read('cs_intel', EMPTY_INTEL);
/** Panel de notas libres. @type {NoteCard[]} */
export let notesData = read('cs_notes_panel', []);

export function saveFavorites() { localStorage.setItem('cs_favs', JSON.stringify(favorites)); }
export function clearFavoritesState() { favorites = {}; saveFavorites(); }

export function saveNotes() { localStorage.setItem('cs_notes', JSON.stringify(notes)); }

export function saveCopyHistory() { localStorage.setItem('cs_hist', JSON.stringify(copyHistory)); }
/** Registra un copiado (truncado a 120 chars, tope 20 entradas). @param {string} text */
export function pushCopyHistory(text) {
  const ts = new Date().toLocaleTimeString();
  copyHistory.unshift({ t: ts, c: text.slice(0, 120) + (text.length > 120 ? '…' : '') });
  if (copyHistory.length > 20) copyHistory.pop();
  saveCopyHistory();
}
export function clearCopyHistoryState() { copyHistory = []; saveCopyHistory(); }

export function saveDoneItems() { localStorage.setItem('cs_done', JSON.stringify(doneItems)); }

export function saveCustomCmds() { localStorage.setItem('cs_custom', JSON.stringify(customCmds)); }
/** @param {CustomCmd[]} arr */
export function setCustomCmds(arr) { customCmds = arr; saveCustomCmds(); }

export function saveIntelData() { localStorage.setItem('cs_intel', JSON.stringify(intelData)); }
export function resetIntelState() { intelData = { ...EMPTY_INTEL, creds: [], flags: [], pivots: [] }; saveIntelData(); }

export function saveNotesData() { localStorage.setItem('cs_notes_panel', JSON.stringify(notesData)); }
/** @param {NoteCard[]} arr */
export function setNotesData(arr) { notesData = arr; saveNotesData(); }
