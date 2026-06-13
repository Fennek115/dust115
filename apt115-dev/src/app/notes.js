// APT115 CODEX ARCANUM — Cheatsheet: notas por comando + panel de notas libres
// El panel de notas libres es estilo Logseq/Quartz: body markdown, enlaces
// [[Título]] entre notas y backlinks. Render de markdown en ./markdown.js.

import { D } from './data.js';
import { $, $in, escHtml, mkId } from './util.js';
import { notes, activeNotes, saveNotes, notesData, setNotesData, saveNotesData } from './state.js';
import { renderRow } from './render.js';
import { renderMarkdown, extractWikiLinks } from './markdown.js';

// ─── NOTA POR FILA ───────────────────────────────────────

/** Re-renderiza en el lugar la fila de un comando del dataset. @param {string} id */
function rerenderRow(id) {
  D.forEach(s => {
    s.groups.forEach((g, gi) => {
      g.c.forEach((cmd, ci) => {
        if (mkId(s.id, gi, ci) === id) {
          const row = $('row_' + id);
          if (row) row.outerHTML = renderRow(cmd, s.id, gi, ci);
        }
      });
    });
  });
}

/** Abre/cierra el editor de nota de una fila. @param {string} id */
export function toggleNote(id) {
  if (activeNotes[id]) {
    delete activeNotes[id];
  } else {
    activeNotes[id] = true;
  }
  rerenderRow(id);
  if (activeNotes[id]) {
    setTimeout(() => { const ta = $('note_' + id); if (ta) ta.focus(); }, 50);
  }
}

/** Persiste la nota al salir del textarea (onblur inline). @param {string} id */
export function saveNote(id) {
  const ta = $in('note_' + id);
  if (!ta) return;
  const val = ta.value.trim();
  if (val) notes[id] = val; else delete notes[id];
  saveNotes();
  delete activeNotes[id];
  rerenderRow(id);
}

// ─── PANEL DE NOTAS LIBRES (markdown + [[wiki]] + backlinks) ───────────────
// El body es markdown; [[Título]] enlaza a otra nota. Por defecto se ve
// renderizado; ✎ abre el editor. Re-render completo al cerrar el editor o al
// salir del título, para refrescar enlaces y backlinks en todas las tarjetas.

/** Editores de body abiertos (transitorio, no persiste). @type {Record<string, boolean>} */
const editing = {};

/** Guarda el panel y actualiza el badge del header. */
function persistNotesPanel() {
  saveNotesData();
  updateNotesCount();
}

export function updateNotesCount() {
  const el = $('notesCount');
  if (el) el.textContent = String(notesData.length);
}

export function toggleNotesPanel() {
  const p = $('notesPanel');
  p.classList.toggle('on');
  if (p.classList.contains('on')) renderNotes();
}

/** Nota por título (case-insensitive), o null. @param {string} title */
function noteByTitle(title) {
  const t = String(title || '').trim().toLowerCase();
  if (!t) return null;
  return notesData.find(n => (n.title || '').trim().toLowerCase() === t) || null;
}

/** Notas que enlazan a `note` por su título. @param {import('./state.js').NoteCard} note */
function backlinksOf(note) {
  const title = (note.title || '').trim().toLowerCase();
  if (!title) return [];
  return notesData.filter(n => n.id !== note.id &&
    extractWikiLinks(n.body).some(t => t.toLowerCase() === title));
}

export function addNote() {
  const note = { id: 'n_' + Date.now(), title: '', body: '', ts: new Date().toLocaleString() };
  notesData.unshift(note);
  editing[note.id] = true; // nota nueva abre en edición
  persistNotesPanel();
  renderNotes();
  setTimeout(() => { const el = $('nt_' + note.id); if (el) el.focus(); }, 50);
}

/**
 * Crea una nota con título + body ya dados y abre el panel (puente desde otras
 * tools, p.ej. netmap → "mandar a una nota"). Si ya existe una nota con ese
 * título, le agrega el body en vez de duplicar. Devuelve el id.
 * @param {string} title @param {string} body @returns {string}
 */
export function createNoteFrom(title, body) {
  const t = String(title || '').trim();
  const b = String(body || '');
  const existing = noteByTitle(t);
  if (existing) {
    existing.body = (existing.body ? existing.body + '\n\n' : '') + b;
    existing.ts = new Date().toLocaleString();
    persistNotesPanel();
  } else {
    const note = { id: 'n_' + Date.now(), title: t, body: b, ts: new Date().toLocaleString() };
    notesData.unshift(note);
    persistNotesPanel();
  }
  const panel = $('notesPanel');
  if (panel && !panel.classList.contains('on')) panel.classList.add('on');
  renderNotes();
  return existing ? existing.id : notesData[0].id;
}

/** @param {string} id */
export function deleteNote(id) {
  delete editing[id];
  setNotesData(notesData.filter(n => n.id !== id));
  renderNotes();
}

/** Guarda el título en vivo (sin re-render, para no perder el foco). @param {string} id @param {string} val */
export function updateNoteTitle(id, val) {
  const n = notesData.find(n => n.id === id);
  if (n) { n.title = val; n.ts = new Date().toLocaleString(); persistNotesPanel(); }
}

/** @param {string} id @param {string} val */
export function updateNoteBody(id, val) {
  const n = notesData.find(n => n.id === id);
  if (n) { n.body = val; n.ts = new Date().toLocaleString(); persistNotesPanel(); }
}

/** Abre el editor de markdown de una nota. @param {string} id */
export function editNoteBody(id) {
  editing[id] = true;
  renderNotes();
  setTimeout(() => {
    const ta = $in('nb_' + id);
    if (ta) { ta.focus(); ta.selectionStart = ta.selectionEnd = ta.value.length; }
  }, 30);
}

/** Cierra el editor (onblur) y re-renderiza para refrescar enlaces/backlinks. @param {string} id */
export function saveNoteBody(id) {
  const ta = $in('nb_' + id);
  if (ta) updateNoteBody(id, ta.value);
  delete editing[id];
  renderNotes();
}

/** Re-render del panel (onblur del título: refresca enlaces/backlinks). */
export function refreshNotesPanel() { renderNotes(); }

/** Click en un [[wiki]]: abre la nota destino, creándola si no existe. @param {HTMLElement} el */
export function openWikiLink(el) {
  const title = el.getAttribute('data-wl') || '';
  let n = noteByTitle(title);
  if (!n) {
    n = { id: 'n_' + Date.now(), title: title.trim(), body: '', ts: new Date().toLocaleString() };
    notesData.unshift(n);
    persistNotesPanel();
  }
  renderNotes();
  const id = n.id;
  setTimeout(() => focusNote(id), 50);
}

/** Desplaza a una nota y la resalta un instante. @param {string} id */
export function focusNote(id) {
  const el = $('nc_' + id);
  if (!el) return;
  el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  el.classList.add('note-flash');
  setTimeout(() => el.classList.remove('note-flash'), 1000);
}

export function renderNotes() {
  const list = $('notesList');
  if (!list) return;
  if (!notesData.length) {
    list.innerHTML = '<div class="notes-empty"><div class="notes-empty-icon">📓</div>Sin notas todavía.<br>' +
      '<span style="font-size:11px;opacity:.6">Creá una con + Nueva nota. Enlazá con [[Título]].</span></div>';
    return;
  }
  const exists = (t) => !!noteByTitle(t);
  list.innerHTML = notesData.map(n => {
    const isEd = editing[n.id];
    const body = isEd
      ? `<textarea class="note-card-body" id="nb_${n.id}" placeholder="Markdown… enlazá con [[Título]]" ` +
        `oninput="updateNoteBody('${n.id}', this.value)" onblur="saveNoteBody('${n.id}')"></textarea>`
      : (n.body && n.body.trim()
          ? `<div class="note-card-rendered" id="nr_${n.id}">${renderMarkdown(n.body, { linkExists: exists })}</div>`
          : `<div class="note-card-rendered empty" id="nr_${n.id}">vacía — ✎ para escribir</div>`);
    const bl = backlinksOf(n);
    const blHtml = bl.length
      ? `<div class="note-backlinks"><span class="note-bl-h">↩ Enlazada desde</span> ` +
        bl.map(b => `<a class="wl" onclick="focusNote('${b.id}')">${escHtml(b.title || '(sin título)')}</a>`).join(' · ') +
        `</div>`
      : '';
    return `
    <div class="note-card" id="nc_${n.id}">
      <div class="note-card-top">
        <input class="note-card-title" id="nt_${n.id}" placeholder="Título de la nota…"
          oninput="updateNoteTitle('${n.id}', this.value)" onblur="refreshNotesPanel()">
        <button class="note-card-edit" onclick="editNoteBody('${n.id}')" title="Editar markdown">✎</button>
        <button class="note-card-del" onclick="deleteNote('${n.id}')" title="Eliminar nota">✕</button>
      </div>
      ${body}
      ${blHtml}
      <div class="note-card-ts">🕐 ${escHtml(n.ts)}</div>
    </div>`;
  }).join('');
  // Set input/textarea values via JS (evita doble-escape de entidades HTML)
  notesData.forEach(n => {
    const ti = $in('nt_' + n.id);
    const tb = $in('nb_' + n.id);
    if (ti) ti.value = n.title;
    if (tb) tb.value = n.body;
  });
  updateNotesCount();
}
