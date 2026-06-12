// APT115 CODEX ARCANUM — Cheatsheet: notas por comando + panel de notas libres

import { D } from './data.js';
import { $, $in, mkId } from './util.js';
import { notes, activeNotes, saveNotes, notesData, setNotesData, saveNotesData } from './state.js';
import { renderRow } from './render.js';

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

// ─── PANEL DE NOTAS LIBRES ───────────────────────────────

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

export function addNote() {
  const note = {
    id: 'n_' + Date.now(),
    title: '',
    body: '',
    ts: new Date().toLocaleString()
  };
  notesData.unshift(note);
  persistNotesPanel();
  renderNotes();
  // Focus title of new note
  setTimeout(() => {
    const el = $('nt_' + note.id);
    if (el) el.focus();
  }, 50);
}

/** @param {string} id */
export function deleteNote(id) {
  setNotesData(notesData.filter(n => n.id !== id));
  updateNotesCount();
  renderNotes();
}

/** @param {string} id @param {string} val */
export function updateNoteTitle(id, val) {
  const n = notesData.find(n => n.id === id);
  if (n) { n.title = val; n.ts = new Date().toLocaleString(); persistNotesPanel(); }
}

/** @param {string} id @param {string} val */
export function updateNoteBody(id, val) {
  const n = notesData.find(n => n.id === id);
  if (n) { n.body = val; n.ts = new Date().toLocaleString(); persistNotesPanel(); }
}

export function renderNotes() {
  const list = $('notesList');
  if (!list) return;
  if (!notesData.length) {
    list.innerHTML = '<div class="notes-empty"><div class="notes-empty-icon">📓</div>No notes yet.<br><span style="font-size:11px;opacity:.6">Create one with + New Note</span></div>';
    return;
  }
  list.innerHTML = notesData.map(n => `
    <div class="note-card" id="nc_${n.id}">
      <div class="note-card-top">
        <input class="note-card-title" id="nt_${n.id}"
          placeholder="Note title..."
          oninput="updateNoteTitle('${n.id}', this.value)">
        <button class="note-card-del" onclick="deleteNote('${n.id}')" title="Delete note">✕</button>
      </div>
      <textarea class="note-card-body" id="nb_${n.id}"
        placeholder="Write your notes here..."
        oninput="updateNoteBody('${n.id}', this.value)"></textarea>
      <div class="note-card-ts">🕐 ${n.ts}</div>
    </div>
  `).join('');
  // Set input/textarea values via JS to avoid HTML entity double-escaping
  notesData.forEach(n => {
    const ti = $in('nt_' + n.id);
    const tb = $in('nb_' + n.id);
    if (ti) ti.value = n.title;
    if (tb) tb.value = n.body;
  });
  updateNotesCount();
}
