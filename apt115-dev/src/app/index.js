// APT115 CODEX ARCANUM — Cheatsheet: entry
// Junta los módulos del app, cuelga de window TODO lo que referencian los
// handlers inline (index.html y el HTML generado por render/favs/custom/intel/
// notes) y corre la secuencia de init del app.js original. El bundle lo emite
// en la posición 4 del manifiesto (tras los data/), con el DOM ya parseado
// (el <script> va al final del <body>).

import { $$, showToast } from './util.js';
import { VARS_DEFAULTS, saveVars, restoreVars, resetVars, toggleVarsBar } from './vars.js';
import {
  buildSidebar, buildSections, refreshSection, toggleDone, toggleGrp,
  updateAllProgressBars, exportSection,
} from './render.js';
import {
  doCopy, doCopyCustom, do1Liner, copyText, toggleHistory, renderHistory, clearHistory,
} from './copy.js';
import {
  toggleFavItem, updateFavCount, toggleFav, removeFav, clearAllFavs, exportFavs,
} from './favs.js';
import {
  toggleNote, saveNote, toggleNotesPanel, addNote, deleteNote,
  updateNoteTitle, updateNoteBody, updateNotesCount,
  editNoteBody, saveNoteBody, refreshNotesPanel, openWikiLink, focusNote, createNoteFrom,
  toggleNotesGraph, exportVault, importVault, pickVaultImport,
} from './notes.js';
import {
  openCustomModal, closeCustomModal, wireCustomModal, saveCustomCommand,
  deleteCustomCmd, buildCustomSection, addCustomSidebarItem, refreshCustomCmds,
} from './custom.js';
import {
  toggleIntel, saveIntel, addIntelItem, removeIntelItem, clearIntel, exportIntel,
} from './intel.js';
import { wireSearch, doSearch, refreshAllCmds } from './search.js';
import { exportSession, importSession } from './session.js';
import {
  toggleShortcuts, toggleSidebar, toggleSidebarDrawer, closeSidebarDrawer,
  initTheme, toggleTheme, wireKeyboard,
  initTimers, wireJumpTop, initOrb,
} from './ui.js';

// ─── GLOBALS (handlers inline + consumidores externos) ────
// showToast también lo usan registry.js y triage.js vía window.
Object.assign(window, {
  // copiado + historial
  doCopy, doCopyCustom, do1Liner, copyText, toggleHistory, clearHistory,
  // favoritos
  toggleFavItem, toggleFav, removeFav, clearAllFavs, exportFavs,
  // notas (por fila + panel markdown/enlaces + grafo + vault)
  toggleNote, saveNote, toggleNotesPanel, addNote, deleteNote, updateNoteTitle, updateNoteBody,
  editNoteBody, saveNoteBody, refreshNotesPanel, openWikiLink, focusNote,
  toggleNotesGraph, exportVault, importVault, pickVaultImport,
  // puente desde tools: crear nota con contenido (p.ej. netmap → nota)
  apt115CreateNote: createNoteFrom,
  // checklist / grupos / secciones
  toggleDone, toggleGrp, exportSection, refreshSection,
  // comandos custom
  openCustomModal, closeCustomModal, saveCustomCommand, deleteCustomCmd,
  // Target Intel
  toggleIntel, saveIntel, addIntelItem, removeIntelItem, clearIntel, exportIntel,
  // sesión
  exportSession, importSession,
  // chrome / vars
  toggleShortcuts, toggleSidebar, toggleSidebarDrawer, closeSidebarDrawer, toggleTheme, toggleVarsBar,
  // resetVars también refresca los comandos visibles (como el original)
  resetVars: () => { resetVars(); refreshAllCmds(); },
  // helpers globales
  showToast, doSearch, refreshAllCmds,
});

// ─── INIT (mismo orden que el app.js original) ────────────
restoreVars();
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

// Inputs de variables: marcar modificado, persistir y re-sustituir comandos
$$('.vi').forEach(i => {
  const input = /** @type {HTMLInputElement} */ (i);
  const def = VARS_DEFAULTS[input.id] || '';
  input.addEventListener('input', () => {
    input.classList.toggle('modified', input.value !== def);
    saveVars();
    refreshAllCmds();
    refreshCustomCmds();
  });
});

wireSearch();
wireKeyboard();
wireCustomModal();
initTheme();
updateNotesCount();
initTimers();
wireJumpTop();
initOrb();
