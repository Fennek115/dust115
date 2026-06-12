// APT115 CODEX ARCANUM — Cheatsheet: dataset
// Los data/ (core/mitre/intel) van ANTES en el bundle y se cuelgan de window
// al cargar; acá solo se juntan en el dataset único que recorre todo el app.

/**
 * @typedef {[string, string, string[]?]} CmdTuple  Comando: [descripción, cuerpo, tags?].
 * @typedef {{ t: string, c: CmdTuple[] }} CmdGroup  Grupo de comandos con título.
 * @typedef {{ id: string, label: string, icon?: string, group: string, groups: CmdGroup[] }} Section
 */

const W = /** @type {any} */ (typeof window !== 'undefined' ? window : globalThis);

/** @type {Section[]} */
export const D = [...W.CORE_DATA, ...W.MITRE_DATA, ...W.INTEL_DATA];
