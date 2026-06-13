// APT115 CODEX ARCANUM — Cheatsheet: helpers de DOM y render

/** Atajo de getElementById. @param {string} id @returns {HTMLElement} */
export const $ = (id) => /** @type {HTMLElement} */ (document.getElementById(id));

/** getElementById casteado a input/textarea/select (para leer .value). @param {string} id @returns {HTMLInputElement} */
export const $in = (id) => /** @type {HTMLInputElement} */ (document.getElementById(id));

/** querySelectorAll tipado a HTMLElement. @param {string} sel @param {ParentNode} [root] @returns {NodeListOf<HTMLElement>} */
export const $$ = (sel, root) => /** @type {NodeListOf<HTMLElement>} */ ((root || document).querySelectorAll(sel));

/** @param {string} s */
export function escHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** Escapa para usar dentro de un atributo HTML entre comillas dobles. @param {string} s */
export function escAttr(s) {
  return escHtml(String(s)).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** Id estable de un comando del dataset. @param {string} secId @param {number} gi @param {number} ci */
export function mkId(secId, gi, ci) { return `c_${secId}_${gi}_${ci}`; }

/** @param {string[] | undefined} tags */
export function renderTags(tags) {
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

/** @param {string[] | undefined} tags */
export function getTagBorderClass(tags) {
  if (!tags || !tags.length) return '';
  if (tags.includes('crit')) return ' tag-crit-row';
  if (tags.includes('high')) return ' tag-high-row';
  if (tags.includes('osep')) return ' tag-osep-row';
  if (tags.includes('med')) return ' tag-med-row';
  return '';
}

let toastTid = 0;

/** Toast global. También lo usan registry.js/triage.js vía window.showToast. @param {string} msg */
export function showToast(msg) {
  const t = $('copyToast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTid);
  toastTid = setTimeout(() => t.classList.remove('show'), 1800);
}

/** Clipboard con fallback a execCommand (file:// sin permisos). @param {string} text */
export function copyToClipboard(text) {
  try { navigator.clipboard.writeText(text); return; } catch (e) {}
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  document.execCommand('copy'); document.body.removeChild(ta);
}
