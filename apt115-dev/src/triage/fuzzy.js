// APT115 CODEX ARCANUM — Fuzzy hashing (TLSH)
// quod est superius est sicut quod inferius
//
// Calcula el TLSH (Trend Micro Locality Sensitive Hash) del archivo y permite
// comparar contra otro TLSH para medir similitud (clustering de muestras). Lo
// usa el panel de Hashes del triage. Motor: vendor/fuzzy/tlsh.min.js (window.TLSH
// = { hash, diff }). 100% local.

export const fuzzy = (function () {
  'use strict';
  let lastTlsh = null; // TLSH del archivo cargado actualmente

  // Uint8Array → string de bytes (TLSH lee data.charCodeAt). Por chunks para
  // no reventar el stack con archivos grandes.
  function toBinaryString(bytes) {
    let s = '';
    const CH = 8192;
    for (let i = 0; i < bytes.length; i += CH) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + CH, bytes.length)));
    }
    return s;
  }

  // Devuelve el TLSH (70 hex) o null si TLSH no está cargado o la entrada es muy
  // chica/simple (TLSH exige cierta complejidad y ~50+ bytes).
  function hashBytes(bytes) {
    lastTlsh = null;
    if (typeof window.TLSH === 'undefined' || typeof window.TLSH.hash !== 'function') return null;
    try { lastTlsh = window.TLSH.hash(toBinaryString(bytes)); return lastTlsh; }
    catch (e) { return null; }
  }

  function classify(d) {
    if (d <= 0) return ['idéntico', 't-ok'];
    if (d <= 30) return ['casi idéntico', 't-ok'];
    if (d <= 80) return ['muy similar', 't-warn'];
    if (d <= 150) return ['similar', 't-warn'];
    return ['distinto', 't-bad'];
  }

  // Handler del botón "comparar" en el panel de Hashes (inline onclick).
  function compare(btn) {
    const box = btn.closest('.tlsh-cmp');
    if (!box) return;
    const inp = box.querySelector('.tlsh-cmp-in');
    const out = box.querySelector('.tlsh-cmp-out');
    if (!lastTlsh) { out.innerHTML = '<span class="t-bad">esta muestra no tiene TLSH</span>'; return; }
    const other = (inp.value || '').trim().replace(/^T1/i, '').toUpperCase();
    if (!/^[0-9A-F]{70}$/.test(other)) { out.innerHTML = '<span class="t-bad">TLSH inválido (se esperan 70 hex)</span>'; return; }
    let d;
    try { d = window.TLSH.diff(lastTlsh, other); }
    catch (e) { out.innerHTML = '<span class="t-bad">no se pudo comparar</span>'; return; }
    const c = classify(d);
    out.innerHTML = 'distancia <b>' + d + '</b> — <span class="' + c[1] + '">' + c[0] + '</span>';
  }

  return { hashBytes, compare };
})();

if (typeof window !== 'undefined') { window.Triage = window.Triage || {}; window.Triage.fuzzy = fuzzy; }
