// APT115 CODEX ARCANUM — Packer / Compiler detection (firmas PEiD)
// solve et coagula
//
// Analyzer del Malware Triage: identifica el packer/cryptor/compilador de un PE
// matcheando firmas estilo PEiD contra el entry point (y, para las no-ep, contra
// el cuerpo del archivo). Complementa Rich Header + entropía + imphash en la
// atribución de toolchain. 100% local.
//
// Base de firmas: data/peid-userdb.js (window.PEID_DB), carga PEREZOSA al
// analizar el primer PE. Firma = lista de bytes con `??` como comodín.

if (typeof window !== 'undefined') window.Triage = window.Triage || {};
export const peid = (function () {
  'use strict';
  const U = Triage.util;
  const DB_SRC = 'data/peid-userdb.js';
  const SCAN_CAP = 256 * 1024; // límite de barrido para firmas no-ep (stubs cerca del header)

  let dbPromise = null;
  let compiled = null; // [{ n, c:[byte|-1], e, anchor:{idx,val}|null }]

  function loadScript(src) {
    return new Promise((res, rej) => {
      const s = document.createElement('script');
      s.src = src; s.onload = res;
      s.onerror = () => rej(new Error('no se pudo cargar ' + src));
      document.head.appendChild(s);
    });
  }

  function compile() {
    compiled = (window.PEID_DB || []).map(([n, s, e]) => {
      const toks = s.split(' ');
      const c = new Array(toks.length);
      for (let i = 0; i < toks.length; i++) c[i] = toks[i] === '??' ? -1 : (parseInt(toks[i], 16) & 0xff);
      let ai = 0; while (ai < c.length && c[ai] < 0) ai++;
      return { n, c, e: !!e, anchor: ai < c.length ? { idx: ai, val: c[ai] } : null };
    });
  }

  function ensureDB() {
    if (!dbPromise) {
      dbPromise = (window.PEID_DB ? Promise.resolve() : loadScript(DB_SRC))
        .then(() => { if (!window.PEID_DB) throw new Error('base de firmas vacía'); compile(); })
        .catch((e) => { dbPromise = null; throw e; });
    }
    return dbPromise;
  }

  function matchAt(bytes, off, c) {
    if (off < 0 || off + c.length > bytes.length) return false;
    for (let i = 0; i < c.length; i++) { const b = c[i]; if (b >= 0 && bytes[off + i] !== b) return false; }
    return true;
  }

  // Barrido anclado en el primer byte concreto de la firma → rápido aunque la
  // firma empiece con comodines.
  function searchAny(bytes, sig, cap) {
    const a = sig.anchor;
    if (!a) return sig.c.length <= bytes.length ? 0 : -1; // firma todo-comodín (degenerada)
    const end = Math.min(bytes.length, cap);
    for (let p = a.idx; p < end; p++) {
      if (bytes[p] !== a.val) continue;
      const off = p - a.idx;
      if (off >= 0 && matchAt(bytes, off, sig.c)) return off;
    }
    return -1;
  }

  function detect(ctx) {
    const ep = ctx.pe.epOffset;
    const epHits = [], anyHits = [], seen = new Set();
    for (const sig of compiled) {
      if (ep >= 0 && matchAt(ctx.bytes, ep, sig.c)) {
        if (!seen.has(sig.n)) { seen.add(sig.n); epHits.push(sig.n); }
        continue;
      }
      if (!sig.e) {
        const off = searchAny(ctx.bytes, sig, SCAN_CAP);
        if (off >= 0 && !seen.has(sig.n)) { seen.add(sig.n); anyHits.push({ n: sig.n, off }); }
      }
    }
    return { ep, epHits, anyHits };
  }

  function render(res) {
    let html = '<div class="lab-row1">Firmas estilo <b>PEiD</b> (' + compiled.length +
      ') sobre el entry point. Identifican packer / cryptor / compilador. ' +
      '<span class="lab-dim">Coincidencia por firma — evadible y con posibles falsos positivos.</span></div>';
    if (!res.epHits.length && !res.anyHits.length) {
      html += '<div class="lab-note">Sin coincidencias de packer/compilador conocido. No implica que ' +
        'no esté empaquetado — cruzá con la <b>entropía</b> y el <b>Rich Header</b>.</div>';
      return html;
    }
    if (res.epHits.length) {
      html += '<div class="lab-sub">En el entry point (0x' + (res.ep >>> 0).toString(16).toUpperCase() + ')</div>' +
        '<div class="lab-badges">' + res.epHits.map(n => '<span class="peid-hit">' + U.esc(n) + '</span>').join('') + '</div>';
    }
    if (res.anyHits.length) {
      html += '<div class="lab-sub">En el cuerpo del archivo</div><div class="peid-list">' +
        res.anyHits.map(h => '<div class="peid-row"><span class="peid-off">0x' + h.off.toString(16).toUpperCase() +
          '</span><span class="peid-hit alt">' + U.esc(h.n) + '</span></div>').join('') + '</div>';
    }
    return html;
  }

  function registerAnalyzer() {
    if (!Triage.analyzers || typeof Triage.analyzers.register !== 'function') return;
    Triage.analyzers.register({
      id: 'peid', title: 'Packer / Compiler', icon: '📦',
      applies(ctx) { return !!ctx.pe; },
      async run(ctx) {
        try { await ensureDB(); }
        catch (e) { return '<div class="lab-err">No se pudo cargar la base de firmas PEiD: ' + U.esc(e.message) + '</div>'; }
        return render(detect(ctx));
      },
    });
  }

  if (typeof window !== 'undefined' && window.Triage && Triage.analyzers) registerAnalyzer();
  // Hook de test (no-op en browser).
  return { compile, detect, matchAt, _setCompiled: (x) => { compiled = x; } };
})();
