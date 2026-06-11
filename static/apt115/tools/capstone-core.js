// APT115 CODEX ARCANUM — Capstone core (loader + render compartidos)
// solve et coagula
//
// Servicio compartido del LAB sobre Capstone v5 WASM (vendor/capstone/).
// Centraliza la carga PEREZOSA del motor (una sola instancia por sesión), el
// desensamblado, el mapa de arquitecturas y el render de tabla. Lo consumen el
// tool `disasm` y el analyzer `epdisasm` del triage — una sola fuente de verdad
// para el WASM de ~1.8 MB, que se paga una vez y sólo si el usuario lo pide.
//
// Carga: import() dinámico del ESM vendorizado. NO corre en file:// (el
// navegador bloquea el módulo ESM/WASM); sí servido (deploy / `hugo server`).
//
// Motor: vendor/capstone/ (Capstone, BSD-3 · capstone-wasm) — ver
// vendor/LICENSE-capstone.txt.

(function () {
  'use strict';

  const ENGINE_URL = 'vendor/capstone/index.mjs';
  const DEFAULT_CAP = 4000; // tope de instrucciones renderizadas

  // arch/mode por nombre de constante (se resuelven con el Const del módulo).
  const ARCHES = [
    { id: 'x64', label: 'x86-64', a: 'CS_ARCH_X86', m: ['CS_MODE_64'] },
    { id: 'x32', label: 'x86-32', a: 'CS_ARCH_X86', m: ['CS_MODE_32'] },
    { id: 'x16', label: 'x86-16', a: 'CS_ARCH_X86', m: ['CS_MODE_16'] },
    { id: 'arm', label: 'ARM', a: 'CS_ARCH_ARM', m: ['CS_MODE_ARM'] },
    { id: 'thumb', label: 'ARM Thumb', a: 'CS_ARCH_ARM', m: ['CS_MODE_THUMB'] },
    { id: 'arm64', label: 'ARM64', a: 'CS_ARCH_ARM64', m: ['CS_MODE_ARM'] },
    { id: 'mips32', label: 'MIPS32', a: 'CS_ARCH_MIPS', m: ['CS_MODE_32'] },
    { id: 'mips64', label: 'MIPS64', a: 'CS_ARCH_MIPS', m: ['CS_MODE_64'] },
  ];

  let enginePromise = null;

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function toHex(b) { return b.toString(16).padStart(2, '0'); }

  // Clase de color según el tipo de instrucción (control de flujo / syscalls).
  function mnClass(mn) {
    if (/^j/.test(mn)) return 'ds-jmp';                 // jmp, je, jne...
    if (/^(call|loop)/.test(mn)) return 'ds-call';
    if (/^(ret|leave|iret)/.test(mn)) return 'ds-ret';
    if (/^(syscall|sysenter|int|int3|svc)/.test(mn)) return 'ds-sys';
    if (/^(nop|hlt)/.test(mn)) return 'ds-dim';
    return '';
  }

  function resolveMode(names, Const) {
    return names.reduce((acc, n) => acc | (Const[n] || 0), 0);
  }

  // Resuelve un arch por id del mapa, o acepta un objeto {a, m} directo.
  function resolveArch(arch) {
    if (arch && typeof arch === 'object' && arch.a) return arch;
    return ARCHES.find(a => a.id === arch) || ARCHES[0];
  }

  // Carga perezosa del motor; cachea la promesa (una sola instancia por sesión).
  function load() {
    if (!enginePromise) {
      const baseURI = (typeof document !== 'undefined' && document.baseURI) || '';
      const url = baseURI ? new URL(ENGINE_URL, baseURI).href : ENGINE_URL;
      enginePromise = import(url)
        .then((m) => m.loadCapstone().then(() => m))
        .catch((e) => { enginePromise = null; throw new Error('no se pudo cargar el motor: ' + (e && e.message || e)); });
    }
    return enginePromise;
  }

  // ¿Está el motor ya cargado en esta sesión? (para el copy de "Cargando…").
  function loaded() { return enginePromise != null; }

  // Desensambla `bytes` con un arch (id del mapa u objeto {a,m}) desde `address`.
  // Devuelve el array de instrucciones de Capstone. Crea y cierra la instancia.
  async function run(bytes, opts) {
    opts = opts || {};
    const m = await load();
    const arch = resolveArch(opts.arch);
    const cs = new m.Capstone(m.Const[arch.a], resolveMode(arch.m, m.Const));
    try {
      return cs.disasm(bytes, { address: opts.address || 0 });
    } finally {
      cs.close();
    }
  }

  // Render de tabla compartido. Devuelve { html, text, decoded, stoppedAt }.
  // `base` = dirección de la primera instrucción; `opts.cap` = tope a renderizar.
  function renderTable(insns, bytes, base, opts) {
    base = base || 0;
    opts = opts || {};
    const cap = opts.cap || DEFAULT_CAP;
    if (!insns.length) {
      return {
        html: '<div class="lab-err">Capstone no decodificó ninguna instrucción ' +
          '(¿bytes inválidos para esta arquitectura?).</div>',
        text: '', decoded: 0, stoppedAt: base,
      };
    }
    let decoded = 0;
    const lines = [];
    let html = '<table class="lab-table ds-table"><thead><tr>' +
      '<th>Dirección</th><th>Bytes</th><th>Instrucción</th></tr></thead><tbody>';
    for (const ins of insns.slice(0, cap)) {
      decoded += ins.size;
      const addr = '0x' + (typeof ins.address === 'bigint' ? ins.address.toString(16) : (ins.address >>> 0).toString(16));
      const hex = [...ins.bytes].map(toHex).join(' ');
      const cls = mnClass(ins.mnemonic);
      html += '<tr><td class="ds-addr">' + addr + '</td>' +
        '<td class="ds-bytes">' + hex + '</td>' +
        '<td class="ds-insn"><span class="ds-mn ' + cls + '">' + esc(ins.mnemonic) + '</span>' +
        (ins.opStr ? ' <span class="ds-ops">' + esc(ins.opStr) + '</span>' : '') + '</td></tr>';
      lines.push(addr.padEnd(12) + hex.padEnd(24) + ins.mnemonic + (ins.opStr ? ' ' + ins.opStr : ''));
    }
    html += '</tbody></table>';

    let note = insns.length + ' instrucciones · ' + decoded + '/' + bytes.length + ' bytes decodificados';
    if (insns.length > cap) note += ' · <span class="lab-dim">mostrando ' + cap + '</span>';
    if (decoded < bytes.length) {
      note += ' · <span class="ds-warn">se detuvo en un byte inválido @ 0x' +
        (base + decoded).toString(16) + '</span>';
    }
    return {
      html: '<div class="lab-row1" style="margin-bottom:6px">' + note + '</div>' + html,
      text: lines.join('\n'),
      decoded,
      stoppedAt: base + decoded,
    };
  }

  const api = {
    ENGINE_URL, ARCHES, load, loaded, run, renderTable,
    resolveArch, resolveMode, mnClass, toHex, esc,
  };

  if (typeof window !== 'undefined') {
    window.LAB = window.LAB || {};
    window.LAB.capstone = api;
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})();
