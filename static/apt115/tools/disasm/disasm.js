// APT115 CODEX ARCANUM — Disassembler (Capstone WASM)
// solve et coagula
//
// Pegás bytes (hex en cualquier formato o base64) y los desensambla con
// Capstone v5 — x86/ARM/MIPS, 100% local. El motor (≈1.8 MB WASM) se carga
// PEREZOSAMENTE al primer "Desensamblar". Pareja natural del revshell/convert:
// pegás el shellcode que generaste y lo leés instrucción por instrucción.
//
// Motor: vendor/capstone/ (Capstone, BSD-3 · capstone-wasm) — ver
// vendor/LICENSE-capstone.txt.
//
// Carga: import() dinámico del módulo ESM vendorizado. Funciona en el sitio
// servido (deploy / `hugo server`); abierto como file:// el navegador bloquea
// la carga del módulo ESM (igual que el caveat de YARA con WASM en file://).

(function () {
  'use strict';

  const ENGINE_URL = 'vendor/capstone/index.mjs';
  const CAP = 4000; // tope de instrucciones renderizadas

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
  let lastText = '';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function ensureEngine() {
    if (!enginePromise) {
      const url = new URL(ENGINE_URL, document.baseURI).href;
      enginePromise = import(url)
        .then((m) => m.loadCapstone().then(() => m))
        .catch((e) => { enginePromise = null; throw new Error('no se pudo cargar el motor: ' + (e && e.message || e)); });
    }
    return enginePromise;
  }

  // Acepta: "55 48 89 e5", "5548 89e5", "\x55\x48", "0x55,0x48", "0x5548",
  // con o sin separadores. base64 si fmt='b64'.
  function parseInput(text, fmt) {
    text = (text || '').trim();
    if (!text) return new Uint8Array(0);
    if (fmt === 'b64') {
      const clean = text.replace(/\s+/g, '');
      const bin = atob(clean); // tira si no es base64 válido
      const b = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i) & 0xff;
      return b;
    }
    const hex = text.replace(/0x/gi, '').replace(/\\x/gi, '').replace(/[^0-9a-fA-F]/g, '');
    if (hex.length === 0) throw new Error('sin dígitos hex en la entrada');
    if (hex.length % 2) throw new Error('número impar de dígitos hex (' + hex.length + ')');
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function resolveMode(names, Const) {
    return names.reduce((acc, n) => acc | (Const[n] || 0), 0);
  }

  // Clase de color según el tipo de instrucción (control de flujo / syscalls).
  function mnClass(mn) {
    if (/^j/.test(mn)) return 'ds-jmp';                 // jmp, je, jne...
    if (/^(call|loop)/.test(mn)) return 'ds-call';
    if (/^(ret|leave|iret)/.test(mn)) return 'ds-ret';
    if (/^(syscall|sysenter|int|int3|svc)/.test(mn)) return 'ds-sys';
    if (/^(nop|hlt)/.test(mn)) return 'ds-dim';
    return '';
  }

  function toHex(b) { return b.toString(16).padStart(2, '0'); }

  function renderInsns(insns, bytes, base) {
    if (!insns.length) {
      return '<div class="lab-err">Capstone no decodificó ninguna instrucción ' +
        '(¿bytes inválidos para esta arquitectura?).</div>';
    }
    let decoded = 0;
    const lines = [];
    let html = '<table class="lab-table ds-table"><thead><tr>' +
      '<th>Dirección</th><th>Bytes</th><th>Instrucción</th></tr></thead><tbody>';
    for (const ins of insns.slice(0, CAP)) {
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
    lastText = lines.join('\n');

    let note = insns.length + ' instrucciones · ' + decoded + '/' + bytes.length + ' bytes decodificados';
    if (insns.length > CAP) note += ' · <span class="lab-dim">mostrando ' + CAP + '</span>';
    if (decoded < bytes.length) {
      note += ' · <span class="ds-warn">se detuvo en un byte inválido @ 0x' +
        (base + decoded).toString(16) + '</span>';
    }
    return '<div class="lab-row1" style="margin-bottom:6px">' + note + '</div>' + html;
  }

  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">⚙ Disassembler</div>' +
      '<span class="sec-cmds-badge">Capstone · local</span></div>' +
      '<div class="lab-intro">Pegá bytes (hex o base64) y los desensambla con ' +
      '<b>Capstone</b> — x86/ARM/MIPS, 100% local. Ideal para leer el shellcode ' +
      'que sale del revshell/convert. El motor (≈1.8 MB) se carga al primer uso.</div>' +
      '<div class="ds-bar">' +
        '<button class="yr-run" id="dsRun">▶ Desensamblar</button>' +
        '<select class="lr-cat" id="dsArch">' +
          ARCHES.map(a => '<option value="' + a.id + '"' + (a.id === 'x64' ? ' selected' : '') + '>' + a.label + '</option>').join('') +
        '</select>' +
        '<select class="lr-cat" id="dsFmt">' +
          '<option value="hex">hex</option><option value="b64">base64</option>' +
        '</select>' +
        '<label class="ioc-chk">base <input class="cv-key" id="dsAddr" value="0x1000" style="max-width:110px"></label>' +
        '<button class="cv-btn" id="dsCopy">copiar</button>' +
        '<span class="yr-status lab-dim" id="dsStatus"></span>' +
      '</div>' +
      '<textarea class="yr-editor" id="dsIn" spellcheck="false" style="min-height:90px" ' +
        'placeholder="Pegá bytes acá…  ej: 55 48 89 e5 48 31 c0 c3   o   \\x55\\x48\\x89\\xe5"></textarea>' +
      '<div id="dsOut"></div>';

    const btn = container.querySelector('#dsRun');
    btn.onclick = () => doDisasm(container);
    container.querySelector('#dsIn').addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); doDisasm(container); }
    });
    container.querySelector('#dsCopy').onclick = () => { if (lastText && window.LAB) LAB.copy(lastText); };
  }

  async function doDisasm(container) {
    const out = container.querySelector('#dsOut');
    const btn = container.querySelector('#dsRun');
    const status = container.querySelector('#dsStatus');
    const fmt = container.querySelector('#dsFmt').value;
    const archId = container.querySelector('#dsArch').value;
    const base = parseInt(container.querySelector('#dsAddr').value, 16) || 0;

    let bytes;
    try { bytes = parseInput(container.querySelector('#dsIn').value, fmt); }
    catch (e) { out.innerHTML = '<div class="lab-err">Entrada inválida: ' + esc(e.message) + '</div>'; return; }
    if (!bytes.length) { out.innerHTML = '<div class="lab-note">Pegá algunos bytes para desensamblar.</div>'; return; }

    btn.disabled = true;
    const firstLoad = !enginePromise;
    out.innerHTML = '<div class="lab-loading">⬡ ' + (firstLoad ? 'Cargando el motor Capstone…' : 'Desensamblando…') + '</div>';
    try {
      const m = await ensureEngine();
      if (status) status.textContent = '';
      const arch = ARCHES.find(a => a.id === archId) || ARCHES[0];
      const cs = new m.Capstone(m.Const[arch.a], resolveMode(arch.m, m.Const));
      let insns;
      try { insns = cs.disasm(bytes, { address: base }); }
      finally { cs.close(); }
      out.innerHTML = renderInsns(insns, bytes, base);
    } catch (e) {
      console.error('[disasm]', e);
      out.innerHTML = '<div class="lab-err">Error del desensamblador: ' + esc(e && e.message || e) + '</div>';
    } finally {
      btn.disabled = false;
    }
  }

  if (typeof window !== 'undefined' && window.LAB) {
    LAB.registerTool({ id: 'disasm', label: 'Disassembler', icon: '⚙', group: '🧪 LAB / TOOLS', render });
  }
  // Hook de test (no-op en browser).
  if (typeof module !== 'undefined' && module.exports) module.exports = { parseInput, mnClass, resolveMode };
})();
