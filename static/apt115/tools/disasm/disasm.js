// APT115 CODEX ARCANUM — Disassembler (Capstone WASM)
// solve et coagula
//
// Pegás bytes (hex en cualquier formato o base64) y los desensambla con
// Capstone v5 — x86/ARM/MIPS, 100% local. El motor (≈1.8 MB WASM) se carga
// PEREZOSAMENTE al primer "Desensamblar". Pareja natural del revshell/convert:
// pegás el shellcode que generaste y lo leés instrucción por instrucción.
//
// El motor, el mapa de arquitecturas y el render de tabla viven en el servicio
// compartido `LAB.capstone` (tools/capstone-core.js); este tool sólo aporta el
// parseo de la entrada (hex/base64) y la UI. Misma fuente de verdad que usa el
// analyzer `epdisasm` del triage.
//
// Carga: import() dinámico del módulo ESM vendorizado. Funciona en el sitio
// servido (deploy / `hugo server`); abierto como file:// el navegador bloquea
// la carga del módulo ESM (igual que el caveat de YARA con WASM en file://).

(function () {
  'use strict';

  // Servicio compartido (loader + arches + render). En browser viene del
  // <script> previo; en Node (tests) se resuelve por require.
  const CS = (typeof window !== 'undefined' && window.LAB && window.LAB.capstone) ||
    (typeof require === 'function' ? (function () { try { return require('../capstone-core.js'); } catch (_) { return null; } })() : null);

  const ARCHES = (CS && CS.ARCHES) || [];

  let lastText = '';

  function esc(s) {
    if (CS) return CS.esc(s);
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
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
    const firstLoad = !CS.loaded();
    out.innerHTML = '<div class="lab-loading">⬡ ' + (firstLoad ? 'Cargando el motor Capstone…' : 'Desensamblando…') + '</div>';
    try {
      const insns = await CS.run(bytes, { arch: archId, address: base });
      if (status) status.textContent = '';
      const res = CS.renderTable(insns, bytes, base);
      lastText = res.text;
      out.innerHTML = res.html;
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
  if (typeof module !== 'undefined' && module.exports) module.exports = { parseInput };
})();
