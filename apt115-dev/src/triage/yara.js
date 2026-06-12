// APT115 CODEX ARCANUM — Motor YARA para el Malware Triage
// solve et coagula
//
// Enchufa libyara (YARA de VirusTotal) compilado a WASM dentro del analyzer
// `yara` de tools/triage/analyzers.js. Escanea el archivo cargado 100% LOCAL:
// ni un byte sale del navegador. El motor (≈1.2 MB, WASM embebido en base64)
// se carga PEREZOSAMENTE recién al primer "Escanear", no al abrir el archivo.
//
// Motor: vendor/yara/libyara-wasm.js (libyara-wasm de Matt Coomber, ISC; libyara
// de VirusTotal, BSD-3) — ver vendor/LICENSE-libyara-wasm.txt.
//
// Contrato con el analyzer: define window.Triage.yara.scan(ctx) -> HTML string.
// El analyzer lo detecta en runtime; este script puede cargarse en cualquier orden.

if (typeof window !== 'undefined') window.Triage = window.Triage || {};
export const yara = (function () {
  'use strict';

  const ENGINE_SRC = 'vendor/yara/libyara-wasm.js';
  const MAX_ROWS = 60;        // tope de coincidencias mostradas por regla
  const HEX_BYTES = 24;       // bytes de preview por match

  // El heap WASM de Emscripten solo CRECE: engine.run() copia el archivo
  // adentro y esa memoria nunca vuelve. Tras escanear un archivo grande,
  // soltamos la instancia (el próximo escaneo re-instancia: el script ya está
  // cargado, el init es sub-segundo) para que el GC devuelva todo el heap.
  const ENGINE_RECYCLE_BYTES = 32 * 1024 * 1024;

  let enginePromise = null;   // cache del motor (instancia única mientras no se recicle)
  let lastCtx = null;         // ctx del archivo actualmente cargado en el panel
  let activePack = null;      // id del pack seleccionado (las reglas NO se vuelcan al editor)

  // Reglas de ejemplo: útiles y offline. Sin `import` de módulos (pe/math) para
  // que compilen en este build mínimo de libyara. Editá libremente y re-escaneá.
  const DEFAULT_RULES = [
    'rule MZ_PE_header',
    '{',
    '    meta:',
    '        description = "Ejecutable Windows (cabecera MZ/PE)"',
    '    condition:',
    '        uint16(0) == 0x5A4D',
    '}',
    '',
    'rule UPX_packer',
    '{',
    '    meta:',
    '        description = "Indicios de empaquetado UPX"',
    '    strings:',
    '        $u0 = "UPX0"',
    '        $u1 = "UPX1"',
    '        $sig = "UPX!"',
    '    condition:',
    '        2 of them',
    '}',
    '',
    'rule Suspicious_WinAPI',
    '{',
    '    meta:',
    '        description = "APIs frecuentes en loaders / inyeccion"',
    '    strings:',
    '        $a = "VirtualAlloc" ascii wide',
    '        $b = "WriteProcessMemory" ascii wide',
    '        $c = "CreateRemoteThread" ascii wide',
    '        $d = "LoadLibrary" ascii wide',
    '        $e = "GetProcAddress" ascii wide',
    '    condition:',
    '        3 of them',
    '}',
    '',
    'rule Embedded_PE',
    '{',
    '    meta:',
    '        description = "Posible PE incrustado (mas de una cabecera MZ)"',
    '    strings:',
    '        $mz = { 4D 5A }',
    '    condition:',
    '        #mz > 1',
    '}',
    '',
    'rule PowerShell_dropper',
    '{',
    '    meta:',
    '        description = "PowerShell codificado / descarga remota"',
    '    strings:',
    '        $enc = "-enc" ascii wide nocase',
    '        $eb  = "-EncodedCommand" ascii wide nocase',
    '        $dl  = "DownloadString" ascii wide nocase',
    '        $iex = "IEX (" ascii wide nocase',
    '    condition:',
    '        any of them',
    '}',
  ].join('\n');

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  function escAttr(s) { return esc(s).replace(/"/g, '&quot;'); }

  function loadScript(src) {
    return new Promise((res, rej) => {
      const s = document.createElement('script');
      s.src = src; s.onload = res;
      s.onerror = () => rej(new Error('No se pudo cargar el motor (' + src + ')'));
      document.head.appendChild(s);
    });
  }

  // Carga perezosa del motor. window.Module es el factory de Emscripten; al
  // invocarlo devuelve una promesa que resuelve la instancia ya inicializada.
  function ensureEngine() {
    if (!enginePromise) {
      enginePromise = (window.Module ? Promise.resolve() : loadScript(ENGINE_SRC))
        .then(() => {
          if (typeof window.Module !== 'function') {
            throw new Error('El motor se cargó pero no expuso su API.');
          }
          return window.Module();
        })
        .catch((e) => { enginePromise = null; throw e; }); // permitir reintento
    }
    return enginePromise;
  }

  // Packs de reglas vendorizados, cargados perezosamente (data/yara-rules-*.js
  // setean window.YARA_PACKS[<id>] = { name, count, rules }).
  const PACK_SRC = {
    mandiant: 'data/yara-rules-mandiant.js',
    gcti: 'data/yara-rules-gcti.js',
    reversinglabs: 'data/yara-rules-reversinglabs.js',
    'signature-base': 'data/yara-rules-signature-base.js',
  };
  const packPromises = {};
  function ensurePack(id) {
    if (!packPromises[id]) {
      const have = window.YARA_PACKS && window.YARA_PACKS[id];
      packPromises[id] = (have ? Promise.resolve() : loadScript(PACK_SRC[id]))
        .then(() => {
          const p = window.YARA_PACKS && window.YARA_PACKS[id];
          if (!p) throw new Error('el pack se cargó pero no expuso sus reglas');
          return p;
        })
        .catch((e) => { packPromises[id] = null; throw e; });
    }
    return packPromises[id];
  }

  // ── UI (devuelta por el analyzer; se inyecta vía innerHTML) ─────────────
  function scan(ctx) {
    lastCtx = ctx;
    activePack = null; // panel nuevo → vuelve a las reglas del editor
    return '' +
      '<div class="lab-row1">Reglas YARA contra <b>' + esc(ctx.file.name) + '</b> ' +
      '<span class="lab-dim">— el motor (≈1.2 MB) se carga al primer escaneo; ' +
      'el archivo nunca sale de tu navegador.</span></div>' +
      '<div class="yr-bar">' +
        '<button class="yr-run" onclick="Triage.yara.run(this)">▶ Escanear</button>' +
        '<select class="yr-pack lr-cat" onchange="Triage.yara.loadPack(this)" ' +
          'title="Cargar un set de reglas en el editor">' +
          '<option value="">cargar reglas…</option>' +
          '<option value="example">Reglas de ejemplo</option>' +
          '<option value="mandiant">Mandiant Red Team (169)</option>' +
          '<option value="gcti">GCTI · Cobalt Strike / C2 (91)</option>' +
          '<option value="reversinglabs">ReversingLabs · malware (1240)</option>' +
          '<option value="signature-base">signature-base · Florian Roth (5271)</option>' +
        '</select>' +
        '<span class="yr-status lab-dim"></span>' +
      '</div>' +
      '<textarea class="yr-editor" spellcheck="false" ' +
        'oninput="Triage.yara.editorTouched(this)" ' +
        'placeholder="Pegá tus reglas YARA acá…">' + esc(DEFAULT_RULES) + '</textarea>' +
      '<div class="yr-out"></div>';
  }

  // Activa un set de reglas. Los packs grandes se bajan lazy y NO se vuelcan
  // al editor (un textarea de ~6 MB cuesta RAM y layout): quedan como pack
  // activo y run() los toma de window.YARA_PACKS. Escribir en el editor
  // desactiva el pack.
  async function loadPack(sel) {
    const val = sel.value;
    const panel = sel.closest('.lab-panel-b');
    const ed = panel.querySelector('.yr-editor');
    sel.value = ''; // el select vuelve al placeholder; es una acción, no un estado
    if (!val || !ed) return;
    if (val === 'example') {
      activePack = null;
      ed.value = DEFAULT_RULES;
      setStatus(panel, 'reglas de ejemplo cargadas');
      return;
    }
    setStatus(panel, 'cargando pack…');
    try {
      const p = await ensurePack(val);
      activePack = val;
      ed.value = '// Pack activo: ' + p.name + ' (' + p.count + ' reglas) — se usa completo al escanear.\n' +
        '// Escribí acá para usar reglas propias (desactiva el pack).';
      setStatus(panel, p.count + ' reglas (' + p.name + ') — ⚠ set grande, el escaneo puede tardar');
    } catch (e) {
      setStatus(panel, 'no se pudo cargar el pack: ' + (e && e.message || e));
    }
  }

  // El usuario escribió en el editor → manda el texto, no el pack.
  function editorTouched(ta) {
    if (!activePack) return;
    activePack = null;
    const panel = ta.closest('.lab-panel-b');
    if (panel) setStatus(panel, 'usando reglas del editor');
  }

  function setStatus(panel, msg) {
    const el = panel.querySelector('.yr-status');
    if (el) el.textContent = msg || '';
  }

  async function run(btn) {
    const panel = btn.closest('.lab-panel-b');
    const ed = panel.querySelector('.yr-editor');
    const out = panel.querySelector('.yr-out');
    const ctx = lastCtx;

    // Reglas efectivas: el pack activo (completo, desde window.YARA_PACKS) o el editor.
    const pack = activePack && window.YARA_PACKS && window.YARA_PACKS[activePack];
    const rules = pack ? pack.rules : (ed && ed.value || '').trim();
    if (!rules) { out.innerHTML = '<div class="lab-note">Escribí o pegá al menos una regla.</div>'; return; }
    if (!ctx || !ctx.bytes) { out.innerHTML = '<div class="lab-err">No hay archivo cargado para escanear.</div>'; return; }

    btn.disabled = true;
    const firstLoad = !enginePromise;
    out.innerHTML = '<div class="lab-loading">⬡ ' +
      (firstLoad ? 'Cargando el motor YARA…' : 'Escaneando…') + '</div>';

    try {
      const engine = await ensureEngine();
      setStatus(panel, '');
      out.innerHTML = '<div class="lab-loading">⬡ Escaneando ' + esc(ctx.file.name) + ' …</div>';
      // Cedemos un tick para que el "Escaneando…" pinte antes del run síncrono.
      await new Promise((r) => setTimeout(r, 16));
      const res = engine.run(ctx.bytes, rules); // ctx.bytes (Uint8Array) → bytes crudos
      out.innerHTML = renderResults(res, ctx);
      // Archivo grande: soltar la instancia para devolver el heap WASM (ver
      // ENGINE_RECYCLE_BYTES). El próximo escaneo re-instancia transparente.
      if (ctx.bytes.length > ENGINE_RECYCLE_BYTES) enginePromise = null;
    } catch (e) {
      console.error('[triage] yara', e);
      out.innerHTML = '<div class="lab-err">Error del motor YARA: ' + esc(e && e.message || e) + '</div>';
    } finally {
      btn.disabled = false;
    }
  }

  function vec(v) {
    const a = [];
    if (!v || typeof v.size !== 'function') return a;
    for (let i = 0; i < v.size(); i++) a.push(v.get(i));
    return a;
  }

  // Preview hex+ascii leyendo los bytes ORIGINALES (el `data` del match viene
  // como string y se corrompe con bytes binarios; los bytes crudos no mienten).
  function hexPreview(bytes, off, len) {
    const n = Math.min(len, HEX_BYTES);
    let hex = '', asc = '';
    for (let i = 0; i < n; i++) {
      const b = bytes[off + i];
      if (b === undefined) break;
      hex += b.toString(16).padStart(2, '0').toUpperCase() + ' ';
      asc += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.';
    }
    if (len > n) hex += '…';
    return { hex: hex.trim(), asc };
  }

  function renderResults(res, ctx) {
    const compileMsgs = vec(res.compileErrors);
    const matched = vec(res.matchedRules);
    let html = '';

    // libyara mete errores Y advertencias en la misma lista, pero cada mensaje
    // trae un flag `warning`: true = advertencia (no fatal, la regla igual
    // compila y escanea); false = error real (aborta TODA la compilación → 0
    // matches). Las separamos para no alarmar por un warning cosmético.
    const errors = compileMsgs.filter((m) => m.warning === false);
    const warnings = compileMsgs.filter((m) => m.warning !== false);

    if (errors.length) {
      html += '<div class="lab-err">✖ Errores de compilación (' + errors.length + ') — ' +
        'la compilación se abortó, ninguna regla se evaluó:' +
        '<div class="yr-msgs">' +
        errors.map((m) => '<div>línea ' + (m.lineNumber != null ? m.lineNumber : '?') +
          ': ' + esc(m.message) + '</div>').join('') +
        '</div></div>';
    }
    if (warnings.length) {
      html += '<div class="lab-note lab-dim">⚠ ' + warnings.length + ' advertencia' +
        (warnings.length === 1 ? '' : 's') + ' del compilador (cosméticas; las reglas igual escanean):' +
        '<div class="yr-msgs">' +
        warnings.map((m) => '<div>línea ' + (m.lineNumber != null ? m.lineNumber : '?') +
          ': ' + esc(m.message) + '</div>').join('') +
        '</div></div>';
    }

    if (!matched.length) {
      html += '<div class="lab-row1" style="margin-top:8px">' +
        (errors.length
          ? 'No hubo coincidencias: la compilación falló (ver errores arriba).'
          : '✓ Sin coincidencias. Las reglas compilaron pero nada matcheó este archivo.') +
        '</div>';
      return html;
    }

    html += '<div class="lab-sub">' + matched.length + ' regla' +
      (matched.length === 1 ? '' : 's') + ' con coincidencias</div>';

    for (const mr of matched) {
      const meta = vec(mr.metadata);
      const matches = vec(mr.resolvedMatches);
      html += '<div class="yr-rule">';
      const cnt = matches.length
        ? matches.length + ' match' + (matches.length === 1 ? '' : 'es')
        : 'por condición';
      html += '<div class="yr-rule-h">⊳ ' + esc(mr.ruleName) +
        ' <span class="lab-dim">(' + cnt + ')</span></div>';

      const desc = meta.find((m) => m.identifier === 'description');
      if (desc) html += '<div class="yr-rule-desc">' + esc(desc.data) + '</div>';
      const otherMeta = meta.filter((m) => m.identifier !== 'description');
      if (otherMeta.length) {
        html += '<div class="yr-meta">' +
          otherMeta.map((m) => '<span class="yr-meta-k">' + esc(m.identifier) + '</span>=' +
            '<span class="yr-meta-v">' + esc(String(m.data)) + '</span>').join('') + '</div>';
      }

      if (matches.length) {
        html += '<table class="lab-table yr-matches"><thead><tr>' +
          '<th>Offset</th><th>String</th><th>Bytes</th><th>ASCII</th></tr></thead><tbody>';
        for (const m of matches.slice(0, MAX_ROWS)) {
          const pv = hexPreview(ctx.bytes, m.location, m.matchLength);
          html += '<tr>' +
            '<td class="yr-off">0x' + (m.location >>> 0).toString(16).toUpperCase() + '</td>' +
            '<td class="yr-sid">' + esc(m.stringIdentifier) + '</td>' +
            '<td class="yr-hex">' + esc(pv.hex) + '</td>' +
            '<td class="yr-asc">' + esc(pv.asc) + '</td>' +
            '</tr>';
        }
        html += '</tbody></table>';
        if (matches.length > MAX_ROWS) {
          html += '<div class="lab-dim" style="font-size:10.5px;margin-top:4px">' +
            '… ' + (matches.length - MAX_ROWS) + ' coincidencias más (truncado).</div>';
        }
      }
      html += '</div>';
    }
    return html;
  }

  // Suelta el archivo retenido (lo invoca el releaseAll del registry al cargar otro).
  function release() { lastCtx = null; activePack = null; }

  window.Triage.yara = { scan, run, loadPack, editorTouched, release };
})();
