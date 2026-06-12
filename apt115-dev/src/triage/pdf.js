// APT115 CODEX ARCANUM — Triage analyzer: pdf (documentos PDF maliciosos)
// quod est superius est sicut quod inferius
//
// Triage de PDF estilo pdfid (Didier Stevens) + un nivel de stream. Los PDF son vector
// de acceso inicial: auto-ejecutan JavaScript al abrir, lanzan programas (/Launch),
// traen archivos embebidos o explotan decoders (JBIG2). Dos niveles:
//
//   1. Estructura (síncrono): versión, conteo de keywords sospechosas con detección de
//      OFUSCACIÓN de nombres (/J#61vaScript ≡ /JavaScript), estructura (obj/stream/xref),
//      acciones automáticas (/OpenAction+/JS), /Launch, /EmbeddedFile, URIs, datos tras EOF.
//   2. Streams (perezoso, navegador): INFLA los streams FlateDecode con DecompressionStream
//      nativo y caza JavaScript ofuscado adentro (eval/unescape/fromCharCode/heap-spray/
//      APIs de Acrobat con CVE conocido) + magics de archivos embebidos.
//
// 100% local, sin vendor (DecompressionStream es nativo). Núcleo síncrono verificable en
// Node contra pdfid.py / peepdf.

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

export const pdf = (function () {
  'use strict';

  function U() { return window.Triage.util; }
  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

  function isPdf(b) {
    // %PDF dentro de los primeros 1KB (algunos traen basura/BOM antes).
    const n = Math.min(b.length, 1024);
    for (let i = 0; i + 4 < n; i++) if (b[i] === 0x25 && b[i + 1] === 0x50 && b[i + 2] === 0x44 && b[i + 3] === 0x46) return i;
    return -1;
  }

  // Nombres PDF sospechosos (sin el '/'). Etiqueta = motivo.
  const NAMES = [
    ['OpenAction', 'acción automática al abrir el documento'],
    ['AA', 'additional actions (auto-ejecución en eventos)'],
    ['JavaScript', 'JavaScript embebido'],
    ['JS', 'JavaScript embebido'],
    ['Launch', 'lanza un programa externo'],
    ['EmbeddedFile', 'archivo embebido'],
    ['JBIG2Decode', 'decoder históricamente explotable (CVEs)'],
    ['RichMedia', 'Flash / medios embebidos'],
    ['XFA', 'formularios XML (XFA)'],
    ['AcroForm', 'formularios'],
    ['URI', 'URL'],
    ['SubmitForm', 'envía datos a una URL'],
    ['GoToR', 'acción a archivo remoto'],
    ['GoToE', 'acción a archivo embebido'],
    ['ObjStm', 'object stream (puede ocultar objetos del análisis)'],
    ['Encrypt', 'documento cifrado'],
    ['GoTo', 'navegación interna'],
  ];
  const STRUCT = ['obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref'];

  // Conteo de tokens estructurales como pdfid: 'obj' NO debe contar dentro de 'endobj'
  // ni 'stream' dentro de 'endstream' ni 'xref' dentro de 'startxref'.
  const STRUCT_RE = {
    obj: /(?<!end)obj\b/g, endobj: /endobj\b/g,
    stream: /(?<!end)stream\b/g, endstream: /endstream\b/g,
    xref: /(?<!start)xref\b/g, trailer: /trailer\b/g, startxref: /startxref\b/g,
  };
  function structCounts(s) {
    const o = {};
    for (const k of STRUCT) o[k] = (s.match(STRUCT_RE[k]) || []).length;
    return o;
  }

  function decodeName(raw) {
    return raw.replace(/#([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  }

  const DELIM = { ' ': 1, '\t': 1, '\n': 1, '\r': 1, '\f': 1, '\0': 1, '(': 1, ')': 1, '<': 1, '>': 1, '[': 1, ']': 1, '{': 1, '}': 1, '/': 1, '%': 1 };

  // Un solo pase: recolecta nombres (decodificando #xx) y marca cuáles venían ofuscados.
  function scanNames(s) {
    const counts = {}, obf = {};
    for (let i = 0; i < s.length; i++) {
      if (s[i] !== '/') continue;
      let j = i + 1, raw = '';
      while (j < s.length && !DELIM[s[j]]) { raw += s[j]; j++; }
      if (raw) {
        const dec = decodeName(raw);
        counts[dec] = (counts[dec] || 0) + 1;
        if (raw.indexOf('#') >= 0) obf[dec] = (obf[dec] || 0) + 1;
      }
      i = j - 1;
    }
    return { counts, obf };
  }

  function countWord(s, w) {
    let n = 0, p = 0;
    while ((p = s.indexOf(w, p)) >= 0) { n++; p += w.length; }
    return n;
  }

  // URIs declaradas (/URI (...)) y destinos de /Launch ( /F (...) ).
  function extractTargets(s) {
    const uris = new Set(), launch = new Set();
    let m; const reUri = /\/URI\s*\(([^)]{1,400})\)/g;
    while ((m = reUri.exec(s)) !== null) uris.add(m[1]);
    const reHttp = /\((https?:\/\/[^)]{3,400})\)/g;
    while ((m = reHttp.exec(s)) !== null) uris.add(m[1]);
    const reLaunch = /\/Launch[\s\S]{0,120}?\/F\s*\(([^)]{1,300})\)/g;
    while ((m = reLaunch.exec(s)) !== null) launch.add(m[1]);
    const reWin = /\/Win\s*<<[\s\S]{0,80}?\/F\s*\(([^)]{1,300})\)/g;
    while ((m = reWin.exec(s)) !== null) launch.add(m[1]);
    return { uris: [...uris], launch: [...launch] };
  }

  let lastCtx = null, lastStr = '';

  function analyze(ctx) {
    lastCtx = ctx;
    const off = isPdf(ctx.bytes);
    const s = new TextDecoder('latin1').decode(ctx.bytes);
    lastStr = s;

    const ver = (s.slice(off, off + 16).match(/%PDF-(\d\.\d)/) || [])[1] || '?';
    const { counts, obf } = scanNames(s);
    const has = (k) => counts[k] || 0;
    const { uris, launch } = extractTargets(s);

    // Veredicto / indicadores
    const flags = [];
    if ((has('OpenAction') || has('AA')) && (has('JavaScript') || has('JS')))
      flags.push('AUTO-EJECUTA JavaScript al abrir (/OpenAction|/AA + /JS) — patrón malicioso clásico');
    else if (has('JavaScript') || has('JS')) flags.push('contiene JavaScript embebido');
    if (has('Launch') || launch.length) flags.push('acción /Launch: puede ejecutar un programa externo' + (launch.length ? ' → ' + launch.map(esc).join(', ') : ''));
    if (has('EmbeddedFile')) flags.push('trae ' + has('EmbeddedFile') + ' archivo(s) embebido(s) (/EmbeddedFile)');
    if (has('JBIG2Decode')) flags.push('/JBIG2Decode presente (decoder con CVEs históricos)');
    if (has('RichMedia')) flags.push('/RichMedia (Flash) embebido');
    if (has('GoToE')) flags.push('/GoToE: acción hacia un archivo embebido');
    const obfNames = Object.keys(obf);
    if (obfNames.length) flags.push('nombres OFUSCADOS con #xx (' + obfNames.map(esc).join(', ') + ') — evasión de parsers/AV');

    let html = '<div class="lab-row1">PDF ' + esc(ver) + (off > 0 ? ' <span class="ds-warn">(header @ offset ' + off + ', no en 0)</span>' : '') +
      ' · análisis estilo <b>pdfid</b>. <span class="lab-dim">Los keywords son indicio, no prueba; confirmá con el nivel de stream.</span></div>';

    if (flags.length) {
      html += '<div class="lab-sub">Indicadores</div><div class="lab-note">⚠ ' + flags.map(esc).join('<br>⚠ ') + '</div>';
    } else {
      html += '<div class="lab-note">Sin acciones automáticas ni JavaScript declarado. Igual puede traer contenido en streams comprimidos — revisá abajo.</div>';
    }

    // Tabla de keywords (solo los presentes)
    const rows = [];
    for (const [name, why] of NAMES) {
      const c = has(name);
      if (!c) continue;
      rows.push([esc('/' + name) + (obf[name] ? ' <span class="ds-warn">(' + obf[name] + ' ofuscado)</span>' : ''),
        '<b>' + c + '</b> <span class="lab-dim">' + esc(why) + '</span>']);
    }
    if (rows.length) html += '<div class="lab-sub">Keywords sospechosas</div>' + kv(rows);

    // Estructura
    const sc = structCounts(s);
    const eof = countWord(s, '%%EOF');
    html += '<div class="lab-sub">Estructura</div>' +
      kv(STRUCT.map(w => [esc(w), String(sc[w])]).concat([['%%EOF', String(eof) + (eof > 1 ? ' <span class="lab-dim">(actualizaciones incrementales / append)</span>' : '')]]));

    // URIs
    if (uris.length) {
      html += '<div class="lab-sub">URLs (' + uris.length + ')</div><div class="lab-strings dim">' +
        uris.slice(0, 30).map(u => '<div class="lab-str"><code>' + esc(u.slice(0, 200)) + '</code></div>').join('') + '</div>';
    }

    // Datos tras el último %%EOF
    const lastEof = s.lastIndexOf('%%EOF');
    if (lastEof >= 0) {
      let tEnd = lastEof + 5;
      while (tEnd < s.length && (s[tEnd] === '\r' || s[tEnd] === '\n' || s[tEnd] === ' ')) tEnd++;
      const trail = ctx.bytes.length - tEnd;
      if (trail > 4) {
        const t = U().detectType(ctx.bytes.subarray(tEnd));
        html += '<div class="lab-note">⚠ ' + U().formatBytes(trail) + ' tras el último %%EOF @ 0x' + tEnd.toString(16) +
          (t ? ' — identificado como <b>' + esc(t.name) + '</b>' : '') + ' (posible payload / polyglot).</div>';
      }
    }

    // Botón perezoso: inflar streams + cazar JS
    html += '<div class="lab-sub">JavaScript / streams</div>' +
      '<div class="ds-bar"><button class="yr-run" onclick="Triage.pdf.streams(this)">▶ Inflar streams y buscar JavaScript</button>' +
      '<span class="lab-dim">descomprime FlateDecode localmente y escanea indicadores</span></div><div class="pdf-streams"></div>';
    return html;
  }

  // ── Nivel de stream (perezoso) ──────────────────────────────────────────────
  const JS_IND = [
    [/eval\s*\(/i, 'eval()'],
    [/unescape\s*\(/i, 'unescape()'],
    [/String\.fromCharCode|fromCharCode/i, 'fromCharCode (construye strings/shellcode)'],
    [/app\.(alert|viewerVersion|doc|setTimeOut|setInterval)/i, 'app.* (API de Acrobat)'],
    [/util\.print[fd]/i, 'util.printf (CVE-2008-2992)'],
    [/this\.exportDataObject/i, 'exportDataObject (suelta un archivo)'],
    [/Collab\.(getIcon|collectEmailInfo)/i, 'Collab.* (CVE-2009-0927 / 2007-5659)'],
    [/media\.newPlayer/i, 'media.newPlayer (CVE-2010-2884)'],
    [/spell\.customDictionaryOpen/i, 'spell.customDictionaryOpen (CVE-2009-1493)'],
    [/getAnnots\s*\(/i, 'getAnnots (lectura de anotaciones)'],
    [/%u[0-9a-fA-F]{4}(?:%u[0-9a-fA-F]{4}){6,}/, 'heap spray (%u… shellcode)'],
    [/(?:\\u[0-9a-fA-F]{4}){10,}/, 'blob \\u… (posible shellcode)'],
    [/\b(powershell|cmd\.exe|wscript|cscript|rundll32|mshta|certutil)\b/i, 'comando de sistema'],
    [/[0-9a-fA-F]{300,}/, 'blob hex largo (payload?)'],
  ];

  async function inflate(bytes) {
    for (const fmt of ['deflate', 'deflate-raw']) {
      try {
        const ds = new DecompressionStream(fmt);
        const ab = await new Response(new Blob([bytes]).stream().pipeThrough(ds)).arrayBuffer();
        return new Uint8Array(ab);
      } catch (e) { /* probar el siguiente */ }
    }
    return null;
  }

  async function streams(btn) {
    const panel = btn.closest('.lab-panel-b');
    const out = panel.querySelector('.pdf-streams');
    const ctx = lastCtx, s = lastStr;
    if (!ctx) { out.innerHTML = '<div class="lab-err">No hay PDF cargado.</div>'; return; }
    btn.disabled = true;
    out.innerHTML = '<div class="lab-loading">⬡ Descomprimiendo streams…</div>';
    try {
      let total = 0, inflated = 0, p = 0;
      const indicators = {}, snippets = [], embedded = [];
      const MAX = 400;
      while ((p = s.indexOf('stream', p)) >= 0 && total < MAX) {
        // 'stream' debe ir seguido de EOL; descartar 'endstream'
        if (s.slice(p - 3, p) === 'end') { p += 6; continue; }
        let d = p + 6;
        if (s[d] === '\r') d++;
        if (s[d] === '\n') d++;
        const e = s.indexOf('endstream', d);
        if (e < 0) break;
        total++;
        const dict = s.slice(Math.max(0, p - 400), p);
        const raw = ctx.bytes.subarray(d, e);
        let data = null;
        if (/\/FlateDecode/.test(dict)) { data = await inflate(raw); if (data) inflated++; }
        else if (/\/ASCIIHexDecode/.test(dict)) { data = asciiHex(s.slice(d, e)); }
        else data = raw;
        p = e + 9;
        if (!data || !data.length) continue;

        // Magic de archivo embebido en el stream descomprimido
        const mt = U().detectType(data);
        if (mt && /exec|archive|script|doc/.test(mt.cat)) embedded.push(mt.name);

        const txt = new TextDecoder('latin1').decode(data.subarray(0, Math.min(data.length, 200000)));
        for (const [re, label] of JS_IND) {
          if (re.test(txt)) {
            indicators[label] = (indicators[label] || 0) + 1;
            if (snippets.length < 8) {
              const mm = txt.match(re);
              if (mm) { const idx = txt.indexOf(mm[0]); snippets.push(txt.slice(Math.max(0, idx - 20), idx + 90).replace(/\s+/g, ' ')); }
            }
          }
        }
      }

      let html = '<div class="lab-row1">' + total + ' streams · ' + inflated + ' inflados (FlateDecode)' +
        (total >= MAX ? ' <span class="lab-dim">[cap ' + MAX + ']</span>' : '') + '</div>';
      const keys = Object.keys(indicators);
      if (keys.length) {
        html += '<div class="lab-note">⚠ Indicadores de JavaScript/exploit:</div><div class="lab-imps">' +
          keys.map(k => '<span class="lab-imp sus" title="' + esc(k) + '">' + esc(k) + ' ×' + indicators[k] + '</span>').join('') + '</div>';
        if (snippets.length) html += '<div class="lab-sub">Fragmentos</div><div class="lab-strings dim">' +
          snippets.map(sn => '<div class="lab-str"><code>' + esc(sn.slice(0, 160)) + '</code></div>').join('') + '</div>';
      } else {
        html += '<div class="lab-note">Sin indicadores de JavaScript/exploit en los streams descomprimidos.</div>';
      }
      if (embedded.length) {
        html += '<div class="lab-sub">Magics en streams (' + embedded.length + ')</div><div class="lab-imps">' +
          [...new Set(embedded)].map(n => '<span class="lab-imp">' + esc(n) + '</span>').join('') + '</div>';
      }
      out.innerHTML = html;
    } catch (e) {
      console.error('[triage] pdf streams', e);
      out.innerHTML = '<div class="lab-err">Error al procesar streams: ' + esc(e && e.message || e) + '</div>';
    } finally {
      btn.disabled = false;
    }
  }

  function asciiHex(str) {
    const hex = str.replace(/[^0-9a-fA-F]/g, '').replace(/>.*/s, '');
    const n = hex.length >> 1, out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function kv(rows) {
    return '<table class="lab-kv"><tbody>' + rows.map(r => '<tr><th>' + r[0] + '</th><td>' + r[1] + '</td></tr>').join('') + '</tbody></table>';
  }

  const Tri = (typeof window !== 'undefined' && window.Triage) || null;
  if (Tri) Tri.pdf = { streams };
  if (Tri && Tri.analyzers) {
    Tri.analyzers.register({
      id: 'pdf', title: 'PDF (documento)', icon: '📕',
      applies(ctx) { return !ctx.pe && !ctx.elf && isPdf(ctx.bytes) >= 0; },
      run(ctx) { return analyze(ctx); },
    });
  }
  return { isPdf, scanNames, decodeName, extractTargets, countWord, structCounts, asciiHex };
})();
