// APT115 CODEX ARCANUM — Triage analyzer: maldoc (macros VBA)
// solve et coagula
//
// Extrae las macros VBA de un Office (OLE legacy .doc/.xls/.ppt u OOXML
// .docm/.xlsm/.pptm) y marca indicadores estilo olevba: auto-ejecución,
// keywords sospechosas y ofuscación, más IOCs embebidos en el código.
// Todo el parseo es local (cfb.js + vba.js); el inflado del ZIP usa
// DecompressionStream nativo. Sin motor pesado, sin red.
//
// LÍMITE v1 (honesto): sólo VBA. Quedan afuera (diferidos) las macros Excel
// 4.0/XLM (otro motor), RTF, docs cifrados/con contraseña y el VBA stomping
// (el código se lee del stream de fuente comprimida; un sample "stomped" puede
// tener la fuente vaciada y el comportamiento real sólo en el p-code).

export const maldoc = (function () {
  'use strict';
  const U = Triage.util;

  // Indicadores (case-insensitive). Cada entrada: [regex, etiqueta].
  const AUTOEXEC = [
    'AutoOpen', 'Auto_Open', 'AutoClose', 'Auto_Close', 'AutoExec', 'AutoNew',
    'Document_Open', 'Document_Close', 'Document_New', 'DocumentOpen',
    'Workbook_Open', 'Workbook_Activate', 'Workbook_Close', 'Worksheet_Activate',
    'Window_Activate', 'app_WorkbookOpen',
  ];
  const SUSPICIOUS = [
    'Shell', 'WScript\\.Shell', 'CreateObject', 'GetObject', 'Environ',
    'ShellExecute', 'powershell', 'cmd\\.exe', 'mshta', 'rundll32', 'regsvr32',
    'certutil', 'bitsadmin', 'URLDownloadToFile', 'XMLHTTP', 'MSXML2', 'WinHttp',
    'ADODB\\.Stream', 'SaveToFile', 'VirtualAlloc', 'RtlMoveMemory', 'CreateThread',
    'GetProcAddress', 'LoadLibrary', 'CallWindowProc', 'Lib\\s+"', 'Declare\\s',
    'Kill\\s', 'Open\\s+"', 'ExecuteExcel4Macro',
  ];
  const OBFUSCATION = [
    'Chr\\s*\\(', 'ChrW\\s*\\(', 'ChrB\\s*\\(', 'StrReverse', 'Xor', 'Hex\\s*\\(',
    'Asc\\s*\\(', 'Replace\\s*\\(', 'Mid\\s*\\(', 'Split\\s*\\(', 'Array\\s*\\(',
    'Base64', 'CLng\\s*\\(', 'CByte\\s*\\(', 'StrConv',
  ];

  function isCfb(b) {
    return b.length >= 8 && b[0] === 0xd0 && b[1] === 0xcf && b[2] === 0x11 && b[3] === 0xe0 &&
      b[4] === 0xa1 && b[5] === 0xb1 && b[6] === 0x1a && b[7] === 0xe1;
  }
  // ZIP que menciona vbaProject.bin: el nombre va literal en los headers del ZIP,
  // así que un indexOf crudo basta (sync, barato, sin inflar).
  const VBP = [0x76, 0x62, 0x61, 0x50, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x62, 0x69, 0x6e]; // "vbaProject.bin"
  function looksOoxmlVba(b) {
    if (b.length < 4 || b[0] !== 0x50 || b[1] !== 0x4b) return false;
    const cap = Math.min(b.length, 4 * 1024 * 1024); // suficiente para el central directory típico
    outer: for (let i = 0; i <= cap - VBP.length; i++) {
      if (b[i] !== VBP[0]) continue;
      for (let j = 1; j < VBP.length; j++) if (b[i + j] !== VBP[j]) continue outer;
      return true;
    }
    return false;
  }

  function countMatches(code, patterns) {
    const found = [];
    for (const p of patterns) {
      const re = new RegExp(p, 'gi');
      const m = code.match(re);
      if (m) found.push({ kw: p.replace(/\\[sw]\\?\*?\(?\??|"/g, '').replace(/\\/g, '') || p, n: m.length });
    }
    return found.sort((a, b) => b.n - a.n);
  }

  function extractIocs(code) {
    const urls = [...new Set((code.match(/https?:\/\/[^\s"'<>)]{4,200}/gi) || []))];
    const ips = [...new Set((code.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))]
      .filter((ip) => ip.split('.').every((o) => +o <= 255));
    return { urls, ips };
  }

  function flagRow(label, cls, found) {
    if (!found.length) return '';
    const chips = found.map((f) =>
      '<span class="lab-tag t-' + cls + '">' + U.esc(f.kw) + (f.n > 1 ? ' ×' + f.n : '') + '</span>').join(' ');
    return '<div class="lab-str"><b style="min-width:96px;display:inline-block">' + label + '</b>' + chips + '</div>';
  }

  function render(res, file) {
    if (!res.found) {
      const why = res.container === 'ooxml-sin-vba' ? 'OOXML sin vbaProject.bin'
        : res.container === 'no-cfb' ? 'no se pudo leer el contenedor'
        : 'sin proyecto VBA';
      return '<div class="lab-note">Documento sin macros VBA (' + why + ').</div>';
    }
    const all = res.modules.map((m) => m.code).join('\n');
    const auto = countMatches(all, AUTOEXEC);
    const susp = countMatches(all, SUSPICIOUS);
    const obf = countMatches(all, OBFUSCATION);
    const iocs = extractIocs(all);

    let h = '<div class="lab-row1">' + res.modules.length + ' módulo(s) VBA · ' +
      all.length + ' bytes de código' +
      (auto.length ? ' · <span class="ds-warn">auto-ejecución detectada</span>' : '') + '</div>';

    if (auto.length || susp.length || obf.length) {
      h += '<div class="lab-sub">Indicadores</div><div class="lab-strings">';
      h += flagRow('Auto-exec', 'exec', auto);
      h += flagRow('Sospechoso', 'url', susp);
      h += flagRow('Ofuscación', 'b64', obf);
      h += '</div>';
    }
    if (iocs.urls.length || iocs.ips.length) {
      h += '<div class="lab-sub">IOCs en el código</div><div class="lab-strings">';
      iocs.urls.forEach((u) => { h += '<div class="lab-str"><span class="lab-tag t-url">url</span><code>' + U.esc(u) + '</code></div>'; });
      iocs.ips.forEach((ip) => { h += '<div class="lab-str"><span class="lab-tag t-ip">ip</span><code>' + U.esc(ip) + '</code></div>'; });
      h += '</div>';
    }

    h += '<div class="lab-sub">Código</div>';
    res.modules.forEach((m) => {
      h += '<details class="lab-mod"><summary>' + U.esc(m.name) +
        ' <span class="lab-dim">' + (m.type || '') + ' · ' + m.code.length + ' bytes</span></summary>' +
        '<pre class="lab-pre">' + U.esc(m.code) + '</pre></details>';
    });
    return h;
  }

  Triage.analyzers.register({
    id: 'vba', title: 'Macros VBA', icon: '📄',
    applies(ctx) { return isCfb(ctx.bytes) || looksOoxmlVba(ctx.bytes); },
    async run(ctx) {
      if (!Triage.vba) return '<div class="lab-err">Módulo VBA no disponible.</div>';
      const res = await Triage.vba.analyze(ctx.bytes);
      return render(res, ctx.file);
    },
  });

  return { countMatches, extractIocs, isCfb, looksOoxmlVba };
})();
