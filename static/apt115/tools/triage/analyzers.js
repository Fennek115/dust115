// APT115 CODEX ARCANUM — Triage analyzers (registro pluggable)
// solve et coagula
//
// Cada analyzer es un módulo independiente con la forma:
//   { id, title, icon, applies(ctx)->bool?, run(ctx)->string|Promise<string> }
// El orquestador (triage.js) corre todos los que aplican y envuelve su salida
// en un panel. Para AGREGAR uno nuevo (p.ej. YARA), basta con
//   Triage.analyzers.register({...})  — ver el stub de YARA al final.
//
// ctx = { bytes:Uint8Array, dv:DataView, file:{name,size}, pe:<obj|null> }

window.Triage = window.Triage || {};
Triage.analyzers = (function () {
  'use strict';
  const U = Triage.util;
  const list = [];

  function register(a) {
    if (!a || !a.id || typeof a.run !== 'function') { console.warn('[triage] analyzer inválido', a); return; }
    list.push(a);
  }
  function all() { return list.slice(); }

  // ── 1. File info ────────────────────────────────────────────
  register({
    id: 'fileinfo', title: 'File Info', icon: '📄',
    run(ctx) {
      const t = U.detectType(ctx.bytes);
      const rows = [
        ['Nombre', U.esc(ctx.file.name)],
        ['Tamaño', U.formatBytes(ctx.file.size) + ' (' + ctx.file.size.toLocaleString() + ' bytes)'],
        ['Tipo (magic bytes)', t ? U.esc(t.name) : '<span class="lab-dim">desconocido</span>'],
      ];
      if (ctx.pe) {
        rows.push(['Arquitectura', U.esc(ctx.pe.machineName) + (ctx.pe.is64 ? ' · PE32+' : ' · PE32')]);
        rows.push(['Tipo PE', ctx.pe.charNames.indexOf('DLL') !== -1 ? 'DLL' : 'EXE']);
        if (ctx.pe.timestampDate) {
          rows.push(['Compile time (TimeDateStamp)', ctx.pe.timestampDate.toISOString().replace('T', ' ').slice(0, 19) + ' UTC']);
        } else if (ctx.pe.timestamp) {
          rows.push(['TimeDateStamp', '0x' + U.toHex(ctx.pe.timestamp, 8) +
            ' <span class="lab-dim">(no es fecha válida — posible reproducible build o stomping)</span>']);
        }
      }
      return kvTable(rows);
    },
  });

  // ── 2. Hashes ───────────────────────────────────────────────
  register({
    id: 'hashes', title: 'Hashes', icon: '#️⃣',
    async run(ctx) {
      const buf = ctx.bytes.buffer.slice(ctx.bytes.byteOffset, ctx.bytes.byteOffset + ctx.bytes.byteLength);
      const md5 = (typeof SparkMD5 !== 'undefined') ? SparkMD5.ArrayBuffer.hash(buf) : '(SparkMD5 no cargado)';
      const sha1 = await digest('SHA-1', buf);
      const sha256 = await digest('SHA-256', buf);
      const rows = [
        ['MD5', hashCell(md5)],
        ['SHA-1', hashCell(sha1)],
        ['SHA-256', hashCell(sha256)],
      ];
      if (ctx.pe && ctx.pe.imphash) rows.push(['imphash', hashCell(ctx.pe.imphash) + ' <span class="lab-dim">(nombres; ordinales como ordN)</span>']);
      if (ctx.pe && ctx.pe.rich && ctx.pe.rich.hash) rows.push(['richhash', hashCell(ctx.pe.rich.hash) + ' <span class="lab-dim">(toolchain de compilación · clustering)</span>']);
      let html = kvTable(rows, true);
      // Lookups opt-in (no consultan solos: sólo abren el link si hacés click)
      if (ctx.pe || true) {
        const s256 = sha256;
        html += '<div class="lab-actions">' +
          extLink('VirusTotal', 'https://www.virustotal.com/gui/file/' + s256) +
          extLink('MalwareBazaar', 'https://bazaar.abuse.ch/browse.php?search=sha256%3A' + s256) +
          '<span class="lab-dim">— consultas opt-in: nada se envía hasta que hagas click</span>' +
          '</div>';
      }
      return html;
    },
  });

  // ── 3. Entropy ──────────────────────────────────────────────
  register({
    id: 'entropy', title: 'Entropía', icon: '🌡',
    run(ctx) {
      const overall = U.entropy(ctx.bytes);
      let html = '<div class="lab-row1">Global: ' + entropyBadge(overall) + '</div>';
      if (ctx.pe && ctx.pe.sections.length) {
        const rows = ctx.pe.sections.map(s => {
          let e = 0;
          if (s.rawsize && s.rawptr + s.rawsize <= ctx.bytes.length) {
            e = U.entropy(ctx.bytes, s.rawptr, s.rawptr + s.rawsize);
          }
          return [U.esc(s.name), entropyBadge(e)];
        });
        html += '<div class="lab-sub">Por sección</div>' + kvTable(rows);
      } else {
        // Bloques (archivos no-PE): muestreo en 8 tramos
        const n = 8, rows = [];
        for (let i = 0; i < n; i++) {
          const a = Math.floor(ctx.bytes.length * i / n);
          const b = Math.floor(ctx.bytes.length * (i + 1) / n);
          rows.push(['Bloque ' + (i + 1), entropyBadge(U.entropy(ctx.bytes, a, b))]);
        }
        html += '<div class="lab-sub">Por bloque</div>' + kvTable(rows);
      }
      html += '<div class="lab-note">≳ 7.2 sugiere datos comprimidos/cifrados → posible packing.</div>';
      return html;
    },
  });

  // ── 4. PE headers / sections / imports ──────────────────────
  register({
    id: 'pe', title: 'PE Structure', icon: '🧩',
    applies(ctx) { return !!ctx.pe; },
    run(ctx) {
      const pe = ctx.pe;
      let html = kvTable([
        ['Machine', U.esc(pe.machineName)],
        ['Subsystem', pe.optional ? U.esc(pe.optional.subsystemName) : '?'],
        ['Entry point (RVA)', pe.optional ? '0x' + U.toHex(pe.optional.entryPoint, 8) : '?'],
        ['Image base', pe.optional ? '0x' + pe.optional.imageBase.toString(16).toUpperCase() : '?'],
        ['Characteristics', pe.charNames.length ? pe.charNames.join(', ') : '—'],
        ['DLL characteristics', (pe.optional && pe.optional.dllCharNames.length) ? pe.optional.dllCharNames.join(', ') : '—'],
      ]);

      // Hardening rápido
      const dc = (pe.optional && pe.optional.dllCharNames) || [];
      const sec = [];
      sec.push(badge(dc.some(x => x.startsWith('DYNAMIC_BASE')), 'ASLR'));
      sec.push(badge(dc.some(x => x.startsWith('NX_COMPAT')), 'DEP/NX'));
      sec.push(badge(dc.some(x => x.startsWith('GUARD_CF')), 'CFG'));
      sec.push(badge(dc.some(x => x.startsWith('FORCE_INTEGRITY')), 'Integrity'));
      html += '<div class="lab-sub">Mitigaciones</div><div class="lab-badges">' + sec.join('') + '</div>';

      // Secciones
      html += '<div class="lab-sub">Secciones (' + pe.sections.length + ')</div>';
      html += '<table class="lab-table"><thead><tr><th>Nombre</th><th>VirtAddr</th><th>VirtSize</th><th>RawSize</th><th>Entropía</th></tr></thead><tbody>';
      for (const s of pe.sections) {
        let e = 0;
        if (s.rawsize && s.rawptr + s.rawsize <= ctx.bytes.length) e = U.entropy(ctx.bytes, s.rawptr, s.rawptr + s.rawsize);
        html += '<tr><td>' + U.esc(s.name) + '</td><td>0x' + U.toHex(s.vaddr, 6) +
          '</td><td>' + U.formatBytes(s.vsize) + '</td><td>' + U.formatBytes(s.rawsize) +
          '</td><td>' + (e ? e.toFixed(2) : '—') + '</td></tr>';
      }
      html += '</tbody></table>';

      // Imports
      if (pe.imports.length) {
        html += '<div class="lab-sub">Imports — ' + pe.importCount + ' funciones de ' + pe.imports.length + ' DLLs ' +
          '<span class="lab-dim">(APIs notables resaltadas)</span></div>';
        for (const imp of pe.imports) {
          const funcs = imp.funcs.map(f => {
            const nm = f.name || ('ord' + f.ordinal);
            const sus = SUSPECT[nm.toLowerCase()];
            return '<span class="lab-imp' + (sus ? ' sus" title="' + U.esc(sus) : '') + '">' + U.esc(nm) + '</span>';
          }).join('');
          html += '<details class="lab-dll"><summary>' + U.esc(imp.dll) +
            ' <span class="lab-dim">(' + imp.funcs.length + ')</span></summary><div class="lab-imps">' + funcs + '</div></details>';
        }
      } else {
        html += '<div class="lab-note">Sin import table legible (¿packed / sin imports / corrupto?).</div>';
      }
      if (pe.warnings.length) html += '<div class="lab-note">⚠ ' + pe.warnings.map(U.esc).join(' · ') + '</div>';
      return html;
    },
  });

  // ── 4b. Rich Header ─────────────────────────────────────────
  register({
    id: 'rich', title: 'Rich Header', icon: '🏷',
    applies(ctx) { return !!(ctx.pe && ctx.pe.rich && ctx.pe.rich.entries && ctx.pe.rich.entries.length); },
    run(ctx) {
      const r = ctx.pe.rich;
      let html = '<div class="lab-row1">Huella del toolchain MSVC que compiló/linkeó el binario. ' +
        'Dos muestras con el mismo <b>richhash</b> salieron de la misma cadena de build ' +
        '<span class="lab-dim">(útil para clustering/atribución)</span>.</div>';
      if (r.hash) html += kvTable([['richhash', hashCell(r.hash)], ['XOR key', '0x' + (r.key >>> 0).toString(16).toUpperCase()]], true);
      html += '<div class="lab-sub">Entradas (' + r.entries.length + ')</div>';
      html += '<table class="lab-table"><thead><tr><th>Product ID</th><th>Build</th><th>Count</th></tr></thead><tbody>';
      for (const e of r.entries) {
        html += '<tr><td>0x' + e.prodId.toString(16).toUpperCase().padStart(4, '0') +
          '</td><td>' + e.build + '</td><td>' + e.count + '</td></tr>';
      }
      html += '</tbody></table>';
      html += '<div class="lab-note">El <b>build</b> identifica la versión exacta del linker/compilador MSVC ' +
        '(lookupable). La ausencia de Rich Header sugiere binario no-MSVC (MinGW/GCC), reescrito o stomped.</div>';
      return html;
    },
  });

  // ── 5. Strings ──────────────────────────────────────────────
  register({
    id: 'strings', title: 'Strings', icon: '🔡',
    run(ctx) {
      const minLen = 5;
      const res = U.extractStrings(ctx.bytes, minLen, 8000);
      const interesting = [];
      for (const it of res.strings) {
        const tag = U.classify(it.s);
        if (tag) interesting.push({ tag, s: it.s, off: it.off, type: it.type });
      }
      let html = '<div class="lab-row1">' + res.strings.length + ' strings (≥' + minLen + ' chars)' +
        (res.capped ? ' <span class="lab-dim">[cap alcanzado]</span>' : '') +
        ' · ' + interesting.length + ' notables</div>';

      if (interesting.length) {
        html += '<div class="lab-sub">Notables (URLs, IPs, rutas, registry, base64…)</div><div class="lab-strings">';
        interesting.slice(0, 200).forEach(it => {
          html += '<div class="lab-str"><span class="lab-tag t-' + it.tag + '">' + it.tag + '</span>' +
            '<code>' + U.esc(it.s.slice(0, 200)) + '</code></div>';
        });
        html += '</div>';
      }
      html += '<div class="lab-sub">Muestra (primeras 120)</div><div class="lab-strings dim">';
      res.strings.slice(0, 120).forEach(it => {
        html += '<div class="lab-str"><span class="lab-off">' + (it.type === 'utf16' ? 'w' : ' ') +
          '0x' + U.toHex(it.off, 6) + '</span><code>' + U.esc(it.s.slice(0, 200)) + '</code></div>';
      });
      html += '</div>';
      return html;
    },
  });

  // ── 6. YARA — SLOT RESERVADO (incorporación futura) ─────────
  // El motor YARA-X compilado a WASM se enchufa acá: cuando esté cargado,
  // este analyzer correrá las reglas contra ctx.bytes 100% local. La
  // arquitectura ya está lista; sólo falta el módulo del motor.
  register({
    id: 'yara', title: 'YARA', icon: '🧷',
    run(ctx) {
      if (window.Triage.yara && typeof window.Triage.yara.scan === 'function') {
        return window.Triage.yara.scan(ctx); // motor real cuando exista
      }
      return '<div class="lab-note">🧷 <b>Slot YARA reservado.</b> El motor (YARA-X → WASM) ' +
        'se incorpora en una fase futura: escanea el archivo cargado de forma 100% local, ' +
        'sin que nada salga de tu máquina. La arquitectura de analyzers ya lo contempla — ' +
        'al cargar <code>Triage.yara</code> con un método <code>scan(ctx)</code>, este panel ' +
        'pasa a correr reglas automáticamente.</div>';
    },
  });

  // ── helpers de render ───────────────────────────────────────
  function kvTable(rows, mono) {
    return '<table class="lab-kv' + (mono ? ' mono' : '') + '"><tbody>' +
      rows.map(r => '<tr><th>' + r[0] + '</th><td>' + r[1] + '</td></tr>').join('') +
      '</tbody></table>';
  }
  function hashCell(h) { return '<code class="lab-hash" onclick="Triage.copy(this.textContent)" title="click para copiar">' + U.esc(h) + '</code>'; }
  function entropyBadge(e) {
    const cls = e >= 7.2 ? 'hi' : e >= 6 ? 'mid' : 'lo';
    return '<span class="lab-ent ' + cls + '">' + e.toFixed(2) + '</span>';
  }
  function badge(on, label) { return '<span class="lab-mit ' + (on ? 'on' : 'off') + '">' + (on ? '✓ ' : '✗ ') + label + '</span>'; }
  function extLink(label, href) { return '<a class="lab-ext" href="' + href + '" target="_blank" rel="noopener noreferrer">↗ ' + label + '</a>'; }
  async function digest(algo, buf) {
    const d = await crypto.subtle.digest(algo, buf);
    return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // APIs notables para triage (resaltado en imports). Valor = motivo.
  const SUSPECT = {
    'virtualalloc': 'alloc memoria RWX', 'virtualallocex': 'alloc en proceso remoto',
    'virtualprotect': 'cambia permisos de memoria', 'writeprocessmemory': 'inyección',
    'readprocessmemory': 'lee memoria de otro proceso', 'createremotethread': 'inyección / hollowing',
    'ntcreatethreadex': 'inyección (Nt)', 'queueuserapc': 'APC injection',
    'setwindowshookex': 'hooking / keylogger', 'getasynckeystate': 'keylogger',
    'loadlibrarya': 'carga dinámica', 'loadlibraryw': 'carga dinámica', 'getprocaddress': 'resuelve APIs en runtime',
    'winexec': 'ejecuta proceso', 'shellexecutea': 'ejecuta proceso', 'shellexecutew': 'ejecuta proceso',
    'createprocessa': 'crea proceso', 'createprocessw': 'crea proceso',
    'urldownloadtofilea': 'descarga payload', 'urldownloadtofilew': 'descarga payload',
    'internetopena': 'red / C2', 'internetopenurla': 'red / C2', 'wininethttpopenrequesta': 'HTTP C2',
    'connect': 'socket saliente', 'send': 'socket', 'recv': 'socket', 'wsastartup': 'red (winsock)',
    'cryptencrypt': 'cifrado (ransomware?)', 'cryptdecrypt': 'descifrado', 'cryptacquirecontexta': 'cripto',
    'regsetvalueexa': 'persistencia (registry)', 'regcreatekeyexa': 'persistencia (registry)',
    'isdebuggerpresent': 'anti-debug', 'checkremotedebuggerpresent': 'anti-debug',
    'ntqueryinformationprocess': 'anti-debug / evasión', 'gettickcount': 'anti-sandbox (timing)',
    'adjusttokenprivileges': 'escalada de privilegios', 'openprocesstoken': 'tokens',
  };

  return { register, all };
})();
