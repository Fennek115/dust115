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

export const analyzers = (function () {
  'use strict';
  const U = Triage.util;
  const list = [];

  function register(a) {
    if (!a || !a.id || typeof a.run !== 'function') { console.warn('[triage] analyzer inválido', a); return; }
    list.push(a);
  }
  function all() { return list.slice(); }

  // Suelta el archivo anterior: los analyzers con estado perezoso (ctx/buffers
  // a nivel módulo para sus botones) implementan release(); el orquestador lo
  // llama al cargar un archivo nuevo, así el viejo no queda retenido.
  function releaseAll() {
    for (const a of list) {
      if (typeof a.release !== 'function') continue;
      try { a.release(); } catch (e) { console.warn('[triage] release', a.id, e); }
    }
  }

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
      } else if (ctx.elf) {
        const e = ctx.elf;
        rows.push(['Arquitectura', U.esc(e.machineName) + ' · ' + e.classLabel + ' · ' + e.endian]);
        rows.push(['Tipo ELF', U.esc(e.typeName) + (e.isStatic ? ' <span class="lab-dim">(linkeo estático)</span>' : '')]);
        rows.push(['OS/ABI', U.esc(e.osabiName)]);
      } else if (ctx.macho) {
        const mo = ctx.macho;
        const arch = mo.fat ? ('universal / fat (' + mo.slices.map(s => U.esc(s.cpuName)).join(', ') + ')') : (U.esc(mo.cpuName) + ' · ' + mo.classLabel);
        rows.push(['Arquitectura', arch]);
        rows.push(['Tipo Mach-O', U.esc(mo.filetypeName) + (mo.platform ? ' <span class="lab-dim">(' + U.esc(mo.platform) + ')</span>' : '')]);
        rows.push(['Firma', mo.signed ? (mo.sig && mo.sig.adhoc ? 'ad-hoc' : 'firmado') : '<span class="lab-mit off">sin firmar</span>']);
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
      if (ctx.elf && ctx.elf.buildId) rows.push(['build-id', hashCell(ctx.elf.buildId) + ' <span class="lab-dim">(GNU build-id · clustering / symbol server)</span>']);
      if (ctx.elf && ctx.elf.telfhash) rows.push(['telfhash', hashCell(ctx.elf.telfhash) + ' <span class="lab-dim">(símbolos · clustering ELF, compat. VirusTotal)</span>']);
      if (ctx.macho && ctx.macho.uuid) rows.push(['LC_UUID', hashCell(ctx.macho.uuid) + ' <span class="lab-dim">(UUID de build · clustering)</span>']);
      const tlsh = (Triage.fuzzy && Triage.fuzzy.hashBytes) ? Triage.fuzzy.hashBytes(ctx.bytes) : null;
      if (tlsh) rows.push(['TLSH', hashCell(tlsh) + ' <span class="lab-dim">(fuzzy · similitud entre muestras)</span>']);
      else rows.push(['TLSH', '<span class="lab-dim">N/A — archivo chico o de baja complejidad</span>']);
      let html = kvTable(rows, true);
      if (tlsh) {
        html += '<div class="tlsh-cmp lab-actions">' +
          '<input class="tlsh-cmp-in" placeholder="pegá otro TLSH para medir similitud…" spellcheck="false">' +
          '<button class="rs-copy" onclick="Triage.fuzzy.compare(this)">comparar</button>' +
          '<span class="tlsh-cmp-out lab-dim"></span></div>';
      }
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

  // ── 4c. Recursos / Firma (version info, manifest, Authenticode) ──
  register({
    id: 'resources', title: 'Recursos / Firma', icon: '🪪',
    applies(ctx) { return !!(ctx.pe && (ctx.pe.versionInfo || (ctx.pe.resources && ctx.pe.resources.length) || ctx.pe.authenticode)); },
    run(ctx) {
      const pe = ctx.pe;
      const ident = (s) => s ? U.esc([s.CN, s.O].filter(Boolean).join(' · ')) : '—';
      let html = '';

      // Version info (CompanyName, OriginalFilename, versiones…)
      const vi = pe.versionInfo;
      if (vi && (vi.fixed || Object.keys(vi.strings).length)) {
        html += '<div class="lab-sub">Version info</div>';
        const rows = [];
        if (vi.fixed) {
          rows.push(['FileVersion (fixed)', U.esc(vi.fixed.fileVersion)]);
          rows.push(['ProductVersion (fixed)', U.esc(vi.fixed.productVersion)]);
        }
        const order = ['CompanyName', 'ProductName', 'FileDescription', 'OriginalFilename',
          'InternalName', 'FileVersion', 'ProductVersion', 'LegalCopyright'];
        const seen = {};
        for (const k of order) if (vi.strings[k]) { rows.push([U.esc(k), U.esc(vi.strings[k])]); seen[k] = 1; }
        for (const k in vi.strings) if (!seen[k]) rows.push([U.esc(k), U.esc(vi.strings[k])]);
        html += kvTable(rows);
        html += '<div class="lab-note">Los campos del version info son <b>autodeclarados</b> y triviales de falsificar — ' +
          'útiles para clustering y para detectar impersonación (un OriginalFilename que no pega con el nombre real).</div>';
      }

      // Manifest: nivel de ejecución pedido
      if (pe.manifest && (pe.manifest.level || pe.manifest.uiAccess)) {
        const lvl = pe.manifest.level || 'asInvoker';
        const hi = /requireAdministrator|highestAvailable/i.test(lvl);
        const mrows = [['requestedExecutionLevel',
          '<span class="lab-mit ' + (hi ? 'off' : 'on') + '">' + U.esc(lvl) + '</span>' +
          (hi ? ' <span class="lab-dim">(pide elevación de privilegios)</span>' : '')]];
        if (pe.manifest.uiAccess) mrows.push(['uiAccess', U.esc(pe.manifest.uiAccess)]);
        html += '<div class="lab-sub">Manifest</div>' + kvTable(mrows);
      }

      // Authenticode
      const a = pe.authenticode;
      html += '<div class="lab-sub">Firma digital (Authenticode)</div>';
      if (a) {
        const rows = [['Estado', '<span class="lab-mit on">✓ firma embebida</span> ' +
          '<span class="lab-dim">(' + U.esc(a.certType) + ' · ' + U.formatBytes(a.size) + ')</span>']];
        if (a.signer) rows.push(['Firmante', '<b>' + ident(a.signer) + '</b>']);
        if (a.signingTime) rows.push(['Signing time', U.esc(a.signingTime)]);
        html += kvTable(rows);
        if (a.subjects && a.subjects.length) {
          html += '<details class="lab-dll"><summary>Cadena de certificados (' + a.subjects.length + ')</summary>' +
            '<div class="lab-imps">' + a.subjects.map(s => '<span class="lab-imp">' + ident(s) + '</span>').join('') + '</div></details>';
        }
        html += '<div class="lab-note">La firma prueba <b>integridad y emisor</b>, no inocuidad. ' +
          'No se valida criptográficamente la cadena ni la revocación acá (eso requiere estado online).</div>';
      } else {
        html += '<div class="lab-note">Sin firma Authenticode embebida. Puede estar firmado por ' +
          '<b>catálogo</b> (.cat del sistema, no verificable offline) o directamente sin firmar.</div>';
      }

      // Inventario de recursos
      if (pe.resources && pe.resources.length) {
        const tot = pe.resources.reduce((s, r) => s + r.count, 0);
        html += '<div class="lab-sub">Recursos (' + tot + ')</div><div class="lab-imps">' +
          pe.resources.map(r => '<span class="lab-imp">' + U.esc(r.name) + ' ×' + r.count + '</span>').join('') + '</div>';
      }
      return html || '<div class="lab-note">Sin recursos ni firma legibles.</div>';
    },
  });

  // ── 4d. ELF structure (binarios Linux/Unix) ─────────────────
  register({
    id: 'elf', title: 'ELF Structure', icon: '🐧',
    applies(ctx) { return !!ctx.elf; },
    run(ctx) {
      const e = ctx.elf;
      const hdr = [
        ['Clase', e.classLabel + ' · ' + e.endian],
        ['Máquina', U.esc(e.machineName)],
        ['Tipo', U.esc(e.typeName)],
        ['OS/ABI', U.esc(e.osabiName) + (e.abiTag ? ' <span class="lab-dim">(' + U.esc(e.abiTag) + ')</span>' : '')],
        ['Entry point', '0x' + e.entry.toString(16)],
        ['Linkeo', e.isStatic ? 'estático (sin intérprete)' : ('dinámico' + (e.interp ? ' — <code>' + U.esc(e.interp) + '</code>' : ''))],
        ['Símbolos', e.stripped ? '<span class="lab-mit off">stripped</span> <span class="lab-dim">(sin tabla de símbolos de debug)</span>' : 'presentes (.symtab)'],
      ];
      if (e.soname) hdr.push(['SONAME', U.esc(e.soname)]);
      if (e.minGlibc) hdr.push(['glibc mínima', U.esc(e.minGlibc) + ' <span class="lab-dim">(versión más alta requerida)</span>']);
      if (e.lang) hdr.push(['Runtime', '<b>' + U.esc(e.lang.name) + '</b>' +
        (e.lang.version ? ' ' + U.esc(e.lang.version) : '') +
        (e.lang.module ? ' <span class="lab-dim">· ' + U.esc(e.lang.module) + '</span>' : '')]);
      if (e.initArray) hdr.push(['Constructores', e.initArray + ' en .init_array <span class="lab-dim">(corren antes de main)</span>']);
      let html = kvTable(hdr);

      // Mitigaciones (análogo a las de PE) + CET moderno
      const relroOn = e.relro === 'completo';
      const sec = [
        badge(e.nx === true, 'NX'),
        badge(e.isPie, 'PIE'),
        badge(relroOn, 'RELRO ' + e.relro),
        badge(e.canary, 'Stack canary'),
        badge(e.fortify, 'FORTIFY'),
        badge(e.bindNow, 'BIND_NOW'),
      ];
      if (e.cet) { sec.push(badge(e.cet.ibt, 'CET/IBT')); sec.push(badge(e.cet.shstk, 'Shadow Stack')); }
      html += '<div class="lab-sub">Mitigaciones</div><div class="lab-badges">' + sec.join('') + '</div>';
      if (e.nx === false) html += '<div class="lab-note">⚠ Pila ejecutable (GNU_STACK con bit X) — inusual y de riesgo.</div>';

      // Heurística de packer / anti-análisis
      const pk = e.packer, flags = [];
      if (pk.rwx.length) flags.push('segmento(s) RWX cargados en ' + pk.rwx.join(', ') + ' (W+X simultáneo — típico de loaders / shellcode)');
      if (pk.upx) flags.push('firma UPX presente (empaquetado)');
      if (pk.entryAnomaly) flags.push('entry point fuera de .text (posible packing / hijack del flujo)');
      if (pk.memGrowExec) flags.push('segmento ejecutable con memsz ≫ filesz (stub que se expande al ejecutar)');
      if (pk.noSections) flags.push('sin tabla de secciones (stripping agresivo / packed)');
      // entropía por segmento LOAD (datos cifrados/comprimidos)
      const hot = [];
      for (const s of e.segments) {
        if (s.type === 1 && s.filesz && s.offset + s.filesz <= ctx.bytes.length) {
          const en = U.entropy(ctx.bytes, s.offset, s.offset + s.filesz);
          if (en >= 7.2) hot.push('LOAD@0x' + s.vaddr.toString(16) + ' (' + en.toFixed(2) + ')');
        }
      }
      if (hot.length) flags.push('entropía alta en ' + hot.join(', ') + ' → datos comprimidos/cifrados');
      if (flags.length) {
        html += '<div class="lab-sub">Señales de packing / anti-análisis</div><div class="lab-note">⚠ ' +
          flags.map(U.esc).join('<br>⚠ ') + '</div>';
      }
      if (e.rpath || e.runpath) {
        html += '<div class="lab-note">⚠ ' + (e.rpath ? 'RPATH=<code>' + U.esc(e.rpath) + '</code> ' : '') +
          (e.runpath ? 'RUNPATH=<code>' + U.esc(e.runpath) + '</code>' : '') +
          ' — rutas de búsqueda embebidas; potencial vector de secuestro de librerías.</div>';
      }

      // Dependencias dinámicas (DT_NEEDED) — el equivalente a los imports de PE
      if (e.needed.length) {
        html += '<div class="lab-sub">Dependencias dinámicas (' + e.needed.length + ')</div><div class="lab-imps">' +
          e.needed.map(n => '<span class="lab-imp">' + U.esc(n) + '</span>').join('') + '</div>';
      } else if (e.isStatic) {
        html += '<div class="lab-note">Binario estático: trae todo adentro, sin dependencias externas.</div>';
      }

      // Símbolos importados (UND) con resaltado de los notables
      if (e.imports.length) {
        const sus = e.imports.filter(n => ELF_SUSPECT[n]);
        html += '<div class="lab-sub">Símbolos importados — ' + e.imports.length +
          ' <span class="lab-dim">(funciones resueltas por el loader' + (sus.length ? '; ' + sus.length + ' notables' : '') + ')</span></div>';
        html += '<div class="lab-imps">' + e.imports.slice(0, 400).map(n => {
          const s = ELF_SUSPECT[n];
          return '<span class="lab-imp' + (s ? ' sus" title="' + U.esc(s) : '') + '">' + U.esc(n) + '</span>';
        }).join('') + '</div>';
        if (e.imports.length > 400) html += '<div class="lab-dim" style="font-size:10.5px;margin-top:4px">… ' + (e.imports.length - 400) + ' más (truncado).</div>';
      }

      // Exportados (sobre todo en .so) — colapsado
      if (e.exports.length) {
        html += '<details class="lab-dll"><summary>Símbolos exportados (' + e.exports.length + ')</summary><div class="lab-imps">' +
          e.exports.slice(0, 400).map(n => '<span class="lab-imp">' + U.esc(n) + '</span>').join('') + '</div></details>';
      }

      // Inventario de secciones / segmentos
      if (e.sections.length) {
        html += '<div class="lab-sub">Secciones (' + e.sections.length + ')</div>';
        html += '<table class="lab-table"><thead><tr><th>Nombre</th><th>Tipo</th><th>Addr</th><th>Tamaño</th></tr></thead><tbody>';
        for (const s of e.sections) {
          if (s.type === 0) continue;
          html += '<tr><td>' + U.esc(s.name || '—') + '</td><td>' + U.esc(s.typeName) +
            '</td><td>0x' + s.addr.toString(16) + '</td><td>' + U.formatBytes(s.size) + '</td></tr>';
        }
        html += '</tbody></table>';
      } else {
        html += '<div class="lab-note">Sin tabla de secciones — el análisis se hizo sobre los program headers ' +
          '(el .dynamic y las dependencias sobreviven igual al strip).</div>';
      }
      if (e.warnings.length) html += '<div class="lab-note">⚠ ' + e.warnings.map(U.esc).join(' · ') + '</div>';
      return html;
    },
  });

  // ── 4b. Mach-O (macOS / iOS) ────────────────────────────────
  const MACHO_SUSPECT = (Triage.macho && Triage.macho.SUSPECT) || {};
  function machoSlice(m, ctx) {
    const hdr = [
      ['Arquitectura', U.esc(m.cpuName) + (m.arm64e ? ' <span class="lab-dim">(arm64e · pointer auth)</span>' : '') + ' · ' + m.classLabel + ' · ' + m.endian],
      ['Tipo', U.esc(m.filetypeName)],
    ];
    if (m.platform) hdr.push(['Plataforma', U.esc(m.platform) + (m.minOS ? ' · min ' + U.esc(m.minOS) : '') + (m.sdk ? ' · SDK ' + U.esc(m.sdk) : '')]);
    if (m.entry !== null) hdr.push(['Entry point', '0x' + m.entry.toString(16) + ' <span class="lab-dim">(' + U.esc(m.entryKind || '') + ')</span>']);
    if (m.installName) hdr.push(['Install name', '<code>' + U.esc(m.installName) + '</code>']);
    if (m.sourceVersion) hdr.push(['Source version', U.esc(m.sourceVersion)]);
    if (m.uuid) hdr.push(['UUID', '<code>' + U.esc(m.uuid) + '</code> <span class="lab-dim">(clustering)</span>']);
    if (m.lang) hdr.push(['Lenguaje', '<b>' + U.esc(m.lang.name) + '</b>']);
    if (m.initCount) hdr.push(['Constructores', m.initCount + ' en __mod_init_func <span class="lab-dim">(corren antes de main)</span>']);
    let html = kvTable(hdr);

    // Mitigaciones
    const sec = [
      badge(m.isPie, 'PIE'),
      badge(m.noHeapExec, 'NX heap'),
      badge(!m.allowStackExec, 'No stack-exec'),
      badge(m.signed, 'Firmado'),
      badge(!!(m.sig && m.sig.runtime), 'Hardened runtime'),
      badge(!!(m.sig && m.sig.libraryValidation), 'Library validation'),
    ];
    if (m.restrictSeg) sec.push(badge(true, '__RESTRICT'));
    html += '<div class="lab-sub">Mitigaciones</div><div class="lab-badges">' + sec.join('') + '</div>';

    // Firma de código
    if (m.signed && m.sig) {
      const s = m.sig;
      const sigRows = [];
      const kind = s.hasCMS ? 'firma CMS (autoridad externa)' : s.adhoc ? '<b>ad-hoc</b> <span class="lab-dim">(sin autoridad — típico de binarios caseros/malware)</span>' : 'sin CMS';
      sigRows.push(['Tipo de firma', kind]);
      if (s.identifier) sigRows.push(['Identifier', '<code>' + U.esc(s.identifier) + '</code>']);
      sigRows.push(['Team ID', s.teamId ? '<code>' + U.esc(s.teamId) + '</code>' : '<span class="lab-dim">ninguno (ad-hoc / sin notarizar)</span>']);
      if (s.hashType) sigRows.push(['Hash', U.esc(s.hashType)]);
      if (s.flags && s.flags.length) sigRows.push(['CS flags', s.flags.map(f => '<span class="lab-tag">' + U.esc(f) + '</span>').join(' ')]);
      html += '<div class="lab-sub">Firma de código</div>' + kvTable(sigRows);
      if (s.dangerousEnts && s.dangerousEnts.length) {
        html += '<div class="lab-note">⚠ Entitlements de riesgo:<br>' +
          s.dangerousEnts.map(e => '<code>' + U.esc(e.key) + '</code> — ' + U.esc(e.why)).join('<br>') + '</div>';
      } else if (s.entitlements) {
        html += '<details class="lab-dll"><summary>Entitlements (' + s.entitlements.length + ' bytes)</summary><pre class="lab-pre">' + U.esc(s.entitlements.slice(0, 4000)) + '</pre></details>';
      }
    } else {
      html += '<div class="lab-note">⚠ Binario <b>sin firmar</b> — en macOS moderno Gatekeeper lo bloquearía; común en muestras de malware o builds locales.</div>';
    }

    // Señales de packing / anti-análisis
    const pk = m.packer, flags = [];
    if (pk.rwx.length) flags.push('segmento(s) RWX (W+X) en ' + pk.rwx.join(', ') + ' — típico de loaders / shellcode');
    if (pk.textWritable) flags.push('__TEXT con permiso de escritura (inusual — self-modifying / unpacking)');
    if (pk.encrypted) flags.push('cifrado FairPlay activo (cryptid=' + m.cryptId + ') — payload encriptado por el loader');
    if (pk.entryAnomaly) flags.push('entry point fuera de __text (posible hijack del flujo / packing)');
    const hot = [];
    for (const s of m.segments) {
      const start = m.sliceOffset + s.fileoff;
      if (s.filesize && start + s.filesize <= ctx.bytes.length && s.name !== '__LINKEDIT') {
        const en = U.entropy(ctx.bytes, start, start + s.filesize);
        if (en >= 7.2) hot.push(s.name + ' (' + en.toFixed(2) + ')');
      }
    }
    if (hot.length) flags.push('entropía alta en ' + hot.join(', ') + ' → datos comprimidos/cifrados');
    if (flags.length) html += '<div class="lab-sub">Señales de packing / anti-análisis</div><div class="lab-note">⚠ ' + flags.map(U.esc).join('<br>⚠ ') + '</div>';

    // rpaths (vector de dylib hijacking)
    if (m.rpaths.length) {
      html += '<div class="lab-note">⚠ RPATH(s): ' + m.rpaths.map(r => '<code>' + U.esc(r) + '</code>').join(' ') +
        ' — rutas de búsqueda de dylibs; con @rpath/@executable_path son vector de <b>dylib hijacking</b>.</div>';
    }

    // Dependencias (dylibs)
    if (m.dylibs.length) {
      html += '<div class="lab-sub">Dylibs linkeadas (' + m.dylibs.length + ')</div><div class="lab-imps">' +
        m.dylibs.map(d => '<span class="lab-imp" title="' + U.esc(d.current || '') + (d.weak ? ' · weak' : d.reexport ? ' · reexport' : d.upward ? ' · upward' : d.lazy ? ' · lazy' : '') + '">' + U.esc(d.name) + '</span>').join('') + '</div>';
    }

    // Símbolos importados (con resaltado de notables)
    if (m.imports.length) {
      const sus = m.imports.filter(n => MACHO_SUSPECT[n.replace(/^_/, '')]);
      html += '<div class="lab-sub">Símbolos importados — ' + m.imports.length +
        ' <span class="lab-dim">(' + (sus.length ? sus.length + ' notables' : 'undefined externos') + ')</span></div><div class="lab-imps">' +
        m.imports.slice(0, 400).map(n => {
          const why = MACHO_SUSPECT[n.replace(/^_/, '')];
          return '<span class="lab-imp' + (why ? ' sus" title="' + U.esc(why) : '') + '">' + U.esc(n) + '</span>';
        }).join('') + '</div>';
      if (m.imports.length > 400) html += '<div class="lab-dim" style="font-size:10.5px;margin-top:4px">… ' + (m.imports.length - 400) + ' más (truncado).</div>';
    }
    if (m.exports.length) {
      html += '<details class="lab-dll"><summary>Símbolos exportados (' + m.exports.length + ')</summary><div class="lab-imps">' +
        m.exports.slice(0, 400).map(n => '<span class="lab-imp">' + U.esc(n) + '</span>').join('') + '</div></details>';
    }

    // Segmentos / secciones
    if (m.segments.length) {
      html += '<div class="lab-sub">Segmentos (' + m.segments.length + ')</div>';
      html += '<table class="lab-table"><thead><tr><th>Nombre</th><th>VM addr</th><th>Tamaño</th><th>prot</th><th>Secciones</th></tr></thead><tbody>';
      const P = (p) => ((p & 1 ? 'r' : '-') + (p & 2 ? 'w' : '-') + (p & 4 ? 'x' : '-'));
      for (const s of m.segments) {
        html += '<tr><td>' + U.esc(s.name) + '</td><td>0x' + s.vmaddr.toString(16) + '</td><td>' + U.formatBytes(s.filesize) +
          '</td><td><code>' + P(s.initprot) + '</code></td><td class="lab-dim">' + (s.sections.map(x => U.esc(x.name)).join(' ') || '—') + '</td></tr>';
      }
      html += '</tbody></table>';
    }
    if (m.warnings && m.warnings.length) html += '<div class="lab-note">⚠ ' + m.warnings.map(U.esc).join(' · ') + '</div>';
    return html;
  }
  register({
    id: 'macho', title: 'Mach-O Structure', icon: '🍎',
    applies(ctx) { return !!ctx.macho; },
    run(ctx) {
      const m = ctx.macho;
      if (m.fat) {
        let html = '<div class="lab-note">Binario <b>universal / fat</b>' + (m.fat64 ? ' (fat64)' : '') + ' con ' + m.slices.length + ' slice(s):</div>';
        html += '<table class="lab-table"><thead><tr><th>Arch</th><th>Offset</th><th>Tamaño</th></tr></thead><tbody>' +
          m.slices.map(s => '<tr><td>' + U.esc(s.cpuName) + '</td><td>0x' + s.offset.toString(16) + '</td><td>' + U.formatBytes(s.size) + '</td></tr>').join('') +
          '</tbody></table>';
        m.slices.forEach((s, i) => {
          html += '<div class="lab-sub" style="margin-top:14px">▸ Slice ' + (i + 1) + ' — ' + U.esc(s.cpuName) + '</div>';
          html += s.macho ? machoSlice(s.macho, ctx) : '<div class="lab-note">slice no parseable.</div>';
        });
        return html;
      }
      return machoSlice(m, ctx);
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
    release() {
      if (window.Triage.yara && typeof window.Triage.yara.release === 'function') window.Triage.yara.release();
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

  // Símbolos ELF notables para triage (resaltado en imports). Valor = motivo.
  const ELF_SUSPECT = {
    'system': 'ejecuta comando shell', 'popen': 'ejecuta comando shell', 'execve': 'reemplaza proceso (exec)',
    'execl': 'exec', 'execlp': 'exec', 'execv': 'exec', 'execvp': 'exec',
    'fork': 'crea proceso', 'vfork': 'crea proceso', 'clone': 'crea proceso/hilo (low-level)',
    'ptrace': 'anti-debug / inyección', 'dlopen': 'carga librería en runtime', 'dlsym': 'resuelve símbolo en runtime',
    'mmap': 'mapea memoria (posible RWX)', 'mprotect': 'cambia permisos de memoria (RWX)',
    'prctl': 'control de proceso (anti-debug / sandbox)', 'syscall': 'syscall directo (evasión)',
    'socket': 'red / C2', 'connect': 'conexión saliente', 'bind': 'escucha (bind shell)',
    'listen': 'escucha (bind shell)', 'accept': 'acepta conexión', 'recv': 'socket', 'send': 'socket',
    'gethostbyname': 'resuelve DNS', 'inet_addr': 'red', 'getaddrinfo': 'resuelve DNS',
    'setuid': 'cambia UID (privilegios)', 'setgid': 'cambia GID', 'seteuid': 'cambia EUID', 'setresuid': 'privilegios',
    'crypt': 'cripto', 'unlink': 'borra archivo', 'chmod': 'cambia permisos', 'chown': 'cambia dueño',
    'inotify_init': 'observa archivos', 'kill': 'señales a procesos', 'getpid': 'reconocimiento',
    'pthread_create': 'crea hilo', 'daemon': 'se demoniza (persistencia)', 'setsid': 'nueva sesión (daemon)',
  };

  return { register, all, releaseAll };
})();

if (typeof window !== 'undefined') { window.Triage = window.Triage || {}; window.Triage.analyzers = analyzers; }
