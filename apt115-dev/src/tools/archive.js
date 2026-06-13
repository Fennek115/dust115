// APT115 CODEX ARCANUM — Archive / APK Inspector
// quod est superius est sicut quod inferius
//
// Inspecciona la ESTRUCTURA de un ZIP/JAR/APK/OOXML SIN extraerlo: lee el
// central directory (reusa el lector de src/app/zip.js), lista entradas con
// tamaños y ratio de compresión, y marca riesgos: zip-slip (`../`, rutas
// absolutas), doble extensión señuelo (factura.pdf.exe), ejecutables/scripts,
// archivos anidados y ratios de compresión absurdos (señal de zip-bomb).
// Para APK detecta AndroidManifest.xml + classes.dex, lista librerías nativas
// (lib/<abi>/) y extrae los permisos del manifiesto binario (AXML string pool).
// 100% local, sin red, no se ejecuta ni se descomprime nada salvo el manifiesto.

import { parseZip, entryBytes } from '../app/zip.js';

export const archive = (function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  function escAttr(s) { return esc(s).replace(/"/g, '&quot;'); }

  function fmtB(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
    return (n / 1073741824).toFixed(2) + ' GB';
  }

  // ── Heurísticas de clasificación de entradas ──────────────────────────
  // Ejecutables/scripts (extensión final peligrosa).
  const EXEC_EXT = new Set(('exe dll scr com pif bat cmd msi msp cpl hta vbs vbe ' +
    'wsf wsh ps1 psm1 sh elf so dylib reg lnk').split(' '));
  // Extensiones "señuelo" plausibles como primer tramo de un doble-extensión.
  const DECOY_EXT = new Set(('pdf doc docx xls xlsx ppt pptx txt rtf csv jpg jpeg ' +
    'png gif bmp svg mp3 mp4 avi mov htm html xml json').split(' '));
  // Extensión final sospechosa para el patrón doble-extensión (incluye jar/js).
  const DOUBLE_TARGET = new Set([...EXEC_EXT, 'jar', 'jse', 'js', 'apk', 'jnlp']);
  // Archivos comprimidos anidados.
  const ARCHIVE_EXT = new Set(('zip jar apk war ear 7z rar gz tgz bz2 xz tar cab ' +
    'iso lzh arj').split(' '));

  /** Extensión final (minúsculas) del nombre base de una ruta. @param {string} name */
  function ext(name) {
    const b = String(name).replace(/.*[/\\]/, '');
    const i = b.lastIndexOf('.');
    return i > 0 ? b.slice(i + 1).toLowerCase() : '';
  }

  /**
   * Banderas de riesgo de una entrada del central directory.
   * @param {{name:string, compSize:number, size:number}} e @returns {string[]}
   */
  function classifyEntry(e) {
    const flags = [];
    const name = String(e.name);
    const base = name.replace(/.*[/\\]/, '');
    // zip-slip / extracción fuera del destino
    if (/(^|[/\\])\.\.([/\\]|$)/.test(name)) flags.push('path-traversal');
    if (/^([/\\]|[A-Za-z]:[/\\])/.test(name)) flags.push('absolute-path');
    else if (name.indexOf('\\') >= 0) flags.push('backslash-path');
    // doble extensión señuelo (factura.pdf.exe)
    const m = /\.([A-Za-z0-9]{1,5})\.([A-Za-z0-9]{1,6})$/.exec(base);
    if (m && DECOY_EXT.has(m[1].toLowerCase()) && DOUBLE_TARGET.has(m[2].toLowerCase()))
      flags.push('double-extension');
    const x = ext(name);
    if (EXEC_EXT.has(x)) flags.push('executable');
    if (ARCHIVE_EXT.has(x) && !/[/\\]$/.test(name)) flags.push('nested-archive');
    // ratio de compresión absurdo en una entrada grande → señal de zip-bomb
    if (e.compSize > 0 && e.size / e.compSize > 100 && e.size > (1 << 20))
      flags.push('high-ratio');
    return flags;
  }

  /** Tipo de contenedor a partir de la lista de nombres. @param {string[]} names */
  function detectType(names) {
    const set = new Set(names);
    const hasDex = names.some(n => /^classes\d*\.dex$/.test(n));
    if (set.has('AndroidManifest.xml') && (hasDex || names.some(n => n.startsWith('lib/'))))
      return 'APK';
    if (set.has('[Content_Types].xml') && names.some(n => /^(word|xl|ppt)\//.test(n)))
      return 'OOXML (docx/xlsx/pptx)';
    if (set.has('mimetype') && names.some(n => n.startsWith('META-INF/')))
      return 'ODF / EPUB';
    if (set.has('META-INF/MANIFEST.MF')) return 'JAR';
    return 'ZIP';
  }

  // ── AXML: string pool del AndroidManifest.xml binario ─────────────────
  // El manifiesto de un APK está en formato binario (AXML). Su primer chunk es
  // un string pool (spec del runtime de recursos de Android, ResStringPool):
  // de ahí salen los nombres de permisos sin necesidad de decodificar el árbol.
  function readLen8(dv, p) { // varint de 1-2 bytes (longitud UTF-8)
    let v = dv.getUint8(p);
    if (v & 0x80) v = ((v & 0x7f) << 8) | dv.getUint8(p + 1), p += 2; else p += 1;
    return [v, p];
  }
  function readLen16(dv, p) { // varint de 1-2 u16 (longitud UTF-16)
    let v = dv.getUint16(p, true);
    if (v & 0x8000) v = ((v & 0x7fff) << 16) | dv.getUint16(p + 2, true), p += 4; else p += 2;
    return [v, p];
  }

  /**
   * Extrae las cadenas del string pool de un AndroidManifest.xml binario (AXML).
   * Best-effort y defensivo: devuelve [] si no parece AXML o si algo no cuadra.
   * @param {Uint8Array} bytes @returns {string[]}
   */
  function parseAxmlStrings(bytes) {
    try {
      const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      if (bytes.length < 16 || dv.getUint16(0, true) !== 0x0003) return [];
      // El string pool es el primer chunk tras la cabecera de archivo (offset 8).
      let off = 8;
      if (dv.getUint16(off, true) !== 0x0001) return [];
      const stringCount = dv.getUint32(off + 8, true);
      const flags = dv.getUint32(off + 16, true);
      const stringsStart = dv.getUint32(off + 20, true);
      const isUtf8 = (flags & 0x100) !== 0;
      const dataBase = off + stringsStart;
      const out = [];
      const dec8 = new TextDecoder('utf-8');
      for (let i = 0; i < stringCount && i < 100000; i++) {
        const so = dv.getUint32(off + 28 + i * 4, true);
        let p = dataBase + so;
        if (p < 0 || p >= bytes.length) { out.push(''); continue; }
        if (isUtf8) {
          let r = readLen8(dv, p); p = r[1];
          r = readLen8(dv, p); const byteLen = r[0]; p = r[1];
          out.push(dec8.decode(bytes.subarray(p, Math.min(p + byteLen, bytes.length))));
        } else {
          const r = readLen16(dv, p); const u16len = r[0]; p = r[1];
          let s = '';
          for (let k = 0; k < u16len && p + k * 2 + 1 < bytes.length; k++)
            s += String.fromCharCode(dv.getUint16(p + k * 2, true));
          out.push(s);
        }
      }
      return out;
    } catch (_) { return []; }
  }

  /** Filtra los strings del manifiesto que son nombres de permiso. @param {string[]} strings */
  function axmlPermissions(strings) {
    return [...new Set(strings.filter(s => /\.permission\.[A-Z][A-Z0-9_]*$/.test(s)))].sort();
  }

  /**
   * Inspección estructural completa (async por si el manifiesto AXML viene
   * deflateado). Núcleo verificable en Node. @param {Uint8Array} bytes
   */
  async function analyze(bytes) {
    let entries;
    try { entries = parseZip(bytes); }
    catch (e) { return { ok: false, error: String((e && e.message) || e) }; }

    const items = entries.map(e => ({
      name: e.name, method: e.method, compSize: e.compSize, size: e.size, crc: e.crc,
      dir: /[/\\]$/.test(e.name),
      ratio: e.compSize > 0 ? e.size / e.compSize : 0,
      flags: classifyEntry(e),
    }));
    const names = entries.map(e => e.name);
    const type = detectType(names);
    const totals = {
      count: items.length,
      files: items.filter(i => !i.dir).length,
      comp: items.reduce((a, i) => a + i.compSize, 0),
      size: items.reduce((a, i) => a + i.size, 0),
    };
    totals.ratio = totals.comp > 0 ? totals.size / totals.comp : 0;

    /** @type {any} */
    const result = { ok: true, type, items, totals, apk: null };

    if (type === 'APK') {
      const man = entries.find(e => e.name === 'AndroidManifest.xml');
      let permissions = []; let manErr = null;
      if (man) {
        try { permissions = axmlPermissions(parseAxmlStrings(await entryBytes(man))); }
        catch (e) { manErr = String((e && e.message) || e); }
      }
      result.apk = {
        permissions,
        dexes: names.filter(n => /^classes\d*\.dex$/.test(n)),
        libs: [...new Set(names.filter(n => /^lib\/[^/]+\//.test(n)).map(n => n.split('/')[1]))].sort(),
        hasManifest: !!man, manErr,
      };
    }
    return result;
  }

  // ── Render ────────────────────────────────────────────────────────────
  const FLAG_INFO = {
    'path-traversal': { t: 'zip-slip', d: 'la ruta sube de directorio (../): puede escribir fuera del destino al extraer' },
    'absolute-path': { t: 'ruta absoluta', d: 'ruta absoluta: apunta a una ubicación fija del sistema' },
    'backslash-path': { t: 'backslash', d: 'separador \\ en el nombre: anómalo en ZIP, posible evasión' },
    'double-extension': { t: 'doble extensión', d: 'extensión señuelo seguida de ejecutable (p.ej. .pdf.exe)' },
    'executable': { t: 'ejecutable', d: 'binario/script que el SO puede ejecutar' },
    'nested-archive': { t: 'anidado', d: 'archivo comprimido dentro del contenedor' },
    'high-ratio': { t: 'ratio alto', d: 'ratio de compresión > 100×: posible zip-bomb' },
  };

  let last = null;

  function render(container) {
    container.innerHTML =
      '<div class="lab-sec">' +
      '<div class="lab-intro"><b>Archive / APK Inspector.</b> Soltá un <b>.zip / .jar / .apk / .ipa / docx</b> ' +
      'y leo su estructura sin extraerla: entradas, tamaños, ratio de compresión y banderas de riesgo ' +
      '(zip-slip <code>../</code>, doble extensión, ejecutables, anidados, ratios de zip-bomb). ' +
      'Para APK detecto manifiesto/dex/libs nativas y extraigo permisos. Todo local — nada se ejecuta ni sale del navegador.</div>' +
      '<div class="lab-drop" id="arcDrop" tabindex="0"><div class="lab-drop-ic">🗜</div>' +
      '<div class="lab-drop-t">Arrastrá un archivo comprimido (ZIP / JAR / APK / OOXML)</div>' +
      '<div class="lab-drop-s">se lee el central directory; el contenido no se descomprime (salvo el manifiesto del APK)</div></div>' +
      '<input type="file" id="arcFile" style="display:none">' +
      '<div id="arcOut"></div>' +
      '</div>';

    const drop = container.querySelector('#arcDrop');
    const input = container.querySelector('#arcFile');
    const handle = (f) => {
      if (!f) return;
      const out = container.querySelector('#arcOut');
      out.innerHTML = '<div class="lab-loading">Leyendo ' + esc(f.name) + '…</div>';
      f.arrayBuffer().then(ab => analyze(new Uint8Array(ab))).then(res => {
        last = res;
        renderOut(out, res, f.name);
      }).catch(err => {
        out.innerHTML = '<div class="lab-note">Error: ' + esc(String((err && err.message) || err)) + '</div>';
      });
    };
    drop.onclick = () => input.click();
    drop.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } };
    input.onchange = () => handle(input.files[0]);
    drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); };
    drop.ondragleave = () => drop.classList.remove('over');
    drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove('over'); handle(e.dataTransfer.files[0]); };
  }

  function flagBadges(flags) {
    return flags.map(f => {
      const info = FLAG_INFO[f] || { t: f, d: '' };
      return '<span class="arc-flag" title="' + escAttr(info.d) + '">' + esc(info.t) + '</span>';
    }).join('');
  }

  function renderOut(out, res, fname) {
    if (!res.ok) { out.innerHTML = '<div class="lab-note">No es un ZIP válido: ' + esc(res.error) + '</div>'; return; }
    const t = res.totals;
    const risky = res.items.filter(i => i.flags.length);

    let html = '';

    // Resumen
    html += '<div class="lab-panel"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
      '<span>📦 ' + esc(res.type) + ' — ' + esc(fname) + '</span><span class="lab-panel-x">▾</span></div>' +
      '<div class="lab-panel-b"><table class="lab-kv"><tbody>' +
      '<tr><th>Tipo</th><td>' + esc(res.type) + '</td></tr>' +
      '<tr><th>Entradas</th><td>' + t.count + ' (' + t.files + ' archivos)</td></tr>' +
      '<tr><th>Comprimido</th><td>' + fmtB(t.comp) + '</td></tr>' +
      '<tr><th>Descomprimido</th><td>' + fmtB(t.size) + '</td></tr>' +
      '<tr><th>Ratio global</th><td>' + (t.ratio ? t.ratio.toFixed(1) + '×' : '—') +
      (t.ratio > 50 ? ' <span class="arc-flag">posible zip-bomb</span>' : '') + '</td></tr>' +
      (risky.length ? '<tr><th>Riesgos</th><td><b class="arc-warn">' + risky.length + ' entrada(s) marcadas</b></td></tr>' : '') +
      '</tbody></table></div></div>';

    // APK
    if (res.apk) {
      const a = res.apk;
      html += '<div class="lab-panel"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
        '<span>🤖 APK</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">';
      html += '<table class="lab-kv"><tbody>' +
        '<tr><th>DEX</th><td>' + (a.dexes.length ? a.dexes.map(esc).join(', ') : '—') + '</td></tr>' +
        '<tr><th>ABIs nativas</th><td>' + (a.libs.length ? a.libs.map(esc).join(', ') : '— (sin lib/)') + '</td></tr>' +
        '</tbody></table>';
      if (a.permissions.length) {
        html += '<div class="arc-sub">Permisos (' + a.permissions.length + ')</div><div class="arc-perms">' +
          a.permissions.map(p => '<code class="arc-perm">' + esc(p) + '</code>').join('') + '</div>';
      } else if (a.hasManifest) {
        html += '<div class="lab-note">No se pudieron extraer permisos del manifiesto' +
          (a.manErr ? ' (' + esc(a.manErr) + ')' : '') + '.</div>';
      } else {
        html += '<div class="lab-note">Sin AndroidManifest.xml.</div>';
      }
      html += '</div></div>';
    }

    // Riesgos
    if (risky.length) {
      html += '<div class="lab-panel"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
        '<span>⚠ Riesgos (' + risky.length + ')</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">' +
        '<table class="lab-table"><thead><tr><th>Entrada</th><th>Banderas</th></tr></thead><tbody>' +
        risky.map(i => '<tr><td><code>' + esc(i.name) + '</code></td><td>' + flagBadges(i.flags) + '</td></tr>').join('') +
        '</tbody></table></div></div>';
    }

    // Todas las entradas
    html += '<div class="lab-panel collapsed"><div class="lab-panel-h" onclick="this.parentElement.classList.toggle(\'collapsed\')">' +
      '<span>🗂 Entradas (' + res.items.length + ')</span><span class="lab-panel-x">▾</span></div><div class="lab-panel-b">' +
      '<table class="lab-table"><thead><tr><th>Nombre</th><th>Tamaño</th><th>Comp.</th><th>Ratio</th><th>Método</th><th></th></tr></thead><tbody>' +
      res.items.map(i => '<tr' + (i.flags.length ? ' class="arc-row-risk"' : '') + '>' +
        '<td><code>' + esc(i.name) + '</code></td>' +
        '<td>' + (i.dir ? '—' : fmtB(i.size)) + '</td>' +
        '<td>' + (i.dir ? '—' : fmtB(i.compSize)) + '</td>' +
        '<td>' + (i.dir || !i.compSize ? '—' : i.ratio.toFixed(1) + '×') + '</td>' +
        '<td>' + (i.method === 8 ? 'deflate' : i.method === 0 ? 'store' : i.method) + '</td>' +
        '<td>' + flagBadges(i.flags) + '</td></tr>').join('') +
      '</tbody></table></div></div>';

    out.innerHTML = html;
  }

  if (typeof window !== 'undefined' && window.LAB) {
    window.LAB.registerTool({ id: 'archive', label: 'Archive / APK', icon: '🗜', group: '🧪 LAB / TOOLS', render });
  }
  // Hook de test (no-op en browser): núcleo verificable desde Node.
  return { classifyEntry, detectType, parseAxmlStrings, axmlPermissions, analyze, ext };
})();
