// APT115 CODEX ARCANUM — SQLite Forensic Browser
// quod est superius est sicut quod inferius
//
// Parser forense propio del formato de archivo SQLite 3 (spec pública
// sqlite.org/fileformat2). Implementado de cero desde la spec — sin motor SQL.
// Pensado para DFIR: el grueso de los artefactos modernos vive en SQLite
// (historial/cookies/descargas de navegadores, WhatsApp/Signal/Telegram, muchos
// artefactos iOS/macOS). 100% local — nada se sube.
//
// Hace lo que un visor SQL NO hace: además de listar el schema y leer registros
// vivos recorriendo los b-tree, **RECUPERA REGISTROS BORRADOS** por carving del
// espacio no asignado de cada página + las páginas de la freelist (donde el
// contenido viejo persiste hasta ser sobreescrito). Verificable contra sqlite3:
// se borran filas, y el carver las vuelve a encontrar.
//
// Núcleo PURO testeable en Node (parse / readTable / recoverDeleted).
// Límite v1: no resuelve overflow de payloads muy grandes (los marca), no parsea
// el -wal/-journal (sólo el archivo principal), y el carving puede dar parciales.

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

export const sqlitef = (function () {
  'use strict';

  const MAGIC = 'SQLite format 3\0';

  function isSqlite(bytes) {
    if (bytes.length < 100) return false;
    for (let i = 0; i < 16; i++) if (bytes[i] !== MAGIC.charCodeAt(i)) return false;
    return true;
  }

  // Varint big-endian base-128 de SQLite (hasta 9 bytes). Devuelve [valor, len].
  // Usa Number (suficiente para forense; valores >2^53 pierden precisión — raro).
  function varint(bytes, off) {
    let val = 0;
    for (let i = 0; i < 8; i++) {
      const b = bytes[off + i];
      if (b === undefined) return [val, i];
      if (i === 8) { val = val * 256 + b; return [val, 9]; }
      val = val * 128 + (b & 0x7f);
      if (!(b & 0x80)) return [val, i + 1];
    }
    // 9º byte: 8 bits completos
    val = val * 256 + (bytes[off + 8] || 0);
    return [val, 9];
  }

  function serialSize(t) {
    if (t <= 4) return t;            // 0..4 → 0,1,2,3,4
    if (t === 5) return 6;
    if (t === 6 || t === 7) return 8;
    if (t === 8 || t === 9) return 0; // const 0 / 1
    return (t - 12) >> 1;            // blob (par) / text (impar): (t-12)/2 ó (t-13)/2
  }

  // ── Cabecera de archivo ────────────────────────────────────────
  function parseHeader(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let pageSize = dv.getUint16(16, false);
    if (pageSize === 1) pageSize = 65536;
    const enc = dv.getUint32(56, false); // 1 utf8, 2 utf16le, 3 utf16be
    return {
      pageSize,
      writeVersion: bytes[18], readVersion: bytes[19],
      reservedPerPage: bytes[20],
      changeCounter: dv.getUint32(24, false),
      pageCount: dv.getUint32(28, false),
      freelistTrunk: dv.getUint32(32, false),
      freelistPages: dv.getUint32(36, false),
      schemaCookie: dv.getUint32(40, false),
      schemaFormat: dv.getUint32(44, false),
      encoding: enc, encodingName: { 1: 'UTF-8', 2: 'UTF-16le', 3: 'UTF-16be' }[enc] || ('?' + enc),
      walMode: bytes[18] === 2 || bytes[19] === 2,
    };
  }

  function decodeText(bytes, a, b, enc) {
    const sub = bytes.subarray(a, b);
    try {
      if (enc === 2) return new TextDecoder('utf-16le').decode(sub);
      if (enc === 3) return new TextDecoder('utf-16be').decode(sub);
      return new TextDecoder('utf-8').decode(sub);
    } catch (e) { return ''; }
  }

  // Parsea un record (payload) → array de valores. usableEnd acota el body.
  function parseRecord(bytes, payStart, payLen, enc) {
    const end = payStart + payLen;
    const [hdrLen, hn] = varint(bytes, payStart);
    if (hdrLen < 1 || hdrLen > payLen) return null;
    const types = [];
    let p = payStart + hn;
    const hdrEnd = payStart + hdrLen;
    while (p < hdrEnd) { const [t, n] = varint(bytes, p); types.push(t); p += n; if (n === 0) return null; }
    // body
    let bp = hdrEnd;
    const values = [];
    for (const t of types) {
      const sz = serialSize(t);
      if (bp + sz > end) return null;
      values.push(readValue(bytes, bp, t, enc));
      bp += sz;
    }
    if (bp !== end) return null; // el body debe consumir EXACTO el payload (filtro fuerte anti-falsos)
    return { values, types };
  }

  function readValue(bytes, off, t, enc) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (t === 0) return null;
    if (t === 8) return 0;
    if (t === 9) return 1;
    if (t === 1) return dv.getInt8(off);
    if (t === 2) return dv.getInt16(off, false);
    if (t === 3) { const v = (bytes[off] << 16) | (bytes[off + 1] << 8) | bytes[off + 2]; return v & 0x800000 ? v - 0x1000000 : v; }
    if (t === 4) return dv.getInt32(off, false);
    if (t === 5) { let v = 0; for (let i = 0; i < 6; i++) v = v * 256 + bytes[off + i]; return v >= 2 ** 47 ? v - 2 ** 48 : v; }
    if (t === 6) { try { return Number(dv.getBigInt64(off, false)); } catch (e) { return 0; } }
    if (t === 7) return dv.getFloat64(off, false);
    const sz = serialSize(t);
    if (t & 1) return decodeText(bytes, off, off + sz, enc);          // TEXT (impar)
    return { blob: sz, hex: hex(bytes, off, Math.min(sz, 16)) };      // BLOB (par)
  }

  function hex(bytes, off, n) { let s = ''; for (let i = 0; i < n; i++) s += bytes[off + i].toString(16).padStart(2, '0'); return s; }

  // Header de página b-tree. base = offset de la página; hdrAt = base (+100 en pág 1).
  function pageHeader(bytes, base, hdrAt) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const type = bytes[hdrAt];
    const interior = (type === 2 || type === 5);
    return {
      type, interior,
      firstFreeblock: dv.getUint16(hdrAt + 1, false),
      cellCount: dv.getUint16(hdrAt + 3, false),
      cellContentStart: dv.getUint16(hdrAt + 5, false) || 65536,
      rightPointer: interior ? dv.getUint32(hdrAt + 8, false) : 0,
      cellPtrArray: hdrAt + (interior ? 12 : 8),
    };
  }

  // Recorre el b-tree de una tabla (root = nº de página) → registros VIVOS.
  function walkTable(bytes, root, h, cap, out) {
    const visited = new Set();
    const stack = [root];
    while (stack.length && out.length < cap) {
      const pg = stack.pop();
      if (!pg || pg < 1 || visited.has(pg)) continue;
      visited.add(pg);
      const base = (pg - 1) * h.pageSize;
      if (base + 8 > bytes.length) continue;
      const hdrAt = pg === 1 ? base + 100 : base;
      const ph = pageHeader(bytes, base, hdrAt);
      const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const usable = h.pageSize - h.reservedPerPage;
      for (let i = 0; i < ph.cellCount && i < 200000; i++) {
        const cpo = ph.cellPtrArray + i * 2;
        if (cpo + 2 > bytes.length) break;
        const cell = base + dv.getUint16(cpo, false);
        if (ph.type === 13) { // leaf table
          const rec = readLeafTableCell(bytes, cell, base + usable, h.encoding);
          if (rec && out.length < cap) out.push({ rowid: rec.rowid, values: rec.values, deleted: false });
        } else if (ph.type === 5) { // interior table → hijos
          if (cell + 4 <= bytes.length) stack.push(dv.getUint32(cell, false));
        }
      }
      if (ph.type === 5 && ph.rightPointer) stack.push(ph.rightPointer);
    }
  }

  // Celda de hoja de tabla: varint(payloadLen) varint(rowid) record [overflow].
  function readLeafTableCell(bytes, off, pageEnd, enc) {
    const [payLen, n1] = varint(bytes, off);
    const [rowid, n2] = varint(bytes, off + n1);
    const payStart = off + n1 + n2;
    if (payLen < 1 || payStart + payLen > bytes.length) {
      // posible overflow (payload mayor que la página) — marcar sin parsear
      return null;
    }
    const rec = parseRecord(bytes, payStart, payLen, enc);
    if (!rec) return null;
    return { rowid, values: rec.values };
  }

  // ── Schema (sqlite_master en la página 1) ───────────────────────
  function readSchema(bytes, h) {
    const rows = [];
    walkTable(bytes, 1, h, 10000, rows);
    const tables = [];
    for (const r of rows) {
      const v = r.values; // [type, name, tbl_name, rootpage, sql]
      if (v.length >= 5) tables.push({ type: v[0], name: v[1], tblName: v[2], rootpage: v[3], sql: typeof v[4] === 'string' ? v[4] : '' });
    }
    return tables;
  }

  // ── Recuperación de borrados ─────────────────────────────────────
  // Intenta una celda de hoja de tabla en `off`; null si no valida. Filtros
  // fuertes anti-falso-positivo: payload acotado, body que consume EXACTO, y al
  // menos un valor no-NULL (descarta zonas en cero / padding).
  function tryLeafCell(bytes, off, limit, enc, pageSize) {
    const [payLen, n1] = varint(bytes, off);
    if (payLen < 2 || payLen > pageSize) return null;
    const [rowid, n2] = varint(bytes, off + n1);
    if (rowid < 0 || n1 + n2 > 9) return null;
    const payStart = off + n1 + n2;
    if (payStart + payLen > limit) return null;
    const rec = parseRecord(bytes, payStart, payLen, enc);
    if (!rec || rec.values.length < 1) return null;
    return { rowid, values: rec.values, end: payStart + payLen };
  }

  function notAllNull(values) { return values.some(v => v !== null); }

  // Carving de [a,b): recupera celdas borradas, saltando las posiciones que son
  // celdas VIVAS (`skip` = Set de offsets de celda viva). `ncols` (Set de conteos
  // de columnas aceptables, del schema) corrige la des-alineación típica del
  // carving: un registro válido debe tener exactamente las columnas de la tabla.
  function carve(bytes, a, b, enc, cap, out, pageSize, skip, ncols) {
    let off = a;
    while (off < b && out.length < cap) {
      if (skip && skip.has(off)) {           // celda viva → saltarla entera
        const c = tryLeafCell(bytes, off, b, enc, pageSize);
        off = c ? c.end : off + 1;
        continue;
      }
      const c = tryLeafCell(bytes, off, b, enc, pageSize);
      if (c && notAllNull(c.values) && (!ncols || ncols.has(c.values.length))) {
        out.push({ rowid: c.rowid, values: c.values, deleted: true, at: off }); off = c.end;
      } else off++;
    }
  }

  // Páginas (interior + hoja) de una tabla + nº de columnas (del 1er registro vivo).
  function tablePages(bytes, root, h) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const pages = new Set(); const stack = [root]; let ncols = 0;
    const usable = h.pageSize - h.reservedPerPage;
    while (stack.length) {
      const pg = stack.pop();
      if (!pg || pg < 1 || pages.has(pg)) continue;
      pages.add(pg);
      const base = (pg - 1) * h.pageSize;
      if (base + 8 > bytes.length) continue;
      const hdrAt = pg === 1 ? base + 100 : base;
      const ph = pageHeader(bytes, base, hdrAt);
      if (ph.type === 5) {
        for (let i = 0; i < ph.cellCount; i++) {
          const cell = base + dv.getUint16(ph.cellPtrArray + i * 2, false);
          if (cell + 4 <= bytes.length) stack.push(dv.getUint32(cell, false));
        }
        if (ph.rightPointer) stack.push(ph.rightPointer);
      } else if (ph.type === 13 && !ncols && ph.cellCount) {
        const cell = base + dv.getUint16(ph.cellPtrArray, false);
        const c = tryLeafCell(bytes, cell, base + usable, h.encoding, h.pageSize);
        if (c) ncols = c.values.length;
      }
    }
    return { pages, ncols };
  }

  // Páginas de la freelist (trunk → leaf). Las leaf son páginas liberadas enteras.
  function freelistPages(bytes, h) {
    const pages = [];
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let trunk = h.freelistTrunk, guard = 0;
    while (trunk && guard++ < 100000) {
      const base = (trunk - 1) * h.pageSize;
      if (base + 8 > bytes.length) break;
      const next = dv.getUint32(base, false);
      const n = dv.getUint32(base + 4, false);
      for (let i = 0; i < n && i < (h.pageSize / 4); i++) {
        const lp = dv.getUint32(base + 8 + i * 4, false);
        if (lp) pages.push(lp);
      }
      trunk = next;
    }
    return pages;
  }

  // Recupera borrados de: (a) el área de contenido de cada página de hoja de
  // tabla (donde quedan las celdas borradas, saltando las vivas), y (b) las
  // páginas de la freelist (liberadas enteras). El primer cell de cada freeblock
  // puede salir parcial (SQLite le pisa 4 bytes con el header del freeblock).
  function recoverDeleted(bytes, h, cap, schema) {
    const out = [];
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const usable = h.pageSize - h.reservedPerPage;
    const total = Math.min(h.pageCount, Math.floor(bytes.length / h.pageSize));
    schema = schema || readSchema(bytes, h);
    // mapa página→nº columnas (del schema) + conteos globales para freelist
    const pageNcols = new Map(); const allNcols = new Set();
    for (const t of schema) {
      if (t.type !== 'table' || !t.rootpage) continue;
      const { pages, ncols } = tablePages(bytes, t.rootpage, h);
      if (ncols) allNcols.add(ncols);
      for (const pg of pages) pageNcols.set(pg, ncols ? new Set([ncols]) : null);
    }
    const free = new Set(freelistPages(bytes, h));
    for (let pg = 1; pg <= total && out.length < cap; pg++) {
      const base = (pg - 1) * h.pageSize;
      if (base + 8 > bytes.length) break;
      if (free.has(pg)) { carve(bytes, base, base + usable, h.encoding, cap, out, h.pageSize, null, allNcols.size ? allNcols : null); continue; }
      const hdrAt = pg === 1 ? base + 100 : base;
      const type = bytes[hdrAt];
      if (type !== 13) continue; // sólo hojas de tabla
      const ph = pageHeader(bytes, base, hdrAt);
      const live = new Set();
      for (let i = 0; i < ph.cellCount && i < 200000; i++) {
        const cpo = ph.cellPtrArray + i * 2;
        if (cpo + 2 > bytes.length) break;
        live.add(base + dv.getUint16(cpo, false));
      }
      const ncols = pageNcols.has(pg) ? pageNcols.get(pg) : (allNcols.size ? allNcols : null);
      carve(bytes, base + ph.cellContentStart, base + usable, h.encoding, cap, out, h.pageSize, live, ncols);
    }
    return out;
  }

  // ── API de alto nivel ───────────────────────────────────────────
  function parse(bytes) {
    if (!isSqlite(bytes)) return null;
    const h = parseHeader(bytes);
    const schema = readSchema(bytes, h);
    return { header: h, schema };
  }

  function readTable(bytes, rootpage, cap) {
    const h = parseHeader(bytes);
    const out = [];
    walkTable(bytes, rootpage, h, cap || 5000, out);
    return out;
  }

  // ════════════════════════════════════════════════════════════════
  // Render (tool LAB, grupo 🔬 Forensics)
  // ════════════════════════════════════════════════════════════════
  let st = null; // { bytes, h, schema }

  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">🗃 SQLite Forensics</div>' +
      '<span class="sec-cmds-badge">local · recupera borrados</span></div>' +
      '<div class="lab-intro">Explora una base <b>SQLite</b> (historial de navegador, apps de chat, ' +
      'artefactos iOS/macOS…) y <b>recupera registros borrados</b> del espacio no asignado y la freelist. ' +
      'Todo <b>100% local</b>. Soltá el archivo <code>.db</code>/<code>.sqlite</code>.</div>' +
      '<div class="lab-drop" id="sqDrop" tabindex="0"><div class="lab-drop-ic">🗃</div>' +
      '<div class="lab-drop-t">Arrastrá una base SQLite acá o hacé click</div>' +
      '<div class="lab-drop-s">.db .sqlite .sqlite3 (cualquier archivo SQLite 3)</div></div>' +
      '<input type="file" id="sqFile" style="display:none"><div id="sqOut"></div>';
    const drop = container.querySelector('#sqDrop'), input = container.querySelector('#sqFile');
    drop.onclick = () => input.click();
    drop.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } };
    input.onchange = () => { if (input.files[0]) load(input.files[0], container); };
    drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); };
    drop.ondragleave = () => drop.classList.remove('over');
    drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) load(e.dataTransfer.files[0], container); };
  }

  function load(file, container) {
    const out = container.querySelector('#sqOut');
    const esc = window.Triage.util.esc;
    out.innerHTML = '<div class="lab-loading">⬡ Leyendo ' + esc(file.name) + ' …</div>';
    const reader = new FileReader();
    reader.onload = (e) => {
      const bytes = new Uint8Array(e.target.result);
      if (!isSqlite(bytes)) { out.innerHTML = '<div class="lab-err">No es un archivo SQLite 3 (falta el magic «SQLite format 3»).</div>'; return; }
      const h = parseHeader(bytes);
      st = { bytes, h, schema: readSchema(bytes, h) };
      out.innerHTML = renderOverview();
      wire(out);
    };
    reader.readAsArrayBuffer(file);
  }

  function renderOverview() {
    const U = window.Triage.util, esc = U.esc, h = st.h;
    const tables = st.schema.filter(t => t.type === 'table' && !/^sqlite_/.test(t.name));
    let html = '<div class="lab-panel"><div class="lab-panel-h">🗃 Base SQLite</div><div class="lab-panel-b">' + kv([
      ['Page size', h.pageSize + ' B'],
      ['Páginas', h.pageCount + ' <span class="lab-dim">(change counter ' + h.changeCounter + ')</span>'],
      ['Encoding', esc(h.encodingName)],
      ['Freelist', h.freelistPages + ' páginas <span class="lab-dim">(contenido borrado recuperable)</span>'],
      ['Schema format', String(h.schemaFormat)],
      ['Tablas', String(tables.length)],
    ]) + '</div></div>';

    html += '<div class="lab-panel"><div class="lab-panel-h">📑 Tablas</div><div class="lab-panel-b">';
    html += '<div class="lab-imps">' + tables.map((t, i) =>
      '<span class="lab-imp sq-tbl" data-i="' + st.schema.indexOf(t) + '" style="cursor:pointer">' + esc(t.name) + '</span>').join('') + '</div>';
    html += '<div class="lab-note">Click en una tabla para ver sus registros vivos + los <b>borrados recuperados</b>.</div>';
    html += '</div></div><div id="sqTable"></div>';

    html += '<div class="lab-panel"><div class="lab-panel-h">♻ Recuperar borrados (toda la base)</div><div class="lab-panel-b">' +
      '<div class="lab-actions"><button class="rs-copy" id="sqRecover">Escanear espacio no asignado + freelist</button> <span id="sqRecMsg" class="lab-dim"></span></div>' +
      '<div class="lab-note">Carving del espacio liberado: recupera filas borradas que aún no fueron sobreescritas. ' +
      'Puede dar resultados parciales. No incluye el <code>-wal</code>/<code>-journal</code> (sólo el archivo principal).</div>' +
      '<div id="sqRecOut"></div></div></div>';
    return html;
  }

  function wire(out) {
    out.querySelectorAll('.sq-tbl').forEach(el => {
      el.onclick = () => showTable(parseInt(el.getAttribute('data-i'), 10), out);
    });
    const rec = out.querySelector('#sqRecover');
    if (rec) rec.onclick = () => {
      const msg = out.querySelector('#sqRecMsg'); msg.textContent = 'escaneando…';
      setTimeout(() => {
        const recovered = recoverDeleted(st.bytes, st.h, 5000, st.schema);
        msg.textContent = recovered.length + ' registro(s) recuperado(s)';
        out.querySelector('#sqRecOut').innerHTML = recovered.length ? recordsTable(recovered, null) :
          '<div class="lab-note">No se recuperaron registros (espacio sobreescrito o base compactada/VACUUM).</div>';
      }, 10);
    };
  }

  function showTable(idx, out) {
    const esc = window.Triage.util.esc;
    const t = st.schema[idx];
    const cols = columnsOf(t.sql);
    const live = []; walkTable(st.bytes, t.rootpage, st.h, 2000, live);
    const cont = out.querySelector('#sqTable');
    let html = '<div class="lab-panel"><div class="lab-panel-h">📄 ' + esc(t.name) + ' <span class="lab-dim">(' + live.length + ' filas vivas)</span></div><div class="lab-panel-b">';
    if (t.sql) html += '<details class="lab-dll"><summary>CREATE statement</summary><pre class="lab-pre">' + esc(t.sql) + '</pre></details>';
    html += recordsTable(live, cols);
    html += '</div></div>';
    cont.innerHTML = html;
  }

  function columnsOf(sql) {
    if (!sql) return null;
    const m = /\(([\s\S]*)\)/.exec(sql);
    if (!m) return null;
    // split por comas de nivel superior, tomar el primer token de cada columna
    const parts = []; let depth = 0, cur = '';
    for (const ch of m[1]) { if (ch === '(') depth++; if (ch === ')') depth--; if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; } else cur += ch; }
    if (cur.trim()) parts.push(cur);
    return parts.map(p => p.trim().split(/\s+/)[0].replace(/["'`\[\]]/g, '')).filter(c => c && !/^(PRIMARY|UNIQUE|CHECK|FOREIGN|CONSTRAINT|KEY)$/i.test(c));
  }

  function cellText(v) {
    const esc = window.Triage.util.esc;
    if (v === null) return '<span class="lab-dim">NULL</span>';
    if (typeof v === 'object' && v.blob != null) return '<span class="lab-dim">‹blob ' + v.blob + ' B: ' + v.hex + '…›</span>';
    let s = String(v); if (s.length > 120) s = s.slice(0, 120) + '…';
    return esc(s);
  }

  function recordsTable(rows, cols) {
    if (!rows.length) return '<div class="lab-note">Sin registros.</div>';
    const esc = window.Triage.util.esc;
    const maxCols = Math.max(...rows.map(r => r.values.length));
    const header = ['rowid'].concat(cols && cols.length >= maxCols ? cols.slice(0, maxCols) : Array.from({ length: maxCols }, (_, i) => 'col' + i));
    let html = '<div style="overflow:auto"><table class="lab-table"><thead><tr><th></th>' + header.map(c => '<th>' + esc(c) + '</th>').join('') + '</tr></thead><tbody>';
    for (const r of rows.slice(0, 1000)) {
      html += '<tr' + (r.deleted ? ' style="opacity:.8"' : '') + '><td>' + (r.deleted ? '♻' : '') + '</td><td class="lab-dim">' + r.rowid + '</td>' +
        r.values.map(v => '<td>' + cellText(v) + '</td>').join('') + '</tr>';
    }
    html += '</tbody></table></div>';
    if (rows.some(r => r.deleted)) html += '<div class="lab-note">♻ = registro <b>recuperado</b> (estaba borrado).</div>';
    return html;
  }

  function kv(rows) { return '<table class="lab-kv"><tbody>' + rows.map(r => '<tr><th>' + r[0] + '</th><td>' + r[1] + '</td></tr>').join('') + '</tbody></table>'; }

  function release() { st = null; }

  if (typeof window !== 'undefined' && window.LAB) {
    window.LAB.registerTool({ id: 'sqlitef', label: 'SQLite Forensics', icon: '🗃', group: '🔬 Forensics', render });
  }

  return { isSqlite, parseHeader, parse, readSchema, readTable, recoverDeleted, walkTable, parseRecord, varint, serialSize, freelistPages, release };
})();

if (typeof window !== 'undefined') { window.Triage = window.Triage || {}; window.Triage.sqlitef = sqlitef; }
