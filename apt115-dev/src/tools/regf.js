// APT115 CODEX ARCANUM — regf (Windows Registry Hive)
// quod est superius est sicut quod inferius
//
// Parser forense de hives del registro de Windows (formato "regf"), portado desde
// la spec del formato (docs de libregf/Joachim Metz + python-registry / Kaitai regf).
// Recorre el árbol de claves (nk) y valores (vk) reconstruyendo:
//   - timeline por **last-write** de cada clave (FILETIME),
//   - **hallazgos forenses**: rutas curadas de persistencia/ejecución (Run/RunOnce,
//     Services, UserAssist, RecentDocs, TypedPaths, RunMRU, USB/MountPoints2…),
//   - **hive sucio** (seq primary ≠ secondary → cierre no limpio / logs sin aplicar).
//
// Diferenciador (estilo sqlitef/mft): **recuperación de claves/valores BORRADOS**
// tallando las celdas LIBRES (size positivo) por firma nk/vk con validación de campos
// (filtro anti-falso-positivo) — Windows no borra el contenido de la celda al liberarla.
//
// 100% local. Núcleo PURO testeable. Verificado byte-a-byte contra **python-registry**
// (Willi Ballenthin, implementación independiente) sobre un hive fabricado spec-exacto.
//
// Se trabaja sobre el HIVE YA EXTRAÍDO (NTUSER.DAT / SOFTWARE / SYSTEM / SAM …), no
// imágenes de disco. Límite v1: no aplica los logs de transacción (.LOG1/.LOG2 →
// se avisa si el hive está sucio); valores "big data" (db, >16 KB) listan tamaño pero
// no reensamblan; descriptores de seguridad (sk) no se decodifican (sólo se cuentan).

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

export const regf = (function () {
  'use strict';

  const BASE = 4096; // tamaño del base block; los offsets de celda son relativos a esto

  // Tipos de valor del registro (REG_*)
  const TYPES = {
    0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY',
    4: 'REG_DWORD', 5: 'REG_DWORD_BE', 6: 'REG_LINK', 7: 'REG_MULTI_SZ',
    8: 'REG_RESOURCE_LIST', 9: 'REG_FULL_RESOURCE_DESCRIPTOR',
    10: 'REG_RESOURCE_REQUIREMENTS_LIST', 11: 'REG_QWORD',
  };

  function filetimeRaw(dv, o) {
    const lo = dv.getUint32(o, true), hi = dv.getUint32(o + 4, true);
    return hi * 4294967296 + lo;
  }
  function ftIso(raw) {
    if (!raw) return '';
    const ms = raw / 10000 - 11644473600000;
    if (ms < 0 || ms > 4102444800000) return ''; // fuera de [1970, 2100]
    return new Date(ms).toISOString();
  }

  // ── Base block ────────────────────────────────────────────────────────────
  function parseBaseBlock(dv) {
    if (dv.getUint32(0, true) !== 0x66676572) return null; // "regf" LE
    const seq1 = dv.getUint32(4, true), seq2 = dv.getUint32(8, true);
    let filename = '';
    for (let i = 48; i < 48 + 64 && i + 1 < dv.byteLength; i += 2) {
      const c = dv.getUint16(i, true);
      if (!c) break;
      filename += String.fromCharCode(c);
    }
    return {
      seq1, seq2, dirty: seq1 !== seq2,
      lastWrite: filetimeRaw(dv, 12),
      major: dv.getUint32(20, true), minor: dv.getUint32(24, true),
      fileType: dv.getUint32(28, true),
      rootOff: dv.getInt32(36, true),
      hbinsSize: dv.getUint32(40, true),
      filename,
    };
  }

  // ── Lectura de una celda: devuelve {sig, dataOff, alloc} o null ─────────────
  // off = offset relativo a BASE. La celda es [size:int32][datos]; size<0 = asignada.
  function cellAt(bytes, dv, off) {
    const abs = BASE + off;
    if (abs < 0 || abs + 4 > bytes.length) return null;
    const size = dv.getInt32(abs, true);
    const len = Math.abs(size);
    if (len < 4 || abs + len > bytes.length) return null;
    return { abs, dataOff: abs + 4, size, alloc: size < 0, len };
  }

  function readName(bytes, dv, o, len, ascii) {
    if (o + (ascii ? len : len * 2) > bytes.length) len = 0;
    let s = '';
    if (ascii) for (let i = 0; i < len; i++) s += String.fromCharCode(bytes[o + i]);
    else for (let i = 0; i < len; i++) s += String.fromCharCode(dv.getUint16(o + i * 2, true));
    return s;
  }

  // ── nk (key node) ───────────────────────────────────────────────────────────
  function parseNk(bytes, dv, dataOff) {
    if (dv.getUint16(dataOff, true) !== 0x6b6e) return null; // "nk" LE
    const flags = dv.getUint16(dataOff + 2, true);
    const nameLen = dv.getUint16(dataOff + 72, true);
    const ascii = !!(flags & 0x20); // KEY_COMP_NAME → nombre Latin-1
    return {
      flags,
      lastWrite: filetimeRaw(dv, dataOff + 4),
      parent: dv.getInt32(dataOff + 16, true),
      nSub: dv.getUint32(dataOff + 20, true),
      subListOff: dv.getInt32(dataOff + 28, true),
      nVals: dv.getUint32(dataOff + 36, true),
      valListOff: dv.getInt32(dataOff + 40, true),
      skOff: dv.getInt32(dataOff + 44, true),
      classOff: dv.getInt32(dataOff + 48, true),
      isRoot: !!(flags & 0x04),
      name: readName(bytes, dv, dataOff + 76, nameLen, ascii),
    };
  }

  // ── vk (value) ────────────────────────────────────────────────────────────
  function parseVk(bytes, dv, dataOff) {
    if (dv.getUint16(dataOff, true) !== 0x6b76) return null; // "vk" LE
    const nameLen = dv.getUint16(dataOff + 2, true);
    let dataLen = dv.getUint32(dataOff + 4, true);
    const inline = !!(dataLen & 0x80000000);
    dataLen &= 0x7fffffff;
    const dataPtr = dv.getInt32(dataOff + 8, true);
    const type = dv.getUint32(dataOff + 12, true);
    const flags = dv.getUint16(dataOff + 16, true);
    const ascii = !!(flags & 0x01);
    const name = nameLen ? readName(bytes, dv, dataOff + 20, nameLen, ascii) : '(default)';
    return { name, type, typeName: TYPES[type] || ('0x' + type.toString(16)), dataLen, inline, dataPtr, dataInlineOff: dataOff + 8 };
  }

  // Obtiene los bytes de datos de un vk (inline o en su celda).
  function valueBytes(bytes, dv, vk) {
    if (vk.dataLen === 0) return new Uint8Array(0);
    if (vk.inline) return bytes.subarray(vk.dataInlineOff, vk.dataInlineOff + Math.min(vk.dataLen, 4));
    const c = cellAt(bytes, dv, vk.dataPtr);
    if (!c) return new Uint8Array(0);
    return bytes.subarray(c.dataOff, c.dataOff + Math.min(vk.dataLen, c.len - 4));
  }

  // Decodifica el valor a una representación legible.
  function decodeValue(bytes, dv, vk) {
    const raw = valueBytes(bytes, dv, vk);
    const ldv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    const utf16 = (u) => {
      let s = '';
      for (let i = 0; i + 1 < u.length; i += 2) {
        const c = u[i] | (u[i + 1] << 8);
        if (!c) break;
        s += String.fromCharCode(c);
      }
      return s;
    };
    switch (vk.type) {
      case 1: case 2: case 6: return utf16(raw);                       // SZ / EXPAND_SZ / LINK
      case 4: return raw.length >= 4 ? ldv.getUint32(0, true) : 0;      // DWORD
      case 5: return raw.length >= 4 ? ldv.getUint32(0, false) : 0;     // DWORD_BE
      case 11: return raw.length >= 8 ? (ldv.getUint32(4, true) * 4294967296 + ldv.getUint32(0, true)) : 0; // QWORD
      case 7: {                                                          // MULTI_SZ
        const parts = []; let cur = '';
        for (let i = 0; i + 1 < raw.length; i += 2) {
          const c = raw[i] | (raw[i + 1] << 8);
          if (!c) { if (cur) parts.push(cur); cur = ''; } else cur += String.fromCharCode(c);
        }
        if (cur) parts.push(cur);
        return parts;
      }
      default: return hex(raw, 64);                                     // BINARY / otros
    }
  }
  function hex(u, max) {
    let s = '';
    for (let i = 0; i < Math.min(u.length, max); i++) s += u[i].toString(16).padStart(2, '0');
    return u.length > max ? s + '…' : s;
  }

  // ── Listas de subkeys: lf / lh / li / ri ────────────────────────────────────
  // Devuelve array de offsets (rel a BASE) de los nk hijos. ri = lista de listas.
  function parseSubkeyList(bytes, dv, off, depth) {
    if (off < 0 || off === 0xffffffff || depth > 16) return [];
    const c = cellAt(bytes, dv, off);
    if (!c) return [];
    const sig = String.fromCharCode(bytes[c.dataOff], bytes[c.dataOff + 1]);
    const n = dv.getUint16(c.dataOff + 2, true);
    const out = [];
    if (sig === 'lf' || sig === 'lh') {          // 8 B por elemento: offset + hash
      for (let i = 0; i < n; i++) {
        const o = c.dataOff + 4 + i * 8;
        if (o + 4 > bytes.length) break;
        out.push(dv.getInt32(o, true));
      }
    } else if (sig === 'li') {                    // 4 B por elemento: sólo offset
      for (let i = 0; i < n; i++) {
        const o = c.dataOff + 4 + i * 4;
        if (o + 4 > bytes.length) break;
        out.push(dv.getInt32(o, true));
      }
    } else if (sig === 'ri') {                    // lista de listas (recursivo)
      for (let i = 0; i < n; i++) {
        const o = c.dataOff + 4 + i * 4;
        if (o + 4 > bytes.length) break;
        out.push(...parseSubkeyList(bytes, dv, dv.getInt32(o, true), depth + 1));
      }
    }
    return out;
  }

  function parseValues(bytes, dv, nk) {
    if (!nk.nVals || nk.nVals === 0xffffffff || nk.valListOff < 0) return [];
    const c = cellAt(bytes, dv, nk.valListOff);
    if (!c) return [];
    const out = [];
    const n = Math.min(nk.nVals, Math.floor((c.len - 4) / 4));
    for (let i = 0; i < n; i++) {
      const voff = dv.getInt32(c.dataOff + i * 4, true);
      const vc = cellAt(bytes, dv, voff);
      if (!vc) continue;
      const vk = parseVk(bytes, dv, vc.dataOff);
      if (!vk) continue;
      out.push({ name: vk.name, type: vk.type, typeName: vk.typeName, dataLen: vk.dataLen, value: decodeValue(bytes, dv, vk) });
    }
    return out;
  }

  // ── Árbol de claves desde root ──────────────────────────────────────────────
  function buildTree(bytes, dv, off, path, depth, st) {
    if (st.count >= st.max || depth > 64) { st.truncated = true; return null; }
    const c = cellAt(bytes, dv, off);
    if (!c) return null;
    const nk = parseNk(bytes, dv, c.dataOff);
    if (!nk) return null;
    st.count++;
    const fullPath = depth === 0 ? '' : (path ? path + '\\' + nk.name : nk.name);
    const node = {
      name: nk.name, path: fullPath, lastWrite: nk.lastWrite,
      nSub: nk.nSub, nVals: nk.nVals,
      values: parseValues(bytes, dv, nk),
      subkeys: [],
    };
    const subOffs = parseSubkeyList(bytes, dv, nk.subListOff, 0);
    for (const so of subOffs) {
      const child = buildTree(bytes, dv, so, fullPath, depth + 1, st);
      if (child) node.subkeys.push(child);
    }
    return node;
  }

  // ── Hallazgos forenses: rutas curadas de alta señal ──────────────────────────
  // Cada patrón matchea por substring case-insensitive sobre el path completo.
  const FORENSIC = [
    { re: /\\Run$/i, tag: 'Persistencia (Run)', why: 'Programas que arrancan al iniciar sesión' },
    { re: /\\RunOnce$/i, tag: 'Persistencia (RunOnce)', why: 'Ejecución única al próximo arranque' },
    { re: /\\Explorer\\Run$/i, tag: 'Persistencia (Policies Run)', why: 'Autorun vía políticas' },
    { re: /\\CurrentVersion\\RunServices/i, tag: 'Persistencia (RunServices)', why: 'Servicios legacy al arranque' },
    { re: /\\Services\\[^\\]+$/i, tag: 'Servicio', why: 'Definición de servicio (posible persistencia)' },
    { re: /\\UserAssist\\/i, tag: 'Ejecución (UserAssist)', why: 'Programas ejecutados por el usuario (ROT13)' },
    { re: /\\RecentDocs/i, tag: 'Actividad (RecentDocs)', why: 'Documentos abiertos recientemente' },
    { re: /\\TypedPaths/i, tag: 'Actividad (TypedPaths)', why: 'Rutas tipeadas en el Explorador' },
    { re: /\\TypedURLs/i, tag: 'Actividad (TypedURLs)', why: 'URLs tipeadas en IE/Edge' },
    { re: /\\RunMRU/i, tag: 'Actividad (RunMRU)', why: 'Comandos del cuadro Ejecutar' },
    { re: /\\MountPoints2/i, tag: 'Dispositivos (MountPoints2)', why: 'Volúmenes/USB montados por el usuario' },
    { re: /\\USBSTOR/i, tag: 'Dispositivos (USBSTOR)', why: 'Dispositivos de almacenamiento USB' },
    { re: /\\Enum\\USB/i, tag: 'Dispositivos (USB Enum)', why: 'Dispositivos USB enumerados' },
    { re: /\\AppCompatFlags\\(AppCompatCache|Compatibility Assistant)/i, tag: 'Ejecución (ShimCache/CA)', why: 'Programas ejecutados (compat cache)' },
    { re: /\\BAM\\|\\bam\\State/i, tag: 'Ejecución (BAM)', why: 'Background Activity Moderator: últimos ejecutables' },
    { re: /\\Image File Execution Options\\[^\\]+$/i, tag: 'Persistencia (IFEO)', why: 'Debugger hijack / técnica de secuestro' },
    { re: /\\Winlogon$/i, tag: 'Persistencia (Winlogon)', why: 'Shell/Userinit (secuestro de logon)' },
    { re: /\\ShellNoRoam\\MUICache/i, tag: 'Ejecución (MUICache)', why: 'Ejecutables vistos por el shell' },
    { re: /\\WordWheelQuery/i, tag: 'Actividad (WordWheelQuery)', why: 'Búsquedas del Explorador' },
  ];

  function findForensic(node, hits) {
    for (const f of FORENSIC) {
      if (f.re.test(node.path)) {
        hits.push({ path: node.path, tag: f.tag, why: f.why, lastWrite: node.lastWrite, values: node.values });
        break;
      }
    }
    for (const s of node.subkeys) findForensic(s, hits);
    return hits;
  }

  function countTree(node, acc) {
    acc.keys++;
    acc.values += node.values.length;
    for (const s of node.subkeys) countTree(s, acc);
    return acc;
  }

  // ── Recuperación de borrados: carving de celdas LIBRES (size>0) ──────────────
  // Recorre los hbins y, en cada celda libre, busca firmas nk/vk con campos válidos.
  function recoverDeleted(bytes, dv, hbinsSize) {
    const recovered = { keys: [], values: [] };
    let off = BASE;
    const end = Math.min(bytes.length, BASE + hbinsSize);
    let guard = 0;
    while (off + 32 <= end && guard++ < 1_000_000) {
      if (dv.getUint32(off, true) !== 0x6e696268) break; // "hbin" LE
      const hbinSize = dv.getUint32(off + 8, true);
      if (hbinSize < 4096 || off + hbinSize > bytes.length + 4096) break;
      // recorrer celdas del hbin
      let c = off + 32;
      const hend = Math.min(off + hbinSize, end);
      let cg = 0;
      while (c + 4 <= hend && cg++ < 200000) {
        const size = dv.getInt32(c, true);
        const len = Math.abs(size);
        if (len < 8 || c + len > hend) break;
        if (size > 0) { // celda LIBRE → escanear por nk/vk borrados
          scanFree(bytes, dv, c + 4, c + len, recovered);
        }
        c += len;
      }
      off += hbinSize;
    }
    return recovered;
  }

  // Escanea una región libre buscando firmas nk/vk consistentes.
  function scanFree(bytes, dv, from, to, recovered) {
    for (let p = from; p + 4 <= to; p += 4) {
      const sig = dv.getUint16(p, true);
      if (sig === 0x6b6e) { // "nk"
        const nk = parseNk(bytes, dv, p);
        if (nk && validRecoveredKey(nk)) {
          recovered.keys.push({ name: nk.name, lastWrite: nk.lastWrite, nVals: nk.nVals, parent: nk.parent });
        }
      } else if (sig === 0x6b76) { // "vk"
        const vk = parseVk(bytes, dv, p);
        if (vk && validRecoveredVal(vk)) {
          recovered.values.push({ name: vk.name, typeName: vk.typeName, dataLen: vk.dataLen, value: decodeValue(bytes, dv, vk) });
        }
      }
    }
  }
  // Filtros anti-falso-positivo: nombre razonable + campos en rango.
  function validRecoveredKey(nk) {
    if (!nk.name || nk.name.length > 255) return false;
    if (!/^[\x20-\x7e]+$/.test(nk.name)) return false; // ASCII imprimible
    if (nk.nVals > 0x10000 && nk.nVals !== 0xffffffff) return false;
    if (nk.flags & 0xf800) return false; // bits de flag inválidos
    return true;
  }
  function validRecoveredVal(vk) {
    if (vk.name === '(default)') return false; // demasiado ruidoso en carving
    if (!vk.name || vk.name.length > 255) return false;
    if (!/^[\x20-\x7e]+$/.test(vk.name)) return false;
    if (vk.dataLen > 0x100000) return false; // 1 MB cap
    if (!(vk.type in TYPES)) return false;
    return true;
  }

  // ── Entry point del núcleo ───────────────────────────────────────────────────
  function parse(bytes, opts) {
    const max = (opts && opts.max) || 200000;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const base = parseBaseBlock(dv);
    if (!base) return { ok: false, error: 'No es un hive de registro (falta el magic "regf").' };
    const st = { count: 0, max, truncated: false };
    const tree = buildTree(bytes, dv, base.rootOff, '', 0, st);
    const counts = tree ? countTree(tree, { keys: 0, values: 0 }) : { keys: 0, values: 0 };
    const forensic = tree ? findForensic(tree, []) : [];
    const recovered = recoverDeleted(bytes, dv, base.hbinsSize);
    return {
      ok: true, base, tree, counts, forensic, recovered,
      truncated: st.truncated,
    };
  }

  // ══════════════════════════════ UI ════════════════════════════════════════
  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">🪟 Registry Hive (regf)</div>' +
      '<span class="sec-cmds-badge">local · árbol + persistencia + borrados</span></div>' +
      '<div class="lab-intro">Parsea un <b>hive del registro de Windows</b> (NTUSER.DAT, SOFTWARE, ' +
      'SYSTEM, SAM…): <b>árbol de claves</b> con last-write, <b>hallazgos de persistencia/ejecución</b> ' +
      '(Run/Services/UserAssist/USB…) y <b>recuperación de claves/valores borrados</b>. Trabajá sobre ' +
      'el <b>hive ya extraído</b>. <b>100% local</b>.</div>' +
      '<div class="lab-drop" id="rgDrop" tabindex="0"><div class="lab-drop-ic">🪟</div>' +
      '<div class="lab-drop-t">Arrastrá un hive acá o hacé click</div>' +
      '<div class="lab-drop-s">Hive de registro (magic «regf»)</div></div>' +
      '<input type="file" id="rgFile" style="display:none"><div id="rgOut"></div>';
    const drop = container.querySelector('#rgDrop'), input = container.querySelector('#rgFile');
    drop.onclick = () => input.click();
    drop.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } };
    input.onchange = () => { if (input.files[0]) load(input.files[0], container); };
    drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); };
    drop.ondragleave = () => drop.classList.remove('over');
    drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) load(e.dataTransfer.files[0], container); };
  }

  let st = null;

  function load(file, container) {
    const out = container.querySelector('#rgOut');
    const esc = window.Triage.util.esc;
    out.innerHTML = '<div class="lab-loading">⬡ Leyendo ' + esc(file.name) + ' …</div>';
    const reader = new FileReader();
    reader.onload = (e) => {
      const bytes = new Uint8Array(e.target.result);
      const r = parse(bytes);
      if (!r.ok) { out.innerHTML = '<div class="lab-err">' + esc(r.error) + '</div>'; return; }
      st = { r, name: file.name };
      out.innerHTML = renderReport(r, file.name);
      wire(out, r);
    };
    reader.readAsArrayBuffer(file);
  }

  function kv(rows) {
    return '<div class="lab-kv">' + rows.map(([k, v]) => '<div class="lab-kv-k">' + k + '</div><div class="lab-kv-v">' + v + '</div>').join('') + '</div>';
  }

  function fmtVal(v) {
    const esc = window.Triage.util.esc;
    if (Array.isArray(v)) return v.map(esc).join('<br>');
    return esc(String(v));
  }

  function renderReport(r, name) {
    const esc = window.Triage.util.esc;
    const b = r.base;
    let html = '<div class="lab-panel"><div class="lab-panel-h">🪟 ' + esc(name) + '</div><div class="lab-panel-b">' + kv([
      ['Versión', b.major + '.' + b.minor],
      ['Nombre interno', esc(b.filename) || '<span class="lab-dim">—</span>'],
      ['Última escritura', esc(ftIso(b.lastWrite)) || '<span class="lab-dim">—</span>'],
      ['Secuencia', b.seq1 + (b.dirty ? ' / ' + b.seq2 + ' <span class="lab-warn">⚠ hive SUCIO (logs sin aplicar)</span>' : ' <span class="lab-dim">(limpio)</span>')],
      ['Claves / Valores', r.counts.keys + ' / ' + r.counts.values + (r.truncated ? ' <span class="lab-dim">(capado)</span>' : '')],
    ]) + '</div></div>';

    // Hallazgos forenses
    if (r.forensic.length) {
      html += '<div class="lab-panel"><div class="lab-panel-h">🎯 Hallazgos forenses <span class="lab-dim">(' + r.forensic.length + ')</span></div><div class="lab-panel-b">';
      for (const f of r.forensic) {
        html += '<div class="rg-finding"><div><b>' + esc(f.tag) + '</b> <span class="lab-dim">— ' + esc(f.why) + '</span></div>' +
          '<div class="lab-dim"><code>' + esc(f.path) + '</code> · ' + esc(ftIso(f.lastWrite)) + '</div>';
        if (f.values.length) {
          html += '<table class="lab-table"><tbody>' + f.values.slice(0, 50).map(v =>
            '<tr><td><code>' + esc(v.name) + '</code></td><td class="lab-dim">' + esc(v.typeName) + '</td><td><code>' + fmtVal(v.value) + '</code></td></tr>').join('') + '</tbody></table>';
        }
        html += '</div>';
      }
      html += '</div></div>';
    }

    // Recuperación de borrados
    const rec = r.recovered;
    if (rec.keys.length || rec.values.length) {
      html += '<div class="lab-panel"><div class="lab-panel-h">🗑 Recuperados de celdas libres <span class="lab-dim">(' + rec.keys.length + ' claves, ' + rec.values.length + ' valores)</span></div><div class="lab-panel-b">';
      if (rec.keys.length) {
        html += '<div class="lab-sub">Claves</div><table class="lab-table"><thead><tr><th>Nombre</th><th>Last-write</th><th>#vals</th></tr></thead><tbody>' +
          rec.keys.slice(0, 200).map(k => '<tr><td><code>' + esc(k.name) + '</code></td><td class="lab-dim">' + esc(ftIso(k.lastWrite)) + '</td><td class="lab-dim">' + (k.nVals === 0xffffffff ? 0 : k.nVals) + '</td></tr>').join('') + '</tbody></table>';
      }
      if (rec.values.length) {
        html += '<div class="lab-sub">Valores</div><table class="lab-table"><thead><tr><th>Nombre</th><th>Tipo</th><th>Datos</th></tr></thead><tbody>' +
          rec.values.slice(0, 200).map(v => '<tr><td><code>' + esc(v.name) + '</code></td><td class="lab-dim">' + esc(v.typeName) + '</td><td><code>' + fmtVal(v.value) + '</code></td></tr>').join('') + '</tbody></table>';
      }
      html += '</div></div>';
    }

    // Árbol navegable
    html += '<div class="lab-panel"><div class="lab-panel-h">🌳 Árbol de claves <button class="cv-btn" id="rgExport" style="float:right">exportar JSON</button> <button class="cv-btn" id="rgNote" style="float:right;margin-right:6px">→ nota</button></div><div class="lab-panel-b"><div class="rg-tree">' +
      renderNode(r.tree, true) + '</div></div></div>';
    return html;
  }

  function renderNode(node, open) {
    if (!node) return '';
    const esc = window.Triage.util.esc;
    const label = (node.name || '(root)') + ' <span class="lab-dim">· ' + esc(ftIso(node.lastWrite)) + (node.values.length ? ' · ' + node.values.length + ' val' : '') + '</span>';
    let inner = '';
    if (node.values.length) {
      inner += '<table class="lab-table"><tbody>' + node.values.slice(0, 200).map(v =>
        '<tr><td><code>' + esc(v.name) + '</code></td><td class="lab-dim">' + esc(v.typeName) + '</td><td><code>' + fmtVal(v.value) + '</code></td></tr>').join('') + '</tbody></table>';
    }
    for (const s of node.subkeys) inner += renderNode(s, false);
    if (!node.subkeys.length && !node.values.length) return '<div class="rg-leaf">📄 ' + label + '</div>';
    return '<details class="lab-dll"' + (open ? ' open' : '') + '><summary>📁 ' + label + '</summary><div class="rg-children">' + inner + '</div></details>';
  }

  function wire(out, r) {
    const exp = out.querySelector('#rgExport');
    if (exp) exp.onclick = () => downloadJson(r);
    const note = out.querySelector('#rgNote');
    if (note) note.onclick = () => { if (typeof window.apt115CreateNote === 'function') window.apt115CreateNote('Hive · ' + (st ? st.name : ''), noteMarkdown(r)); };
  }

  function noteMarkdown(r) {
    let md = '# Registry Hive · ' + (st ? st.name : '') + '\n\n- Versión: ' + r.base.major + '.' + r.base.minor +
      '\n- Claves/Valores: ' + r.counts.keys + ' / ' + r.counts.values +
      (r.base.dirty ? '\n- ⚠ Hive SUCIO (logs de transacción sin aplicar)' : '') + '\n';
    if (r.forensic.length) {
      md += '\n## 🎯 Hallazgos forenses\n\n';
      r.forensic.forEach(f => {
        md += '- **' + f.tag + '** `' + f.path + '` (' + ftIso(f.lastWrite) + ')\n';
        f.values.forEach(v => { md += '  - `' + v.name + '` (' + v.typeName + ') = ' + (Array.isArray(v.value) ? v.value.join(' | ') : v.value) + '\n'; });
      });
    }
    if (r.recovered.keys.length || r.recovered.values.length) {
      md += '\n## 🗑 Recuperados de celdas libres\n\n';
      r.recovered.keys.forEach(k => { md += '- clave borrada: `' + k.name + '` (' + ftIso(k.lastWrite) + ')\n'; });
      r.recovered.values.forEach(v => { md += '- valor borrado: `' + v.name + '` (' + v.typeName + ') = ' + (Array.isArray(v.value) ? v.value.join(' | ') : v.value) + '\n'; });
    }
    return md;
  }

  function downloadJson(r) {
    const data = { file: st ? st.name : null, base: { version: r.base.major + '.' + r.base.minor, filename: r.base.filename, lastWrite: ftIso(r.base.lastWrite), dirty: r.base.dirty }, counts: r.counts, forensic: r.forensic.map(f => ({ tag: f.tag, path: f.path, lastWrite: ftIso(f.lastWrite), values: f.values })), recovered: r.recovered, tree: r.tree };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = (st && st.name ? st.name : 'hive') + '.apt115.json'; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  if (typeof window !== 'undefined' && window.LAB) {
    LAB.registerTool({ id: 'regf', label: 'Registry Hive (regf)', icon: '🪟', group: '🔬 Forensics', render });
  }
  // Hook de test (no-op en browser): núcleo puro.
  return { parse, parseBaseBlock, parseNk, parseVk, parseSubkeyList, decodeValue, recoverDeleted, ftIso };
})();
