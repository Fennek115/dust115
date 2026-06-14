// APT115 CODEX ARCANUM — $MFT (NTFS Master File Table)
// quod est superius est sicut quod inferius
//
// Parser forense del $MFT de NTFS, portado desde la spec del formato (registros
// FILE, [MS-…] / docs de ntfs-3g / analyzeMFT / dfir_ntfs). Reconstruye el
// **timeline del filesystem** y caza **timestomping** (anti-forense): comparar los
// timestamps de $STANDARD_INFORMATION (cambiables por API) contra los de
// $FILE_NAME (mucho más difíciles de alterar). También lista **archivos borrados**
// (registro no en uso) y data **residente** (contenido chico embebido en el MFT).
//
// 100% local. Núcleo PURO testeable. Verificado byte-a-byte contra **analyzeMFT**
// sobre un $MFT fabricado spec-exacto (filenames/MACE/SI-vs-FN/borrado/residente).
//
// Se trabaja sobre el $MFT YA EXTRAÍDO (no imágenes de disco completas — límite de
// memoria). Límite v1: $DATA no-residente lista runs pero no resuelve el contenido;
// no sigue ATTRIBUTE_LIST a registros de extensión; sin $MFT muy grande (cap).

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

export const mft = (function () {
  'use strict';

  const SIG = 0x454c4946; // "FILE" LE

  function filetimeRaw(dv, o) {
    const lo = dv.getUint32(o, true), hi = dv.getUint32(o + 4, true);
    return hi * 4294967296 + lo;
  }
  function ftIso(raw) {
    if (!raw) return '';
    const ms = raw / 10000 - 11644473600000;
    if (ms < 0 || ms > 4102444800000) return ''; // fuera de [1970, 2100] → inválido
    return new Date(ms).toISOString();
  }

  function detectRecSize(bytes) {
    // Estándar 1024. Si el header del primer FILE trae alloc size potencia de 2, usarla.
    if (bytes.length >= 32) {
      const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      if (dv.getUint32(0, true) === SIG) {
        const alloc = dv.getUint32(28, true);
        if (alloc >= 256 && alloc <= 8192 && (alloc & (alloc - 1)) === 0) return alloc;
      }
    }
    return 1024;
  }

  // Aplica el fixup (Update Sequence Array): los últimos 2 bytes de cada sector
  // deben igualar la USN; se restauran los valores originales guardados en la USA.
  function applyFixup(rec, dv) {
    const usaOff = dv.getUint16(4, true), usaCnt = dv.getUint16(6, true);
    if (!usaOff || usaCnt < 1) return true;
    const usn = dv.getUint16(usaOff, true);
    let ok = true;
    for (let i = 1; i < usaCnt; i++) {
      const secEnd = i * 512 - 2;
      if (secEnd + 2 > rec.length) break;
      if (dv.getUint16(secEnd, true) !== usn) ok = false; // sector inconsistente
      const orig = dv.getUint16(usaOff + i * 2, true);
      rec[secEnd] = orig & 0xff; rec[secEnd + 1] = (orig >> 8) & 0xff;
    }
    return ok;
  }

  function parseRecord(bytes, off, recSize, index) {
    const rec = bytes.subarray(off, off + recSize).slice(); // copia (el fixup muta)
    const dv = new DataView(rec.buffer, rec.byteOffset, rec.byteLength);
    if (dv.getUint32(0, true) !== SIG) return null; // no es FILE (BAAD/cero)
    const fixupOk = applyFixup(rec, dv);
    const seq = dv.getUint16(16, true);
    const links = dv.getUint16(18, true);
    const attrOff = dv.getUint16(20, true);
    const flags = dv.getUint16(22, true);
    const baseRef = filetimeRaw(dv, 32) & 0xffffffffffff; // 48 bits
    const recordnum = dv.getUint32(44, true);

    const out = {
      index, recordnum, seq, links,
      inUse: !!(flags & 0x01), isDir: !!(flags & 0x02),
      isExtension: baseRef !== 0,
      fixupOk,
      si: null, fnList: [], dataResident: null, dataNonResident: null,
      attrTypes: [],
    };

    // Recorrer atributos
    let p = attrOff;
    let guard = 0;
    while (p + 4 <= recSize && guard++ < 200) {
      const type = dv.getUint32(p, true);
      if (type === 0xffffffff || type === 0) break;
      const len = dv.getUint32(p + 4, true);
      if (len < 16 || p + len > recSize) break;
      const nonResident = rec[p + 8];
      out.attrTypes.push(type);

      if (!nonResident) {
        const contentLen = dv.getUint32(p + 16, true);
        const contentOff = dv.getUint16(p + 20, true);
        const c = p + contentOff;
        if (type === 0x10 && c + 32 <= recSize) { // $STANDARD_INFORMATION
          out.si = {
            crtime: filetimeRaw(dv, c), mtime: filetimeRaw(dv, c + 8),
            ctime: filetimeRaw(dv, c + 16), atime: filetimeRaw(dv, c + 24),
          };
        } else if (type === 0x30 && c + 0x42 <= recSize) { // $FILE_NAME
          const parentRef = filetimeRaw(dv, c) & 0xffffffffffff;
          const nameLen = rec[c + 0x40], ns = rec[c + 0x41];
          let name = '';
          for (let i = 0; i < nameLen && c + 0x42 + i * 2 + 1 < recSize; i++) name += String.fromCharCode(dv.getUint16(c + 0x42 + i * 2, true));
          out.fnList.push({
            name, namespace: ns, parentRef,
            crtime: filetimeRaw(dv, c + 8), mtime: filetimeRaw(dv, c + 16),
            ctime: filetimeRaw(dv, c + 24), atime: filetimeRaw(dv, c + 32),
            realSize: filetimeRaw(dv, c + 0x30),
          });
        } else if (type === 0x80) { // $DATA residente
          out.dataResident = { size: contentLen, off: c };
        }
      } else if (type === 0x80) { // $DATA no-residente
        const allocSize = filetimeRaw(dv, p + 40), realSize = filetimeRaw(dv, p + 48);
        out.dataNonResident = { allocSize, realSize };
      }
      p += len;
    }
    return out;
  }

  // Elige el $FILE_NAME para mostrar (preferir WIN32/POSIX sobre DOS 8.3).
  function primaryFn(fnList) {
    if (!fnList.length) return null;
    return fnList.find(f => f.namespace !== 2) || fnList[0];
  }

  // Heurística de timestomping: SI vs FN. FN sólo lo actualiza el kernel al crear/
  // mover; SI es trivial de alterar (SetFileTime/timestomp). Señales:
  //  - SI.crtime < FN.crtime (creado "antes" de existir su nombre): muy fuerte.
  //  - SI sub-segundo en cero (muchos stompers truncan a segundos): heurística.
  function timestompSignals(si, fn) {
    const sig = [];
    if (!si || !fn) return sig;
    if (si.crtime && fn.crtime && si.crtime < fn.crtime)
      sig.push('SI.crtime anterior a FN.crtime (' + ftIso(si.crtime) + ' < ' + ftIso(fn.crtime) + ')');
    if (si.mtime && fn.mtime && si.mtime < fn.mtime)
      sig.push('SI.mtime anterior a FN.mtime');
    // sub-segundo en cero en SI pero no en FN
    const frac = (t) => t % 10000000;
    if (si.crtime && frac(si.crtime) === 0 && fn.crtime && frac(fn.crtime) !== 0)
      sig.push('SI.crtime sin fracción de segundo (posible truncado por stomper)');
    return sig;
  }

  function parse(bytes, opts) {
    const max = (opts && opts.max) || 500000;
    const recSize = detectRecSize(bytes);
    const total = Math.floor(bytes.length / recSize);
    const records = [];
    let truncated = false;
    for (let i = 0; i < total; i++) {
      if (i >= max) { truncated = true; break; }
      const r = parseRecord(bytes, i * recSize, recSize, i);
      if (r) records.push(r);
    }
    return { recSize, totalSlots: total, parsed: records.length, truncated, records, summary: summarize(records) };
  }

  function summarize(records) {
    let deleted = 0, dirs = 0, files = 0, resident = 0, fixupBad = 0;
    const timestomped = [];
    for (const r of records) {
      if (!r.inUse) deleted++;
      if (r.isDir) dirs++; else files++;
      if (r.dataResident) resident++;
      if (!r.fixupOk) fixupBad++;
      const fn = primaryFn(r.fnList);
      const sig = timestompSignals(r.si, fn);
      if (sig.length) timestomped.push({ recordnum: r.recordnum, name: fn ? fn.name : '', signals: sig });
    }
    return { count: records.length, deleted, dirs, files, resident, fixupBad, timestomped };
  }

  // ══════════════════════════════ UI ════════════════════════════════════
  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">🗂 $MFT (NTFS)</div>' +
      '<span class="sec-cmds-badge">local · timeline + timestomping</span></div>' +
      '<div class="lab-intro">Parsea el <b>$MFT</b> de NTFS: timeline de archivos (MACE), ' +
      '<b>archivos borrados</b>, data <b>residente</b> y detección de <b>timestomping</b> ' +
      '(SI vs FN). Trabajá sobre el <b>$MFT ya extraído</b>. <b>100% local</b>.</div>' +
      '<div class="lab-drop" id="mfDrop" tabindex="0"><div class="lab-drop-ic">🗂</div>' +
      '<div class="lab-drop-t">Arrastrá un $MFT acá o hacé click</div>' +
      '<div class="lab-drop-s">$MFT extraído (registros FILE de 1024 B)</div></div>' +
      '<input type="file" id="mfFile" style="display:none"><div id="mfOut"></div>';
    const drop = container.querySelector('#mfDrop'), input = container.querySelector('#mfFile');
    drop.onclick = () => input.click();
    drop.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } };
    input.onchange = () => { if (input.files[0]) load(input.files[0], container); };
    drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); };
    drop.ondragleave = () => drop.classList.remove('over');
    drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) load(e.dataTransfer.files[0], container); };
  }

  let st = null;

  function load(file, container) {
    const out = container.querySelector('#mfOut');
    const esc = window.Triage.util.esc;
    out.innerHTML = '<div class="lab-loading">⬡ Leyendo ' + esc(file.name) + ' …</div>';
    const reader = new FileReader();
    reader.onload = (e) => {
      const bytes = new Uint8Array(e.target.result);
      const parsed = parse(bytes);
      if (!parsed.records.length) { out.innerHTML = '<div class="lab-err">No se encontraron registros FILE (¿es un $MFT extraído?).</div>'; return; }
      st = { parsed, name: file.name };
      out.innerHTML = renderReport(parsed, file.name);
      wire(out, parsed);
    };
    reader.readAsArrayBuffer(file);
  }

  function kv(rows) {
    return '<div class="lab-kv">' + rows.map(([k, v]) => '<div class="lab-kv-k">' + k + '</div><div class="lab-kv-v">' + v + '</div>').join('') + '</div>';
  }

  function renderReport(p, name) {
    const esc = window.Triage.util.esc;
    const s = p.summary;
    let html = '<div class="lab-panel"><div class="lab-panel-h">🗂 ' + esc(name) + '</div><div class="lab-panel-b">' + kv([
      ['Registros', p.parsed + ' <span class="lab-dim">de ' + p.totalSlots + ' slots' + (p.truncated ? ' (capado)' : '') + '</span>'],
      ['Tamaño registro', p.recSize + ' B'],
      ['Archivos / Directorios', s.files + ' / ' + s.dirs],
      ['Borrados', String(s.deleted)],
      ['Data residente', String(s.resident)],
      ['Fixup inconsistente', s.fixupBad ? '<span class="lab-warn">' + s.fixupBad + '</span>' : '0'],
    ]) + '</div></div>';

    // Timestomping
    if (s.timestomped.length) {
      html += '<div class="lab-panel"><div class="lab-panel-h">⚠ Timestomping sospechado <span class="lab-dim">(' + s.timestomped.length + ')</span></div><div class="lab-panel-b"><div style="overflow:auto"><table class="lab-table"><thead><tr><th>rec#</th><th>Nombre</th><th>Señales</th></tr></thead><tbody>' +
        s.timestomped.slice(0, 200).map(t => '<tr><td class="lab-dim">' + t.recordnum + '</td><td><code>' + esc(t.name) + '</code></td><td class="lab-warn">' + t.signals.map(esc).join('<br>') + '</td></tr>').join('') +
        '</tbody></table></div></div></div>';
    }

    // Tabla de registros
    html += '<div class="lab-panel"><div class="lab-panel-h">📄 Registros <button class="cv-btn" id="mfExport" style="float:right">exportar JSON</button> <button class="cv-btn" id="mfNote" style="float:right;margin-right:6px">→ nota</button></div><div class="lab-panel-b"><div style="overflow:auto"><table class="lab-table"><thead><tr><th>rec#</th><th></th><th>Nombre</th><th>↑padre</th><th>Tamaño</th><th>SI creado</th><th>SI modif.</th></tr></thead><tbody>';
    for (const r of p.records.slice(0, 3000)) {
      const fn = primaryFn(r.fnList);
      const size = r.dataResident ? r.dataResident.size : (r.dataNonResident ? r.dataNonResident.realSize : (fn ? fn.realSize : 0));
      const icon = !r.inUse ? '🗑' : (r.isDir ? '📁' : '');
      html += '<tr' + (!r.inUse ? ' style="opacity:.6"' : '') + '><td class="lab-dim">' + r.recordnum + '</td><td>' + icon + '</td><td><code>' + esc(fn ? fn.name : '') + '</code></td><td class="lab-dim">' + (fn ? fn.parentRef : '') + '</td><td class="lab-dim">' + (size || '') + '</td><td class="lab-dim">' + esc(r.si ? ftIso(r.si.crtime) : '') + '</td><td class="lab-dim">' + esc(r.si ? ftIso(r.si.mtime) : '') + '</td></tr>';
    }
    html += '</tbody></table></div>' + (p.records.length > 3000 ? '<div class="lab-note">Mostrando los primeros 3000 de ' + p.records.length + '.</div>' : '') + '</div></div>';
    return html;
  }

  function wire(out, p) {
    const exp = out.querySelector('#mfExport');
    if (exp) exp.onclick = () => downloadJson(p);
    const note = out.querySelector('#mfNote');
    if (note) note.onclick = () => { if (typeof window.apt115CreateNote === 'function') window.apt115CreateNote('$MFT · ' + (st ? st.name : ''), noteMarkdown(p)); };
  }

  function noteMarkdown(p) {
    const s = p.summary;
    let md = '# $MFT · ' + (st ? st.name : '') + '\n\n- Registros: ' + p.parsed + '\n- Borrados: ' + s.deleted + '\n- Data residente: ' + s.resident + '\n';
    if (s.timestomped.length) {
      md += '\n## ⚠ Timestomping\n\n';
      s.timestomped.forEach(t => { md += '- rec' + t.recordnum + ' `' + t.name + '`: ' + t.signals.join('; ') + '\n'; });
    }
    return md;
  }

  function downloadJson(p) {
    const recs = p.records.map(r => { const fn = primaryFn(r.fnList); return { recordnum: r.recordnum, inUse: r.inUse, isDir: r.isDir, name: fn ? fn.name : '', parentRef: fn ? fn.parentRef : null, si: r.si && mapIso(r.si), fn: fn && mapIso(fn), residentSize: r.dataResident ? r.dataResident.size : null }; });
    const data = { file: st ? st.name : null, summary: p.summary, records: recs };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = (st && st.name ? st.name : 'mft') + '.apt115.json'; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  function mapIso(t) { return { crtime: ftIso(t.crtime), mtime: ftIso(t.mtime), ctime: ftIso(t.ctime), atime: ftIso(t.atime) }; }

  if (typeof window !== 'undefined' && window.LAB) {
    LAB.registerTool({ id: 'mft', label: '$MFT (NTFS)', icon: '🗂', group: '🔬 Forensics', render });
  }
  // Hook de test (no-op en browser): núcleo puro.
  return { parse, parseRecord, primaryFn, timestompSignals, ftIso, detectRecSize, applyFixup };
})();
