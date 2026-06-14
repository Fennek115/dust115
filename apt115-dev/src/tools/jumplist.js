// APT115 CODEX ARCANUM — Jump Lists (Windows)
// quod est superius est sicut quod inferius
//
// Parser forense de las Jump Lists de Windows — prueba muy fuerte de actividad de
// usuario (archivos/apps abiertos, aun borrados, en USB o en red). Reúsa CASI TODO
// lo que ya tenemos:
//   - automaticDestinations-ms = contenedor **CFB** → src/triage/cfb.js
//     · streams numerados (en hex) = **SHLLINK** → src/triage/lnk.js (ya parsea LNK)
//     · stream **DestList** = orden MRU/MFU + último acceso + pin + hostname (lo NUEVO acá)
//   - customDestinations-ms = secuencia de LNKs (sin CFB) → se **tallan** y se parsean con lnk.js
//
// El AppID (nombre del archivo, hex) identifica la app que generó la lista. Base de
// AppIDs PARCIAL (curada) — los no listados se muestran con su hex.
//
// 100% local. Núcleo PURO testeable: `parseDestList` (propio) verificado byte-a-byte
// contra la muestra real (entry-id ↔ stream) + LNKs cruzados con LnkParse3.
// Ref. formato DestList: ForensicsWiki "Jump Lists", JLECmd (Eric Zimmerman).

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

export const jumplist = (function () {
  'use strict';

  // ── AppIDs conocidos (parcial; hex del nombre de archivo → app) ───────
  const APPIDS = {
    'f01b4d95cf55d32a': 'Windows Explorer',
    '5f7b5f1e01b83767': 'Windows Explorer (Quick Access)',
    '1b4dd67f29cb1962': 'Windows Explorer (Win7)',
    '7e4dca80246863e3': 'Panel de Control',
    '1bc392b8e104a00e': 'Remote Desktop (mstsc.exe)',
    '9b9cdc69c1c24e2b': 'Notepad',
    '5d696d521de238c3': 'Google Chrome',
    'b8c27cef40c9fdf4': 'Microsoft Edge',
    'de2199a049894b34': 'PowerShell',
    'a5e46e3c8a8c2c5e': 'cmd.exe',
    '9839aff842b315b9': 'Microsoft Word',
    'adba00420b7c5fab': 'Microsoft Excel',
    '7beb045a4b5d3e08': '7-Zip',
    '16f2f0042ddbe0e8': 'Windows Terminal',
  };
  const appName = (hex) => APPIDS[(hex || '').toLowerCase()] || null;

  function filetime(lo, hi) {
    const ft = hi * 4294967296 + lo;
    if (!ft) return '';
    return new Date(ft / 10000 - 11644473600000).toISOString();
  }

  // ── Stream DestList (el aporte NUEVO; reúsa cfb/lnk para el resto) ─────
  // Header (32 B): version(4) nEntries(4) nPinned(4) … lastEntry@16 … lastRev@24.
  // Entrada v≥3 (Win10/11): hostname@72[16] entryId@88(4) lastAccess@100(FILETIME)
  //   pin@108(int32: -1=no, ≥0=pos) strlen@128(2) path(UTF-16LE) + 4 B de cola.
  // Entrada v1 (Win7/8): igual pero strlen@112, sin los 16 B extra ni la cola.
  function parseDestList(b) {
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const u32 = (o) => dv.getUint32(o, true), u16 = (o) => dv.getUint16(o, true);
    if (b.length < 32) return { version: 0, nEntries: 0, nPinned: 0, entries: [] };
    const version = u32(0), nEntries = u32(4), nPinned = u32(8);
    const v1 = version < 3;
    const slOff = v1 ? 112 : 128;        // offset del largo de string dentro de la entrada
    const fixedMin = slOff + 2;          // parte fija mínima
    const entries = [];
    let o = 32;
    for (let i = 0; i < nEntries && o + fixedMin <= b.length; i++) {
      let host = '';
      for (let j = 0; j < 16; j++) { const ch = b[o + 72 + j]; if (ch >= 32 && ch < 127) host += String.fromCharCode(ch); }
      const entryId = u32(o + 88);
      const lastAccess = filetime(u32(o + 100), u32(o + 104));
      const pin = dv.getInt32(o + 108, true);
      const strlen = u16(o + slOff);
      let path = '';
      for (let j = 0; j < strlen && o + slOff + 2 + j * 2 + 1 < b.length; j++) {
        const ch = u16(o + slOff + 2 + j * 2);
        path += (ch >= 0xd800 && ch < 0xe000) ? '·' : String.fromCharCode(ch);
      }
      entries.push({ mru: i, entryId, stream: entryId.toString(16), hostname: host.trim(), lastAccess, pinned: pin >= 0, path });
      o += slOff + 2 + strlen * 2 + (v1 ? 0 : 4);
    }
    return { version, nEntries, nPinned, entries };
  }

  // ── Detalle de un SHLLINK ya parseado por lnk.js ──────────────────────
  function lnkDetail(L) {
    const li = L.linkInfo || {};
    const base = li.localBasePath || '';
    const target = base + (li.pathSuffix ? (base && !base.endsWith('\\') ? '\\' : '') + li.pathSuffix : '');
    return {
      target,
      drive: li.driveType || '',
      volume: li.volumeLabel || '',
      machineId: (L.extra && L.extra.tracker && L.extra.tracker.machineId) || '',
      ctime: L.creationTime || '', atime: L.accessTime || '', wtime: L.writeTime || '',
      size: L.targetSize || 0,
      net: li.flags === 2 || /^\\\\/.test(target) || (li.driveType === 'red'),
      removable: li.driveType === 'extraíble' || li.driveType === 'removable',
    };
  }

  // ── Orquestación (deps inyectadas: cfb, lnk) ──────────────────────────
  function analyze(bytes, deps) {
    const cfb = deps.cfb, lnk = deps.lnk;
    if (cfb.isCfb(bytes)) return analyzeAutomatic(bytes, cfb, lnk);
    return analyzeCustom(bytes, lnk);
  }

  function analyzeAutomatic(bytes, cfb, lnk) {
    const c = cfb.parse(bytes);
    const streams = {};
    for (const e of c.entries) if (e.isStream && /^[0-9a-f]+$/i.test(e.name)) streams[e.name.toLowerCase()] = e;
    const dlEntry = c.byPath('DestList');
    const dl = dlEntry ? parseDestList(dlEntry.read()) : { version: 0, nEntries: 0, nPinned: 0, entries: [] };

    const rows = [];
    for (const de of dl.entries) {
      const row = { ...de };
      const s = streams[de.stream];
      if (s) { try { row.lnk = lnkDetail(lnk.parse(s.read())); } catch (e) { row.lnkError = String(e && e.message || e); } }
      rows.push(row);
    }
    // streams SHLLINK sin entrada en DestList (huérfanos — pueden indicar borrado de DestList)
    const referenced = new Set(dl.entries.map(e => e.stream));
    const orphans = [];
    for (const name in streams) {
      if (!referenced.has(name)) {
        try { orphans.push({ stream: name, lnk: lnkDetail(lnk.parse(streams[name].read())) }); } catch (e) { /* ignora */ }
      }
    }
    return { kind: 'automatic', cfbVersion: dl.version, nEntries: dl.nEntries, nPinned: dl.nPinned, streamCount: Object.keys(streams).length, rows, orphans, indicators: indicators(rows.concat(orphans)) };
  }

  function analyzeCustom(bytes, lnk) {
    const rows = [];
    for (let i = 0; i + 0x4c <= bytes.length; i++) {
      if (bytes[i] === 0x4c && bytes[i + 1] === 0 && bytes[i + 2] === 0 && bytes[i + 3] === 0 &&
        bytes[i + 4] === 0x01 && bytes[i + 5] === 0x14 && bytes[i + 6] === 0x02 && bytes[i + 7] === 0) {
        try {
          const L = lnk.parse(bytes.subarray(i));
          rows.push({ offset: i, lnk: lnkDetail(L) });
        } catch (e) { /* firma falsa: seguir */ }
      }
    }
    return { kind: 'custom', count: rows.length, rows, indicators: indicators(rows) };
  }

  function indicators(rows) {
    const machineIds = new Set(), nets = [], removables = [], exes = [];
    for (const r of rows) {
      const L = r.lnk; if (!L) continue;
      if (L.machineId) machineIds.add(L.machineId);
      if (L.net && L.target) nets.push(L.target);
      if (L.removable && L.target) removables.push(L.target);
      if (/\.(exe|dll|scr|com|bat|cmd|ps1|vbs|js|hta|msi|lnk)$/i.test(L.target)) exes.push(L.target);
    }
    return { machineIds: [...machineIds], net: [...new Set(nets)], removable: [...new Set(removables)], executables: [...new Set(exes)] };
  }

  // ══════════════════════════════ UI ════════════════════════════════════
  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">📌 Jump Lists</div>' +
      '<span class="sec-cmds-badge">local · actividad de usuario</span></div>' +
      '<div class="lab-intro">Lee las <b>Jump Lists</b> de Windows (<code>*.automaticDestinations-ms</code> / ' +
      '<code>*.customDestinations-ms</code>): qué archivos/apps abrió el usuario, cuándo, desde qué unidad ' +
      '(local/red/USB) y en qué equipo. Reúsa los parsers CFB + LNK. <b>100% local</b>.</div>' +
      '<div class="lab-drop" id="jlDrop" tabindex="0"><div class="lab-drop-ic">📌</div>' +
      '<div class="lab-drop-t">Arrastrá una Jump List acá o hacé click</div>' +
      '<div class="lab-drop-s">…Recent\\AutomaticDestinations\\*.automaticDestinations-ms · CustomDestinations\\*.customDestinations-ms</div></div>' +
      '<input type="file" id="jlFile" style="display:none"><div id="jlOut"></div>';
    const drop = container.querySelector('#jlDrop'), input = container.querySelector('#jlFile');
    drop.onclick = () => input.click();
    drop.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } };
    input.onchange = () => { if (input.files[0]) load(input.files[0], container); };
    drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); };
    drop.ondragleave = () => drop.classList.remove('over');
    drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) load(e.dataTransfer.files[0], container); };
  }

  let st = null;

  function load(file, container) {
    const out = container.querySelector('#jlOut');
    const esc = window.Triage.util.esc;
    out.innerHTML = '<div class="lab-loading">⬡ Leyendo ' + esc(file.name) + ' …</div>';
    const reader = new FileReader();
    reader.onload = (e) => {
      const bytes = new Uint8Array(e.target.result);
      const cfb = window.Triage.cfb, lnk = window.Triage.lnk;
      if (!cfb || !lnk) { out.innerHTML = '<div class="lab-err">Faltan los parsers CFB/LNK (bug de build).</div>'; return; }
      if (!cfb.isCfb(bytes) && !/customDestinations/i.test(file.name) && !hasLnkSig(bytes)) {
        out.innerHTML = '<div class="lab-err">No parece una Jump List (ni CFB ni secuencia de LNKs).</div>'; return;
      }
      const res = analyze(bytes, { cfb, lnk });
      const appId = (file.name.match(/^([0-9a-f]+)\./i) || [])[1] || '';
      st = { res, name: file.name, appId };
      out.innerHTML = renderReport(res, file.name, appId);
      wire(out, res);
    };
    reader.readAsArrayBuffer(file);
  }

  function hasLnkSig(b) {
    for (let i = 0; i + 8 < Math.min(b.length, 4096); i++)
      if (b[i] === 0x4c && b[i + 1] === 0 && b[i + 4] === 0x01 && b[i + 5] === 0x14) return true;
    return false;
  }

  function kv(rows) {
    return '<div class="lab-kv">' + rows.map(([k, v]) =>
      '<div class="lab-kv-k">' + k + '</div><div class="lab-kv-v">' + v + '</div>').join('') + '</div>';
  }

  function renderReport(res, name, appId) {
    const esc = window.Triage.util.esc;
    const an = appName(appId);
    let html = '<div class="lab-panel"><div class="lab-panel-h">📌 ' + esc(name) + '</div><div class="lab-panel-b">' + kv([
      ['Tipo', res.kind === 'automatic' ? 'automaticDestinations (CFB + DestList)' : 'customDestinations (LNKs tallados)'],
      ['AppID', appId ? (esc(appId) + (an ? ' <span class="lab-dim">→ ' + esc(an) + '</span>' : ' <span class="lab-dim">(app no identificada)</span>')) : '—'],
    ].concat(res.kind === 'automatic'
      ? [['DestList', 'v' + res.cfbVersion + ' · ' + res.nEntries + ' entradas (' + res.nPinned + ' pinned)'],
         ['Streams SHLLINK', String(res.streamCount)]]
      : [['LNKs tallados', String(res.count)]])) + '</div></div>';

    // Indicadores
    const ind = res.indicators;
    if (ind.machineIds.length || ind.net.length || ind.removable.length || ind.executables.length) {
      html += '<div class="lab-panel"><div class="lab-panel-h">⚠ Indicadores</div><div class="lab-panel-b">';
      if (ind.machineIds.length) html += '<div class="lab-kv"><div class="lab-kv-k">MachineIDs</div><div class="lab-kv-v">' + ind.machineIds.map(esc).join(', ') + ' <span class="lab-dim">(atribución/clustering)</span></div></div>';
      if (ind.net.length) html += impList('🌐 Rutas de red (UNC)', ind.net, esc);
      if (ind.removable.length) html += impList('💾 Unidades extraíbles (USB)', ind.removable, esc);
      if (ind.executables.length) html += impList('⚙ Ejecutables/scripts', ind.executables, esc);
      html += '</div></div>';
    }

    // Tabla principal
    if (res.kind === 'automatic') {
      html += '<div class="lab-panel"><div class="lab-panel-h">📄 Entradas (orden MRU) <button class="cv-btn" id="jlExport" style="float:right">exportar JSON</button> <button class="cv-btn" id="jlNote" style="float:right;margin-right:6px">→ nota</button></div><div class="lab-panel-b"><div style="overflow:auto"><table class="lab-table"><thead><tr><th>MRU</th><th>id</th><th>Objetivo</th><th>Unidad</th><th>Último acceso</th><th>Pin</th><th>Host</th></tr></thead><tbody>' +
        res.rows.map(r => '<tr><td class="lab-dim">' + r.mru + '</td><td class="lab-dim">' + r.entryId + '</td><td><code>' + esc((r.lnk && r.lnk.target) || r.path || '') + '</code></td><td>' + esc((r.lnk && r.lnk.drive) || '') + (r.lnk && r.lnk.volume ? ' <span class="lab-dim">' + esc(r.lnk.volume) + '</span>' : '') + '</td><td class="lab-dim">' + esc(r.lastAccess) + '</td><td>' + (r.pinned ? '📌' : '') + '</td><td class="lab-dim">' + esc(r.hostname) + '</td></tr>').join('') +
        '</tbody></table></div>' +
        (res.orphans.length ? '<div class="lab-note">⚠ ' + res.orphans.length + ' stream(s) SHLLINK sin entrada en DestList (posible borrado de DestList).</div>' : '') +
        '</div></div>';
    } else {
      html += '<div class="lab-panel"><div class="lab-panel-h">📄 Destinos (LNKs) <button class="cv-btn" id="jlExport" style="float:right">exportar JSON</button> <button class="cv-btn" id="jlNote" style="float:right;margin-right:6px">→ nota</button></div><div class="lab-panel-b"><div style="overflow:auto"><table class="lab-table"><thead><tr><th>#</th><th>Objetivo</th><th>Unidad</th><th>Modificado</th><th>Host</th></tr></thead><tbody>' +
        res.rows.map((r, i) => '<tr><td class="lab-dim">' + i + '</td><td><code>' + esc(r.lnk.target) + '</code></td><td>' + esc(r.lnk.drive) + '</td><td class="lab-dim">' + esc(r.lnk.wtime) + '</td><td class="lab-dim">' + esc(r.lnk.machineId) + '</td></tr>').join('') +
        '</tbody></table></div></div></div>';
    }
    return html;
  }

  function impList(label, list, esc) {
    return '<div class="lab-kv"><div class="lab-kv-k">' + label + '</div><div class="lab-kv-v">' +
      list.slice(0, 50).map(v => '<div><code>' + esc(v) + '</code></div>').join('') + '</div></div>';
  }

  function wire(out, res) {
    const exp = out.querySelector('#jlExport');
    if (exp) exp.onclick = () => downloadJson(res);
    const note = out.querySelector('#jlNote');
    if (note) note.onclick = () => {
      if (typeof window.apt115CreateNote !== 'function') return;
      window.apt115CreateNote('Jump List · ' + (st ? st.name : ''), noteMarkdown(res));
    };
  }

  function noteMarkdown(res) {
    let md = '# Jump List · ' + (st ? st.name : '') + '\n\n';
    if (st && st.appId) md += '- AppID: ' + st.appId + (appName(st.appId) ? ' (' + appName(st.appId) + ')' : '') + '\n';
    md += '- Tipo: ' + res.kind + '\n\n## Objetivos\n\n';
    const rows = res.rows || [];
    rows.forEach(r => { const t = (r.lnk && r.lnk.target) || r.path || ''; md += '- ' + t + (r.lastAccess ? ' — ' + r.lastAccess : '') + (r.pinned ? ' 📌' : '') + '\n'; });
    const ind = res.indicators;
    if (ind.net.length) md += '\n## Rutas de red\n\n' + ind.net.map(x => '- ' + x).join('\n') + '\n';
    if (ind.removable.length) md += '\n## USB\n\n' + ind.removable.map(x => '- ' + x).join('\n') + '\n';
    if (ind.machineIds.length) md += '\n## MachineIDs\n\n' + ind.machineIds.map(x => '- ' + x).join('\n') + '\n';
    return md;
  }

  function downloadJson(res) {
    const data = { file: st ? st.name : null, appId: st ? st.appId : null, app: st ? appName(st.appId) : null, ...res };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = (st && st.name ? st.name : 'jumplist') + '.apt115.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  if (typeof window !== 'undefined' && window.LAB) {
    LAB.registerTool({ id: 'jumplist', label: 'Jump Lists', icon: '📌', group: '🔬 Forensics', render });
  }
  // Hook de test (no-op en browser): núcleo puro + orquestador con deps inyectadas.
  return { parseDestList, analyze, analyzeAutomatic, analyzeCustom, lnkDetail, appName, filetime };
})();
