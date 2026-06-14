// APT115 CODEX ARCANUM — journald (Linux systemd Journal)
// quod est superius est sicut quod inferius
//
// Parser forense de los logs binarios de systemd-journald (.journal), portado de la
// spec oficial (systemd.io/JOURNAL_FILE_FORMAT + Kaitai systemd_journal CC0). Es el
// equivalente Linux a EVTX. Recorre la **cadena de entry arrays** → objetos ENTRY →
// objetos DATA, y reconstruye cada entrada con todos sus campos (MESSAGE, _PID, _UID,
// _COMM, _SYSTEMD_UNIT, PRIORITY, _HOSTNAME, _EXE…), resaltando señales forenses
// (sudo/su, sshd login/fallo, sesiones, servicios caídos, prioridad de error, kernel).
//
// 100% local. Núcleo PURO testeable. Verificado contra **journalctl** (systemd, oráculo
// independiente) sobre journals reales de este WSL.
//
// Soporta el formato moderno **COMPACT** (items le32) + KEYED-HASH (no afecta la lectura
// secuencial). Los payloads DATA grandes (>512 B) pueden venir **comprimidos** (ZSTD/LZ4/
// XZ); en la práctica los campos chicos NO se comprimen, así que la inmensa mayoría se lee
// directo. Los payloads comprimidos se MARCAN (DecompressionStream no soporta zstd/lz4/xz);
// descomprimirlos queda como mejora futura (vendorizar un decoder pure-JS).

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

export const journald = (function () {
  'use strict';

  const SIG = 'LPKSHHRH';
  // incompatible flags
  const F_COMP_XZ = 0x1, F_COMP_LZ4 = 0x2, F_KEYED = 0x4, F_COMP_ZSTD = 0x8, F_COMPACT = 0x10;
  // object types
  const OBJ_DATA = 1, OBJ_ENTRY = 3, OBJ_ENTRY_ARRAY = 6;

  function ascii(bytes, o, len) { let s = ''; for (let i = 0; i < len; i++) s += String.fromCharCode(bytes[o + i]); return s; }
  function hexId(bytes, o, n) { let s = ''; for (let i = 0; i < n; i++) s += bytes[o + i].toString(16).padStart(2, '0'); return s; }
  function u64(dv, o) { return Number(dv.getBigUint64(o, true)); }
  function realtimeIso(us) {
    if (!us) return '';
    const ms = us / 1000;
    if (ms < 0 || ms > 4102444800000) return '';
    return new Date(ms).toISOString();
  }

  function parseHeader(dv, bytes) {
    if (ascii(bytes, 0, 8) !== SIG) return null;
    const incompat = dv.getUint32(12, true);
    return {
      compatFlags: dv.getUint32(8, true),
      incompatFlags: incompat,
      compact: !!(incompat & F_COMPACT),
      keyed: !!(incompat & F_KEYED),
      compZstd: !!(incompat & F_COMP_ZSTD),
      compLz4: !!(incompat & F_COMP_LZ4),
      compXz: !!(incompat & F_COMP_XZ),
      state: bytes[16],
      fileId: hexId(bytes, 24, 16),
      machineId: hexId(bytes, 40, 16),
      bootId: hexId(bytes, 56, 16),
      headerSize: u64(dv, 88),
      arenaSize: u64(dv, 96),
      tailObjectOffset: u64(dv, 136),
      nObjects: u64(dv, 144),
      nEntries: u64(dv, 152),
      entryArrayOffset: u64(dv, 176),
      headRealtime: u64(dv, 184),
      tailRealtime: u64(dv, 192),
    };
  }

  function objHeader(dv, bytes, o) {
    if (o < 0 || o + 16 > bytes.length) return null;
    return { type: bytes[o], flags: bytes[o + 1], size: u64(dv, o + 8) };
  }

  // Payload de un objeto DATA → { field, value, compressed }
  function readData(dv, bytes, o, compact) {
    const oh = objHeader(dv, bytes, o);
    if (!oh || oh.type !== OBJ_DATA) return null;
    const payOff = o + (compact ? 72 : 64);
    const payLen = oh.size - (compact ? 72 : 64);
    if (payLen < 0 || payOff + payLen > bytes.length) return null;
    const comp = oh.flags & (F_COMP_XZ | F_COMP_LZ4 | F_COMP_ZSTD);
    if (comp) {
      const algo = (oh.flags & F_COMP_ZSTD) ? 'zstd' : (oh.flags & F_COMP_LZ4) ? 'lz4' : 'xz';
      return { field: '', value: '[' + algo + ' comprimido, ' + payLen + ' B]', compressed: algo, raw: '' };
    }
    // "FIELD=value" en bytes crudos (value puede ser binario)
    let eq = -1;
    for (let i = 0; i < payLen; i++) { if (bytes[payOff + i] === 0x3d) { eq = i; break; } }
    if (eq < 0) return { field: ascii(bytes, payOff, Math.min(payLen, 64)), value: '', compressed: null };
    const field = ascii(bytes, payOff, eq);
    const value = utf8(bytes, payOff + eq + 1, payLen - eq - 1);
    return { field, value, compressed: null };
  }

  function utf8(bytes, o, len) {
    // decodifica UTF-8 (los MESSAGE pueden traer no-ASCII); cae a latin1 si falla
    try { return new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(o, o + len)); }
    catch (e) { let s = ''; for (let i = 0; i < len; i++) s += String.fromCharCode(bytes[o + i]); return s; }
  }

  function parseEntry(dv, bytes, o, compact, max) {
    const oh = objHeader(dv, bytes, o);
    if (!oh || oh.type !== OBJ_ENTRY) return null;
    const seqnum = u64(dv, o + 16);
    const realtime = u64(dv, o + 24);
    const monotonic = u64(dv, o + 32);
    const bootId = hexId(bytes, o + 40, 16);
    const itemSize = compact ? 4 : 16;
    const nItems = Math.floor((oh.size - 64) / itemSize);
    const fields = {};
    for (let i = 0; i < nItems && i < 512; i++) {
      const itemOff = o + 64 + i * itemSize;
      const dataOff = compact ? dv.getUint32(itemOff, true) : u64(dv, itemOff);
      if (!dataOff) continue;
      const d = readData(dv, bytes, dataOff, compact);
      if (d && d.field && !(d.field in fields)) fields[d.field] = d.value;
    }
    return { seqnum, realtime, monotonic, bootId, fields };
  }

  function parse(bytes, opts) {
    const max = (opts && opts.max) || 200000;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const header = parseHeader(dv, bytes);
    if (!header) return { ok: false, error: 'No es un journal de systemd (falta el magic "LPKSHHRH").' };

    const entries = [];
    let truncated = false, eaCount = 0, parseErrors = 0;
    const seen = new Set();
    let eaOff = header.entryArrayOffset;
    let guard = 0;
    while (eaOff && guard++ < 1000000) {
      if (seen.has(eaOff)) break; // anti-loop
      seen.add(eaOff);
      const oh = objHeader(dv, bytes, eaOff);
      if (!oh || oh.type !== OBJ_ENTRY_ARRAY) break;
      eaCount++;
      const nextOff = u64(dv, eaOff + 16);
      const itemSize = header.compact ? 4 : 8;
      const nItems = Math.floor((oh.size - 24) / itemSize);
      for (let i = 0; i < nItems; i++) {
        const itemOff = eaOff + 24 + i * itemSize;
        const entryOff = header.compact ? dv.getUint32(itemOff, true) : u64(dv, itemOff);
        if (!entryOff) continue; // padding / no usado
        try {
          const e = parseEntry(dv, bytes, entryOff, header.compact, max);
          if (e) entries.push(e);
        } catch (err) { parseErrors++; }
        if (entries.length >= max) { truncated = true; break; }
      }
      if (truncated) break;
      eaOff = nextOff;
    }

    const forensic = scanForensic(entries);
    return { ok: true, header, entries, count: entries.length, entryArrays: eaCount, forensic, truncated, parseErrors };
  }

  // ── Señales forenses ─────────────────────────────────────────────────────────
  const PRIO = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'];
  function scanForensic(entries) {
    const hits = [];
    for (const e of entries) {
      const f = e.fields;
      const msg = f.MESSAGE || '';
      const comm = f._COMM || f.SYSLOG_IDENTIFIER || '';
      const prio = f.PRIORITY != null ? parseInt(f.PRIORITY, 10) : 6;
      let tag = null, sev = 'info', why = '';
      if (/^(sshd|sshd-session)/.test(comm) || /sshd\[/.test(msg)) {
        if (/Failed password|Invalid user|authentication failure|Connection closed by authenticating/i.test(msg)) { tag = 'SSH login fallido'; sev = 'med'; why = 'Posible fuerza bruta / acceso no autorizado'; }
        else if (/Accepted (password|publickey)/i.test(msg)) { tag = 'SSH login exitoso'; sev = 'med'; why = 'Inicio de sesión remoto'; }
      }
      if (!tag && (comm === 'sudo' || /sudo\[/.test(msg) || /\bsudo:/.test(msg))) {
        if (/COMMAND=/.test(msg)) { tag = 'sudo — comando'; sev = 'med'; why = 'Ejecución con privilegios'; }
        else if (/authentication failure|incorrect password/i.test(msg)) { tag = 'sudo — fallo de auth'; sev = 'med'; why = 'Intento fallido de privilegios'; }
        else { tag = 'sudo'; sev = 'med'; why = 'Uso de sudo'; }
      }
      if (!tag && (comm === 'su' || /\bsu(\[|\:)/.test(msg))) { tag = 'su'; sev = 'med'; why = 'Cambio de usuario'; }
      if (!tag && /authentication failure|pam_unix.*failure|Failed/i.test(msg) && /pam|login|auth/i.test(comm + msg)) { tag = 'Fallo de autenticación'; sev = 'med'; why = 'PAM/login fallido'; }
      if (!tag && /(New session \d+|session opened|session closed) (of|for) user/i.test(msg)) { tag = 'Sesión de usuario'; sev = 'info'; why = 'Apertura/cierre de sesión'; }
      if (!tag && /segfault|general protection|Killed process|Out of memory|oom-kill/i.test(msg)) { tag = 'Crash / OOM'; sev = 'med'; why = 'Proceso caído (posible explotación)'; }
      if (!tag && /\.service: (Failed|Main process exited|Start request repeated)/i.test(msg)) { tag = 'Servicio falló'; sev = 'info'; why = 'Unit de systemd con error'; }
      if (!tag && prio <= 3) { tag = 'Prioridad ' + (PRIO[prio] || prio); sev = 'med'; why = 'Mensaje de error/crítico'; }
      if (tag) hits.push({ seqnum: e.seqnum, time: realtimeIso(e.realtime), comm, unit: f._SYSTEMD_UNIT || '', pid: f._PID || '', uid: f._UID || '', tag, sev, why, message: msg });
    }
    return hits;
  }

  // ══════════════════════════════ UI ════════════════════════════════════════
  const SEV_CLASS = { high: 'lab-warn', med: 'lab-warn', info: 'lab-dim' };

  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">🐧 journald (systemd)</div>' +
      '<span class="sec-cmds-badge">local · entradas + señales forenses</span></div>' +
      '<div class="lab-intro">Parsea un <b>journal de systemd</b> (.journal): recorre los objetos ' +
      'ENTRY/DATA y reconstruye cada entrada (MESSAGE, _PID, _UID, _COMM, _SYSTEMD_UNIT, PRIORITY…), ' +
      'resaltando <b>señales forenses</b> (sudo/su, SSH, sesiones, servicios caídos, errores). Soporta ' +
      'el formato <b>COMPACT</b>. Trabajá sobre el <b>.journal ya extraído</b>. <b>100% local</b>.</div>' +
      '<div class="lab-drop" id="jdDrop" tabindex="0"><div class="lab-drop-ic">🐧</div>' +
      '<div class="lab-drop-t">Arrastrá un .journal acá o hacé click</div>' +
      '<div class="lab-drop-s">systemd journal (magic «LPKSHHRH»)</div></div>' +
      '<input type="file" id="jdFile" style="display:none"><div id="jdOut"></div>';
    const drop = container.querySelector('#jdDrop'), input = container.querySelector('#jdFile');
    drop.onclick = () => input.click();
    drop.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } };
    input.onchange = () => { if (input.files[0]) load(input.files[0], container); };
    drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); };
    drop.ondragleave = () => drop.classList.remove('over');
    drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) load(e.dataTransfer.files[0], container); };
  }

  let st = null;

  function load(file, container) {
    const out = container.querySelector('#jdOut');
    const esc = window.Triage.util.esc;
    out.innerHTML = '<div class="lab-loading">⬡ Parseando ' + esc(file.name) + ' …</div>';
    const reader = new FileReader();
    reader.onload = (e) => {
      const bytes = new Uint8Array(e.target.result);
      let r;
      try { r = parse(bytes); } catch (err) { out.innerHTML = '<div class="lab-err">Error: ' + esc(String(err && err.message || err)) + '</div>'; return; }
      if (!r.ok) { out.innerHTML = '<div class="lab-err">' + esc(r.error) + '</div>'; return; }
      st = { r, name: file.name };
      out.innerHTML = renderReport(r, file.name);
      wire(out, r);
    };
    reader.readAsArrayBuffer(file);
  }

  function kv(rows) { return '<div class="lab-kv">' + rows.map(([k, v]) => '<div class="lab-kv-k">' + k + '</div><div class="lab-kv-v">' + v + '</div>').join('') + '</div>'; }

  function renderReport(r, name) {
    const esc = window.Triage.util.esc;
    const h = r.header;
    const flags = [h.compact && 'COMPACT', h.keyed && 'KEYED-HASH', h.compZstd && 'ZSTD', h.compLz4 && 'LZ4', h.compXz && 'XZ'].filter(Boolean).join(' · ') || 'ninguno';
    let html = '<div class="lab-panel"><div class="lab-panel-h">🐧 ' + esc(name) + '</div><div class="lab-panel-b">' + kv([
      ['Machine ID', '<code>' + esc(h.machineId) + '</code>'],
      ['Boot ID', '<code>' + esc(h.bootId) + '</code>'],
      ['Flags', esc(flags)],
      ['Entradas', r.count + ' <span class="lab-dim">de ' + h.nEntries + '</span>' + (r.truncated ? ' (capado)' : '') + (r.parseErrors ? ' · <span class="lab-warn">' + r.parseErrors + ' err</span>' : '')],
      ['Rango', esc(realtimeIso(h.headRealtime).replace('T', ' ').replace(/\..*/, '')) + ' → ' + esc(realtimeIso(h.tailRealtime).replace('T', ' ').replace(/\..*/, ''))],
    ]) + '</div></div>';

    if (r.forensic.length) {
      const shown = r.forensic.slice(0, 500);
      html += '<div class="lab-panel"><div class="lab-panel-h">🎯 Hallazgos forenses <span class="lab-dim">(' + r.forensic.length + ')</span></div><div class="lab-panel-b"><div style="overflow:auto"><table class="lab-table"><thead><tr><th>Hora</th><th>Qué</th><th>Proceso</th><th>Mensaje</th></tr></thead><tbody>' +
        shown.map(f => '<tr><td class="lab-dim">' + esc((f.time || '').replace('T', ' ').replace(/\.\d+Z?$/, '')) + '</td><td class="' + (SEV_CLASS[f.sev] || '') + '">' + esc(f.tag) + '</td><td class="lab-dim">' + esc(f.comm || f.unit) + (f.pid ? '[' + esc(f.pid) + ']' : '') + '</td><td class="lab-dim">' + esc((f.message || '').slice(0, 160)) + '</td></tr>').join('') +
        '</tbody></table></div>' + (r.forensic.length > 500 ? '<div class="lab-note">Mostrando 500 de ' + r.forensic.length + '.</div>' : '') + '</div></div>';
    }

    const shown = r.entries.slice(0, 3000);
    html += '<div class="lab-panel"><div class="lab-panel-h">📄 Entradas <button class="cv-btn" id="jdExport" style="float:right">exportar JSON</button> <button class="cv-btn" id="jdNote" style="float:right;margin-right:6px">→ nota</button></div><div class="lab-panel-b"><div style="overflow:auto"><table class="lab-table"><thead><tr><th>Hora</th><th>Unit / Proceso</th><th>PID</th><th>Pri</th><th>Mensaje</th></tr></thead><tbody>' +
      shown.map(e => { const f = e.fields; const prio = f.PRIORITY != null ? parseInt(f.PRIORITY, 10) : 6; return '<tr><td class="lab-dim">' + esc((realtimeIso(e.realtime) || '').replace('T', ' ').replace(/\.\d+Z?$/, '')) + '</td><td>' + esc(f._SYSTEMD_UNIT || f._COMM || f.SYSLOG_IDENTIFIER || '') + '</td><td class="lab-dim">' + esc(f._PID || '') + '</td><td class="' + (prio <= 3 ? 'lab-warn' : 'lab-dim') + '">' + (PRIO[prio] || '') + '</td><td>' + esc((f.MESSAGE || '').slice(0, 200)) + '</td></tr>'; }).join('') +
      '</tbody></table></div>' + (r.entries.length > 3000 ? '<div class="lab-note">Mostrando 3000 de ' + r.entries.length + '.</div>' : '') + '</div></div>';
    return html;
  }

  function wire(out, r) {
    const exp = out.querySelector('#jdExport');
    if (exp) exp.onclick = () => downloadJson(r);
    const note = out.querySelector('#jdNote');
    if (note) note.onclick = () => { if (typeof window.apt115CreateNote === 'function') window.apt115CreateNote('journald · ' + (st ? st.name : ''), noteMarkdown(r)); };
  }

  function noteMarkdown(r) {
    let md = '# journald · ' + (st ? st.name : '') + '\n\n- Machine ID: ' + r.header.machineId + '\n- Boot ID: ' + r.header.bootId + '\n- Entradas: ' + r.count + '\n';
    if (r.forensic.length) {
      md += '\n## 🎯 Hallazgos forenses (' + r.forensic.length + ')\n\n';
      r.forensic.slice(0, 200).forEach(f => { md += '- ' + (f.time || '') + ' **' + f.tag + '** ' + (f.comm || f.unit) + (f.pid ? '[' + f.pid + ']' : '') + (f.message ? ' — ' + f.message.slice(0, 160) : '') + '\n'; });
    }
    return md;
  }

  function downloadJson(r) {
    const ents = r.entries.map(e => ({ seqnum: e.seqnum, time: realtimeIso(e.realtime), bootId: e.bootId, fields: e.fields }));
    const data = { file: st ? st.name : null, header: r.header, count: r.count, forensic: r.forensic, entries: ents };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = (st && st.name ? st.name : 'journal') + '.apt115.json'; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  if (typeof window !== 'undefined' && window.LAB) {
    LAB.registerTool({ id: 'journald', label: 'journald (systemd)', icon: '🐧', group: '🔬 Forensics', render });
  }
  // Hook de test (no-op en browser): núcleo puro.
  return { parse, parseHeader, realtimeIso };
})();
