// APT115 CODEX ARCANUM — utmp / wtmp / btmp (Linux login records)
// quod est superius est sicut quod inferius
//
// Parser forense de los registros de sesión de Linux, portado desde la spec
// pública del struct (`man 5 utmp`, glibc bits/utmp.h):
//   - /var/run/utmp  → sesiones ACTUALES
//   - /var/log/wtmp  → histórico de logins/logouts/reboots (append-only)
//   - /var/log/btmp  → intentos de login FALLIDOS (brute-force, accesos no autorizados)
// Responde "quién entró, cuándo, desde qué IP, reinicios y logins fallidos".
//
// 100% local — el archivo se procesa en el navegador, nada se sube. Núcleo PURO
// testeable en Node, verificado byte-a-byte contra `utmpdump`.
//
// Struct asumido: amd64 / glibc, registro de **384 bytes** (ut_session+ut_tv en
// int32 por __WORDSIZE_TIME64_COMPAT32 → compat 32/64). Otras arch/glibc pueden
// variar el tamaño (se detecta heurísticamente y se documenta el límite).

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

export const utmp = (function () {
  'use strict';

  const REC = 384; // tamaño del registro en amd64/glibc

  // ut_type → nombre (utmp.h)
  const TYPES = {
    0: 'EMPTY', 1: 'RUN_LVL', 2: 'BOOT_TIME', 3: 'NEW_TIME', 4: 'OLD_TIME',
    5: 'INIT_PROCESS', 6: 'LOGIN_PROCESS', 7: 'USER_PROCESS', 8: 'DEAD_PROCESS', 9: 'ACCOUNTING',
  };
  const typeName = (t) => TYPES[t] || ('TYPE_' + t);

  // Offsets dentro del registro (amd64/glibc). Numéricos en little-endian.
  const O = {
    type: 0, pid: 4, line: 8, id: 40, user: 44, host: 76,
    exitTerm: 332, exitCode: 334, session: 336, tvSec: 340, tvUsec: 344, addr: 348,
  };

  function cstr(b, o, max) {
    let s = '';
    for (let i = 0; i < max; i++) {
      const c = b[o + i];
      if (c === 0) break;
      s += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
    }
    return s;
  }

  // ut_addr_v6: 4×int32 (16 bytes), dirección en orden de red. Si [1..3]==0 → IPv4.
  function addr(b, o) {
    const v1 = b[o + 4] | b[o + 5] | b[o + 6] | b[o + 7] |
      b[o + 8] | b[o + 9] | b[o + 10] | b[o + 11] | b[o + 12] | b[o + 13] | b[o + 14] | b[o + 15];
    if (v1 === 0) return b[o] + '.' + b[o + 1] + '.' + b[o + 2] + '.' + b[o + 3];
    // IPv6: 8 grupos de 16 bits, compresión simple RFC 5952
    const g = [];
    for (let i = 0; i < 8; i++) g.push((b[o + i * 2] << 8) | b[o + i * 2 + 1]);
    let best = -1, bestLen = 0, cur = -1, curLen = 0;
    for (let i = 0; i < 8; i++) {
      if (g[i] === 0) { if (cur < 0) cur = i; curLen++; if (curLen > bestLen) { bestLen = curLen; best = cur; } }
      else { cur = -1; curLen = 0; }
    }
    if (bestLen < 2) best = -1;
    let out = '';
    for (let i = 0; i < 8; i++) {
      if (i === best) { out += (i === 0 ? '::' : ':'); i += bestLen - 1; continue; }
      out += g[i].toString(16) + (i < 7 ? ':' : '');
    }
    if (out.endsWith(':') && !out.endsWith('::')) out = out.slice(0, -1);
    return out || '::';
  }

  // ── Detección heurística del tamaño de registro ───────────────────────
  // 384 (amd64) cubre el caso normal. Si el archivo no es múltiplo de 384 pero sí
  // de otro tamaño plausible, lo señalamos (no cambiamos el layout: límite v1).
  function detectRecSize(len) {
    if (len > 0 && len % REC === 0) return REC;
    return REC; // se asume amd64; el reporte avisa del posible desajuste
  }

  // ── Parseo de un registro ─────────────────────────────────────────────
  function parseRecord(b, off, idx) {
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const i16 = (o) => dv.getInt16(off + o, true);
    const i32 = (o) => dv.getInt32(off + o, true);
    const type = i16(O.type);
    const tvSec = i32(O.tvSec) >>> 0, tvUsec = i32(O.tvUsec) >>> 0;
    // ¿registro todo-cero? (clásico de manipulación: editores que blanquean en vez de borrar)
    let zero = true;
    for (let i = 0; i < REC; i++) if (b[off + i] !== 0) { zero = false; break; }
    return {
      idx,
      type, typeName: typeName(type),
      pid: i32(O.pid),
      line: cstr(b, off + O.line, 32),
      id: cstr(b, off + O.id, 4),
      user: cstr(b, off + O.user, 32),
      host: cstr(b, off + O.host, 256),
      addr: addr(b, off + O.addr),
      session: i32(O.session),
      tvSec, tvUsec,
      time: tvSec ? new Date(tvSec * 1000).toISOString().replace(/\.\d{3}Z$/, '') + '.' + String(tvUsec).padStart(6, '0') + 'Z' : '',
      zero,
    };
  }

  function parse(bytes, opts) {
    const max = (opts && opts.max) || 100000;
    const recSize = detectRecSize(bytes.length);
    const total = Math.floor(bytes.length / recSize);
    const trailing = bytes.length - total * recSize;
    const records = [];
    let truncated = false;
    for (let i = 0; i < total; i++) {
      if (i >= max) { truncated = true; break; }
      records.push(parseRecord(bytes, i * recSize, i));
    }
    return {
      recSize, total, trailing, truncated,
      records,
      anomalies: detectAnomalies(records),
      stats: stats(records),
    };
  }

  // ── Anomalías / indicios de manipulación ──────────────────────────────
  function detectAnomalies(records) {
    const out = [];
    let prevTime = 0;
    const valid = (r) => r && !r.zero && (r.tvSec > 0 || r.type !== 0);
    for (let i = 0; i < records.length; i++) {
      const r = records[i];
      // 1) registro EMPTY/cero rodeado de registros VÁLIDOS en AMBOS lados — el patrón
      //    del blanqueo quirúrgico (editar un login en vez de removerlo). Un bloque de
      //    EMPTY al final o agrupado NO se marca (es benigno).
      if ((r.zero || (r.type === 0 && !r.tvSec)) && valid(records[i - 1]) && valid(records[i + 1])) {
        out.push({ idx: i, kind: 'registro vacío intercalado', detail: 'EMPTY/cero entre registros válidos — posible blanqueo (rootkit/utmp editor)' });
      }
      // 2) retroceso temporal en wtmp (debería ser append-only cronológico)
      if (r.tvSec && prevTime && r.tvSec < prevTime - 1) {
        out.push({ idx: i, kind: 'timestamp fuera de orden', detail: 'más antiguo que el registro previo (' + r.time + ' < ' + new Date(prevTime * 1000).toISOString() + ') — posible inserción/edición' });
      }
      if (r.tvSec) prevTime = r.tvSec;
    }
    return out;
  }

  function stats(records) {
    const byType = {};
    const users = new Set(), hosts = new Set(), ips = new Set();
    let reboots = 0, logins = 0, failed = 0;
    for (const r of records) {
      byType[r.typeName] = (byType[r.typeName] || 0) + 1;
      if (r.type === 2) reboots++;
      if (r.type === 7) { logins++; if (r.user) users.add(r.user); }
      if (r.user && r.type !== 0) users.add(r.user);
      if (r.host) hosts.add(r.host);
      if (r.addr && r.addr !== '0.0.0.0' && r.addr !== '::') ips.add(r.addr);
    }
    return { byType, reboots, logins, users: [...users].sort(), hosts: [...hosts].sort(), ips: [...ips].sort() };
  }

  // ══════════════════════════════ UI ════════════════════════════════════
  function render(container) {
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">🧾 utmp / wtmp / btmp</div>' +
      '<span class="sec-cmds-badge">local · logins Linux</span></div>' +
      '<div class="lab-intro">Lee los registros de sesión de Linux: <b>utmp</b> (sesiones actuales), ' +
      '<b>wtmp</b> (histórico de logins/reboots) y <b>btmp</b> (logins <b>fallidos</b>). ' +
      'Detecta indicios de <b>manipulación</b> (registros blanqueados, timestamps fuera de orden). ' +
      'Todo <b>100% local</b>. Asume struct amd64/glibc (384 B).</div>' +
      '<div class="lab-drop" id="utDrop" tabindex="0"><div class="lab-drop-ic">🧾</div>' +
      '<div class="lab-drop-t">Arrastrá utmp/wtmp/btmp acá o hacé click</div>' +
      '<div class="lab-drop-s">/var/run/utmp · /var/log/wtmp · /var/log/btmp</div></div>' +
      '<input type="file" id="utFile" style="display:none"><div id="utOut"></div>';
    const drop = container.querySelector('#utDrop'), input = container.querySelector('#utFile');
    drop.onclick = () => input.click();
    drop.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } };
    input.onchange = () => { if (input.files[0]) load(input.files[0], container); };
    drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); };
    drop.ondragleave = () => drop.classList.remove('over');
    drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) load(e.dataTransfer.files[0], container); };
  }

  let st = null;

  function load(file, container) {
    const out = container.querySelector('#utOut');
    const esc = window.Triage.util.esc;
    out.innerHTML = '<div class="lab-loading">⬡ Leyendo ' + esc(file.name) + ' …</div>';
    const reader = new FileReader();
    reader.onload = (e) => {
      const bytes = new Uint8Array(e.target.result);
      if (bytes.length < REC) { out.innerHTML = '<div class="lab-err">Archivo demasiado chico para un registro utmp (384 B).</div>'; return; }
      const parsed = parse(bytes);
      st = { parsed, name: file.name };
      out.innerHTML = renderReport(parsed, file.name);
      wire(out, parsed);
    };
    reader.readAsArrayBuffer(file);
  }

  function kv(rows) {
    return '<div class="lab-kv">' + rows.map(([k, v]) =>
      '<div class="lab-kv-k">' + k + '</div><div class="lab-kv-v">' + v + '</div>').join('') + '</div>';
  }

  function renderReport(p, name) {
    const esc = window.Triage.util.esc;
    const s = p.stats;
    let html = '<div class="lab-panel"><div class="lab-panel-h">🧾 ' + esc(name) + '</div><div class="lab-panel-b">' + kv([
      ['Registros', p.total + (p.truncated ? ' <span class="lab-warn">(capado a ' + p.records.length + ')</span>' : '')],
      ['Tamaño registro', p.recSize + ' B <span class="lab-dim">(amd64/glibc)</span>'],
      ['Reinicios', String(s.reboots)],
      ['Logins de usuario', String(s.logins)],
      ['Usuarios', s.users.length ? esc(s.users.join(', ')) : '—'],
      ['IPs remotas', s.ips.length ? esc(s.ips.join(', ')) : '—'],
    ].concat(p.trailing ? [['⚠ Cola sobrante', p.trailing + ' B <span class="lab-warn">(tamaño no múltiplo de 384 — ¿otra arch/glibc?)</span>']] : [])) + '</div></div>';

    // Anomalías
    if (p.anomalies.length) {
      html += '<div class="lab-panel"><div class="lab-panel-h">⚠ Indicios de manipulación <span class="lab-dim">(' + p.anomalies.length + ')</span></div><div class="lab-panel-b"><div style="overflow:auto"><table class="lab-table"><thead><tr><th>#</th><th>Tipo</th><th>Detalle</th></tr></thead><tbody>' +
        p.anomalies.slice(0, 200).map(a => '<tr><td class="lab-dim">' + a.idx + '</td><td class="lab-warn">' + esc(a.kind) + '</td><td>' + esc(a.detail) + '</td></tr>').join('') +
        '</tbody></table></div></div></div>';
    }

    // Protocolos / tipos
    html += '<div class="lab-panel"><div class="lab-panel-h">📊 Tipos de registro</div><div class="lab-panel-b"><div class="lab-imps">' +
      Object.entries(s.byType).sort((a, b) => b[1] - a[1]).map(([k, v]) => '<span class="lab-imp">' + esc(k) + ' <span class="lab-dim">' + v + '</span></span>').join('') +
      '</div></div></div>';

    // Tabla de registros (orden utmpdump: type pid id user line host addr time)
    html += '<div class="lab-panel"><div class="lab-panel-h">📄 Registros <span class="lab-dim">(' + p.records.length + ')</span> <button class="cv-btn" id="utExport" style="float:right">exportar JSON</button> <button class="cv-btn" id="utNote" style="float:right;margin-right:6px">→ nota</button></div><div class="lab-panel-b"><div style="overflow:auto"><table class="lab-table"><thead><tr><th>#</th><th>Tipo</th><th>PID</th><th>Usuario</th><th>Línea</th><th>Host</th><th>IP</th><th>Fecha</th></tr></thead><tbody>' +
      p.records.slice(0, 2000).map(r => '<tr' + (r.zero ? ' style="opacity:.5"' : '') + '><td class="lab-dim">' + r.idx + '</td><td>' + esc(r.typeName) + '</td><td class="lab-dim">' + (r.pid || '') + '</td><td>' + esc(r.user) + '</td><td>' + esc(r.line) + '</td><td>' + esc(r.host) + '</td><td>' + (r.addr !== '0.0.0.0' && r.addr !== '::' ? esc(r.addr) : '<span class="lab-dim">' + esc(r.addr) + '</span>') + '</td><td class="lab-dim">' + esc(r.time) + '</td></tr>').join('') +
      '</tbody></table></div>' +
      (p.records.length > 2000 ? '<div class="lab-note">Mostrando los primeros 2000 de ' + p.records.length + '.</div>' : '') +
      '<div class="lab-note">Si el archivo es <b>btmp</b>, cada fila es un <b>login fallido</b> (usuario/IP de origen del intento).</div>' +
      '</div></div>';
    return html;
  }

  function wire(out, p) {
    const exp = out.querySelector('#utExport');
    if (exp) exp.onclick = () => downloadJson(p);
    const note = out.querySelector('#utNote');
    if (note) note.onclick = () => {
      if (typeof window.apt115CreateNote !== 'function') return;
      window.apt115CreateNote('utmp · ' + (st ? st.name : 'login records'), noteMarkdown(p));
    };
  }

  function noteMarkdown(p) {
    const s = p.stats;
    let md = '# Login records · ' + (st ? st.name : '') + '\n\n';
    md += '- Registros: ' + p.total + '\n- Reinicios: ' + s.reboots + '\n- Logins: ' + s.logins + '\n';
    md += '- Usuarios: ' + (s.users.join(', ') || '—') + '\n- IPs remotas: ' + (s.ips.join(', ') || '—') + '\n';
    if (p.anomalies.length) {
      md += '\n## ⚠ Indicios de manipulación\n\n';
      p.anomalies.forEach(a => { md += '- #' + a.idx + ' ' + a.kind + ': ' + a.detail + '\n'; });
    }
    return md;
  }

  function downloadJson(p) {
    const data = { file: st ? st.name : null, total: p.total, stats: p.stats, anomalies: p.anomalies, records: p.records };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = (st && st.name ? st.name : 'utmp') + '.apt115.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  if (typeof window !== 'undefined' && window.LAB) {
    LAB.registerTool({ id: 'utmp', label: 'utmp / wtmp / btmp', icon: '🧾', group: '🔬 Forensics', render });
  }
  // Hook de test (no-op en browser): núcleo puro.
  return { parse, parseRecord, detectAnomalies, stats, addr, typeName, REC };
})();
