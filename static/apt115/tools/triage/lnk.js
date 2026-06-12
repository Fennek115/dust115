// APT115 CODEX ARCANUM — Triage analyzer: lnk (Windows Shell Link / .lnk)
// quod est superius est sicut quod inferius
//
// Parser propio del formato [MS-SHLLINK] (Shell Link Binary File Format). Los .lnk
// son un vector de ACCESO INICIAL muy común: el ícono dice "documento" pero el target
// es cmd/powershell con argumentos ofuscados, o traen un payload apendizado. Extrae:
//
//   · Header: flags, atributos, timestamps (FILETIME), show command, hotkey.
//   · LinkInfo: ruta local del target, volumen (label/tipo de disco), share de red.
//   · StringData: NAME, RELATIVE_PATH, WORKING_DIR, ARGUMENTS, ICON_LOCATION.
//   · ExtraData de alta señal: EnvironmentVariableDataBlock (target/command real),
//     IconEnvironmentDataBlock (ícono spoofeado), TrackerDataBlock (MachineID = nombre
//     NetBIOS de la máquina que lo creó → atribución/clustering).
//   · Datos apendizados tras la estructura (payload embebido).
//   · Indicadores: powershell/mshta/rundll32/-enc/IEX/DownloadString/UNC/env vars…
//
// 100% local, byte-level (sin Canvas/cripto) → verificable en Node contra LnkParse3.

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

(function () {
  'use strict';

  function U() { return window.Triage.util; }
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // CLSID esperado: {00021401-0000-0000-C000-000000000046}
  const CLSID = [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];

  const FLAGS = [
    'HasLinkTargetIDList', 'HasLinkInfo', 'HasName', 'HasRelativePath', 'HasWorkingDir',
    'HasArguments', 'HasIconLocation', 'IsUnicode', 'ForceNoLinkInfo', 'HasExpString',
    'RunInSeparateProcess', 'Unused1', 'HasDarwinID', 'RunAsUser', 'HasExpIcon', 'NoPidlAlias',
    'Unused2', 'RunWithShimLayer', 'ForceNoLinkTrack', 'EnableTargetMetadata', 'DisableLinkPathTracking',
    'DisableKnownFolderTracking', 'DisableKnownFolderAlias', 'AllowLinkToLink', 'UnaliasOnSave',
    'PreferEnvironmentPath', 'KeepLocalIDListForUNCTarget',
  ];
  const SHOW = { 1: 'SW_SHOWNORMAL', 3: 'SW_SHOWMAXIMIZED', 7: 'SW_SHOWMINNOACTIVE' };
  const DRIVE = { 0: 'desconocido', 1: 'sin raíz', 2: 'removible', 3: 'fijo', 4: 'remoto (red)', 5: 'CD-ROM', 6: 'RAM disk' };

  function isLnk(b) {
    if (b.length < 0x4C) return false;
    if (!(b[0] === 0x4C && b[1] === 0 && b[2] === 0 && b[3] === 0)) return false;
    for (let i = 0; i < 16; i++) if (b[4 + i] !== CLSID[i]) return false;
    return true;
  }

  // ── lector LE con cursor + bounds ───────────────────────────────────────────
  function Reader(b) { this.b = b; this.p = 0; }
  Reader.prototype.u16 = function (o) { o = o == null ? this.p : o; const v = this.b[o] | (this.b[o + 1] << 8); if (o === this.p) this.p += 2; return v >>> 0; };
  Reader.prototype.u32 = function (o) { o = o == null ? this.p : o; const v = (this.b[o] | (this.b[o + 1] << 8) | (this.b[o + 2] << 16) | (this.b[o + 3] << 24)) >>> 0; if (o === this.p) this.p += 4; return v; };

  // FILETIME (8 bytes, 100ns desde 1601) → ISO o null.
  function filetime(b, o) {
    if (o + 8 > b.length) return null;
    let lo = 0n, hi = 0n;
    for (let i = 0; i < 4; i++) lo |= BigInt(b[o + i]) << BigInt(8 * i);
    for (let i = 0; i < 4; i++) hi |= BigInt(b[o + 4 + i]) << BigInt(8 * i);
    const ft = (hi << 32n) | lo;
    if (ft === 0n) return null;
    const ms = (ft - 116444736000000000n) / 10000n;
    const n = Number(ms);
    if (!isFinite(n) || n < -62135596800000 || n > 253402300799000) return null;
    try { return new Date(n).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'; } catch (e) { return null; }
  }

  function ansiz(b, o, max) { let s = ''; for (let i = o; i < max && i < b.length && b[i] !== 0; i++) s += String.fromCharCode(b[i]); return s; }
  function utf16z(b, o, max) { let s = ''; for (let i = o; i + 1 < max && i + 1 < b.length; i += 2) { const c = b[i] | (b[i + 1] << 8); if (!c) break; s += String.fromCharCode(c); } return s; }

  function parse(bytes) {
    if (!isLnk(bytes)) return null;
    const r = new Reader(bytes);
    const out = { warnings: [], strings: {}, extra: {}, suspect: [] };

    const flags = r.u32(0x14);
    out.flagsRaw = flags;
    out.flags = FLAGS.filter((_, i) => flags & (1 << i));
    const has = (name) => out.flags.indexOf(name) >= 0;
    const unicode = has('IsUnicode');

    out.fileAttributes = r.u32(0x18);
    out.creationTime = filetime(bytes, 0x1C);
    out.accessTime = filetime(bytes, 0x24);
    out.writeTime = filetime(bytes, 0x2C);
    out.targetSize = r.u32(0x34);
    out.iconIndex = r.u32(0x38) | 0;
    out.showCommand = r.u32(0x3C);
    out.showName = SHOW[out.showCommand] || ('0x' + out.showCommand.toString(16));
    out.hotkey = r.u16(0x40);

    let p = 0x4C; // tras el header

    // LinkTargetIDList (lo saltamos: shell items son complejos; registramos tamaño)
    if (has('HasLinkTargetIDList')) {
      if (p + 2 > bytes.length) { out.warnings.push('IDList truncado'); return finalize(out, bytes, p); }
      const idSize = r.u16(p);
      out.idListSize = idSize;
      p += 2 + idSize;
    }

    // LinkInfo
    if (has('HasLinkInfo') && !has('ForceNoLinkInfo')) {
      const li = parseLinkInfo(bytes, p);
      if (li) { out.linkInfo = li; p += li.size; }
      else out.warnings.push('LinkInfo ilegible');
    }

    // StringData (orden fijo, sólo las presentes por flags)
    const order = [['HasName', 'name'], ['HasRelativePath', 'relativePath'],
      ['HasWorkingDir', 'workingDir'], ['HasArguments', 'arguments'], ['HasIconLocation', 'iconLocation']];
    for (const [fl, key] of order) {
      if (!has(fl)) continue;
      if (p + 2 > bytes.length) { out.warnings.push('StringData truncado en ' + key); break; }
      const count = r.u16(p); p += 2;
      const bytesLen = count * (unicode ? 2 : 1);
      out.strings[key] = unicode ? utf16str(bytes, p, count) : ansistr(bytes, p, count);
      p += bytesLen;
    }

    return finalize(out, bytes, p);
  }

  function utf16str(b, o, count) { let s = ''; for (let i = 0; i < count; i++) { const c = b[o + i * 2] | (b[o + i * 2 + 1] << 8); s += String.fromCharCode(c); } return s; }
  function ansistr(b, o, count) { let s = ''; for (let i = 0; i < count; i++) s += String.fromCharCode(b[o + i]); return s; }

  function parseLinkInfo(b, base) {
    if (base + 28 > b.length) return null;
    const r = new Reader(b);
    const size = r.u32(base);
    if (size < 0x1C || base + size > b.length) return null;
    const headerSize = r.u32(base + 4);
    const liFlags = r.u32(base + 8);
    const volIdOff = r.u32(base + 12);
    const localBaseOff = r.u32(base + 16);
    const cnrlOff = r.u32(base + 20);
    const suffixOff = r.u32(base + 24);
    const out = { size, headerSize, flags: liFlags };
    let localBaseUniOff = 0, suffixUniOff = 0;
    if (headerSize >= 0x24) { localBaseUniOff = r.u32(base + 28); suffixUniOff = r.u32(base + 32); }

    // VolumeIDAndLocalBasePath
    if ((liFlags & 1) && localBaseOff) out.localBasePath = ansiz(b, base + localBaseOff, base + size);
    if ((liFlags & 1) && localBaseUniOff) out.localBasePathU = utf16z(b, base + localBaseUniOff, base + size);
    if ((liFlags & 1) && volIdOff && base + volIdOff + 16 <= b.length) {
      const r2 = new Reader(b);
      const dt = r2.u32(base + volIdOff + 4);
      const labelOff = r2.u32(base + volIdOff + 12);
      out.driveType = DRIVE[dt] || ('0x' + dt.toString(16));
      if (labelOff) out.volumeLabel = ansiz(b, base + volIdOff + labelOff, base + size);
    }
    // CommonNetworkRelativeLink (share de red)
    if ((liFlags & 2) && cnrlOff && base + cnrlOff + 20 <= b.length) {
      const r3 = new Reader(b);
      const netNameOff = r3.u32(base + cnrlOff + 8);
      if (netNameOff) out.netName = ansiz(b, base + cnrlOff + netNameOff, base + size);
    }
    if (suffixOff) out.pathSuffix = ansiz(b, base + suffixOff, base + size);
    return out;
  }

  // ── ExtraData + trailing ────────────────────────────────────────────────────
  function finalize(out, bytes, p) {
    // ExtraData: bloques { size(4), sig(4), data } hasta TerminalBlock (size<4).
    while (p + 4 <= bytes.length) {
      const r = new Reader(bytes);
      const blockSize = r.u32(p);
      if (blockSize < 4) break; // terminal
      if (p + blockSize > bytes.length) { out.warnings.push('ExtraData truncado'); break; }
      const sig = r.u32(p + 4);
      parseExtraBlock(out, bytes, p, blockSize, sig);
      p += blockSize;
    }
    // Algunos LNK no traen terminal; avanzar el cursor 4 si el último fue terminal 0.
    if (p + 4 <= bytes.length && new Reader(bytes).u32(p) < 4) p += 4;
    const trail = bytes.length - p;
    if (trail > 0) out.trailing = { offset: p, size: trail };

    collectSuspect(out, bytes);
    return out;
  }

  function parseExtraBlock(out, b, p, size, sig) {
    const d = p + 8; // tras size+sig
    switch (sig >>> 0) {
      case 0xA0000001: { // EnvironmentVariableDataBlock: TargetAnsi(260) + TargetUnicode(520)
        const a = ansiz(b, d, d + 260);
        const u = utf16z(b, d + 260, d + 260 + 520);
        out.extra.envTarget = u || a;
        break;
      }
      case 0xA0000007: { // IconEnvironmentDataBlock
        const a = ansiz(b, d, d + 260);
        const u = utf16z(b, d + 260, d + 260 + 520);
        out.extra.iconEnv = u || a;
        break;
      }
      case 0xA0000006: out.extra.darwin = ansiz(b, d, d + 260); break; // DarwinDataBlock (MSI)
      case 0xA0000003: { // TrackerDataBlock: Length(4) Version(4) MachineID(16 ANSI) + droids
        const machineId = ansiz(b, d + 8, d + 8 + 16);
        out.extra.tracker = { machineId };
        break;
      }
      case 0xA0000005: out.extra.specialFolder = true; break;
      case 0xA0000009: out.extra.propertyStore = true; break;
      case 0xA000000C: out.extra.vistaIdList = true; break;
      case 0xA0000002: out.extra.console = true; break;
      case 0xA0000008: out.extra.shim = true; break;
      default: (out.extra.unknown = out.extra.unknown || []).push('0x' + (sig >>> 0).toString(16)); break;
    }
  }

  // ── Indicadores sospechosos ─────────────────────────────────────────────────
  const SUS = [
    [/powershell|pwsh/i, 'PowerShell'], [/cmd(\.exe)?\b|comspec/i, 'cmd / %comspec%'],
    [/mshta/i, 'mshta'], [/rundll32/i, 'rundll32'], [/regsvr32/i, 'regsvr32'],
    [/wscript|cscript/i, 'WSH (wscript/cscript)'], [/bitsadmin/i, 'bitsadmin'],
    [/certutil/i, 'certutil'], [/\bmsiexec/i, 'msiexec'], [/wmic/i, 'wmic'],
    [/-enc(odedcommand)?\b/i, 'PowerShell -EncodedCommand'], [/-nop(rofile)?\b/i, '-NoProfile'],
    [/-w(indowstyle)?\s+hidden|-w\s+h\b/i, 'ventana oculta'], [/-ex(ecutionpolicy)?\s+bypass/i, 'ExecutionPolicy Bypass'],
    [/iex|invoke-expression/i, 'Invoke-Expression'], [/downloadstring|downloadfile|invoke-webrequest|\biwr\b|curl|wget/i, 'descarga remota'],
    [/frombase64string|::frombase64/i, 'base64 decode'], [/https?:\/\//i, 'URL embebida'],
    [/\\\\[^\\]/, 'ruta UNC (\\\\)'],
    // Nota: las env vars (%ProgramFiles% etc.) son rutinarias en accesos benignos del
    // Start Menu → NO se marcan solas; los intérpretes específicos (cmd/%comspec%) sí.
    [/\.(scr|pif|hta|js|jse|vbs|vbe|wsf|bat|cmd)\b/i, 'extensión de script/ejecutable'],
    [/[A-Za-z0-9+/]{60,}={0,2}/, 'blob base64 largo'],
  ];

  function collectSuspect(out, bytes) {
    const fields = [out.strings.arguments, out.strings.relativePath, out.strings.workingDir,
      out.strings.iconLocation, out.strings.name, out.extra.envTarget, out.extra.iconEnv,
      out.linkInfo && out.linkInfo.localBasePath, out.linkInfo && out.linkInfo.netName].filter(Boolean);
    const blob = fields.join('\n');
    const seen = {};
    for (const [re, label] of SUS) if (re.test(blob) && !seen[label]) { out.suspect.push(label); seen[label] = 1; }

    // Spoofing de ícono: target es script host pero el ícono apunta a un doc/legit.
    const tgt = (out.strings.arguments || '') + ' ' + (out.extra.envTarget || '') + ' ' + (out.linkInfo && out.linkInfo.localBasePath || '');
    const icon = out.strings.iconLocation || '';
    if (/powershell|cmd|mshta|rundll32|wscript|cscript/i.test(tgt) &&
        /\.(ico|exe)$|\\(imageres|shell32|explorer|winword|excel|acro|notepad)/i.test(icon)) {
      out.suspect.push('ícono spoofeado (apunta a app legítima/documento; target es un intérprete)');
    }
    if (out.trailing && out.trailing.size > 64) {
      const t = U().detectType(bytes.subarray(out.trailing.offset));
      out.trailing.type = t ? t.name : null;
      out.suspect.push('datos apendizados tras la estructura (' + U().formatBytes(out.trailing.size) +
        (t ? ', ' + t.name : '') + ') — posible payload embebido');
    }
  }

  // ── Render ──────────────────────────────────────────────────────────────────
  function kv(rows) {
    return '<table class="lab-kv"><tbody>' +
      rows.map(r => '<tr><th>' + r[0] + '</th><td>' + r[1] + '</td></tr>').join('') + '</tbody></table>';
  }

  function analyze(ctx) {
    const lnk = parse(ctx.bytes);
    if (!lnk) return '<div class="lab-note">No es un Shell Link válido (header/CLSID no coincide).</div>';
    const u = U();
    let html = '';

    // Lo más importante arriba: qué ejecuta.
    const target = (lnk.linkInfo && (lnk.linkInfo.localBasePath || lnk.linkInfo.localBasePathU)) ||
      lnk.extra.envTarget || lnk.strings.relativePath || '—';
    const cmd = lnk.strings.arguments || '';
    html += '<div class="lab-sub">Qué ejecuta</div>';
    const t = [
      ['Target', '<code>' + esc(target) + '</code>'],
      ['Argumentos', cmd ? '<code>' + esc(cmd) + '</code>' : '<span class="lab-dim">—</span>'],
    ];
    if (lnk.extra.envTarget) t.push(['Env target', '<code>' + esc(lnk.extra.envTarget) + '</code> <span class="lab-dim">(EnvironmentVariableDataBlock)</span>']);
    if (lnk.strings.workingDir) t.push(['Working dir', '<code>' + esc(lnk.strings.workingDir) + '</code>']);
    if (lnk.strings.iconLocation) t.push(['Ícono', '<code>' + esc(lnk.strings.iconLocation) + '</code>']);
    if (lnk.strings.name) t.push(['Descripción', esc(lnk.strings.name)]);
    if (lnk.linkInfo && lnk.linkInfo.netName) t.push(['Share de red', '<code>' + esc(lnk.linkInfo.netName) + '</code>']);
    html += kv(t);

    // Indicadores
    if (lnk.suspect.length) {
      html += '<div class="lab-sub">Indicadores</div><div class="lab-note">⚠ ' +
        lnk.suspect.map(esc).join('<br>⚠ ') + '</div>';
    } else {
      html += '<div class="lab-note">Sin indicadores de ejecución sospechosa detectados. Igual revisá el target manualmente.</div>';
    }

    // Metadata del header
    html += '<div class="lab-sub">Cabecera</div>';
    const h = [
      ['Show command', esc(lnk.showName)],
      ['Target size (declarado)', u.formatBytes(lnk.targetSize)],
    ];
    if (lnk.creationTime) h.push(['Creación', esc(lnk.creationTime)]);
    if (lnk.writeTime) h.push(['Modificación', esc(lnk.writeTime)]);
    if (lnk.accessTime) h.push(['Acceso', esc(lnk.accessTime)]);
    if (lnk.linkInfo && lnk.linkInfo.driveType) h.push(['Volumen', esc(lnk.linkInfo.driveType) + (lnk.linkInfo.volumeLabel ? ' · «' + esc(lnk.linkInfo.volumeLabel) + '»' : '')]);
    if (lnk.extra.tracker && lnk.extra.tracker.machineId) h.push(['MachineID (build host)', '<code>' + esc(lnk.extra.tracker.machineId) + '</code> <span class="lab-dim">(TrackerDataBlock · atribución)</span>']);
    if (lnk.extra.darwin) h.push(['Darwin/MSI', '<code>' + esc(lnk.extra.darwin) + '</code>']);
    html += kv(h);

    // Flags + extra blocks
    html += '<div class="lab-sub">LinkFlags (0x' + lnk.flagsRaw.toString(16) + ')</div><div class="lab-imps">' +
      lnk.flags.map(f => '<span class="lab-imp">' + esc(f) + '</span>').join('') + '</div>';
    const blocks = Object.keys(lnk.extra).filter(k => k !== 'unknown');
    if (blocks.length || (lnk.extra.unknown && lnk.extra.unknown.length)) {
      const names = blocks.concat((lnk.extra.unknown || []).map(s => 'unknown ' + s));
      html += '<div class="lab-sub">ExtraData blocks</div><div class="lab-imps">' +
        names.map(n => '<span class="lab-imp">' + esc(n) + '</span>').join('') + '</div>';
    }
    if (lnk.warnings.length) html += '<div class="lab-note">⚠ ' + lnk.warnings.map(esc).join(' · ') + '</div>';
    return html;
  }

  const Tri = (typeof window !== 'undefined' && window.Triage) || null;
  if (Tri && Tri.analyzers) {
    Tri.analyzers.register({
      id: 'lnk', title: 'Windows Shortcut (LNK)', icon: '🔗',
      applies(ctx) { return !ctx.pe && !ctx.elf && isLnk(ctx.bytes); },
      run(ctx) { return analyze(ctx); },
    });
  }

  if (typeof module !== 'undefined' && module.exports) module.exports = { parse, isLnk, filetime, parseLinkInfo };
})();
