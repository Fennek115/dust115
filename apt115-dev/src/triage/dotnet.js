// APT115 CODEX ARCANUM — Triage analyzer: .NET / CLR metadata
// quod est superius est sicut quod inferius
//
// Parser propio de metadata managed (.NET / CLR). EXTIENDE el parser PE
// (src/triage/pe.js): un assembly .NET es un PE con el COM Descriptor
// (DataDirectory[14], el "CLR header" o COR20) no vacío. A partir de ahí el
// formato es propio de .NET (ECMA-335, Partition II) y nada tiene que ver con
// el resto del PE. Extrae:
//
//   · COR20 / CLI header: cb, runtime version, MetaData RVA/Size, flags
//     (ILONLY / 32BITREQUIRED / STRONGNAMESIGNED / NATIVE_ENTRYPOINT…),
//     EntryPointToken, StrongName signature.
//   · Metadata root ("BSJB" magic): versión del runtime (ej "v4.0.30319") y
//     los stream headers (#~ o #-, #Strings, #US, #GUID, #Blob).
//   · Tabla #~: header (HeapSizes, bitmasks Valid/Sorted → qué tablas existen
//     y cuántas filas cada una), row sizes calculados según ECMA-335 (índices
//     simples + coded indexes + tamaño de heaps) → ubicación de cada tabla.
//     Lee Module (nombre), Assembly (nombre/versión) y AssemblyRef (deps), y
//     resume Module/TypeDef/MethodDef/AssemblyRef/Field/Param.
//   · Detección de ofuscadores: firmas de marca (ConfuserEx, .NET Reactor,
//     Dotfuscator, SmartAssembly, Eazfuscator, Babel…) en #Strings, más
//     heurística sobre los nombres (renombrado Unicode/ininteligible, entropía,
//     #US grande = posible cifrado de strings).
//
// 100% local, byte-level. Núcleo PURO testeable en Node: parse(pe, bytes).
// NO decodifica IL — el alcance es metadata + triage de ofuscación.

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

export const dotnet = (function () {
  'use strict';

  // ── Tablas de metadata (ECMA-335 II.22) por índice ──────────────
  const TABLE_NAMES = {
    0x00: 'Module', 0x01: 'TypeRef', 0x02: 'TypeDef', 0x03: 'FieldPtr',
    0x04: 'Field', 0x05: 'MethodPtr', 0x06: 'MethodDef', 0x07: 'ParamPtr',
    0x08: 'Param', 0x09: 'InterfaceImpl', 0x0A: 'MemberRef', 0x0B: 'Constant',
    0x0C: 'CustomAttribute', 0x0D: 'FieldMarshal', 0x0E: 'DeclSecurity',
    0x0F: 'ClassLayout', 0x10: 'FieldLayout', 0x11: 'StandAloneSig',
    0x12: 'EventMap', 0x13: 'EventPtr', 0x14: 'Event', 0x15: 'PropertyMap',
    0x16: 'PropertyPtr', 0x17: 'Property', 0x18: 'MethodSemantics',
    0x19: 'MethodImpl', 0x1A: 'ModuleRef', 0x1B: 'TypeSpec', 0x1C: 'ImplMap',
    0x1D: 'FieldRVA', 0x1E: 'EncLog', 0x1F: 'EncMap', 0x20: 'Assembly',
    0x21: 'AssemblyProcessor', 0x22: 'AssemblyOS', 0x23: 'AssemblyRef',
    0x24: 'AssemblyRefProcessor', 0x25: 'AssemblyRefOS', 0x26: 'File',
    0x27: 'ExportedType', 0x28: 'ManifestResource', 0x29: 'NestedClass',
    0x2A: 'GenericParam', 0x2B: 'MethodSpec', 0x2C: 'GenericParamConstraint',
  };

  // Coded indexes: lista ordenada de tablas (−1 = slot sin usar) + bits de tag.
  const CODED = {
    TypeDefOrRef: { tables: [0x02, 0x01, 0x1b], bits: 2 },
    HasConstant: { tables: [0x04, 0x08, 0x17], bits: 2 },
    HasCustomAttribute: { tables: [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b], bits: 5 },
    HasFieldMarshall: { tables: [0x04, 0x08], bits: 1 },
    HasDeclSecurity: { tables: [0x02, 0x06, 0x20], bits: 2 },
    MemberRefParent: { tables: [0x02, 0x01, 0x1a, 0x06, 0x1b], bits: 3 },
    HasSemantics: { tables: [0x14, 0x17], bits: 1 },
    MethodDefOrRef: { tables: [0x06, 0x0a], bits: 1 },
    MemberForwarded: { tables: [0x04, 0x06], bits: 1 },
    Implementation: { tables: [0x26, 0x23, 0x27], bits: 2 },
    CustomAttributeType: { tables: [-1, -1, 0x06, 0x0a, -1], bits: 3 },
    ResolutionScope: { tables: [0x00, 0x1a, 0x23, 0x01], bits: 2 },
    TypeOrMethodDef: { tables: [0x02, 0x06], bits: 1 },
  };

  // Esquema de columnas por tabla. Tokens: 2/4 = constante de N bytes;
  // 'S'/'G'/'B' = índice a heap #Strings/#GUID/#Blob; {t:idx} = índice simple a
  // una tabla; {c:'Name'} = coded index.
  const C = (name) => ({ c: name });
  const I = (idx) => ({ t: idx });
  const SCHEMA = {
    0x00: [2, 'S', 'G', 'G', 'G'],
    0x01: [C('ResolutionScope'), 'S', 'S'],
    0x02: [4, 'S', 'S', C('TypeDefOrRef'), I(0x04), I(0x06)],
    0x03: [I(0x04)],
    0x04: [2, 'S', 'B'],
    0x05: [I(0x06)],
    0x06: [4, 2, 2, 'S', 'B', I(0x08)],
    0x07: [I(0x08)],
    0x08: [2, 2, 'S'],
    0x09: [I(0x02), C('TypeDefOrRef')],
    0x0A: [C('MemberRefParent'), 'S', 'B'],
    0x0B: [2, C('HasConstant'), 'B'],
    0x0C: [C('HasCustomAttribute'), C('CustomAttributeType'), 'B'],
    0x0D: [C('HasFieldMarshall'), 'B'],
    0x0E: [2, C('HasDeclSecurity'), 'B'],
    0x0F: [2, 4, I(0x02)],
    0x10: [4, I(0x04)],
    0x11: ['B'],
    0x12: [I(0x02), I(0x14)],
    0x13: [I(0x14)],
    0x14: [2, 'S', C('TypeDefOrRef')],
    0x15: [I(0x02), I(0x17)],
    0x16: [I(0x17)],
    0x17: [2, 'S', 'B'],
    0x18: [2, I(0x06), C('HasSemantics')],
    0x19: [I(0x02), C('MethodDefOrRef'), C('MethodDefOrRef')],
    0x1A: ['S'],
    0x1B: ['B'],
    0x1C: [2, C('MemberForwarded'), 'S', I(0x1a)],
    0x1D: [4, I(0x04)],
    0x1E: [4, 4],
    0x1F: [4],
    0x20: [4, 2, 2, 2, 2, 4, 'B', 'S', 'S'],
    0x21: [4],
    0x22: [4, 4, 4],
    0x23: [2, 2, 2, 2, 4, 'B', 'S', 'S', 'B'],
    0x24: [4, I(0x23)],
    0x25: [4, 4, 4, I(0x23)],
    0x26: [4, 'S', 'B'],
    0x27: [4, 4, 'S', 'S', C('Implementation')],
    0x28: [4, 4, 'S', C('Implementation')],
    0x29: [I(0x02), I(0x02)],
    0x2A: [2, 2, C('TypeOrMethodDef'), 'S'],
    0x2B: [C('MethodDefOrRef'), 'B'],
    0x2C: [I(0x2a), C('TypeDefOrRef')],
  };

  // COR20 / IMAGE_COR20_HEADER flags (COMIMAGE_FLAGS).
  const COR_FLAGS = [
    [0x00000001, 'ILONLY'],
    [0x00000002, '32BITREQUIRED'],
    [0x00000004, 'IL_LIBRARY'],
    [0x00000008, 'STRONGNAMESIGNED'],
    [0x00000010, 'NATIVE_ENTRYPOINT'],
    [0x00010000, 'TRACKDEBUGDATA'],
    [0x00020000, '32BITPREFERRED'],
  ];

  // ── Firmas de ofuscadores / protectores .NET ───────────────────
  // Cada firma busca substrings (en #Strings + nombres de tipos/atributos).
  const OBFUSCATORS = [
    { name: 'ConfuserEx', why: 'ofuscador open-source muy usado por malware', sigs: ['ConfusedByAttribute', 'ConfuserEx'] },
    { name: '.NET Reactor', why: 'protector comercial (control flow + cifrado de strings)', sigs: ['.NET Reactor', 'NETReactor', 'ReactorAttribute'] },
    { name: 'Dotfuscator', why: 'ofuscador comercial (PreEmptive)', sigs: ['DotfuscatorAttribute', 'PreEmptive.', 'DotfuscatorEvent'] },
    { name: 'SmartAssembly', why: 'ofuscador comercial (Red Gate)', sigs: ['SmartAssembly.Attributes', 'PoweredByAttribute', 'SmartAssembly.HouseOfCards'] },
    { name: 'Eazfuscator.NET', why: 'ofuscador comercial (virtualización opcional)', sigs: ['Eazfuscator', 'EazfuscatorAttribute'] },
    { name: 'Babel', why: 'ofuscador comercial', sigs: ['BabelAttribute', 'BabelObfuscatorAttribute'] },
    { name: 'Obfuscar', why: 'ofuscador open-source', sigs: ['ObfuscarAttribute', 'Obfuscar'] },
    { name: 'Agile.NET / CliSecure', why: 'protector comercial', sigs: ['CliSecure', 'SecureTeam', 'Agile.NET'] },
    { name: 'ILProtector', why: 'protector (IL en runtime)', sigs: ['ProtectedWithILProtector', 'ILProtector'] },
    { name: 'Goliath.NET', why: 'ofuscador', sigs: ['GoliathProtector', 'Goliath.NET'] },
    { name: 'Spices.Net', why: 'ofuscador comercial (9Rays)', sigs: ['Spices.Net', '9rays'] },
    { name: 'Crypto Obfuscator', why: 'protector comercial (LogicNP)', sigs: ['CryptoObfuscator', 'CryptoObfuscatorAttribute'] },
  ];

  // ── helpers de bytes ────────────────────────────────────────────
  const td = (typeof TextDecoder !== 'undefined') ? new TextDecoder('utf-8') : null;
  function utf8(bytes, start, len) {
    const slice = bytes.subarray(start, start + len);
    if (td) return td.decode(slice);
    let s = ''; for (let i = 0; i < slice.length; i++) s += String.fromCharCode(slice[i]); return s;
  }

  function rvaToOffset(pe, rva) {
    for (const s of pe.sections) {
      const span = Math.max(s.vsize, s.rawsize);
      if (rva >= s.vaddr && rva < s.vaddr + span) return s.rawptr + (rva - s.vaddr);
    }
    return -1;
  }

  // ── núcleo: parse(pe, bytes) → objeto .NET o null ───────────────
  function parse(pe, bytes) {
    if (!pe || !pe.optional || !(pe.optional.numRva > 14)) return null;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    // DataDirectory[14] = COM Descriptor (CLR header)
    const ddCor = pe.optional.ddStart + 14 * 8;
    if (ddCor + 8 > bytes.length) return null;
    const corRva = dv.getUint32(ddCor, true);
    const corSize = dv.getUint32(ddCor + 4, true);
    if (!corRva) return null;

    const warnings = [];
    const out = { warnings, cor: null, metaVersion: null, streams: [], tables: null, heuristics: null };

    const corOff = rvaToOffset(pe, corRva);
    if (corOff < 0 || corOff + 72 > bytes.length) { warnings.push('CLR header fuera de las secciones'); return out; }

    // ── COR20 / IMAGE_COR20_HEADER ──
    const flags = dv.getUint32(corOff + 16, true);
    const entryToken = dv.getUint32(corOff + 20, true);
    const cor = {
      cb: dv.getUint32(corOff, true),
      runtime: dv.getUint16(corOff + 4, true) + '.' + dv.getUint16(corOff + 6, true),
      metaRva: dv.getUint32(corOff + 8, true),
      metaSize: dv.getUint32(corOff + 12, true),
      flags,
      flagNames: COR_FLAGS.filter(([b]) => flags & b).map(([, n]) => n),
      entryToken,
      strongName: { rva: dv.getUint32(corOff + 32, true), size: dv.getUint32(corOff + 36, true) },
      resources: { rva: dv.getUint32(corOff + 24, true), size: dv.getUint32(corOff + 28, true) },
    };
    // EntryPointToken: byte alto = tabla (6=MethodDef), 3 bajos = fila. Si es
    // NATIVE_ENTRYPOINT, es un RVA, no un token.
    if (entryToken) {
      if (flags & 0x10) cor.entryDesc = 'RVA nativo 0x' + entryToken.toString(16);
      else {
        const tbl = (entryToken >>> 24) & 0xff, row = entryToken & 0xffffff;
        cor.entryDesc = (TABLE_NAMES[tbl] || ('tabla 0x' + tbl.toString(16))) + '[' + row + ']';
      }
    }
    out.cor = cor;

    // ── Metadata root ("BSJB") ──
    const metaOff = rvaToOffset(pe, cor.metaRva);
    if (metaOff < 0 || metaOff + 20 > bytes.length) { warnings.push('Metadata root fuera de las secciones'); return out; }
    if (dv.getUint32(metaOff, true) !== 0x424A5342) { warnings.push('Magic BSJB ausente (metadata corrupta?)'); return out; }
    out.metaMajor = dv.getUint16(metaOff + 4, true);
    out.metaMinor = dv.getUint16(metaOff + 6, true);
    const verLen = dv.getUint32(metaOff + 12, true);
    if (verLen > 256 || metaOff + 16 + verLen > bytes.length) { warnings.push('Versión de metadata inválida'); return out; }
    out.metaVersion = utf8(bytes, metaOff + 16, verLen).replace(/\0+$/, '');

    let p = metaOff + 16 + verLen;
    p += 2; // flags (u16)
    const nStreams = dv.getUint16(p, true); p += 2;
    const streams = {};
    for (let i = 0; i < nStreams && i < 16; i++) {
      if (p + 8 > bytes.length) break;
      const sOff = dv.getUint32(p, true);
      const sSize = dv.getUint32(p + 4, true);
      p += 8;
      let name = '';
      const nameStart = p;
      while (p < bytes.length && bytes[p] !== 0) { name += String.fromCharCode(bytes[p]); p++; }
      // nombre null-terminado y padded: el siguiente header arranca en el
      // próximo múltiplo de 4 contado desde nameStart (el null cuenta).
      const nameLen = (p - nameStart) + 1;
      p = nameStart + (Math.ceil(nameLen / 4) * 4);
      streams[name] = { off: sOff, size: sSize };
      out.streams.push({ name, off: sOff, size: sSize });
    }

    // Heaps (offsets absolutos en el archivo, relativos al metadata root)
    const heap = (s) => (s && s.off != null) ? { off: metaOff + s.off, size: s.size } : null;
    const hStrings = heap(streams['#Strings']);
    const hUS = heap(streams['#US']);
    const hBlob = heap(streams['#Blob']);
    const hGuid = heap(streams['#GUID']);

    function readStr(idx) {
      if (!hStrings || idx == null) return '';
      const base = hStrings.off + idx;
      if (idx >= hStrings.size || base >= bytes.length) return '';
      let end = base; const lim = Math.min(hStrings.off + hStrings.size, bytes.length);
      while (end < lim && bytes[end] !== 0) end++;
      return utf8(bytes, base, end - base);
    }

    // ── Tabla de tablas: #~ (comprimida/óptima) o #- (sin comprimir / EnC) ──
    const tStream = streams['#~'] || streams['#-'];
    if (tStream) {
      try { out.tables = parseTables(metaOff + tStream.off, !!streams['#-'], readStr, dv, bytes, warnings, hStrings, hGuid, hBlob); }
      catch (e) { warnings.push('Tabla #~ ilegible: ' + e.message); }
    } else {
      warnings.push('Sin stream de tablas (#~/#-)');
    }

    // ── Heurística de ofuscación ──
    out.heuristics = heuristics(out, hStrings, hUS, bytes);

    return out;
  }

  // Parsea el stream #~/#- (header + row counts + ubicación de tablas) y lee
  // las tablas de alto valor para triage (Module, Assembly, AssemblyRef).
  function parseTables(base, uncompressed, readStr, dv, bytes, warnings, hStrings, hGuid, hBlob) {
    const heapSizes = bytes[base + 6];
    const tableMajor = bytes[base + 4], tableMinor = bytes[base + 5];
    const valid = dv.getBigUint64(base + 8, true);
    const sorted = dv.getBigUint64(base + 16, true);

    const strSize = (heapSizes & 0x01) ? 4 : 2;
    const guidSize = (heapSizes & 0x02) ? 4 : 2;
    const blobSize = (heapSizes & 0x04) ? 4 : 2;

    // Row counts: un u32 por cada bit en Valid (de menor a mayor).
    const rows = {}; const present = [];
    let q = base + 24;
    let validCount = 0;
    for (let t = 0; t < 64; t++) {
      if ((valid >> BigInt(t)) & 1n) {
        validCount++;
        if (q + 4 > bytes.length) throw new Error('row counts truncados');
        rows[t] = dv.getUint32(q, true); q += 4;
        present.push(t);
      }
    }
    let sortedCount = 0;
    for (let t = 0; t < 64; t++) if ((sorted >> BigInt(t)) & 1n) sortedCount++;

    // Tamaño de un índice simple a la tabla t (2 ó 4 bytes).
    const simpleSize = (t) => ((rows[t] || 0) >= 0x10000 ? 4 : 2);
    // Tamaño de un coded index.
    const codedSize = (name) => {
      const cd = CODED[name];
      let max = 0;
      for (const t of cd.tables) if (t >= 0) max = Math.max(max, rows[t] || 0);
      return (max < (1 << (16 - cd.bits))) ? 2 : 4;
    };
    const colSize = (col) => {
      if (col === 2) return 2;
      if (col === 4) return 4;
      if (col === 'S') return strSize;
      if (col === 'G') return guidSize;
      if (col === 'B') return blobSize;
      if (col.t != null) return simpleSize(col.t);
      if (col.c != null) return codedSize(col.c);
      throw new Error('columna desconocida');
    };
    const rowSize = (t) => {
      const sc = SCHEMA[t];
      if (!sc) throw new Error('sin esquema para tabla 0x' + t.toString(16));
      let n = 0; for (const col of sc) n += colSize(col);
      return n;
    };

    // Ubicación (offset) de cada tabla presente: las filas vienen tras el array
    // de row counts, en orden de índice creciente.
    const tableOff = {};
    let cur = q;
    for (const t of present) {
      tableOff[t] = cur;
      cur += (rows[t] || 0) * rowSize(t);
    }

    // Lector de una fila como array de valores crudos (todas las columnas son
    // 2 ó 4 bytes → numbers; los índices a heap quedan como números).
    function readRow(t, rowIdx) {
      const sc = SCHEMA[t];
      let pos = tableOff[t] + rowIdx * rowSize(t);
      const vals = [];
      for (const col of sc) {
        const sz = colSize(col);
        vals.push(sz === 2 ? dv.getUint16(pos, true) : dv.getUint32(pos, true));
        pos += sz;
      }
      return vals;
    }

    const res = {
      heapSizes, tableMajor, tableMinor, validCount, sortedCount,
      kind: uncompressed ? '#-' : '#~',
      counts: {}, module: null, assembly: null, assemblyRefs: [],
      summary: {},
    };
    for (const t of present) res.counts[TABLE_NAMES[t] || ('0x' + t.toString(16))] = rows[t];

    // Resumen de las tablas de mayor interés para triage.
    res.summary = {
      Module: rows[0x00] || 0, TypeDef: rows[0x02] || 0, Field: rows[0x04] || 0,
      MethodDef: rows[0x06] || 0, Param: rows[0x08] || 0, TypeRef: rows[0x01] || 0,
      MemberRef: rows[0x0a] || 0, CustomAttribute: rows[0x0c] || 0, AssemblyRef: rows[0x23] || 0,
    };

    // Module (tabla 0): Name es la 2ª columna.
    if (rows[0x00]) res.module = readStr(readRow(0x00, 0)[1]);
    // Assembly (tabla 0x20): versión (cols 1..4) + Name (col 7).
    if (rows[0x20]) {
      const a = readRow(0x20, 0);
      res.assembly = { name: readStr(a[7]), version: a[1] + '.' + a[2] + '.' + a[3] + '.' + a[4], flags: a[5] };
    }
    // AssemblyRef (tabla 0x23): versión (cols 0..3) + Name (col 6).
    if (rows[0x23]) {
      const n = Math.min(rows[0x23], 256);
      for (let i = 0; i < n; i++) {
        const r = readRow(0x23, i);
        res.assemblyRefs.push({ name: readStr(r[6]), version: r[0] + '.' + r[1] + '.' + r[2] + '.' + r[3] });
      }
    }
    return res;
  }

  // Extrae todos los nombres del heap #Strings (para heurística de renombrado).
  function heapNames(hStrings, bytes, cap) {
    const out = [];
    if (!hStrings) return out;
    const start = hStrings.off, end = Math.min(hStrings.off + hStrings.size, bytes.length);
    let i = start + 1; // índice 0 = string vacío
    let cur = i;
    for (; i < end && out.length < cap; i++) {
      if (bytes[i] === 0) {
        if (i > cur) out.push(utf8(bytes, cur, i - cur));
        cur = i + 1;
      }
    }
    return out;
  }

  // Entropía de Shannon de un string (bits/char).
  function entropy(s) {
    if (!s) return 0;
    const f = {};
    for (const ch of s) f[ch] = (f[ch] || 0) + 1;
    let h = 0; const L = s.length;
    for (const k in f) { const pr = f[k] / L; h -= pr * Math.log2(pr); }
    return h;
  }

  function heuristics(out, hStrings, hUS, bytes) {
    const names = heapNames(hStrings, bytes, 20000);
    const hay = names.join('\n');

    // Firmas de marca
    const signatures = [];
    for (const ob of OBFUSCATORS) {
      const hit = ob.sigs.find((s) => hay.indexOf(s) !== -1);
      if (hit) signatures.push({ name: ob.name, why: ob.why, evidence: hit });
    }

    // Renombrado: nombres no-ASCII (Unicode garbage, típico de ConfuserEx) y
    // nombres muy cortos / de alta entropía.
    let nonAscii = 0, ctrl = 0, short = 0, hiEnt = 0;
    let totalLen = 0;
    for (const n of names) {
      totalLen += n.length;
      let na = false, cc = false;
      for (let k = 0; k < n.length; k++) {
        const c = n.charCodeAt(k);
        if (c > 0x7e) na = true;
        if (c < 0x20) cc = true;
      }
      if (na) nonAscii++;
      if (cc) ctrl++;
      if (n.length <= 2) short++;
      if (n.length >= 6 && entropy(n) >= 3.8) hiEnt++;
    }
    const total = names.length || 1;
    const renamed = (nonAscii + ctrl) / total > 0.15 || short / total > 0.5;

    const flags = [];
    if (nonAscii / total > 0.10) flags.push('≈' + Math.round(100 * nonAscii / total) + '% de los nombres usan caracteres no-ASCII (renombrado Unicode — típico de ConfuserEx)');
    if (ctrl / total > 0.02) flags.push('nombres con caracteres de control (renombrado agresivo / anti-decompiler)');
    if (short / total > 0.5 && total > 30) flags.push('≈' + Math.round(100 * short / total) + '% de los nombres tienen ≤2 caracteres (renombrado a identificadores cortos)');
    if (hiEnt / total > 0.25 && total > 30) flags.push('nombres de alta entropía (identificadores aleatorios)');

    // #US grande → muchas/ largas cadenas de usuario (posible cifrado de strings).
    let usSusp = false;
    if (hUS && hUS.size > 4096) {
      const fileLen = bytes.length || 1;
      if (hUS.size / fileLen > 0.15) { usSusp = true; flags.push('heap #US grande (' + (hUS.size / 1024 | 0) + ' KB, ' + Math.round(100 * hUS.size / fileLen) + '% del archivo) — posible cifrado/empaquetado de strings'); }
    }

    return {
      nameCount: names.length, nonAscii, ctrl, short, hiEnt,
      avgLen: names.length ? totalLen / names.length : 0,
      renamed, signatures, flags, usSize: hUS ? hUS.size : 0, usSusp,
    };
  }

  // ── Render del analyzer (HTML) ──────────────────────────────────
  function analyze(ctx) {
    const d = ctx.dotnet;
    const U = window.Triage.util;
    const esc = U.esc;
    const kv = (rows) => '<table class="lab-kv"><tbody>' + rows.map(r => '<tr><th>' + r[0] + '</th><td>' + r[1] + '</td></tr>').join('') + '</tbody></table>';

    if (!d || !d.cor) return '<div class="lab-note">No se pudo leer el CLR header.</div>';
    const c = d.cor;

    let html = '<div class="lab-row1">Assembly <b>.NET / CLR</b> managed — runtime ' +
      (d.metaVersion ? '<code>' + esc(d.metaVersion) + '</code>' : '?') +
      (c.flagNames.indexOf('ILONLY') === -1 ? ' <span class="lab-dim">(mixed-mode: contiene también código nativo)</span>' : '') +
      '.</div>';

    html += '<div class="lab-sub">CLR header (COR20)</div>';
    const hdr = [
      ['Runtime version', esc(c.runtime) + ' <span class="lab-dim">(major.minor del header)</span>'],
      ['Metadata version', d.metaVersion ? '<code>' + esc(d.metaVersion) + '</code>' : '?'],
      ['Metadata', '0x' + U.toHex(c.metaRva, 8) + ' · ' + U.formatBytes(c.metaSize)],
      ['Flags', c.flagNames.length ? c.flagNames.map(f => '<span class="lab-tag">' + esc(f) + '</span>').join(' ') : '—'],
    ];
    if (c.entryDesc) hdr.push(['Entry point token', '0x' + U.toHex(c.entryToken, 8) + ' <span class="lab-dim">→ ' + esc(c.entryDesc) + '</span>']);
    if (c.strongName.size) hdr.push(['Strong name signature', U.formatBytes(c.strongName.size) + ' <span class="lab-dim">(firmado con nombre fuerte)</span>']);
    html += kv(hdr);

    // Mitigaciones / propiedades rápidas
    const sn = c.flagNames.indexOf('STRONGNAMESIGNED') !== -1 || c.strongName.size > 0;
    const badges = [
      '<span class="lab-mit ' + (c.flagNames.indexOf('ILONLY') !== -1 ? 'on' : 'off') + '">' + (c.flagNames.indexOf('ILONLY') !== -1 ? '✓ ' : '✗ ') + 'IL-only</span>',
      '<span class="lab-mit ' + (sn ? 'on' : 'off') + '">' + (sn ? '✓ ' : '✗ ') + 'Strong name</span>',
      '<span class="lab-mit ' + (c.flagNames.indexOf('NATIVE_ENTRYPOINT') !== -1 ? 'off' : 'on') + '">' + (c.flagNames.indexOf('NATIVE_ENTRYPOINT') !== -1 ? '⚠ native EP' : '✓ managed EP') + '</span>',
    ];
    html += '<div class="lab-badges">' + badges.join('') + '</div>';

    // Identidad
    if (d.tables && (d.tables.module || d.tables.assembly)) {
      const t = d.tables;
      const id = [];
      if (t.assembly) id.push(['Assembly', '<b>' + esc(t.assembly.name) + '</b> <span class="lab-dim">v' + esc(t.assembly.version) + '</span>']);
      if (t.module) id.push(['Module', '<code>' + esc(t.module) + '</code>']);
      if (id.length) html += '<div class="lab-sub">Identidad</div>' + kv(id);
    }

    // Streams
    if (d.streams.length) {
      html += '<div class="lab-sub">Streams de metadata</div><div class="lab-imps">' +
        d.streams.map(s => '<span class="lab-imp" title="' + U.formatBytes(s.size) + '">' + esc(s.name) + ' <span class="lab-dim">(' + U.formatBytes(s.size) + ')</span></span>').join('') + '</div>';
    }

    // Resumen de tablas
    if (d.tables) {
      const s = d.tables.summary;
      html += '<div class="lab-sub">Tablas de metadata (' + d.tables.validCount + ' presentes, ' + d.tables.sortedCount + ' ordenadas · #~ v' + d.tables.tableMajor + '.' + d.tables.tableMinor + ')</div>';
      html += kv([
        ['Tipos (TypeDef)', String(s.TypeDef) + ' <span class="lab-dim">· TypeRef ' + s.TypeRef + '</span>'],
        ['Métodos (MethodDef)', String(s.MethodDef)],
        ['Campos / Params', s.Field + ' / ' + s.Param],
        ['MemberRef / CustomAttribute', s.MemberRef + ' / ' + s.CustomAttribute],
        ['AssemblyRef', String(s.AssemblyRef)],
      ]);
    }

    // AssemblyRef (dependencias)
    if (d.tables && d.tables.assemblyRefs.length) {
      html += '<details class="lab-dll"><summary>Referencias a assemblies (' + d.tables.assemblyRefs.length + ')</summary><div class="lab-imps">' +
        d.tables.assemblyRefs.map(r => '<span class="lab-imp" title="v' + esc(r.version) + '">' + esc(r.name) + ' <span class="lab-dim">v' + esc(r.version) + '</span></span>').join('') + '</div></details>';
    }

    // Ofuscación
    const h = d.heuristics;
    if (h) {
      if (h.signatures.length) {
        html += '<div class="lab-sub">⚠ Ofuscador / protector detectado</div>';
        html += h.signatures.map(s => '<div class="lab-note">🛡 <b>' + esc(s.name) + '</b> — ' + esc(s.why) +
          ' <span class="lab-dim">(marca: <code>' + esc(s.evidence) + '</code>)</span></div>').join('');
      }
      if (h.flags.length) {
        html += '<div class="lab-sub">Señales de ofuscación</div><div class="lab-note">⚠ ' + h.flags.map(esc).join('<br>⚠ ') + '</div>';
      }
      if (!h.signatures.length && !h.flags.length) {
        html += '<div class="lab-note">Sin firmas de ofuscador conocidas ni renombrado evidente. Nombres legibles ' +
          '(promedio ' + h.avgLen.toFixed(1) + ' chars sobre ' + h.nameCount + ' identificadores).</div>';
      }
      html += '<div class="lab-note"><b>Para profundizar:</b> abrí el assembly en <b>dnSpyEx</b>/<b>ILSpy</b> (decompiladores .NET) — ' +
        'este panel hace triage de metadata, no decodifica IL.</div>';
    }

    if (d.warnings.length) html += '<div class="lab-note">⚠ ' + d.warnings.map(esc).join(' · ') + '</div>';
    return html;
  }

  const Tri = (typeof window !== 'undefined' && window.Triage) || null;
  if (Tri && Tri.analyzers) {
    Tri.analyzers.register({
      id: 'dotnet', title: '.NET / CLR', icon: '🟣',
      applies(ctx) { return !!ctx.dotnet; },
      run(ctx) { return analyze(ctx); },
    });
  }

  return { parse, TABLE_NAMES, CODED, SCHEMA, OBFUSCATORS };
})();

if (typeof window !== 'undefined') { window.Triage = window.Triage || {}; window.Triage.dotnet = dotnet; }
