// APT115 CODEX ARCANUM — Minimal PE parser
// Parser propio y enfocado del formato Portable Executable (Windows).
// Extrae lo que importa para triage: headers, características, secciones,
// import table e imphash. Sin dependencias salvo SparkMD5 (opcional, para
// imphash). Resuelve RVA→offset vía el mapa de secciones. Guardas contra
// archivos malformados (todos los loops están acotados).
//
// Caveat imphash: los imports por ORDINAL se representan como "ordN". pefile
// resuelve ordinales conocidos (ej. ws2_32) a nombres, así que el imphash
// coincide con pefile sólo cuando los imports son por nombre. Se marca abajo.

export const pe = (function () {
  'use strict';

  const MACHINE = {
    0x14c: 'x86 (i386)', 0x8664: 'x64 (AMD64)', 0x1c0: 'ARM',
    0x1c4: 'ARMv7 (Thumb)', 0xaa64: 'ARM64', 0x200: 'IA64', 0x1c2: 'ARM Thumb',
  };
  const SUBSYS = {
    0: 'Unknown', 1: 'Native', 2: 'Windows GUI', 3: 'Windows Console',
    5: 'OS/2 Console', 7: 'POSIX', 9: 'Windows CE GUI', 10: 'EFI App',
    14: 'Xbox', 16: 'Boot App',
  };
  const CHARS = [
    [0x0002, 'EXECUTABLE'], [0x2000, 'DLL'], [0x0020, 'LARGE_ADDRESS_AWARE'],
    [0x0100, '32BIT_MACHINE'], [0x0001, 'RELOCS_STRIPPED'], [0x0200, 'DEBUG_STRIPPED'],
    [0x1000, 'SYSTEM'], [0x4000, 'UP_SYSTEM_ONLY'],
  ];
  const DLLCHARS = [
    [0x0020, 'HIGH_ENTROPY_VA'], [0x0040, 'DYNAMIC_BASE (ASLR)'], [0x0080, 'FORCE_INTEGRITY'],
    [0x0100, 'NX_COMPAT (DEP)'], [0x0200, 'NO_ISOLATION'], [0x0400, 'NO_SEH'],
    [0x0800, 'NO_BIND'], [0x1000, 'APPCONTAINER'], [0x2000, 'WDM_DRIVER'],
    [0x4000, 'GUARD_CF'], [0x8000, 'TERMINAL_SERVER_AWARE'],
  ];

  // Tipos de recurso PE (RT_*) por ID.
  const RT_NAMES = {
    1: 'Cursor', 2: 'Bitmap', 3: 'Icono', 4: 'Menú', 5: 'Diálogo', 6: 'String',
    7: 'FontDir', 8: 'Font', 9: 'Accelerator', 10: 'RCData', 11: 'MessageTable',
    12: 'GroupCursor', 14: 'GroupIcon', 16: 'Version', 17: 'DlgInclude',
    19: 'PlugPlay', 20: 'VXD', 21: 'AniCursor', 22: 'AniIcon', 23: 'HTML', 24: 'Manifest',
  };

  function flagsToNames(value, table) {
    const out = [];
    for (const [bit, name] of table) if (value & bit) out.push(name);
    return out;
  }

  // Devuelve objeto PE o null si no es PE. No tira: ante datos corruptos
  // junta lo que pudo y agrega avisos en `warnings`.
  function parse(bytes) {
    if (bytes.length < 0x40 || bytes[0] !== 0x4D || bytes[1] !== 0x5A) return null; // 'MZ'
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const warnings = [];

    const eLfanew = dv.getUint32(0x3C, true);
    if (eLfanew + 24 > bytes.length) return null;
    if (dv.getUint32(eLfanew, true) !== 0x00004550) return null; // 'PE\0\0' (LE)

    const coff = eLfanew + 4;
    const machine = dv.getUint16(coff, true);
    const numSections = dv.getUint16(coff + 2, true);
    const timestamp = dv.getUint32(coff + 4, true); // COFF TimeDateStamp @ +4
    const sizeOptional = dv.getUint16(coff + 16, true);
    const characteristics = dv.getUint16(coff + 18, true);

    const opt = coff + 20;
    const magic = dv.getUint16(opt, true);
    const is64 = magic === 0x20b;
    // ¿El TimeDateStamp parece una fecha real? Los reproducible builds (MS
    // moderno) lo setean a un hash → fechas absurdas. Sólo lo tratamos como
    // fecha si cae entre 1990 y ~ahora.
    const tsPlausible = timestamp >= 631152000 && timestamp <= (Date.now() / 1000 + 86400);
    const pe = {
      is64, magic,
      machine, machineName: MACHINE[machine] || ('0x' + machine.toString(16)),
      timestamp, timestampDate: tsPlausible ? new Date(timestamp * 1000) : null,
      numSections, characteristics, charNames: flagsToNames(characteristics, CHARS),
      optional: null, sections: [], imports: [], imphash: null, warnings,
    };

    // Optional header (subconjunto útil). PE32 vs PE32+ cambian offsets.
    try {
      const entryPoint = dv.getUint32(opt + 16, true);
      const imageBase = is64
        ? Number(dv.getBigUint64(opt + 24, true))
        : dv.getUint32(opt + 28, true);
      const subsystem = dv.getUint16(opt + (is64 ? 68 : 68), true);
      const dllChars = dv.getUint16(opt + (is64 ? 70 : 70), true);
      const numRvaPos = opt + (is64 ? 108 : 92);
      const numRva = dv.getUint32(numRvaPos, true);
      const ddStart = numRvaPos + 4; // inicio del array de DataDirectory
      pe.optional = {
        entryPoint, imageBase, subsystem, subsystemName: SUBSYS[subsystem] || ('0x' + subsystem.toString(16)),
        dllChars, dllCharNames: flagsToNames(dllChars, DLLCHARS), numRva, ddStart,
      };
    } catch (e) { warnings.push('Optional header incompleto'); }

    // Section headers
    const secStart = opt + sizeOptional;
    const secCount = Math.min(numSections, 96);
    for (let i = 0; i < secCount; i++) {
      const base = secStart + i * 40;
      if (base + 40 > bytes.length) { warnings.push('Tabla de secciones truncada'); break; }
      let name = '';
      for (let j = 0; j < 8; j++) {
        const c = bytes[base + j];
        if (c === 0) break;
        name += String.fromCharCode(c);
      }
      pe.sections.push({
        name: name || '(sin nombre)',
        vsize: dv.getUint32(base + 8, true),
        vaddr: dv.getUint32(base + 12, true),
        rawsize: dv.getUint32(base + 16, true),
        rawptr: dv.getUint32(base + 20, true),
        chars: dv.getUint32(base + 36, true),
      });
    }

    // RVA → file offset usando el mapa de secciones
    function rvaToOffset(rva) {
      for (const s of pe.sections) {
        const span = Math.max(s.vsize, s.rawsize);
        if (rva >= s.vaddr && rva < s.vaddr + span) {
          return s.rawptr + (rva - s.vaddr);
        }
      }
      return -1;
    }

    function readCString(off, max) {
      max = max || 512;
      let s = '';
      for (let i = 0; i < max; i++) {
        const c = bytes[off + i];
        if (c === undefined || c === 0) break;
        s += String.fromCharCode(c);
      }
      return s;
    }

    // Import directory = DataDirectory[1]
    if (pe.optional && pe.optional.numRva > 1) {
      try {
        const ddImport = pe.optional.ddStart + 1 * 8;
        const impRva = dv.getUint32(ddImport, true);
        if (impRva) parseImports(impRva);
      } catch (e) { warnings.push('Import directory ilegible'); }
    }

    function parseImports(impRva) {
      let off = rvaToOffset(impRva);
      if (off < 0) { warnings.push('Import RVA fuera de las secciones'); return; }
      for (let d = 0; d < 1024; d++) {
        const base = off + d * 20;
        if (base + 20 > bytes.length) break;
        const oft = dv.getUint32(base, true);       // OriginalFirstThunk (ILT)
        const nameRva = dv.getUint32(base + 12, true);
        const ft = dv.getUint32(base + 16, true);   // FirstThunk (IAT)
        if (oft === 0 && nameRva === 0 && ft === 0) break; // terminador
        const nameOff = rvaToOffset(nameRva);
        const dll = nameOff >= 0 ? readCString(nameOff) : '(desconocido)';
        const funcs = parseThunks(oft || ft);
        pe.imports.push({ dll, funcs });
      }
    }

    function parseThunks(thunkRva) {
      const funcs = [];
      let off = rvaToOffset(thunkRva);
      if (off < 0) return funcs;
      const step = is64 ? 8 : 4;
      const ordinalFlag = is64 ? 0x8000000000000000 : 0x80000000;
      for (let i = 0; i < 4096; i++) {
        const pos = off + i * step;
        if (pos + step > bytes.length) break;
        let val, isOrdinal, ordinal, nameRva;
        if (is64) {
          val = dv.getBigUint64(pos, true);
          if (val === 0n) break;
          isOrdinal = (val & BigInt('0x8000000000000000')) !== 0n;
          ordinal = Number(val & 0xffffn);
          nameRva = Number(val & 0x7fffffffn);
        } else {
          val = dv.getUint32(pos, true);
          if (val === 0) break;
          isOrdinal = (val & 0x80000000) !== 0;
          ordinal = val & 0xffff;
          nameRva = val & 0x7fffffff;
        }
        if (isOrdinal) {
          funcs.push({ ordinal, name: null });
        } else {
          const nOff = rvaToOffset(nameRva);
          // IMAGE_IMPORT_BY_NAME = WORD hint + ASCII name
          const name = nOff >= 0 ? readCString(nOff + 2) : null;
          funcs.push({ ordinal: null, name: name || '(?)' });
        }
      }
      return funcs;
    }

    pe.imphash = computeImphash(pe);
    pe.importCount = pe.imports.reduce((a, x) => a + x.funcs.length, 0);
    // Offset de archivo del entry point (lo usa el matcher PEiD). -1 si no resuelve.
    pe.epOffset = (pe.optional && pe.optional.entryPoint != null) ? rvaToOffset(pe.optional.entryPoint) : -1;

    // ── Recursos (DataDirectory[2]): version info, manifest, inventario ──
    pe.resources = null; pe.versionInfo = null; pe.manifest = null;
    try {
      if (pe.optional && pe.optional.numRva > 2) {
        const dd = pe.optional.ddStart + 2 * 8;
        const rva = dv.getUint32(dd, true);
        if (rva) parseResources(rva);
      }
    } catch (e) { warnings.push('Directorio de recursos ilegible'); }

    // ── Authenticode (DataDirectory[4] = tabla de certificados) ──
    // Ojo: este directorio guarda un OFFSET DE ARCHIVO, no un RVA.
    pe.authenticode = null;
    try {
      if (pe.optional && pe.optional.numRva > 4) {
        const dd = pe.optional.ddStart + 4 * 8;
        const off = dv.getUint32(dd, true);
        const sz = dv.getUint32(dd + 4, true);
        if (off && sz) pe.authenticode = parseAuthenticode(off, sz);
      }
    } catch (e) { warnings.push('Tabla de certificados ilegible'); }

    // Rich Header: huella del toolchain de compilación (linker MSVC). Sirve
    // para clustering/atribución — binarios de la misma máquina/compilador
    // comparten el mismo rich hash.
    try {
      pe.rich = parseRich(bytes, dv, eLfanew);
      if (pe.rich && typeof SparkMD5 !== 'undefined') {
        pe.rich.hash = SparkMD5.ArrayBuffer.hash(pe.rich.clearData.buffer);
      }
    } catch (e) { warnings.push('Rich Header ilegible'); }

    // ── Recursos: recorre el árbol de 3 niveles (tipo → nombre → idioma) ──
    function parseResources(resRva) {
      const baseOff = rvaToOffset(resRva);
      if (baseOff < 0) return;
      const leaves = []; // { typeId, dataRva, size }
      function walkDir(relOff, level, typeId, depth) {
        const dirOff = baseOff + relOff;
        if (depth > 3 || dirOff + 16 > bytes.length) return;
        const named = dv.getUint16(dirOff + 12, true);
        const ids = dv.getUint16(dirOff + 14, true);
        const total = Math.min(named + ids, 8192);
        for (let i = 0; i < total; i++) {
          const e = dirOff + 16 + i * 8;
          if (e + 8 > bytes.length) break;
          const nameField = dv.getUint32(e, true);
          const offField = dv.getUint32(e + 4, true);
          const isDir = (offField & 0x80000000) !== 0;
          const child = offField & 0x7fffffff;
          const thisType = level === 1
            ? ((nameField & 0x80000000) ? -1 : nameField) // nivel 1 = tipo
            : typeId;
          if (isDir) {
            walkDir(child, level + 1, thisType, depth + 1);
          } else {
            const de = baseOff + child;
            if (de + 16 <= bytes.length) {
              leaves.push({ typeId: thisType, dataRva: dv.getUint32(de, true), size: dv.getUint32(de + 4, true) });
            }
          }
        }
      }
      walkDir(0, 1, -1, 0);
      if (!leaves.length) return;
      const byType = {};
      for (const lf of leaves) byType[lf.typeId] = (byType[lf.typeId] || 0) + 1;
      pe.resources = Object.keys(byType)
        .map((k) => ({ id: +k, name: RT_NAMES[+k] || ('Tipo ' + k), count: byType[k] }))
        .sort((a, b) => b.count - a.count);
      const ver = leaves.find((l) => l.typeId === 16);
      if (ver) { const o = rvaToOffset(ver.dataRva); if (o >= 0) pe.versionInfo = parseVersionInfo(o, ver.size); }
      const man = leaves.find((l) => l.typeId === 24);
      if (man) { const o = rvaToOffset(man.dataRva); if (o >= 0) pe.manifest = parseManifest(o, man.size); }
    }

    // VS_VERSIONINFO: árbol de nodos { wLength, wValueLength, wType, szKey(UTF-16) }.
    function parseVersionInfo(off, size) {
      const end = Math.min(off + size, bytes.length);
      const out = { fixed: null, strings: {} };
      const al4 = (p) => (p + 3) & ~3;
      const verStr = (ms, ls) => ((ms >>> 16) & 0xffff) + '.' + (ms & 0xffff) + '.' + ((ls >>> 16) & 0xffff) + '.' + (ls & 0xffff);
      function readKey(p) {
        let s = '';
        while (p + 1 < end) { const c = dv.getUint16(p, true); p += 2; if (c === 0) break; s += String.fromCharCode(c); }
        return { str: s, next: p };
      }
      function walk(p, stop, depth) {
        while (p + 6 <= stop && depth < 8) {
          const wLength = dv.getUint16(p, true);
          if (wLength < 6) break;
          const wValueLength = dv.getUint16(p + 2, true);
          const wType = dv.getUint16(p + 4, true);
          const nodeEnd = Math.min(p + wLength, stop);
          const k = readKey(p + 6);
          const vp = al4(k.next);
          const vbytes = (wType === 1) ? wValueLength * 2 : wValueLength;
          if (k.str === 'VS_VERSION_INFO' && wValueLength >= 52 && vp + 52 <= end && dv.getUint32(vp, true) === 0xFEEF04BD) {
            out.fixed = {
              fileVersion: verStr(dv.getUint32(vp + 8, true), dv.getUint32(vp + 12, true)),
              productVersion: verStr(dv.getUint32(vp + 16, true), dv.getUint32(vp + 20, true)),
            };
          } else if (wType === 1 && wValueLength > 0 && k.str) {
            let s = '';
            for (let i = 0; i + 1 < vbytes && vp + i + 1 < end; i += 2) { const c = dv.getUint16(vp + i, true); if (c === 0) break; s += String.fromCharCode(c); }
            if (s) out.strings[k.str] = s;
          }
          const childStart = al4(vp + vbytes);
          if (childStart < nodeEnd) walk(childStart, nodeEnd, depth + 1);
          const np = al4(nodeEnd);
          if (np <= p) break;
          p = np;
        }
      }
      try { walk(off, end, 0); } catch (e) {}
      return out;
    }

    // Manifest (XML embebido): sólo nos interesa el nivel de ejecución pedido.
    function parseManifest(off, size) {
      const n = Math.min(size, bytes.length - off, 32768);
      let s = '';
      for (let i = 0; i < n; i++) { const c = bytes[off + i]; if (c) s += String.fromCharCode(c); }
      const lvl = /level\s*=\s*"([^"]+)"/i.exec(s);
      const ua = /uiAccess\s*=\s*"([^"]+)"/i.exec(s);
      return { level: lvl ? lvl[1] : null, uiAccess: ua ? ua[1] : null };
    }

    // ── Authenticode: WIN_CERTIFICATE → PKCS#7 SignedData (DER, ASN.1) ──
    function parseAuthenticode(secOff, secSize) {
      const res = { size: secSize, certType: null, subjects: [], signer: null, signingTime: null };
      if (secOff + 8 > bytes.length) return res;
      const dwLength = dv.getUint32(secOff, true);
      const wType = dv.getUint16(secOff + 6, true);
      res.certType = wType === 2 ? 'PKCS#7' : ('tipo 0x' + wType.toString(16));
      const derStart = secOff + 8;
      const derEnd = Math.min(secOff + dwLength, bytes.length);
      if (wType === 2) { try { parsePkcs7(derStart, derEnd, res); } catch (e) {} }
      return res;
    }

    // Lector TLV de ASN.1 DER (acotado). Devuelve null ante datos inválidos.
    function tlv(p, limit) {
      if (p + 2 > limit) return null;
      const tag = bytes[p];
      let lb = bytes[p + 1], hlen = 2, len = 0;
      if (lb < 0x80) { len = lb; }
      else { const n = lb & 0x7f; if (n > 4 || p + 2 + n > limit) return null; for (let i = 0; i < n; i++) len = len * 256 + bytes[p + 2 + i]; hlen = 2 + n; }
      const start = p + hlen, ennd = start + len;
      if (ennd > limit) return null;
      return { tag, start, len, end: ennd, p };
    }
    function kids(node, limit) {
      const out = []; const lim = Math.min(node.end, limit); let p = node.start;
      for (let i = 0; i < 4096 && p < lim; i++) { const t = tlv(p, lim); if (!t) break; out.push(t); if (t.end <= p) break; p = t.end; }
      return out;
    }
    function oidStr(node) {
      if (node.tag !== 0x06 || node.len < 1) return '';
      const o = []; let v = bytes[node.start]; o.push(Math.floor(v / 40)); o.push(v % 40);
      let acc = 0;
      for (let i = 1; i < node.len; i++) { const b = bytes[node.start + i]; acc = acc * 128 + (b & 0x7f); if (!(b & 0x80)) { o.push(acc); acc = 0; } }
      return o.join('.');
    }
    function derText(node) {
      let s = '';
      if (node.tag === 0x1e) { // BMPString = UTF-16BE
        for (let i = 0; i + 1 < node.len; i += 2) { const c = dv.getUint16(node.start + i, false); if (c) s += String.fromCharCode(c); }
      } else { // PrintableString / UTF8String / IA5String
        for (let i = 0; i < node.len; i++) { const c = bytes[node.start + i]; if (c) s += String.fromCharCode(c); }
      }
      return s.trim();
    }
    function hexOf(node) { let h = ''; for (let i = 0; i < node.len && i < 40; i++) h += bytes[node.start + i].toString(16).padStart(2, '0'); return h; }
    function parseName(nameNode) {
      const o = {};
      for (const rdn of kids(nameNode, nameNode.end)) {
        for (const atv of kids(rdn, rdn.end)) {
          const cs = kids(atv, atv.end);
          if (cs.length >= 2 && cs[0].tag === 0x06) {
            const oid = oidStr(cs[0]);
            if (oid === '2.5.4.3') o.CN = derText(cs[1]);
            else if (oid === '2.5.4.10') o.O = derText(cs[1]);
            else if (oid === '2.5.4.11') o.OU = derText(cs[1]);
          }
        }
      }
      return o;
    }
    function parsePkcs7(derStart, derEnd, res) {
      const ci = tlv(derStart, derEnd); if (!ci) return;            // ContentInfo SEQUENCE
      const ciK = kids(ci, derEnd);
      const wrap = ciK.find((n) => n.tag === 0xA0); if (!wrap) return; // [0] EXPLICIT
      const sd = tlv(wrap.start, wrap.end); if (!sd) return;         // SignedData SEQUENCE
      const sdK = kids(sd, sd.end);
      const certsNode = sdK.find((n) => n.tag === 0xA0);            // [0] IMPLICIT certificates
      const signerSet = sdK.filter((n) => n.tag === 0x31).pop();   // signerInfos SET (último)
      const certs = []; // { subject, serial }
      if (certsNode) {
        for (const c of kids(certsNode, certsNode.end)) {
          if (c.tag !== 0x30) continue;
          const tbs = kids(c, c.end)[0]; if (!tbs) continue;
          const tk = kids(tbs, tbs.end);
          let idx = 0;
          if (tk[0] && tk[0].tag === 0xA0) idx = 1;                 // version [0] opcional
          const serial = tk[idx];                                   // serialNumber INTEGER
          const subject = tk[idx + 4];                              // ...subject Name
          if (serial && subject && subject.tag === 0x30) {
            certs.push({ subject: parseName(subject), serial: hexOf(serial) });
          }
        }
      }
      res.subjects = certs.map((c) => c.subject).filter((s) => s.CN || s.O);
      // Firmante: el SignerInfo referencia issuerAndSerialNumber → casamos por serial.
      if (signerSet) {
        const si = kids(signerSet, signerSet.end)[0];
        if (si) {
          const sik = kids(si, si.end);
          const ias = sik.find((n) => n.tag === 0x30);             // issuerAndSerialNumber
          if (ias) {
            const iasK = kids(ias, ias.end);
            const serial = iasK.find((n) => n.tag === 0x02);
            if (serial) {
              const sh = hexOf(serial);
              const match = certs.find((c) => c.serial === sh);
              if (match) res.signer = match.subject;
            }
          }
          // signingTime en los atributos autenticados ([0])
          const attrs = sik.find((n) => n.tag === 0xA0);
          if (attrs) {
            for (const a of kids(attrs, attrs.end)) {
              const ak = kids(a, a.end);
              if (ak[0] && ak[0].tag === 0x06 && oidStr(ak[0]) === '1.2.840.113549.1.9.5') {
                const set = ak[1]; if (set) { const tv = kids(set, set.end)[0]; if (tv) res.signingTime = derText(tv); }
              }
            }
          }
        }
      }
      if (!res.signer && res.subjects.length) res.signer = res.subjects[0];
    }

    return pe;
  }

  // Parsea el Rich Header (entre el DOS stub y el PE header). Devuelve null si
  // no hay. Estructura: termina en "Rich" + XOR key; hacia atrás, todo está
  // XOR'd con la key hasta el marcador "DanS"; entre medio hay pares
  // (comp_id, count) donde comp_id = (productId << 16) | build.
  function parseRich(bytes, dv, eLfanew) {
    const DANS = 0x536E6144; // "DanS" LE
    const end = Math.min(eLfanew, bytes.length - 8);
    if (end <= 0x40) return null;
    // "Rich" = 52 69 63 68. Suele estar alineado a 4; scan alineado primero.
    let richOff = -1;
    for (let i = 0x40; i < end; i += 4) {
      if (bytes[i] === 0x52 && bytes[i + 1] === 0x69 && bytes[i + 2] === 0x63 && bytes[i + 3] === 0x68) { richOff = i; break; }
    }
    if (richOff < 0) return null;
    const key = dv.getUint32(richOff + 4, true);
    // Hacia atrás en pasos de 4, decodificando, hasta "DanS".
    let dansOff = -1;
    for (let i = richOff - 4; i >= 0x40; i -= 4) {
      if ((dv.getUint32(i, true) ^ key) === DANS) { dansOff = i; break; }
    }
    if (dansOff < 0) return null;
    const entries = [];
    // Saltamos DanS (4) + 3 DWORDs de padding (12) = 16 bytes.
    for (let i = dansOff + 16; i + 8 <= richOff; i += 8) {
      const comp = (dv.getUint32(i, true) ^ key) >>> 0;
      const count = (dv.getUint32(i + 4, true) ^ key) >>> 0;
      if (comp === 0 && count === 0) continue;
      entries.push({ prodId: comp >>> 16, build: comp & 0xFFFF, count });
    }
    // clear data = DWORDs decodificados desde DanS hasta "Rich" → base del hash.
    const len = richOff - dansOff;
    const clear = new Uint8Array(len);
    const cdv = new DataView(clear.buffer);
    for (let i = 0; i + 4 <= len; i += 4) {
      cdv.setUint32(i, (dv.getUint32(dansOff + i, true) ^ key) >>> 0, true);
    }
    return { key, dansOff, richOff, entries, clearData: clear, hash: null };
  }

  // imphash estilo pefile: "<dll-sin-extensión>.<func>" en minúsculas, en
  // orden, unidos por comas, MD5. Ordinales → "ordN" (ver caveat arriba).
  function computeImphash(pe) {
    if (typeof SparkMD5 === 'undefined' || !pe.imports.length) return null;
    const exts = ['ocx', 'sys', 'dll'];
    const parts = [];
    for (const imp of pe.imports) {
      let lib = (imp.dll || '').toLowerCase();
      const dot = lib.lastIndexOf('.');
      if (dot > 0 && exts.indexOf(lib.slice(dot + 1)) !== -1) lib = lib.slice(0, dot);
      for (const f of imp.funcs) {
        const fn = f.name ? f.name.toLowerCase() : ('ord' + f.ordinal);
        parts.push(lib + '.' + fn);
      }
    }
    if (!parts.length) return null;
    return SparkMD5.hash(parts.join(','));
  }

  return { parse, computeImphash, MACHINE, SUBSYS };
})();

if (typeof window !== 'undefined') { window.Triage = window.Triage || {}; window.Triage.pe = pe; }
