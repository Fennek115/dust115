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

window.Triage = window.Triage || {};
Triage.pe = (function () {
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

    // Rich Header: huella del toolchain de compilación (linker MSVC). Sirve
    // para clustering/atribución — binarios de la misma máquina/compilador
    // comparten el mismo rich hash.
    try {
      pe.rich = parseRich(bytes, dv, eLfanew);
      if (pe.rich && typeof SparkMD5 !== 'undefined') {
        pe.rich.hash = SparkMD5.ArrayBuffer.hash(pe.rich.clearData.buffer);
      }
    } catch (e) { warnings.push('Rich Header ilegible'); }

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
