// APT115 CODEX ARCANUM — Minimal ELF parser
// El análogo Linux del parser PE: extrae lo que importa para triage estático.
// header (clase/endianness/ABI/tipo/máquina), segmentos (program headers),
// secciones, .dynamic (DT_NEEDED = dependencias dinámicas, el equivalente a los
// imports de PE), símbolos dinámicos importados/exportados, build-id (clustering),
// intérprete (static vs dynamic) y mitigaciones (NX, PIE, RELRO, canary, RPATH).
//
// Robusto ante binarios stripped/packed: las dependencias y el .dynamic se leen
// vía program headers (que sobreviven al strip), no sólo vía section headers.
// Sin dependencias. Todos los loops acotados; ante datos corruptos junta lo que
// pudo y agrega avisos en `warnings`.

window.Triage = window.Triage || {};
Triage.elf = (function () {
  'use strict';

  const E_TYPE = { 0: 'NONE', 1: 'REL (objeto)', 2: 'EXEC (ejecutable)', 3: 'DYN (PIE / shared object)', 4: 'CORE (volcado)' };
  const E_MACHINE = {
    0x02: 'SPARC', 0x03: 'x86 (i386)', 0x08: 'MIPS', 0x14: 'PowerPC', 0x15: 'PowerPC64',
    0x16: 'S390', 0x28: 'ARM', 0x2A: 'SuperH', 0x32: 'IA-64', 0x3E: 'x86-64 (AMD64)',
    0xB7: 'AArch64 (ARM64)', 0xF3: 'RISC-V', 0x101: 'WDC 65C816', 0x5441: 'Fur',
  };
  const OSABI = {
    0: 'System V', 1: 'HP-UX', 2: 'NetBSD', 3: 'Linux/GNU', 6: 'Solaris', 9: 'FreeBSD',
    12: 'OpenBSD', 0x40: 'Standalone',
  };
  const PT = {
    1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 5: 'SHLIB', 6: 'PHDR', 7: 'TLS',
    0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK', 0x6474e552: 'GNU_RELRO', 0x6474e553: 'GNU_PROPERTY',
  };
  const SHT = {
    0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA', 5: 'HASH', 6: 'DYNAMIC',
    7: 'NOTE', 8: 'NOBITS', 9: 'REL', 11: 'DYNSYM', 14: 'INIT_ARRAY', 15: 'FINI_ARRAY',
    0x6ffffff6: 'GNU_HASH', 0x6ffffffe: 'VERNEED', 0x6fffffff: 'VERSYM',
  };
  // Dynamic tags relevantes
  const DT_NULL = 0, DT_NEEDED = 1, DT_STRTAB = 5, DT_SYMTAB = 6, DT_STRSZ = 10,
    DT_SONAME = 14, DT_RPATH = 15, DT_FLAGS = 30, DT_RUNPATH = 29, DT_FLAGS_1 = 0x6ffffffb,
    DT_BIND_NOW = 24;
  const DF_BIND_NOW = 0x8, DF_1_PIE = 0x08000000, DF_1_NOW = 0x1;

  function parse(bytes) {
    if (bytes.length < 64 || bytes[0] !== 0x7F || bytes[1] !== 0x45 || bytes[2] !== 0x4C || bytes[3] !== 0x46) return null; // \x7fELF
    const cls = bytes[4];          // 1 = 32-bit, 2 = 64-bit
    const dataEnc = bytes[5];      // 1 = LE, 2 = BE
    const is64 = cls === 2;
    const le = dataEnc !== 2;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const warnings = [];

    // lectores que respetan endianness y clase
    const u16 = (o) => dv.getUint16(o, le);
    const u32 = (o) => dv.getUint32(o, le);
    const uXW = (o) => is64 ? Number(dv.getBigUint64(o, le)) : dv.getUint32(o, le); // word nativa
    const cstr = (off, max) => {
      max = max || 4096; let s = '';
      for (let i = 0; i < max; i++) { const c = bytes[off + i]; if (c === undefined || c === 0) break; s += String.fromCharCode(c); }
      return s;
    };

    const osabi = bytes[7];
    const eType = u16(16);
    const eMachine = u16(18);
    const elf = {
      is64, le, osabi, osabiName: OSABI[osabi] || ('0x' + osabi.toString(16)),
      type: eType, typeName: E_TYPE[eType] || ('0x' + eType.toString(16)),
      machine: eMachine, machineName: E_MACHINE[eMachine] || ('0x' + eMachine.toString(16)),
      classLabel: is64 ? 'ELF64' : 'ELF32', endian: le ? 'little-endian' : 'big-endian',
      entry: null, interp: null, isPie: eType === 3, isStatic: false, stripped: true,
      segments: [], sections: [], needed: [], soname: null, runpath: null, rpath: null,
      imports: [], exports: [], buildId: null,
      nx: null, relro: 'ninguno', bindNow: false, canary: false, fortify: false,
      warnings,
    };

    // Offsets del header dependientes de la clase
    const off = is64
      ? { entry: 24, phoff: 32, shoff: 40, phentsize: 54, phnum: 56, shentsize: 58, shnum: 60, shstrndx: 62 }
      : { entry: 24, phoff: 28, shoff: 32, phentsize: 42, phnum: 44, shentsize: 46, shnum: 48, shstrndx: 50 };
    elf.entry = uXW(off.entry);
    const phoff = uXW(off.phoff), shoff = uXW(off.shoff);
    const phentsize = u16(off.phentsize), phnum = u16(off.phnum);
    const shentsize = u16(off.shentsize), shnum = u16(off.shnum), shstrndx = u16(off.shstrndx);

    // mapa vaddr → offset de archivo (vía LOAD); robusto aunque no haya secciones
    const loads = [];
    let dynSeg = null, gnuStack = null, gnuRelro = null, noteSegs = [];

    // ── Program headers (segmentos) ──
    for (let i = 0; i < Math.min(phnum, 256); i++) {
      const b = phoff + i * phentsize;
      if (b + (is64 ? 56 : 32) > bytes.length) { warnings.push('Program headers truncados'); break; }
      let p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz;
      if (is64) {
        p_type = u32(b); p_flags = u32(b + 4);
        p_offset = uXW(b + 8); p_vaddr = uXW(b + 16);
        p_filesz = uXW(b + 32); p_memsz = uXW(b + 40);
      } else {
        p_type = u32(b); p_offset = uXW(b + 4); p_vaddr = uXW(b + 8);
        p_filesz = uXW(b + 16); p_memsz = uXW(b + 20); p_flags = u32(b + 24);
      }
      elf.segments.push({ type: p_type, typeName: PT[p_type] || ('0x' + p_type.toString(16)), flags: p_flags, offset: p_offset, vaddr: p_vaddr, filesz: p_filesz, memsz: p_memsz });
      if (p_type === 1) loads.push({ vaddr: p_vaddr, offset: p_offset, filesz: p_filesz });
      else if (p_type === 2) dynSeg = { offset: p_offset, filesz: p_filesz };
      else if (p_type === 3) { const s = cstr(p_offset, p_filesz || 256); if (s) elf.interp = s; }
      else if (p_type === 0x6474e551) gnuStack = p_flags;
      else if (p_type === 0x6474e552) gnuRelro = true;
      else if (p_type === 4) noteSegs.push({ offset: p_offset, filesz: p_filesz });
    }
    elf.isStatic = !elf.interp && !dynSeg;
    // NX: el segmento GNU_STACK sin bit X (1) → pila no ejecutable
    if (gnuStack != null) elf.nx = (gnuStack & 1) === 0;
    if (gnuRelro) elf.relro = 'parcial';

    function vaddrToOffset(va) {
      for (const l of loads) if (va >= l.vaddr && va < l.vaddr + l.filesz) return l.offset + (va - l.vaddr);
      return -1;
    }

    // ── .dynamic: dependencias y flags (vía program header, sobrevive al strip) ──
    if (dynSeg) {
      const step = is64 ? 16 : 8;
      const entries = [];
      let strtabVA = 0, strsz = 0;
      const end = Math.min(dynSeg.offset + dynSeg.filesz, bytes.length);
      for (let p = dynSeg.offset; p + step <= end; p += step) {
        const tag = uXW(p); const val = uXW(p + (is64 ? 8 : 4));
        if (tag === DT_NULL) break;
        entries.push([tag, val]);
        if (tag === DT_STRTAB) strtabVA = val;
        else if (tag === DT_STRSZ) strsz = val;
        else if (tag === DT_FLAGS && (val & DF_BIND_NOW)) elf.bindNow = true;
        else if (tag === DT_FLAGS_1) { if (val & DF_1_NOW) elf.bindNow = true; if (val & DF_1_PIE) elf.isPie = true; }
        else if (tag === DT_BIND_NOW) elf.bindNow = true;
      }
      const strOff = strtabVA ? vaddrToOffset(strtabVA) : -1;
      const dynstr = (o) => (strOff >= 0) ? cstr(strOff + o, 1024) : ('@0x' + o.toString(16));
      for (const [tag, val] of entries) {
        if (tag === DT_NEEDED) elf.needed.push(dynstr(val));
        else if (tag === DT_SONAME) elf.soname = dynstr(val);
        else if (tag === DT_RUNPATH) elf.runpath = dynstr(val);
        else if (tag === DT_RPATH) elf.rpath = dynstr(val);
      }
    }
    if (gnuRelro && elf.bindNow) elf.relro = 'completo';

    // ── Section headers: nombres, símbolos (.dynsym/.symtab), notas ──
    const sections = [];
    if (shnum && shoff && shstrndx < shnum) {
      const shentEnd = shoff + shnum * shentsize;
      if (shentEnd <= bytes.length) {
        // primero la tabla de nombres de secciones
        const strHdr = shoff + shstrndx * shentsize;
        const shstrOff = uXW(strHdr + (is64 ? 24 : 16));
        for (let i = 0; i < Math.min(shnum, 512); i++) {
          const b = shoff + i * shentsize;
          const nameIdx = u32(b);
          const sh_type = u32(b + 4);
          const sh_addr = uXW(b + (is64 ? 16 : 12));
          const sh_offset = uXW(b + (is64 ? 24 : 16));
          const sh_size = uXW(b + (is64 ? 32 : 20));
          const sh_link = u32(b + (is64 ? 40 : 24));
          const sh_entsize = uXW(b + (is64 ? 56 : 36));
          const name = cstr(shstrOff + nameIdx, 128);
          sections.push({ name, type: sh_type, typeName: SHT[sh_type] || ('0x' + sh_type.toString(16)), addr: sh_addr, offset: sh_offset, size: sh_size, link: sh_link, entsize: sh_entsize });
        }
        elf.sections = sections;
        elf.stripped = !sections.some(s => s.type === 2); // sin SYMTAB → stripped
        // símbolos dinámicos: importados (UND) y exportados (definidos globales)
        const dynsym = sections.find(s => s.type === 11);
        if (dynsym && dynsym.entsize) parseSymbols(dynsym, sections);
        // build-id desde .note.gnu.build-id
        const noteSec = sections.find(s => s.name === '.note.gnu.build-id');
        if (noteSec) elf.buildId = readBuildId(noteSec.offset, noteSec.size);
      } else warnings.push('Section headers fuera de rango');
    } else {
      // binario sin secciones (stripped fuerte): build-id desde PT_NOTE
      for (const ns of noteSegs) { const bid = readBuildId(ns.offset, ns.filesz); if (bid) { elf.buildId = bid; break; } }
    }

    function parseSymbols(symSec, secs) {
      const strSec = secs[symSec.link];
      const strBase = strSec ? strSec.offset : -1;
      const symStep = is64 ? 24 : 16;
      const count = Math.min(Math.floor(symSec.size / symStep), 20000);
      const imp = [], exp = [];
      for (let i = 0; i < count; i++) {
        const b = symSec.offset + i * symStep;
        if (b + symStep > bytes.length) break;
        const nameIdx = u32(b);
        let info, shndx;
        if (is64) { info = bytes[b + 4]; shndx = u16(b + 6); }
        else { info = bytes[b + 12]; shndx = u16(b + 14); }
        const bind = info >> 4, type = info & 0xf; // bind: 1=GLOBAL 2=WEAK; type: 2=FUNC
        if (!nameIdx) continue;
        const nm = strBase >= 0 ? cstr(strBase + nameIdx, 256) : '';
        if (!nm) continue;
        if (shndx === 0) { // SHN_UNDEF → símbolo importado (lo resuelve el loader)
          imp.push(nm);
          if (nm === '__stack_chk_fail' || nm === '__stack_chk_guard') elf.canary = true;
          if (/_chk$/.test(nm)) elf.fortify = true;
        } else if ((bind === 1 || bind === 2) && type === 2) {
          exp.push(nm); // FUNC global/weak definido → exportado
        }
      }
      elf.imports = dedup(imp);
      elf.exports = dedup(exp);
    }

    function readBuildId(noteOff, noteSize) {
      // ELF note: namesz(4), descsz(4), type(4), name(namesz, padded4), desc(descsz)
      const end = Math.min(noteOff + noteSize, bytes.length);
      let p = noteOff;
      for (let g = 0; g < 32 && p + 12 <= end; g++) {
        const namesz = u32(p), descsz = u32(p + 4), ntype = u32(p + 8);
        const nameOff = p + 12;
        const descOff = nameOff + ((namesz + 3) & ~3);
        const name = cstr(nameOff, namesz);
        if (ntype === 3 && name === 'GNU' && descOff + descsz <= end) { // NT_GNU_BUILD_ID
          let h = '';
          for (let i = 0; i < descsz && i < 40; i++) h += bytes[descOff + i].toString(16).padStart(2, '0');
          return h;
        }
        p = descOff + ((descsz + 3) & ~3);
        if (p <= noteOff) break;
      }
      return null;
    }

    function dedup(arr) { const seen = {}, out = []; for (const x of arr) if (!seen[x]) { seen[x] = 1; out.push(x); } return out; }

    return elf;
  }

  return { parse, E_MACHINE, E_TYPE };
})();
