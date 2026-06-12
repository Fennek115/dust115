// APT115 CODEX ARCANUM — Mach-O parser (macOS / iOS)
// El análogo Apple del parser PE/ELF, pensado para triage de malware de macOS.
// Soporta thin (32/64-bit, ambas endianness) y fat/universal (varias slices).
//
// Por slice extrae: header (cputype/subtype incl. arm64e, filetype, flags), load
// commands → segmentos (+secciones, con detección de __mod_init_func / Obj-C / Swift),
// dylibs linkeadas con versiones (= imports de PE / DT_NEEDED de ELF), dylinker, entry
// (LC_MAIN o LC_UNIXTHREAD), UUID (clustering), rpaths (vector de dylib hijacking),
// plataforma/SDK, símbolos importados/exportados (LC_SYMTAB nlist), cifrado FairPlay
// (LC_ENCRYPTION_INFO cryptid) y —lo más jugoso para triage Apple— la FIRMA DE CÓDIGO:
// CodeDirectory (versión, flags adhoc/hard/kill/runtime/library-validation, teamID,
// identifier, hashType, rango del blob para CDHash) + ENTITLEMENTS (plist) con marcado
// de las peligrosas (get-task-allow, disable-library-validation, allow-dyld-env-vars,
// allow-unsigned-executable-memory…). Mitigaciones: PIE, NX heap, stack exec, hardened
// runtime, library validation.
//
// Sin dependencias. Loops acotados; ante datos corruptos junta lo que pudo y agrega
// avisos en `warnings`. Expone para `epdisasm`: entry (vaddr), entryOffset (file off),
// cpuType, is64, le, segments[{vmaddr,fileoff,filesize}]. La firma de código se lee en
// BIG-ENDIAN siempre (formato de red), independiente de la endianness de la slice.

window.Triage = window.Triage || {};
Triage.macho = (function () {
  'use strict';

  const MH_MAGIC = 0xFEEDFACE, MH_MAGIC_64 = 0xFEEDFACF;
  const FAT_MAGIC = 0xCAFEBABE, FAT_MAGIC_64 = 0xCAFEBABF;   // siempre big-endian

  const CPU = {
    7: 'x86 (i386)', 0x01000007: 'x86_64', 12: 'ARM', 0x0100000C: 'ARM64',
    0x0200000C: 'ARM64_32', 18: 'PowerPC', 0x01000012: 'PowerPC64',
  };
  const FILETYPE = {
    1: 'OBJECT (.o)', 2: 'EXECUTE (ejecutable)', 3: 'FVMLIB', 4: 'CORE (volcado)',
    5: 'PRELOAD', 6: 'DYLIB (.dylib)', 7: 'DYLINKER', 8: 'BUNDLE (.bundle/plugin)',
    9: 'DYLIB_STUB', 10: 'DSYM (símbolos)', 11: 'KEXT_BUNDLE (extensión de kernel)',
  };
  const PLATFORM = {
    1: 'macOS', 2: 'iOS', 3: 'tvOS', 4: 'watchOS', 5: 'bridgeOS', 6: 'Mac Catalyst',
    7: 'iOS Simulator', 8: 'tvOS Simulator', 9: 'watchOS Simulator', 10: 'DriverKit',
  };
  const MH_NOUNDEFS = 0x1, MH_TWOLEVEL = 0x80, MH_ALLOW_STACK_EXECUTION = 0x20000,
    MH_PIE = 0x200000, MH_NO_HEAP_EXECUTION = 0x1000000, MH_HAS_TLV_DESCRIPTORS = 0x800000,
    MH_APP_EXTENSION_SAFE = 0x02000000;

  // OJO: `0xNN | 0x80000000` da un int32 NEGATIVO en JS; el cmd se lee con `>>> 0`
  // (positivo), así que el bit LC_REQ_DYLD se suma (no se OR-ea) para que matcheen.
  const LC_REQ_DYLD = 0x80000000;
  const LC = {
    SEGMENT: 0x1, SYMTAB: 0x2, THREAD: 0x4, UNIXTHREAD: 0x5, LOAD_DYLIB: 0xC,
    ID_DYLIB: 0xD, LOAD_DYLINKER: 0xE, ID_DYLINKER: 0xF, LOAD_WEAK_DYLIB: 0x18 + LC_REQ_DYLD,
    SEGMENT_64: 0x19, UUID: 0x1B, RPATH: 0x1C + LC_REQ_DYLD, CODE_SIGNATURE: 0x1D,
    ENCRYPTION_INFO: 0x21, DYLD_INFO: 0x22, DYLD_INFO_ONLY: 0x22 + LC_REQ_DYLD,
    VERSION_MIN_MACOSX: 0x24, VERSION_MIN_IPHONEOS: 0x25, MAIN: 0x28 + LC_REQ_DYLD,
    ENCRYPTION_INFO_64: 0x2C, VERSION_MIN_TVOS: 0x2F, VERSION_MIN_WATCHOS: 0x30,
    SOURCE_VERSION: 0x2A, BUILD_VERSION: 0x32, REEXPORT_DYLIB: 0x1F + LC_REQ_DYLD,
    LOAD_UPWARD_DYLIB: 0x23 + LC_REQ_DYLD, LAZY_LOAD_DYLIB: 0x20,
    DYLD_CHAINED_FIXUPS: 0x34 + LC_REQ_DYLD, DYLD_EXPORTS_TRIE: 0x33 + LC_REQ_DYLD,
    FUNCTION_STARTS: 0x26,
  };
  const DYLIB_CMDS = [LC.LOAD_DYLIB, LC.LOAD_WEAK_DYLIB, LC.REEXPORT_DYLIB, LC.LOAD_UPWARD_DYLIB, LC.LAZY_LOAD_DYLIB];

  // Code-signing
  const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0, CSMAGIC_CODEDIRECTORY = 0xfade0c02,
    CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171, CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xfade7172,
    CSMAGIC_BLOBWRAPPER = 0xfade0b01, CSMAGIC_REQUIREMENTS = 0xfade0c01;
  const CS_ADHOC = 0x2, CS_HARD = 0x100, CS_KILL = 0x200, CS_RESTRICT = 0x800,
    CS_ENFORCEMENT = 0x1000, CS_REQUIRE_LV = 0x2000, CS_RUNTIME = 0x10000, CS_LINKER_SIGNED = 0x20000;
  const CS_HASHTYPE = { 1: 'SHA-1', 2: 'SHA-256', 3: 'SHA-256 (trunc)', 4: 'SHA-384', 5: 'SHA-512' };
  const CS_FLAGS = [
    [CS_ADHOC, 'adhoc'], [CS_HARD, 'hard'], [CS_KILL, 'kill'], [CS_RESTRICT, 'restrict'],
    [CS_ENFORCEMENT, 'enforcement'], [CS_REQUIRE_LV, 'library-validation'],
    [CS_RUNTIME, 'hardened-runtime'], [CS_LINKER_SIGNED, 'linker-signed'],
  ];
  // entitlements de alto riesgo (clave → por qué importa)
  const DANGER_ENT = {
    'com.apple.security.get-task-allow': 'depurable (task port abierto) — dev o anti-análisis',
    'com.apple.security.cs.disable-library-validation': 'permite cargar dylibs sin firmar → inyección',
    'com.apple.security.cs.allow-dyld-environment-variables': 'habilita DYLD_INSERT_LIBRARIES → inyección',
    'com.apple.security.cs.allow-unsigned-executable-memory': 'memoria ejecutable sin firmar → JIT/shellcode',
    'com.apple.security.cs.disable-executable-page-protection': 'desactiva W^X → shellcode',
    'com.apple.security.cs.allow-jit': 'JIT habilitado',
    'com.apple.security.automation.apple-events': 'automatiza/controla otras apps (AppleEvents)',
    'com.apple.security.device.camera': 'acceso a cámara',
    'com.apple.security.device.microphone': 'acceso a micrófono',
    'com.apple.security.personal-information.location': 'acceso a ubicación',
  };
  // símbolos de alta señal (nlist suele prefijar con '_')
  const SUSPECT = {
    ptrace: 'anti-debug (PT_DENY_ATTACH)', task_for_pid: 'acceso a memoria de otro proceso',
    mach_vm_write: 'inyección de memoria', vm_write: 'inyección de memoria',
    mach_vm_protect: 'cambiar permisos de memoria', mprotect: 'RWX en runtime',
    NSCreateObjectFileImageFromMemory: 'carga de dylib desde memoria', NSLinkModule: 'carga de módulo en memoria',
    dlopen: 'carga dinámica de librería', dlsym: 'resolución dinámica de símbolo',
    fork: 'crea proceso', execve: 'ejecuta binario', posix_spawn: 'lanza proceso',
    system: 'ejecuta comando de shell', popen: 'ejecuta comando',
    sysctl: 'anti-debug (chequeo P_TRACED)', csops: 'consulta flags de code-signing',
    CGEventTapCreate: 'intercepta input (keylogging)', CGEventPost: 'inyecta input',
    AXIsProcessTrusted: 'permisos de accesibilidad (keylogging)', SMJobBless: 'instala helper privilegiado',
    AuthorizationExecuteWithPrivileges: 'escalada de privilegios (deprecado)',
    SecKeychainFindGenericPassword: 'roba credenciales del llavero',
    IOServiceGetMatchingService: 'enumera dispositivos/IOKit', syscall: 'syscall directa',
  };

  function fmtVer(v) { return (v >>> 16) + '.' + ((v >>> 8) & 0xff) + '.' + (v & 0xff); }

  function probe(bytes, base) {
    if (base + 4 > bytes.length) return null;
    const b0 = bytes[base], b1 = bytes[base + 1], b2 = bytes[base + 2], b3 = bytes[base + 3];
    const beVal = (b0 << 24 | b1 << 16 | b2 << 8 | b3) >>> 0;
    const leVal = (b3 << 24 | b2 << 16 | b1 << 8 | b0) >>> 0;
    if (beVal === FAT_MAGIC || beVal === FAT_MAGIC_64) return { kind: 'fat', fat64: beVal === FAT_MAGIC_64 };
    if (beVal === MH_MAGIC) return { kind: 'thin', is64: false, le: false };
    if (beVal === MH_MAGIC_64) return { kind: 'thin', is64: true, le: false };
    if (leVal === MH_MAGIC) return { kind: 'thin', is64: false, le: true };
    if (leVal === MH_MAGIC_64) return { kind: 'thin', is64: true, le: true };
    return null;
  }

  function parseThin(bytes, base, is64, le) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const warnings = [];
    const u32 = (o) => dv.getUint32(base + o, le);
    const u64 = (o) => Number(dv.getBigUint64(base + o, le));
    const cstr = (off, max) => {
      max = max || 1024; let s = '';
      for (let i = 0; i < max; i++) { const c = bytes[off + i]; if (c === undefined || c === 0) break; s += String.fromCharCode(c); }
      return s;
    };

    const cpuType = u32(4) >>> 0;
    const cpuSub = u32(8) >>> 0;
    const filetype = u32(12);
    const ncmds = u32(16);
    const flags = u32(24);

    const m = {
      sliceOffset: base, is64, le,
      cpuType, cpuName: CPU[cpuType] || ('0x' + cpuType.toString(16)),
      cpuSub: cpuSub & 0x00ffffff, arm64e: (cpuType === 0x0100000C && (cpuSub & 0xff) === 2),
      filetype, filetypeName: FILETYPE[filetype] || ('0x' + filetype.toString(16)),
      flags, ncmds, classLabel: is64 ? 'Mach-O 64' : 'Mach-O 32', endian: le ? 'little-endian' : 'big-endian',
      isPie: !!(flags & MH_PIE), noHeapExec: !!(flags & MH_NO_HEAP_EXECUTION),
      allowStackExec: !!(flags & MH_ALLOW_STACK_EXECUTION), twoLevel: !!(flags & MH_TWOLEVEL),
      noUndefs: !!(flags & MH_NOUNDEFS), hasTLV: !!(flags & MH_HAS_TLV_DESCRIPTORS),
      appExtSafe: !!(flags & MH_APP_EXTENSION_SAFE),
      segments: [], dylibs: [], rpaths: [], imports: [], exports: [],
      interp: null, installName: null, uuid: null, entry: null, entryOffset: -1, entryKind: null,
      encrypted: false, cryptId: 0, platform: null, minOS: null, sdk: null, sourceVersion: null,
      dyldInfo: false, chainedFixups: false, restrictSeg: false, funcStarts: 0,
      lang: null, initCount: 0,                     // Obj-C / Swift + constructores __mod_init_func
      signed: false, sig: null,                     // detalle de firma de código
      objc: false, swift: false,
      packer: { rwx: [], textWritable: false, encrypted: false, entryAnomaly: false },
      warnings,
    };

    let off = is64 ? 32 : 28;
    let symtab = null, mainEntryOff = null, threadEntryVaddr = null, sigOff = 0, sigSize = 0;
    for (let i = 0; i < ncmds && i < 100000; i++) {
      if (base + off + 8 > bytes.length) { warnings.push('load commands truncados'); break; }
      const cmd = u32(off) >>> 0;
      const cmdsize = u32(off + 4);
      if (cmdsize < 8 || base + off + cmdsize > bytes.length) { warnings.push('cmdsize inválido en LC #' + i); break; }
      const c = base + off;

      if (cmd === LC.SEGMENT_64 || cmd === LC.SEGMENT) {
        const wide = cmd === LC.SEGMENT_64;
        const name = cstr(c + 8, 16);
        const r = (rel) => wide ? Number(dv.getBigUint64(c + rel, le)) : dv.getUint32(c + rel, le);
        let p = 24;
        const vmaddr = r(p); p += wide ? 8 : 4;
        const vmsize = r(p); p += wide ? 8 : 4;
        const fileoff = r(p); p += wide ? 8 : 4;
        const filesize = r(p); p += wide ? 8 : 4;
        const maxprot = dv.getInt32(c + p, le); p += 4;
        const initprot = dv.getInt32(c + p, le); p += 4;
        const nsects = dv.getUint32(c + p, le); p += 4;
        p += 4; // flags
        const seg = { name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, sections: [] };
        if ((initprot & 2) && (initprot & 4)) m.packer.rwx.push(name || '(sin nombre)');
        if (name === '__TEXT' && (initprot & 2)) m.packer.textWritable = true;
        if (name === '__RESTRICT') m.restrictSeg = true;
        const secSize = wide ? 80 : 68;
        let sp = c + (wide ? 72 : 56);
        for (let s = 0; s < nsects && s < 4096; s++) {
          if (sp + secSize > bytes.length) break;
          const sectname = cstr(sp, 16);
          const addr = wide ? Number(dv.getBigUint64(sp + 32, le)) : dv.getUint32(sp + 32, le);
          const size = wide ? Number(dv.getBigUint64(sp + 40, le)) : dv.getUint32(sp + 40, le);
          const soff = wide ? dv.getUint32(sp + 48, le) : dv.getUint32(sp + 44, le);
          const sflags = wide ? dv.getUint32(sp + 64, le) : dv.getUint32(sp + 60, le);
          seg.sections.push({ name: sectname, seg: name, addr, size, offset: soff, flags: sflags });
          // S_MOD_INIT_FUNC_POINTERS = 0x9 (constructores) o nombre __mod_init_func
          if ((sflags & 0xff) === 0x9 || sectname === '__mod_init_func') {
            m.initCount += Math.floor(size / (is64 ? 8 : 4));
          }
          if (sectname.indexOf('__objc_') === 0 || sectname === '__objc_classlist') m.objc = true;
          if (sectname.indexOf('__swift5') === 0 || sectname.indexOf('__swift') === 0) m.swift = true;
          sp += secSize;
        }
        m.segments.push(seg);
      } else if (DYLIB_CMDS.indexOf(cmd) !== -1) {
        const strOff = u32(off + 8);
        const cur = u32(off + 16), compat = u32(off + 20);
        m.dylibs.push({
          name: cstr(c + strOff, cmdsize), weak: cmd === LC.LOAD_WEAK_DYLIB,
          reexport: cmd === LC.REEXPORT_DYLIB, upward: cmd === LC.LOAD_UPWARD_DYLIB,
          lazy: cmd === LC.LAZY_LOAD_DYLIB, current: fmtVer(cur), compat: fmtVer(compat),
        });
      } else if (cmd === LC.ID_DYLIB) {
        m.installName = cstr(c + u32(off + 8), cmdsize);
      } else if (cmd === LC.LOAD_DYLINKER || cmd === LC.ID_DYLINKER) {
        m.interp = cstr(c + u32(off + 8), cmdsize);
      } else if (cmd === LC.RPATH) {
        m.rpaths.push(cstr(c + u32(off + 8), cmdsize));
      } else if (cmd === LC.UUID) {
        let h = ''; for (let k = 0; k < 16; k++) h += bytes[c + 8 + k].toString(16).padStart(2, '0');
        m.uuid = h.replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
      } else if (cmd === LC.MAIN) {
        mainEntryOff = u64(off + 8); m.entryKind = 'LC_MAIN';
      } else if (cmd === LC.UNIXTHREAD || cmd === LC.THREAD) {
        threadEntryVaddr = readThreadPC(dv, c, cmdsize, cpuType, le);
        if (threadEntryVaddr !== null) m.entryKind = 'LC_UNIXTHREAD';
      } else if (cmd === LC.CODE_SIGNATURE) {
        sigOff = u32(off + 8); sigSize = u32(off + 12); m.signed = true;
      } else if (cmd === LC.ENCRYPTION_INFO || cmd === LC.ENCRYPTION_INFO_64) {
        m.cryptId = u32(off + 16); m.encrypted = m.cryptId !== 0;
        if (m.encrypted) m.packer.encrypted = true;
      } else if (cmd === LC.VERSION_MIN_MACOSX || cmd === LC.VERSION_MIN_IPHONEOS ||
        cmd === LC.VERSION_MIN_TVOS || cmd === LC.VERSION_MIN_WATCHOS) {
        m.minOS = fmtVer(u32(off + 8)); m.sdk = fmtVer(u32(off + 12));
        m.platform = m.platform || (cmd === LC.VERSION_MIN_MACOSX ? 'macOS' :
          cmd === LC.VERSION_MIN_IPHONEOS ? 'iOS' : cmd === LC.VERSION_MIN_TVOS ? 'tvOS' : 'watchOS');
      } else if (cmd === LC.BUILD_VERSION) {
        const plat = u32(off + 8); m.platform = PLATFORM[plat] || ('plat ' + plat);
        m.minOS = fmtVer(u32(off + 12)); m.sdk = fmtVer(u32(off + 16));
      } else if (cmd === LC.SOURCE_VERSION) {
        const a = u64(off + 8);
        m.sourceVersion = [Math.floor(a / 2 ** 40) & 0xffffff, Math.floor(a / 2 ** 30) & 0x3ff,
          Math.floor(a / 2 ** 20) & 0x3ff, Math.floor(a / 2 ** 10) & 0x3ff, a & 0x3ff].join('.');
      } else if (cmd === LC.SYMTAB) {
        symtab = { symoff: u32(off + 8), nsyms: u32(off + 12), stroff: u32(off + 16), strsize: u32(off + 20) };
      } else if (cmd === LC.DYLD_INFO || cmd === LC.DYLD_INFO_ONLY) {
        m.dyldInfo = true;
      } else if (cmd === LC.DYLD_CHAINED_FIXUPS) {
        m.chainedFixups = true;
      } else if (cmd === LC.FUNCTION_STARTS) {
        m.funcStarts = 1; // presencia (el conteo exacto requiere descomprimir ULEB)
      }
      off += cmdsize;
    }

    if (symtab && symtab.nsyms && symtab.nsyms < 2000000) parseSymtab(bytes, base, is64, le, symtab, m);
    if (sigOff && sigSize) m.sig = parseCodeSig(bytes, base + sigOff, sigSize);

    // fingerprint de lenguaje (igual estilo que ELF Go/Rust)
    if (m.swift) m.lang = { name: 'Swift' };
    else if (m.objc) m.lang = { name: 'Objective-C' };
    else if (m.dylibs.some(d => /libswiftCore/.test(d.name))) { m.swift = true; m.lang = { name: 'Swift' }; }

    // resolver entry: vaddr + file offset (offset relativo a la slice → absoluto = base + ...)
    const text = m.segments.find(s => s.name === '__TEXT');
    if (mainEntryOff !== null) {
      m.entryOffset = base + mainEntryOff;
      m.entry = mainEntryOff + (text ? (text.vmaddr - text.fileoff) : 0);
    } else if (threadEntryVaddr !== null) {
      m.entry = threadEntryVaddr;
      const fo = vaddrToFileOff(m, threadEntryVaddr);
      m.entryOffset = fo >= 0 ? base + fo : -1;
    }
    // EP fuera de una sección ejecutable (__text) → posible hijack/packing
    if (m.entry !== null && text) {
      const exec = (text.sections || []).find(s => s.name === '__text');
      if (exec && (m.entry < exec.addr || m.entry >= exec.addr + exec.size)) m.packer.entryAnomaly = true;
    }
    return m;
  }

  function vaddrToFileOff(m, va) {
    for (const s of m.segments) {
      if (s.filesize && va >= s.vmaddr && va < s.vmaddr + s.filesize) return s.fileoff + (va - s.vmaddr);
    }
    return -1;
  }

  function readThreadPC(dv, c, cmdsize, cpuType, le) {
    try {
      const st = c + 16; // tras cmd, cmdsize, flavor, count
      if (cpuType === 0x01000007) return Number(dv.getBigUint64(st + 16 * 8, le)); // x86_64 rip
      if (cpuType === 0x0100000C) return Number(dv.getBigUint64(st + 32 * 8, le)); // arm64 pc
      if (cpuType === 7) return dv.getUint32(st + 10 * 4, le);                      // i386 eip
      if (cpuType === 12) return dv.getUint32(st + 15 * 4, le);                     // arm r15/pc
    } catch (e) { /* fuera de rango */ }
    return null;
  }

  function parseSymtab(bytes, base, is64, le, st, m) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const nlistSize = is64 ? 16 : 12;
    const symBase = base + st.symoff, strBase = base + st.stroff;
    const cap = Math.min(st.nsyms, 200000);
    const impSet = new Set(), expSet = new Set();
    for (let i = 0; i < cap; i++) {
      const o = symBase + i * nlistSize;
      if (o + nlistSize > bytes.length) break;
      const strx = dv.getUint32(o, le);
      const ntype = bytes[o + 4];
      if (ntype & 0xe0) continue;                  // N_STAB (debug)
      const ext = ntype & 0x01, type = ntype & 0x0e;
      if (!strx) continue;
      const so = strBase + strx;
      if (so >= bytes.length) continue;
      let name = ''; for (let k = 0; k < 512; k++) { const ch = bytes[so + k]; if (ch === undefined || ch === 0) break; name += String.fromCharCode(ch); }
      if (!name) continue;
      if (type === 0x00 && ext) impSet.add(name);          // N_UNDF + ext = import
      else if (type === 0x0e && ext) expSet.add(name);     // N_SECT + ext = export
    }
    m.imports = [...impSet].slice(0, 4000);
    m.exports = [...expSet].slice(0, 4000);
  }

  // Firma de código: SuperBlob embebido (BIG-ENDIAN siempre). Devuelve detalle o null.
  function parseCodeSig(bytes, off, size) {
    if (!off || off + 12 > bytes.length) return null;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const be32 = (o) => dv.getUint32(o, false);
    const cstr = (o, max) => { let s = ''; for (let i = 0; i < (max || 4096); i++) { const c = bytes[o + i]; if (c === undefined || c === 0) break; s += String.fromCharCode(c); } return s; };
    const sig = {
      cdVersion: null, flags: [], adhoc: false, runtime: false, libraryValidation: false,
      teamId: null, identifier: null, hashType: null, hasCMS: false, hasRequirements: false,
      cdBlob: null, entitlements: null, dangerousEnts: [],
    };
    try {
      if (be32(off) !== CSMAGIC_EMBEDDED_SIGNATURE) return sig;
      const count = be32(off + 8);
      for (let i = 0; i < count && i < 128; i++) {
        const idx = off + 12 + i * 8;
        if (idx + 8 > bytes.length) break;
        const blobOff = off + be32(idx + 4);
        if (blobOff + 8 > bytes.length) continue;
        const bmagic = be32(blobOff);
        const blen = be32(blobOff + 4);
        if (bmagic === CSMAGIC_CODEDIRECTORY && !sig.cdBlob) {
          sig.cdBlob = { offset: blobOff, size: blen };  // para CDHash (sha del blob)
          const version = be32(blobOff + 8);
          const flags = be32(blobOff + 12);
          const identOff = be32(blobOff + 20);
          const hashType = bytes[blobOff + 37];
          sig.cdVersion = '0x' + version.toString(16);
          sig.hashType = CS_HASHTYPE[hashType] || ('tipo ' + hashType);
          sig.flags = CS_FLAGS.filter(f => flags & f[0]).map(f => f[1]);
          sig.adhoc = !!(flags & CS_ADHOC);
          sig.runtime = !!(flags & CS_RUNTIME);
          sig.libraryValidation = !!(flags & CS_REQUIRE_LV);
          if (identOff && blobOff + identOff < bytes.length) sig.identifier = cstr(blobOff + identOff, 256);
          if (version >= 0x20200) {                      // teamOffset existe desde v2.2
            const teamOff = be32(blobOff + 48);
            if (teamOff && blobOff + teamOff < bytes.length) sig.teamId = cstr(blobOff + teamOff, 128);
          }
        } else if (bmagic === CSMAGIC_EMBEDDED_ENTITLEMENTS) {
          const xml = cstr(blobOff + 8, Math.min(blen - 8, 65536));
          sig.entitlements = xml;
          for (const k in DANGER_ENT) if (xml.indexOf(k) !== -1) sig.dangerousEnts.push({ key: k, why: DANGER_ENT[k] });
        } else if (bmagic === CSMAGIC_BLOBWRAPPER) {
          sig.hasCMS = true;                             // firma CMS real (no ad-hoc)
        } else if (bmagic === CSMAGIC_REQUIREMENTS) {
          sig.hasRequirements = true;
        }
      }
    } catch (e) { /* firma malformada */ }
    return sig;
  }

  function parse(bytes) {
    const p = probe(bytes, 0);
    if (!p) return null;
    if (p.kind === 'thin') { const m = parseThin(bytes, 0, p.is64, p.le); m.fat = false; return m; }
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const nfat = dv.getUint32(4, false);
    const slices = [];
    const stride = p.fat64 ? 32 : 20;
    for (let i = 0; i < nfat && i < 64; i++) {
      const a = 8 + i * stride;
      if (a + stride > bytes.length) break;
      const cputype = dv.getUint32(a, false) >>> 0;
      const offset = p.fat64 ? Number(dv.getBigUint64(a + 8, false)) : dv.getUint32(a + 8, false);
      const ssize = p.fat64 ? Number(dv.getBigUint64(a + 16, false)) : dv.getUint32(a + 12, false);
      const sub = probe(bytes, offset);
      let parsed = null;
      if (sub && sub.kind === 'thin') { try { parsed = parseThin(bytes, offset, sub.is64, sub.le); } catch (e) { /* slice corrupta */ } }
      slices.push({ cpuType: cputype, cpuName: CPU[cputype] || ('0x' + cputype.toString(16)), offset, size: ssize, macho: parsed });
    }
    const main = slices.find(s => s.macho) || {};
    const top = main.macho || { segments: [], dylibs: [], imports: [], exports: [], rpaths: [], warnings: [] };
    top.fat = true; top.fat64 = p.fat64; top.slices = slices;
    return top;
  }

  return { parse, probe, CPU, SUSPECT, DANGER_ENT };
})();
