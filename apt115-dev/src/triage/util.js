// APT115 CODEX ARCANUM — Triage utils
// Utilidades puras compartidas por los analyzers del lab de triage.
// Sin estado, sin DOM, sin dependencias → fácil de testear y reusar.

export const util = (function () {
  'use strict';

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function formatBytes(n) {
    if (n < 1024) return n + ' B';
    const u = ['KB', 'MB', 'GB'];
    let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return n.toFixed(n < 10 ? 2 : 1) + ' ' + u[i];
  }

  function toHex(n, pad) {
    let h = (n >>> 0).toString(16).toUpperCase();
    if (pad) while (h.length < pad) h = '0' + h;
    return h;
  }

  // Entropía de Shannon (0..8 bits/byte) sobre un rango [start,end).
  // >7.2 sugiere datos comprimidos/cifrados (packing).
  function entropy(bytes, start, end) {
    start = start || 0;
    end = (end == null) ? bytes.length : end;
    if (end <= start) return 0;
    const freq = new Uint32Array(256);
    for (let i = start; i < end; i++) freq[bytes[i]]++;
    const len = end - start;
    let h = 0;
    for (let i = 0; i < 256; i++) {
      if (!freq[i]) continue;
      const p = freq[i] / len;
      h -= p * Math.log2(p);
    }
    return h;
  }

  // bytes de un string ASCII (firmas legibles).
  function S(str) { const a = []; for (let i = 0; i < str.length; i++) a.push(str.charCodeAt(i) & 0xff); return a; }

  // Firmas de archivo (magic bytes). Primer match gana → orden de más
  // específico a más genérico. `off` = offset de la firma; `refine(bytes)`
  // desambigua subtipos (ZIP→docx/apk, RIFF→wav/webp, ftyp→mp4/heic…).
  const SIGNATURES = [
    // ── Ejecutables / código ──
    { name: 'PE / DOS executable (MZ)', ext: 'exe/dll', cat: 'exec', off: 0, sig: [0x4D, 0x5A] },
    { name: 'ELF executable', ext: 'elf/so', cat: 'exec', off: 0, sig: [0x7F, 0x45, 0x4C, 0x46] },
    { name: 'Mach-O 32-bit (BE)', ext: 'macho', cat: 'exec', off: 0, sig: [0xFE, 0xED, 0xFA, 0xCE] },
    { name: 'Mach-O 64-bit (BE)', ext: 'macho', cat: 'exec', off: 0, sig: [0xFE, 0xED, 0xFA, 0xCF] },
    { name: 'Mach-O 32-bit (LE)', ext: 'macho', cat: 'exec', off: 0, sig: [0xCE, 0xFA, 0xED, 0xFE] },
    { name: 'Mach-O 64-bit (LE)', ext: 'macho', cat: 'exec', off: 0, sig: [0xCF, 0xFA, 0xED, 0xFE] },
    { name: 'Mach-O fat / Java class', ext: 'macho/class', cat: 'exec', off: 0, sig: [0xCA, 0xFE, 0xBA, 0xBE], refine: refineCafebabe },
    { name: 'Dalvik DEX', ext: 'dex', cat: 'exec', off: 0, sig: [0x64, 0x65, 0x78, 0x0A] },
    { name: 'WebAssembly module', ext: 'wasm', cat: 'exec', off: 0, sig: [0x00, 0x61, 0x73, 0x6D] },
    { name: 'Windows shortcut (LNK)', ext: 'lnk', cat: 'exec', off: 0, sig: [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00] },
    // ── Contenedores / comprimidos ──
    { name: 'OLE2 / MS Office legacy (doc/xls/msi)', ext: 'ole', cat: 'doc', off: 0, sig: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] },
    { name: 'ZIP / OOXML / JAR / APK', ext: 'zip', cat: 'archive', off: 0, sig: [0x50, 0x4B, 0x03, 0x04], refine: refineZip },
    { name: 'ZIP (vacío)', ext: 'zip', cat: 'archive', off: 0, sig: [0x50, 0x4B, 0x05, 0x06] },
    { name: 'ZIP (spanned)', ext: 'zip', cat: 'archive', off: 0, sig: [0x50, 0x4B, 0x07, 0x08] },
    { name: 'RAR archive', ext: 'rar', cat: 'archive', off: 0, sig: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07] },
    { name: '7-Zip archive', ext: '7z', cat: 'archive', off: 0, sig: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] },
    { name: 'gzip', ext: 'gz', cat: 'archive', off: 0, sig: [0x1F, 0x8B] },
    { name: 'bzip2', ext: 'bz2', cat: 'archive', off: 0, sig: [0x42, 0x5A, 0x68] },
    { name: 'XZ', ext: 'xz', cat: 'archive', off: 0, sig: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] },
    { name: 'Zstandard', ext: 'zst', cat: 'archive', off: 0, sig: [0x28, 0xB5, 0x2F, 0xFD] },
    { name: 'LZ4', ext: 'lz4', cat: 'archive', off: 0, sig: [0x04, 0x22, 0x4D, 0x18] },
    { name: 'Microsoft Cabinet (CAB)', ext: 'cab', cat: 'archive', off: 0, sig: S('MSCF') },
    { name: 'Unix ar / Debian .deb', ext: 'ar/deb', cat: 'archive', off: 0, sig: S('!<arch>\n') },
    { name: 'TAR archive', ext: 'tar', cat: 'archive', off: 257, sig: S('ustar') },
    { name: 'ISO 9660 (CD/DVD)', ext: 'iso', cat: 'archive', off: 0x8001, sig: S('CD001') },
    // ── Documentos ──
    { name: 'PDF document', ext: 'pdf', cat: 'doc', off: 0, sig: [0x25, 0x50, 0x44, 0x46] },
    { name: 'RTF document', ext: 'rtf', cat: 'doc', off: 0, sig: S('{\\rtf') },
    // ── Imágenes ──
    { name: 'PNG image', ext: 'png', cat: 'image', off: 0, sig: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] },
    { name: 'JPEG image', ext: 'jpg', cat: 'image', off: 0, sig: [0xFF, 0xD8, 0xFF] },
    { name: 'GIF image', ext: 'gif', cat: 'image', off: 0, sig: [0x47, 0x49, 0x46, 0x38] },
    { name: 'BMP image', ext: 'bmp', cat: 'image', off: 0, sig: [0x42, 0x4D] },
    { name: 'TIFF image (LE)', ext: 'tiff', cat: 'image', off: 0, sig: [0x49, 0x49, 0x2A, 0x00] },
    { name: 'TIFF image (BE)', ext: 'tiff', cat: 'image', off: 0, sig: [0x4D, 0x4D, 0x00, 0x2A] },
    { name: 'Windows icon (ICO)', ext: 'ico', cat: 'image', off: 0, sig: [0x00, 0x00, 0x01, 0x00] },
    { name: 'Photoshop (PSD)', ext: 'psd', cat: 'image', off: 0, sig: S('8BPS') },
    // ── Media (RIFF / ISO-BMFF / otros) ──
    { name: 'RIFF container', ext: 'riff', cat: 'media', off: 0, sig: S('RIFF'), refine: refineRiff },
    { name: 'ISO-BMFF (MP4/MOV/HEIC)', ext: 'mp4', cat: 'media', off: 4, sig: S('ftyp'), refine: refineFtyp },
    { name: 'Ogg', ext: 'ogg', cat: 'media', off: 0, sig: S('OggS') },
    { name: 'FLAC audio', ext: 'flac', cat: 'media', off: 0, sig: S('fLaC') },
    { name: 'MP3 (ID3)', ext: 'mp3', cat: 'media', off: 0, sig: S('ID3') },
    { name: 'Matroska / WebM', ext: 'mkv', cat: 'media', off: 0, sig: [0x1A, 0x45, 0xDF, 0xA3] },
    // ── Cripto / forense / datos ──
    { name: 'PEM (cert / clave)', ext: 'pem', cat: 'crypto', off: 0, sig: S('-----BEGIN ') },
    { name: 'SQLite 3 database', ext: 'sqlite', cat: 'data', off: 0, sig: S('SQLite format 3\0') },
    { name: 'PCAP capture (LE)', ext: 'pcap', cat: 'forensic', off: 0, sig: [0xD4, 0xC3, 0xB2, 0xA1] },
    { name: 'PCAP capture (BE)', ext: 'pcap', cat: 'forensic', off: 0, sig: [0xA1, 0xB2, 0xC3, 0xD4] },
    { name: 'PCAPNG capture', ext: 'pcapng', cat: 'forensic', off: 0, sig: [0x0A, 0x0D, 0x0D, 0x0A] },
    { name: 'Windows Event Log (EVTX)', ext: 'evtx', cat: 'forensic', off: 0, sig: S('ElfFile\0') },
    { name: 'Windows Registry hive', ext: 'hive', cat: 'forensic', off: 0, sig: S('regf') },
    // ── Scripts ──
    { name: 'Shell script (#!)', ext: 'sh', cat: 'script', off: 0, sig: [0x23, 0x21] },
  ];

  function matchSig(bytes, s) {
    if (bytes.length < s.off + s.sig.length) return false;
    for (let i = 0; i < s.sig.length; i++) {
      if (bytes[s.off + i] !== s.sig[i]) return false;
    }
    return true;
  }

  // CAFEBABE: Mach-O fat vs Java class (mismo magic). Los rangos no se solapan:
  // en Java el DWORD@4 es minor(16)+major(16) con major 45..~70; en Mach-O fat
  // es nfat_arch (cantidad de arquitecturas, típicamente 1..~20).
  function refineCafebabe(bytes) {
    const dword = ((bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7]) >>> 0;
    const major = (bytes[6] << 8) | bytes[7]; // candidato a major version Java
    if (major >= 43 && major <= 75 && (bytes[4] === 0x00 || bytes[4] === 0xFF)) {
      return { name: 'Java class', ext: 'class', cat: 'exec' };
    }
    if (dword >= 1 && dword <= 30) return { name: 'Mach-O (fat/universal)', ext: 'macho', cat: 'exec' };
    return { name: 'Mach-O fat / Java class', ext: 'macho/class', cat: 'exec' };
  }

  // RIFF: el subtipo está en el offset 8 (WAVE/AVI /WEBP…).
  function refineRiff(bytes) {
    if (bytes.length < 12) return null;
    const t = asciiSlice(bytes, 8, 12);
    const map = { 'WAVE': ['WAV audio', 'wav'], 'AVI ': ['AVI video', 'avi'], 'WEBP': ['WebP image', 'webp'] };
    const m = map[t];
    if (m) return { name: m[0], ext: m[1], cat: m[1] === 'webp' ? 'image' : 'media' };
    return { name: 'RIFF container (' + t.trim() + ')', ext: 'riff', cat: 'media' };
  }

  // ISO-BMFF: el brand está en el offset 8 (isom/mp4/qt/heic/avif/m4a/3gp…).
  function refineFtyp(bytes) {
    if (bytes.length < 12) return null;
    const brand = asciiSlice(bytes, 8, 12).toLowerCase();
    if (/^hei|^hev/.test(brand)) return { name: 'HEIF / HEIC image', ext: 'heic', cat: 'image' };
    if (brand.startsWith('avif')) return { name: 'AVIF image', ext: 'avif', cat: 'image' };
    if (brand.startsWith('qt')) return { name: 'QuickTime (MOV)', ext: 'mov', cat: 'media' };
    if (brand.startsWith('m4a')) return { name: 'M4A audio', ext: 'm4a', cat: 'media' };
    if (brand.startsWith('3g')) return { name: '3GP video', ext: '3gp', cat: 'media' };
    if (/^isom|^mp4|^avc|^dash|^iso2/.test(brand)) return { name: 'MP4 video', ext: 'mp4', cat: 'media' };
    return { name: 'ISO-BMFF (' + brand.trim() + ')', ext: 'mp4', cat: 'media' };
  }

  // ZIP: los nombres de archivo del local-header van en claro → sniff OOXML/APK/JAR.
  function refineZip(bytes) {
    const n = Math.min(bytes.length, 8192);
    const head = asciiSlice(bytes, 0, n);
    if (head.indexOf('AndroidManifest.xml') >= 0 || head.indexOf('classes.dex') >= 0) return { name: 'Android APK', ext: 'apk', cat: 'archive' };
    if (head.indexOf('[Content_Types].xml') >= 0) {
      if (head.indexOf('word/') >= 0) return { name: 'Word OOXML (docx)', ext: 'docx', cat: 'doc' };
      if (head.indexOf('xl/') >= 0) return { name: 'Excel OOXML (xlsx)', ext: 'xlsx', cat: 'doc' };
      if (head.indexOf('ppt/') >= 0) return { name: 'PowerPoint OOXML (pptx)', ext: 'pptx', cat: 'doc' };
      return { name: 'Office OOXML', ext: 'ooxml', cat: 'doc' };
    }
    if (head.indexOf('META-INF/MANIFEST.MF') >= 0 || head.indexOf('.class') >= 0) return { name: 'Java JAR', ext: 'jar', cat: 'archive' };
    if (head.indexOf('mimetypeapplication/epub') >= 0) return { name: 'EPUB book', ext: 'epub', cat: 'doc' };
    if (head.indexOf('mimetypeapplication/vnd.oasis') >= 0) return { name: 'OpenDocument (ODF)', ext: 'odf', cat: 'doc' };
    return null; // → nombre por defecto del SIGNATURE
  }

  // Devuelve {name, ext, cat} o null. Orden: firmas curadas (con refiners) →
  // firmas extra de Tika (window.MAGIC_EXTRA, si está cargada) → heurística de texto.
  function detectType(bytes) {
    for (const s of SIGNATURES) {
      if (!matchSig(bytes, s)) continue;
      if (s.refine) { const r = s.refine(bytes); if (r) return r; }
      return { name: s.name, ext: s.ext, cat: s.cat };
    }
    const extra = (typeof window !== 'undefined' && window.MAGIC_EXTRA) || [];
    for (let i = 0; i < extra.length; i++) {
      const e = extra[i]; // [name, ext, cat, off, [bytes]]
      if (matchSig(bytes, { off: e[3], sig: e[4] })) return { name: e[0], ext: e[1], cat: e[2] };
    }
    return detectText(bytes);
  }

  // Fallback: ningún magic binario matcheó → ¿es texto? (BOM o ratio imprimible).
  function detectText(bytes) {
    if (!bytes.length) return null;
    if (bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) return { name: 'Texto UTF-8 (BOM)', ext: 'txt', cat: 'text' };
    if (bytes[0] === 0xFF && bytes[1] === 0xFE) return { name: 'Texto UTF-16 LE (BOM)', ext: 'txt', cat: 'text' };
    if (bytes[0] === 0xFE && bytes[1] === 0xFF) return { name: 'Texto UTF-16 BE (BOM)', ext: 'txt', cat: 'text' };
    const n = Math.min(bytes.length, 1024);
    let printable = 0;
    for (let i = 0; i < n; i++) {
      const b = bytes[i];
      if (b === 0) return null; // NUL → binario
      if ((b >= 0x20 && b < 0x7F) || b === 0x09 || b === 0x0A || b === 0x0D || b >= 0x80) printable++;
    }
    if (printable / n < 0.9) return null;
    const head = asciiSlice(bytes, 0, Math.min(bytes.length, 64)).trim().toLowerCase();
    if (head.startsWith('<?xml')) return { name: 'XML', ext: 'xml', cat: 'text' };
    if (head.startsWith('<!doctype html') || head.startsWith('<html')) return { name: 'HTML', ext: 'html', cat: 'text' };
    if (head.startsWith('%!ps')) return { name: 'PostScript', ext: 'ps', cat: 'doc' };
    if (head[0] === '{' || head[0] === '[') return { name: 'JSON / texto estructurado', ext: 'json', cat: 'text' };
    return { name: 'Texto / script (ASCII/UTF-8)', ext: 'txt', cat: 'text' };
  }

  // Extrae strings imprimibles ASCII y UTF-16LE de longitud >= minLen.
  // Cap de seguridad para no colgar el navegador con archivos enormes.
  function extractStrings(bytes, minLen, cap) {
    minLen = minLen || 5;
    cap = cap || 5000;
    const out = [];
    const isPrint = (b) => b >= 0x20 && b <= 0x7E;

    // ASCII
    let start = -1;
    for (let i = 0; i < bytes.length && out.length < cap; i++) {
      if (isPrint(bytes[i])) {
        if (start < 0) start = i;
      } else {
        if (start >= 0 && i - start >= minLen) {
          out.push({ off: start, type: 'ascii', s: asciiSlice(bytes, start, i) });
        }
        start = -1;
      }
    }
    if (start >= 0 && bytes.length - start >= minLen && out.length < cap) {
      out.push({ off: start, type: 'ascii', s: asciiSlice(bytes, start, bytes.length) });
    }

    // UTF-16LE: byte imprimible seguido de 0x00, repetido
    let u16start = -1, u16chars = '';
    for (let i = 0; i + 1 < bytes.length && out.length < cap; i += 2) {
      if (isPrint(bytes[i]) && bytes[i + 1] === 0x00) {
        if (u16start < 0) { u16start = i; u16chars = ''; }
        u16chars += String.fromCharCode(bytes[i]);
      } else {
        if (u16start >= 0 && u16chars.length >= minLen) {
          out.push({ off: u16start, type: 'utf16', s: u16chars });
        }
        u16start = -1; u16chars = '';
      }
    }
    if (u16start >= 0 && u16chars.length >= minLen && out.length < cap) {
      out.push({ off: u16start, type: 'utf16', s: u16chars });
    }

    return { strings: out, capped: out.length >= cap };
  }

  function asciiSlice(bytes, a, b) {
    let s = '';
    for (let i = a; i < b; i++) s += String.fromCharCode(bytes[i]);
    return s;
  }

  // Patrones "interesantes" para destacar en el output.
  const INTEREST = [
    { tag: 'url', re: /\bhttps?:\/\/[^\s"'<>]{4,}/i },
    { tag: 'ip', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/ },
    { tag: 'unc', re: /\\\\[^\s"'<>]{3,}/ },
    { tag: 'reg', re: /\b(HKLM|HKCU|HKEY_[A-Z_]+)\\/ },
    { tag: 'path', re: /[A-Za-z]:\\[^\s"'<>]{2,}/ },
    { tag: 'b64', re: /\b[A-Za-z0-9+/]{24,}={0,2}\b/ },
    { tag: 'email', re: /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/ },
  ];

  function classify(str) {
    for (const p of INTEREST) if (p.re.test(str)) return p.tag;
    return null;
  }

  return {
    esc, formatBytes, toHex, entropy,
    detectType, extractStrings, classify,
    SIGNATURES, INTEREST,
  };
})();

if (typeof window !== 'undefined') { window.Triage = window.Triage || {}; window.Triage.util = util; }
