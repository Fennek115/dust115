// APT115 CODEX ARCANUM — Triage utils
// Utilidades puras compartidas por los analyzers del lab de triage.
// Sin estado, sin DOM, sin dependencias → fácil de testear y reusar.

window.Triage = window.Triage || {};
Triage.util = (function () {
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

  // Firmas de archivo (magic bytes). El primer match gana.
  const SIGNATURES = [
    { name: 'PE / DOS executable (MZ)', ext: 'exe/dll', off: 0, sig: [0x4D, 0x5A] },
    { name: 'ELF executable', ext: 'elf/so', off: 0, sig: [0x7F, 0x45, 0x4C, 0x46] },
    { name: 'Mach-O (32-bit)', ext: 'macho', off: 0, sig: [0xFE, 0xED, 0xFA, 0xCE] },
    { name: 'Mach-O (64-bit)', ext: 'macho', off: 0, sig: [0xFE, 0xED, 0xFA, 0xCF] },
    { name: 'Mach-O (fat/universal)', ext: 'macho', off: 0, sig: [0xCA, 0xFE, 0xBA, 0xBE] },
    { name: 'Java class', ext: 'class', off: 0, sig: [0xCA, 0xFE, 0xBA, 0xBE] },
    { name: 'WebAssembly module', ext: 'wasm', off: 0, sig: [0x00, 0x61, 0x73, 0x6D] },
    { name: 'OLE2 / MS Office legacy (doc/xls/msi)', ext: 'ole', off: 0, sig: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] },
    { name: 'ZIP / Office OOXML / JAR / APK', ext: 'zip', off: 0, sig: [0x50, 0x4B, 0x03, 0x04] },
    { name: 'RAR archive', ext: 'rar', off: 0, sig: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07] },
    { name: '7-Zip archive', ext: '7z', off: 0, sig: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] },
    { name: 'gzip', ext: 'gz', off: 0, sig: [0x1F, 0x8B] },
    { name: 'bzip2', ext: 'bz2', off: 0, sig: [0x42, 0x5A, 0x68] },
    { name: 'XZ', ext: 'xz', off: 0, sig: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] },
    { name: 'PDF document', ext: 'pdf', off: 0, sig: [0x25, 0x50, 0x44, 0x46] },
    { name: 'PNG image', ext: 'png', off: 0, sig: [0x89, 0x50, 0x4E, 0x47] },
    { name: 'JPEG image', ext: 'jpg', off: 0, sig: [0xFF, 0xD8, 0xFF] },
    { name: 'GIF image', ext: 'gif', off: 0, sig: [0x47, 0x49, 0x46, 0x38] },
    { name: 'BMP image', ext: 'bmp', off: 0, sig: [0x42, 0x4D] },
    { name: 'Shell script (#!)', ext: 'sh', off: 0, sig: [0x23, 0x21] },
  ];

  function matchSig(bytes, s) {
    if (bytes.length < s.off + s.sig.length) return false;
    for (let i = 0; i < s.sig.length; i++) {
      if (bytes[s.off + i] !== s.sig[i]) return false;
    }
    return true;
  }

  // Devuelve {name, ext} o null. Maneja la colisión Mach-O fat / Java class
  // (mismo CAFEBABE): si el 5º byte es un conteo de arcos chico, es Mach-O fat;
  // de lo contrario lo tratamos como Java class.
  function detectType(bytes) {
    for (const s of SIGNATURES) {
      if (!matchSig(bytes, s)) continue;
      if (s.ext === 'macho' && s.sig[0] === 0xCA) {
        // CAFEBABE: heurística Java vs Mach-O fat
        const maybeCount = (bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7];
        if (maybeCount > 0 && maybeCount < 64) return { name: 'Mach-O (fat/universal)', ext: 'macho' };
        return { name: 'Java class', ext: 'class' };
      }
      return { name: s.name, ext: s.ext };
    }
    return null;
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
