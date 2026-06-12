// APT115 CODEX ARCANUM — Extractor de macros VBA ([MS-OVBA])
// quod est superius est sicut quod inferius
//
// Sobre un CFB (cfb.js) ubica el storage VBA, descomprime el stream `dir` para
// enumerar los módulos y descomprime el código fuente de cada uno. Implementa el
// algoritmo de descompresión de [MS-OVBA] §2.4.1 (CompressedContainer: chunks de
// 4096, tokens literal/copy estilo LZ77 con bitcount dependiente de la posición).
//
// Trampa conocida: en el stream `dir`, el record PROJECTVERSION (Id 0x0009) NO
// respeta el patrón Id+Size — trae un Reserved(u32) fijo + Major(u32) + Minor(u16).
// Tratarlo como Size=4 desincroniza el resto del parseo. Se castea aparte.
//
// Verificado byte-a-byte contra oletools/olevba sobre un vbaProject.bin real.

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

export const vba = (function () {
  'use strict';

  // ── Descompresión [MS-OVBA] §2.4.1 ──
  // buf: Uint8Array; start: índice del SignatureByte 0x01. Devuelve Uint8Array.
  function decompress(buf, start) {
    start = start || 0;
    if (!buf || buf[start] !== 0x01) return null;
    const out = [];
    let p = start + 1;
    while (p + 1 < buf.length) {
      const header = buf[p] | (buf[p + 1] << 8);
      const size = (header & 0x0fff) + 3;     // tamaño total del chunk (incluye header)
      const compressed = (header & 0x8000) !== 0;
      const dataStart = p + 2;
      const dataEnd = Math.min(p + size, buf.length);
      const chunkStart = out.length;          // inicio del chunk en la salida

      if (!compressed) {
        for (let i = dataStart; i < dataEnd; i++) out.push(buf[i]);
      } else {
        let i = dataStart;
        while (i < dataEnd) {
          const flags = buf[i++];
          for (let bit = 0; bit < 8 && i < dataEnd; bit++) {
            if (!(flags & (1 << bit))) {
              out.push(buf[i++]);             // literal
            } else {
              if (i + 1 >= buf.length) { i = dataEnd; break; }
              const token = buf[i] | (buf[i + 1] << 8); i += 2;
              const diff = out.length - chunkStart;
              let bc = 0; while ((1 << bc) < diff) bc++; if (bc < 4) bc = 4;
              const lenMask = 0xffff >> bc;
              const offMask = (~lenMask) & 0xffff;
              const length = (token & lenMask) + 3;
              const offset = ((token & offMask) >> (16 - bc)) + 1;
              let src = out.length - offset;
              if (src < 0) { i = dataEnd; break; }
              for (let k = 0; k < length; k++) out.push(out[src++]); // copia (puede solaparse)
            }
          }
        }
      }
      p = p + size;
      if (size <= 2) break; // chunk degenerado → corte de seguridad
    }
    return Uint8Array.from(out);
  }

  // ── Parseo del stream `dir` (ya descomprimido) → lista de módulos ──
  // Walk plano Id(u16)+Size(u32)+payload, con el caso especial de PROJECTVERSION.
  function parseDir(dir) {
    const dv = new DataView(dir.buffer, dir.byteOffset, dir.byteLength);
    const dec = (off, len) => { // MBCS/ASCII → string (latin1 best-effort)
      let s = ''; for (let i = 0; i < len; i++) s += String.fromCharCode(dir[off + i]); return s;
    };
    const modules = [];
    let cur = null;
    let p = 0, guard = 0;
    while (p + 6 <= dir.length && guard++ < 100000) {
      const id = dv.getUint16(p, true);
      if (id === 0x0009) { p += 2 + 4 + 4 + 2; continue; } // PROJECTVERSION: Reserved+Major+Minor
      const size = dv.getUint32(p + 2, true);
      const data = p + 6;
      if (data + size > dir.length + 0) { /* size inválido */ if (size > dir.length) break; }
      switch (id) {
        case 0x0019: // MODULENAME → inicia un módulo
          cur = { name: dec(data, size), streamName: null, textOffset: null, type: null };
          modules.push(cur);
          break;
        case 0x001a: // MODULESTREAMNAME
          if (cur) cur.streamName = dec(data, size);
          break;
        case 0x0031: // MODULEOFFSET (u32)
          if (cur && size >= 4) cur.textOffset = dv.getUint32(data, true);
          break;
        case 0x0021: cur && (cur.type = 'procedural'); break; // MODULETYPE procedural
        case 0x0022: cur && (cur.type = 'document/class'); break;
        default: break;
      }
      p = data + size;
    }
    return modules.filter((m) => m.streamName && m.textOffset != null);
  }

  // Localiza el stream `dir` dentro de un storage VBA y devuelve {dirEntry, prefix}.
  function findVbaDir(cfb) {
    const dir = cfb.entries.find((e) => e.isStream && e.name === 'dir' &&
      /(^|\/)VBA$/i.test(e.path.slice(0, e.path.length - e.name.length - 1)));
    if (dir) return { dirEntry: dir, prefix: dir.path.slice(0, dir.path.length - 3) }; // sin "dir"
    // Fallback: cualquier stream llamado 'dir' que descomprima a algo con módulos.
    const any = cfb.entries.find((e) => e.isStream && e.name === 'dir');
    return any ? { dirEntry: any, prefix: any.path.slice(0, any.path.length - 3) } : null;
  }

  // ── Punto de entrada: CFB → { found, modules:[{name,streamName,type,code}] } ──
  function extract(cfb) {
    if (!cfb) return { found: false, modules: [] };
    const loc = findVbaDir(cfb);
    if (!loc) return { found: false, modules: [] };
    const dirRaw = decompress(loc.dirEntry.read(), 0);
    if (!dirRaw) return { found: false, modules: [] };
    const mods = parseDir(dirRaw);
    const out = [];
    for (const m of mods) {
      const entry = cfb.byPath(loc.prefix + m.streamName) ||
        cfb.entries.find((e) => e.isStream && e.name === m.streamName);
      if (!entry) continue;
      const stream = entry.read();
      const code = decompress(stream, m.textOffset);
      out.push({
        name: m.name, streamName: m.streamName, type: m.type,
        code: code ? utf8(code) : '',
      });
    }
    return { found: out.length > 0, modules: out, storage: loc.prefix };
  }

  // Decodifica bytes de código como texto (los módulos VBA suelen ser MBCS/ASCII;
  // usamos latin1 para no perder bytes — el código es ASCII en la práctica).
  function utf8(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
  }

  // ── OOXML (.docm/.xlsm/.pptm): ZIP que contiene */vbaProject.bin ──
  // Inflado con DecompressionStream nativo ('deflate-raw') — sin vendorizar nada.
  async function inflateRaw(bytes) {
    if (typeof DecompressionStream === 'undefined') throw new Error('DecompressionStream no disponible');
    const ds = new DecompressionStream('deflate-raw');
    const stream = new Response(bytes).body.pipeThrough(ds);
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  function u16(dv, o) { return dv.getUint16(o, true); }
  function u32(dv, o) { return dv.getUint32(o, true); }

  // Devuelve los bytes (inflados) de */vbaProject.bin dentro del OOXML, o null.
  async function ooxmlVbaProject(bytes) {
    if (bytes[0] !== 0x50 || bytes[1] !== 0x4b) return null; // 'PK'
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    // Localizar el End Of Central Directory (firma 0x06054b50) desde el final.
    let eocd = -1;
    const minScan = Math.max(0, bytes.length - 65557);
    for (let i = bytes.length - 22; i >= minScan; i--) {
      if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) return null;
    let cd = u32(dv, eocd + 16);            // offset del central directory
    const count = u16(dv, eocd + 10);
    for (let n = 0; n < count && cd + 46 <= bytes.length; n++) {
      if (dv.getUint32(cd, true) !== 0x02014b50) break;
      const method = u16(dv, cd + 10);
      const compSize = u32(dv, cd + 20);
      const fnLen = u16(dv, cd + 28);
      const extraLen = u16(dv, cd + 30);
      const cmtLen = u16(dv, cd + 32);
      const lho = u32(dv, cd + 42);
      let name = '';
      for (let i = 0; i < fnLen; i++) name += String.fromCharCode(bytes[cd + 46 + i]);
      if (/vbaProject\.bin$/i.test(name)) {
        // Saltar al local file header para ubicar el inicio real de los datos.
        if (dv.getUint32(lho, true) !== 0x04034b50) return null;
        const lFn = u16(dv, lho + 26), lEx = u16(dv, lho + 28);
        const dataStart = lho + 30 + lFn + lEx;
        const comp = bytes.subarray(dataStart, dataStart + compSize);
        return method === 0 ? comp.slice() : await inflateRaw(comp); // 0=stored, 8=deflate
      }
      cd += 46 + fnLen + extraLen + cmtLen;
    }
    return null;
  }

  // Orquestador: detecta CFB directo u OOXML y devuelve el resultado de extract().
  // Necesita window.Triage.cfb (o que se le pase un parser cfb).
  async function analyze(bytes, cfbParse) {
    const parse = cfbParse || (typeof window !== 'undefined' && window.Triage && window.Triage.cfb && window.Triage.cfb.parse);
    if (!parse) throw new Error('cfb.parse no disponible');
    let cfbBytes = bytes;
    if (bytes[0] === 0x50 && bytes[1] === 0x4b) {           // OOXML ZIP
      const vbp = await ooxmlVbaProject(bytes);
      if (!vbp) return { found: false, modules: [], container: 'ooxml-sin-vba' };
      cfbBytes = vbp;
    }
    const cfb = parse(cfbBytes);
    if (!cfb) return { found: false, modules: [], container: 'no-cfb' };
    return extract(cfb);
  }

  const api = { decompress, parseDir, extract, ooxmlVbaProject, analyze };
  if (typeof window !== 'undefined') window.Triage.vba = api;
  return api;
})();
