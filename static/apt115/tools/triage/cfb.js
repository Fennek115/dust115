// APT115 CODEX ARCANUM — Lector CFB / OLE Compound File ([MS-CFB])
// quod est superius est sicut quod inferius
//
// Parser propio del Compound File Binary (AKA OLE2 Structured Storage): el
// contenedor de los Office legacy (.doc/.xls/.ppt), los .msi y el vbaProject.bin
// que vive dentro de los OOXML con macros. Devuelve el árbol de storages/streams
// con lectura perezosa de cada stream. Lo consume el extractor VBA (vba.js).
//
// Soporta v3 (sectores de 512) y v4 (4096) con el mismo código: el tamaño de
// sector sale del header (sectorShift) y el offset de un sector es siempre
// (sector + 1) << sectorShift — el header de 512 bytes ocupa la región del
// sector 0. Maneja FAT, DIFAT (cadena), miniFAT + mini stream del Root Entry.
//
// Estilo y robustez al estilo pe.js/elf.js: guardas contra archivos truncados,
// topes contra cadenas infinitas, devuelve null si no es CFB.

if (typeof window !== 'undefined') window.Triage = window.Triage || {};

(function () {
  'use strict';

  const SIG = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
  const ENDOFCHAIN = 0xfffffffe;
  const FREESECT = 0xffffffff;
  const NOSTREAM = 0xffffffff;
  // FATSECT (0xfffffffd) y DIFSECT (0xfffffffc) marcan sectores reservados;
  // como terminadores de cadena se tratan igual que >= ENDOFCHAIN.

  function parse(bytes) {
    if (!bytes || bytes.length < 512) return null;
    for (let i = 0; i < 8; i++) if (bytes[i] !== SIG[i]) return null;

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const u16 = (o) => dv.getUint16(o, true);
    const u32 = (o) => dv.getUint32(o, true);

    const minor = u16(24), major = u16(26);
    if (u16(28) !== 0xfffe) return null; // byte order mark (little-endian)
    const sectorShift = u16(30);
    const miniSectorShift = u16(32);
    if (sectorShift < 7 || sectorShift > 16 || miniSectorShift < 2 || miniSectorShift > sectorShift) return null;
    const secSize = 1 << sectorShift;
    const miniSize = 1 << miniSectorShift;

    const numFatSectors = u32(44);
    const firstDirSector = u32(48);
    const miniCutoff = u32(56) || 4096;
    const firstMiniFat = u32(60);
    const firstDifat = u32(68), numDifatSectors = u32(72);

    const totalSectors = Math.floor((bytes.length - 512) / secSize) + 1;
    const secOffset = (s) => ((s + 1) << sectorShift);

    function sectorBytes(s) {
      const o = secOffset(s);
      if (o < 0 || o + secSize > bytes.length) return null;
      return bytes.subarray(o, o + secSize);
    }

    // ── DIFAT: ubicaciones de los sectores FAT. 109 en el header (offset 76)
    //    + la cadena de sectores DIFAT (último u32 de cada uno apunta al próximo).
    const fatSectorList = [];
    for (let i = 0; i < 109; i++) {
      const v = u32(76 + i * 4);
      if (v === FREESECT || v >= ENDOFCHAIN) continue;
      fatSectorList.push(v);
    }
    let difat = firstDifat, guard = 0;
    const perDifat = secSize / 4;
    while (difat !== ENDOFCHAIN && difat < ENDOFCHAIN && guard++ < totalSectors + 2 && numDifatSectors) {
      const sb = sectorBytes(difat);
      if (!sb) break;
      const sv = new DataView(sb.buffer, sb.byteOffset, sb.byteLength);
      for (let i = 0; i < perDifat - 1; i++) {
        const v = sv.getUint32(i * 4, true);
        if (v !== FREESECT && v < ENDOFCHAIN) fatSectorList.push(v);
      }
      difat = sv.getUint32((perDifat - 1) * 4, true);
    }

    // ── FAT: concatenar los sectores FAT en un array de next-pointers.
    const fat = new Uint32Array(fatSectorList.length * perDifat);
    let fi = 0;
    for (const fs of fatSectorList) {
      const sb = sectorBytes(fs);
      if (!sb) { fi += perDifat; continue; }
      const sv = new DataView(sb.buffer, sb.byteOffset, sb.byteLength);
      for (let i = 0; i < perDifat; i++) fat[fi++] = sv.getUint32(i * 4, true);
    }

    // Sigue una cadena de la FAT y devuelve la lista de sectores (con tope).
    function fatChain(start) {
      const out = [];
      let s = start, n = 0;
      while (s < ENDOFCHAIN && n++ <= totalSectors + 1) {
        out.push(s);
        s = s < fat.length ? fat[s] : ENDOFCHAIN;
      }
      return out;
    }

    function readFat(start, size) {
      const chain = fatChain(start);
      const out = new Uint8Array(chain.length * secSize);
      let p = 0;
      for (const s of chain) { const sb = sectorBytes(s); if (sb) out.set(sb, p); p += secSize; }
      return (size != null && size <= out.length) ? out.subarray(0, size) : out;
    }

    // ── Directorio (cadena FAT desde firstDirSector). Entradas de 128 bytes.
    const dirBytes = readFat(firstDirSector);
    const numEntries = Math.floor(dirBytes.length / 128);
    const ddv = new DataView(dirBytes.buffer, dirBytes.byteOffset, dirBytes.byteLength);
    const raw = [];
    for (let i = 0; i < numEntries; i++) {
      const b = i * 128;
      const type = dirBytes[b + 66]; // 0 vacío, 1 storage, 2 stream, 5 root
      if (type !== 1 && type !== 2 && type !== 5) { raw.push(null); continue; }
      let nameLen = ddv.getUint16(b + 64, true);
      if (nameLen > 64) nameLen = 64;
      let name = '';
      for (let j = 0; j + 1 < nameLen; j += 2) {
        const c = ddv.getUint16(b + j, true);
        if (c === 0) break;
        name += String.fromCharCode(c);
      }
      raw.push({
        id: i, name, type,
        left: ddv.getUint32(b + 68, true),
        right: ddv.getUint32(b + 72, true),
        child: ddv.getUint32(b + 76, true),
        start: ddv.getUint32(b + 116, true),
        size: ddv.getUint32(b + 120, true), // low 32 bits (v3 deja el high en 0)
      });
    }
    const root = raw[0];
    if (!root || root.type !== 5) return null;

    // ── Mini stream (contenedor de los streams chicos) + miniFAT.
    const miniStream = readFat(root.start, root.size);
    const miniFatBytes = firstMiniFat < ENDOFCHAIN ? readFat(firstMiniFat) : new Uint8Array(0);
    const miniFat = new Uint32Array(miniFatBytes.buffer, miniFatBytes.byteOffset, Math.floor(miniFatBytes.length / 4));
    const numMini = Math.floor(miniStream.length / miniSize);

    function readMini(start, size) {
      const out = new Uint8Array(Math.ceil((size || 0) / miniSize) * miniSize || miniSize);
      let s = start, p = 0, n = 0;
      while (s < ENDOFCHAIN && n++ <= numMini + 1) {
        const o = s * miniSize;
        if (o + miniSize <= miniStream.length) out.set(miniStream.subarray(o, o + miniSize), p);
        p += miniSize;
        s = s < miniFat.length ? miniFat[s] : ENDOFCHAIN;
      }
      return (size != null && size <= out.length) ? out.subarray(0, size) : out.subarray(0, p);
    }

    // Lee el contenido de una entrada stream (mini o FAT según el cutoff).
    function readEntry(e) {
      if (!e || e.type !== 2) return new Uint8Array(0);
      if (e.size < miniCutoff) return readMini(e.start, e.size).slice();
      return readFat(e.start, e.size).slice();
    }

    // ── Recorrido del árbol rojo-negro → lista plana con paths relativos al root.
    const entries = [];
    const byPath = {};
    const seen = new Set();
    function walkSiblings(id, prefix) {
      if (id === NOSTREAM || id >= raw.length || seen.has(id)) return;
      seen.add(id);
      const e = raw[id];
      if (!e) return;
      walkSiblings(e.left, prefix);
      const path = prefix ? prefix + '/' + e.name : e.name;
      const rec = { name: e.name, path, type: e.type, size: e.size, isStream: e.type === 2 };
      rec.read = () => readEntry(e);
      entries.push(rec);
      byPath[path] = rec;
      if (e.type === 1 && e.child !== NOSTREAM) walkSiblings(e.child, path); // descender al storage
      walkSiblings(e.right, prefix);
    }
    if (root.child !== NOSTREAM) walkSiblings(root.child, '');

    return {
      major, minor, secSize, miniSize, miniCutoff,
      root: { name: root.name, size: root.size },
      entries,
      paths: () => entries.map((e) => e.path),
      byPath: (p) => byPath[p] || null,
      // Busca un stream cuyo path matchee (case-insensitive en el último segmento).
      find: (re) => entries.find((e) => e.isStream && re.test(e.name)) || null,
    };
  }

  const api = { parse, isCfb: (b) => !!b && b.length >= 8 && SIG.every((v, i) => b[i] === v) };
  if (typeof window !== 'undefined') window.Triage.cfb = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})();
