// APT115 CODEX ARCANUM — Primitivas ZIP compartidas (núcleo PURO, sin DOM).
//
// Lector/escritor ZIP propio + CRC-32, extraído de vault.js (Fase A4) para
// compartirlo con el inspector de archivos (Fase C, src/tools/archive.js) sin
// duplicar el parser. vault.js re-exporta estas funciones para conservar su API.
//
// El escritor usa método STORE (sin compresión): síncrono y 100% verificable en
// Node. El lector entiende STORE (0) y DEFLATE (8); para DEFLATE hay que inflar
// los bytes crudos con inflateRaw/DecompressionStream. Verificable en Node:
// DecompressionStream/CompressionStream existen ahí.

// CRC-32 (IEEE 802.3).
const CRCT = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();

/** CRC-32 de un buffer. @param {Uint8Array} b @returns {number} */
export function crc32(b) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < b.length; i++) c = CRCT[(c ^ b[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

/** @param {Uint8Array[]} arr */
function concatBytes(arr) {
  let total = 0;
  arr.forEach(a => { total += a.length; });
  const out = new Uint8Array(total);
  let p = 0;
  for (const a of arr) { out.set(a, p); p += a.length; }
  return out;
}

/**
 * Escribe un ZIP (método STORE) desde entradas {name, text|data}: cabeceras
 * locales + central directory + EOCD, CRC-32 por entrada, flag UTF-8 en el
 * nombre. Síncrono. @param {{name:string, text?:string, data?:Uint8Array}[]} entries
 * @returns {Uint8Array}
 */
export function buildZip(entries) {
  const files = entries.map(e => ({
    nameBytes: enc.encode(e.name),
    data: e.data ? e.data : enc.encode(e.text || ''),
  }));
  /** @type {Uint8Array[]} */
  const local = [];
  /** @type {Uint8Array[]} */
  const central = [];
  let offset = 0;
  for (const f of files) {
    const crc = crc32(f.data);
    const size = f.data.length;
    const lh = new Uint8Array(30 + f.nameBytes.length);
    const dv = new DataView(lh.buffer);
    dv.setUint32(0, 0x04034b50, true);   // local file header sig
    dv.setUint16(4, 20, true);           // version needed
    dv.setUint16(6, 0x0800, true);       // flag: UTF-8 filename (bit 11)
    dv.setUint16(8, 0, true);            // method: store
    dv.setUint16(10, 0, true);           // mod time
    dv.setUint16(12, 0x21, true);        // mod date (1980-01-01)
    dv.setUint32(14, crc, true);
    dv.setUint32(18, size, true);        // compressed size
    dv.setUint32(22, size, true);        // uncompressed size
    dv.setUint16(26, f.nameBytes.length, true);
    dv.setUint16(28, 0, true);           // extra length
    lh.set(f.nameBytes, 30);
    local.push(lh, f.data);

    const ch = new Uint8Array(46 + f.nameBytes.length);
    const cv = new DataView(ch.buffer);
    cv.setUint32(0, 0x02014b50, true);   // central dir header sig
    cv.setUint16(4, 20, true);           // version made by
    cv.setUint16(6, 20, true);           // version needed
    cv.setUint16(8, 0x0800, true);       // flag UTF-8
    cv.setUint16(10, 0, true);           // method
    cv.setUint16(12, 0, true);           // mod time
    cv.setUint16(14, 0x21, true);        // mod date
    cv.setUint32(16, crc, true);
    cv.setUint32(20, size, true);        // compressed size
    cv.setUint32(24, size, true);        // uncompressed size
    cv.setUint16(28, f.nameBytes.length, true);
    cv.setUint16(30, 0, true);           // extra length
    cv.setUint16(32, 0, true);           // comment length
    cv.setUint16(34, 0, true);           // disk number start
    cv.setUint16(36, 0, true);           // internal attrs
    cv.setUint32(38, 0, true);           // external attrs
    cv.setUint32(42, offset, true);      // local header offset
    ch.set(f.nameBytes, 46);
    central.push(ch);

    offset += lh.length + f.data.length;
  }
  const cdSize = central.reduce((s, c) => s + c.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);     // EOCD sig
  ev.setUint16(8, files.length, true);   // entries on this disk
  ev.setUint16(10, files.length, true);  // total entries
  ev.setUint32(12, cdSize, true);        // central dir size
  ev.setUint32(16, offset, true);        // central dir offset
  return concatBytes(local.concat(central, [eocd]));
}

/**
 * @typedef {object} ZipEntry
 * @property {string} name       Nombre/ruta de la entrada.
 * @property {number} method     0=store, 8=deflate.
 * @property {number} crc        CRC-32 declarado en el central directory.
 * @property {number} compSize   Tamaño comprimido (bytes en disco).
 * @property {number} size       Tamaño descomprimido declarado.
 * @property {Uint8Array} data   Bytes CRUDOS del file data (inflar si method 8).
 */

/**
 * Lee las entradas de un ZIP por su central directory: nombre, método (0=store,
 * 8=deflate), tamaños comprimido/descomprimido y los bytes CRUDOS del file data
 * (para método 8 hay que inflar con inflateRaw). Lanza si no encuentra el EOCD.
 * @param {Uint8Array} bytes @returns {ZipEntry[]}
 */
export function parseZip(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let eocd = -1;
  for (let i = bytes.length - 22; i >= 0; i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('ZIP inválido: no se encontró el End of Central Directory.');
  const count = dv.getUint16(eocd + 10, true);
  let p = dv.getUint32(eocd + 16, true);
  const out = [];
  for (let i = 0; i < count && p + 46 <= bytes.length; i++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const method = dv.getUint16(p + 10, true);
    const crc = dv.getUint32(p + 16, true);
    const compSize = dv.getUint32(p + 20, true);
    const size = dv.getUint32(p + 24, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const lho = dv.getUint32(p + 42, true);
    const name = dec.decode(bytes.subarray(p + 46, p + 46 + nameLen));
    const lNameLen = dv.getUint16(lho + 26, true);
    const lExtraLen = dv.getUint16(lho + 28, true);
    const dataStart = lho + 30 + lNameLen + lExtraLen;
    out.push({ name, method, crc, compSize, size, data: bytes.subarray(dataStart, dataStart + compSize) });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

/** Infla bytes DEFLATE crudos (método 8) con DecompressionStream nativo.
 * @param {Uint8Array} bytes @returns {Promise<Uint8Array>} */
export async function inflateRaw(bytes) {
  const ds = new DecompressionStream('deflate-raw');
  const w = ds.writable.getWriter();
  w.write(/** @type {BufferSource} */ (bytes));
  w.close();
  const ab = await new Response(ds.readable).arrayBuffer();
  return new Uint8Array(ab);
}

/** Bytes descomprimidos de una entrada ZIP (infla si método 8).
 * @param {{method:number, data:Uint8Array}} entry @returns {Promise<Uint8Array>} */
export async function entryBytes(entry) {
  return entry.method === 8 ? await inflateRaw(entry.data) : entry.data;
}

/** Contenido textual de una entrada ZIP (infla si método 8).
 * @param {{name:string, method:number, data:Uint8Array}} entry @returns {Promise<string>} */
export async function entryText(entry) {
  return dec.decode(await entryBytes(entry));
}
