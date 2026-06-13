// APT115 CODEX ARCANUM — Notas: núcleo del vault (export/import .zip de .md)
// Núcleo PURO y verificable en Node (sin DOM ni estado): escritor/lector ZIP
// propio, CRC-32, serialización de notas a markdown con frontmatter YAML y
// fusión. El wiring de UI (descarga/file input/confirm) vive en notes.js.
//
// Formato de export: un .zip "vault" con un .md por nota. El .md lleva
// frontmatter YAML (title, created=ts, id) + el body markdown tal cual, con los
// [[links]] preservados (round-trip y compatible con Obsidian/Logseq/Quartz).
// Los derivados (backlinks, grafo) NO se exportan: se re-derivan escaneando los
// [[...]] al renderizar. El ZIP se escribe con método STORE (sin compresión):
// las notas son texto chico, así el escritor queda síncrono y 100% verificable;
// el lector igual acepta entradas DEFLATE (método 8) por si entra un .zip de
// otra herramienta, inflándolas con DecompressionStream.

// CRC-32 (IEEE 802.3) — espeja el de src/tools/stego.js; local acá para no
// cruzar el límite tool↔app (stego es un IIFE de tool, no un módulo importable).
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

// ─── Nota ↔ markdown ──────────────────────────────────────

/** Cita un valor para YAML solo si tiene caracteres que lo requieren. @param {string} s */
function yamlStr(s) {
  if (s === '') return '""';
  if (/^[\w .\-/]+$/.test(s) && !/^\s|\s$/.test(s)) return s;
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

/** Desescapa un valor YAML simple (quita comillas, resuelve \" y \\). @param {string} v */
function unyaml(v) {
  v = v.trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    v = v.slice(1, -1);
    if (v.indexOf('\\') >= 0) v = v.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  return v;
}

/**
 * Nombre de archivo .md desde el título: minúsculas, no-alfanumérico→guion,
 * recortado. Conserva letras acentuadas (el ZIP marca el nombre como UTF-8).
 * Fallback al id si el título queda vacío. @param {string} title @param {string} id
 */
export function slugifyTitle(title, id) {
  let s = String(title || '').trim().toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
  if (!s) s = String(id || 'nota');
  return s;
}

/**
 * Nota → texto markdown con frontmatter YAML + body intacto.
 * @param {import('./state.js').NoteCard} note @returns {string}
 */
export function noteToMarkdown(note) {
  const fm = ['---',
    'title: ' + yamlStr(String(note.title || '')),
    'created: ' + yamlStr(String(note.ts || '')),
    'id: ' + yamlStr(String(note.id || '')),
    '---', ''].join('\n');
  return fm + (note.body || '');
}

/**
 * Texto markdown (con o sin frontmatter) → nota. Si falta el id se genera; si
 * falta el título se deriva del nombre de archivo. No re-deriva enlaces: salen
 * de escanear los [[...]] al renderizar. @param {string} filename @param {string} text
 * @returns {import('./state.js').NoteCard}
 */
export function parseMarkdownNote(filename, text) {
  let body = String(text == null ? '' : text).replace(/^﻿/, '');
  /** @type {Record<string, string>} */
  const fm = {};
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(body);
  if (m) {
    m[1].split(/\r?\n/).forEach(line => {
      const mm = /^([A-Za-z][\w-]*):\s?(.*)$/.exec(line);
      if (mm) fm[mm[1].toLowerCase()] = unyaml(mm[2]);
    });
    body = body.slice(m[0].length);
  }
  const base = String(filename || '').replace(/.*[/\\]/, '').replace(/\.md$/i, '');
  const title = (fm.title != null && fm.title !== '') ? fm.title : base;
  const id = fm.id || ('n_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7));
  const ts = fm.created || new Date().toLocaleString();
  return { id, title, body, ts };
}

// ─── ZIP ──────────────────────────────────────────────────

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
 * Lee las entradas de un ZIP por su central directory: nombre, método (0=store,
 * 8=deflate) y los bytes CRUDOS del file data (para método 8 hay que inflar con
 * inflateRaw). Lanza si no encuentra el EOCD. @param {Uint8Array} bytes
 * @returns {{name:string, method:number, data:Uint8Array, crc:number}[]}
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
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const lho = dv.getUint32(p + 42, true);
    const name = dec.decode(bytes.subarray(p + 46, p + 46 + nameLen));
    const lNameLen = dv.getUint16(lho + 26, true);
    const lExtraLen = dv.getUint16(lho + 28, true);
    const dataStart = lho + 30 + lNameLen + lExtraLen;
    out.push({ name, method, crc, data: bytes.subarray(dataStart, dataStart + compSize) });
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

/** Contenido textual de una entrada ZIP (infla si método 8).
 * @param {{name:string, method:number, data:Uint8Array}} entry @returns {Promise<string>} */
export async function entryText(entry) {
  const raw = entry.method === 8 ? await inflateRaw(entry.data) : entry.data;
  return dec.decode(raw);
}

// ─── Notas ↔ vault ────────────────────────────────────────

/** Notas → entradas de ZIP (un .md por nota), evitando nombres duplicados.
 * @param {import('./state.js').NoteCard[]} arr @returns {{name:string, text:string}[]} */
export function notesToZipEntries(arr) {
  const used = new Set();
  return arr.map(n => {
    const base = slugifyTitle(n.title, n.id);
    let name = base + '.md';
    let i = 2;
    while (used.has(name.toLowerCase())) name = base + '-' + (i++) + '.md';
    used.add(name.toLowerCase());
    return { name, text: noteToMarkdown(n) };
  });
}

/**
 * Fusiona notas entrantes sobre una base: misma id reemplaza en su lugar, id
 * nueva se agrega al frente. @param {import('./state.js').NoteCard[]} base
 * @param {import('./state.js').NoteCard[]} incoming @returns {import('./state.js').NoteCard[]}
 */
export function mergeNotes(base, incoming) {
  const order = base.slice();
  const idxById = new Map(order.map((n, i) => [n.id, i]));
  for (const n of incoming) {
    if (idxById.has(n.id)) {
      order[/** @type {number} */ (idxById.get(n.id))] = n;
    } else {
      order.unshift(n);
      // los índices previos corrieron +1: re-mapear es O(n); como import es
      // puntual, reconstruimos el mapa.
      idxById.clear();
      order.forEach((x, i) => idxById.set(x.id, i));
    }
  }
  return order;
}
