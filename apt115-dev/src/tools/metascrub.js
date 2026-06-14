// APT115 CODEX ARCANUM — Metadata Inspector & Scrubber
// quod est superius est sicut quod inferius
//
// LEE toda la metadata de un archivo y produce una COPIA LIMPIA descargable
// (modelo MAT2: `nombre.cleaned.ext`, sin tocar el original). 100% local — el
// archivo se procesa en el navegador, nada se sube. Pensado para OPSEC/forense:
// quitar el rastro (EXIF/GPS de fotos, autor/fechas de documentos, etc.).
//
// Formatos:
//   · JPEG  — segmentos APPn/COM; lee EXIF (TIFF/IFD0/Exif/GPS), XMP, IPTC, ICC;
//             scrub = quita APP1(EXIF/XMP), APP13(IPTC), APP2(ICC opc.), COM y
//             APPn de metadata, conservando JFIF/Adobe y el scan → limpio de verdad.
//   · PNG   — chunks de texto tEXt/zTXt/iTXt + eXIf + tIME; scrub = los elimina,
//             conservando los chunks críticos/render → limpio de verdad.
//   · OOXML — docx/xlsx/pptx: lee docProps/core.xml + app.xml; scrub = borra
//             docProps/* + thumbnail y limpia [Content_Types].xml y _rels/.rels,
//             reempaqueta con el escritor ZIP propio → limpio de verdad.
//   · PDF   — /Info (Author/Producer/Creator/fechas…) + XMP; scrub = BLANQUEA esos
//             valores in-place (preserva offsets/xref). LÍMITE: no cubre objetos en
//             object streams comprimidos ni versiones incrementales/firmadas.
//
// Reutiliza: src/app/zip.js (parseZip/buildZip/entryBytes), Web APIs nativas.
// Núcleo PURO testeable en Node (parse + scrub). Oráculo: exiftool.

import { parseZip, buildZip, entryBytes } from '../app/zip.js';

export const metascrub = (function () {
  'use strict';

  const dec = new TextDecoder('utf-8');
  const latin1 = new TextDecoder('latin1');

  // ── Detección de formato ────────────────────────────────────────
  function detect(bytes, name) {
    if (bytes.length < 4) return null;
    if (bytes[0] === 0xFF && bytes[1] === 0xD8) return 'jpeg';
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) return 'png';
    if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) return 'pdf'; // %PDF
    // ZIP → ¿OOXML? (PK\x03\x04 + extensión/contenido OOXML)
    if (bytes[0] === 0x50 && bytes[1] === 0x4B && (bytes[2] === 0x03 || bytes[2] === 0x05)) {
      const ext = (name || '').toLowerCase().split('.').pop();
      if (['docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm'].includes(ext)) return 'ooxml';
      // heurística: buscar "[Content_Types].xml" en el head
      const head = latin1.decode(bytes.subarray(0, Math.min(bytes.length, 4096)));
      if (head.includes('[Content_Types].xml')) return 'ooxml';
    }
    return null;
  }

  // ════════════════════════════════════════════════════════════════
  // JPEG
  // ════════════════════════════════════════════════════════════════
  const APP_NAMES = {
    0xE0: 'APP0 (JFIF)', 0xE1: 'APP1 (EXIF/XMP)', 0xE2: 'APP2 (ICC)', 0xE3: 'APP3',
    0xE4: 'APP4', 0xE5: 'APP5', 0xE6: 'APP6', 0xE7: 'APP7', 0xE8: 'APP8', 0xE9: 'APP9',
    0xEA: 'APP10', 0xEB: 'APP11', 0xEC: 'APP12', 0xED: 'APP13 (IPTC/Photoshop)',
    0xEE: 'APP14 (Adobe)', 0xEF: 'APP15', 0xFE: 'COM (comentario)',
  };

  // Recorre los segmentos de cabecera hasta el SOS. Devuelve {segments, sosAt}.
  function jpegSegments(bytes) {
    const segs = [];
    let p = 2; // tras SOI
    while (p + 4 <= bytes.length) {
      if (bytes[p] !== 0xFF) break;
      const marker = bytes[p + 1];
      if (marker === 0xD9) break;                       // EOI
      if (marker === 0xDA) return { segments: segs, sosAt: p }; // SOS → empieza el scan
      // marcadores sin payload
      if (marker === 0x01 || (marker >= 0xD0 && marker <= 0xD7)) { p += 2; continue; }
      const len = (bytes[p + 2] << 8) | bytes[p + 3];   // big-endian
      if (len < 2) break;
      segs.push({ marker, start: p, len: len + 2, dataStart: p + 4, dataLen: len - 2 });
      p += 2 + len;
    }
    return { segments: segs, sosAt: -1 };
  }

  // EXIF: TIFF (II/MM) → IFD0 + sub-IFDs (Exif 0x8769, GPS 0x8825).
  const EXIF_TAGS = {
    0x010F: 'Make', 0x0110: 'Model', 0x0131: 'Software', 0x0132: 'DateTime',
    0x013B: 'Artist', 0x8298: 'Copyright', 0x0112: 'Orientation', 0x9003: 'DateTimeOriginal',
    0x9004: 'DateTimeDigitized', 0xA430: 'CameraOwnerName', 0xA431: 'BodySerialNumber',
    0xA433: 'LensMake', 0xA434: 'LensModel', 0x9286: 'UserComment', 0x927C: 'MakerNote',
    0xC614: 'UniqueCameraModel', 0xA420: 'ImageUniqueID',
  };
  const GPS_TAGS = { 0x0001: 'GPSLatitudeRef', 0x0002: 'GPSLatitude', 0x0003: 'GPSLongitudeRef', 0x0004: 'GPSLongitude', 0x0005: 'GPSAltitudeRef', 0x0006: 'GPSAltitude', 0x001D: 'GPSDateStamp' };
  const TYPE_SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };

  function readExif(tiff) {
    // tiff = bytes desde el byte-order ("II"/"MM")
    if (tiff.length < 8) return null;
    const le = tiff[0] === 0x49 && tiff[1] === 0x49;
    const be = tiff[0] === 0x4D && tiff[1] === 0x4D;
    if (!le && !be) return null;
    const dv = new DataView(tiff.buffer, tiff.byteOffset, tiff.byteLength);
    const r16 = (o) => dv.getUint16(o, le);
    const r32 = (o) => dv.getUint32(o, le);
    if (r16(2) !== 42) return null;
    const out = { tags: {}, count: 0, gps: null };

    function value(type, count, valOff) {
      const sz = TYPE_SIZE[type] || 1;
      const total = sz * count;
      let off = valOff;
      if (total > 4) { off = r32(valOff); }
      if (off + total > tiff.length) return null;
      if (type === 2) { // ASCII
        let s = ''; for (let i = 0; i < count; i++) { const c = tiff[off + i]; if (c === 0) break; s += String.fromCharCode(c); } return s.trim();
      }
      if (type === 3) return r16(off);
      if (type === 4) return r32(off);
      if (type === 5) { const arr = []; for (let i = 0; i < count; i++) { const n = r32(off + i * 8), d = r32(off + i * 8 + 4); arr.push(d ? n / d : 0); } return arr.length === 1 ? arr[0] : arr; }
      if (type === 1 || type === 7) return total <= 4 ? '(' + total + ' B inline)' : '(' + total + ' B)';
      return null;
    }

    function ifd(start, names, isGps) {
      if (start + 2 > tiff.length) return 0;
      const n = r16(start);
      let exifPtr = 0, gpsPtr = 0;
      for (let i = 0; i < n && i < 256; i++) {
        const e = start + 2 + i * 12;
        if (e + 12 > tiff.length) break;
        const tag = r16(e), type = r16(e + 2), count = r32(e + 4);
        out.count++;
        if (!isGps && tag === 0x8769) { exifPtr = r32(e + 8); continue; }
        if (!isGps && tag === 0x8825) { gpsPtr = r32(e + 8); continue; }
        const nm = names[tag];
        if (nm) { const v = value(type, count, e + 8); if (v !== null && v !== '') out.tags[nm] = v; if (isGps) (out.gps = out.gps || {})[nm] = v; }
      }
      return { exifPtr, gpsPtr, next: r32(start + 2 + n * 12) };
    }

    const i0 = ifd(r32(4), EXIF_TAGS, false);
    if (i0 && i0.exifPtr) ifd(i0.exifPtr, EXIF_TAGS, false);
    if (i0 && i0.gpsPtr) ifd(i0.gpsPtr, GPS_TAGS, true);
    out.gpsDecimal = gpsToDecimal(out.gps);
    return out;
  }

  function gpsToDecimal(g) {
    if (!g || !Array.isArray(g.GPSLatitude) || !Array.isArray(g.GPSLongitude)) return null;
    const dms = (a) => (a[0] || 0) + (a[1] || 0) / 60 + (a[2] || 0) / 3600;
    let lat = dms(g.GPSLatitude), lon = dms(g.GPSLongitude);
    if (g.GPSLatitudeRef === 'S') lat = -lat;
    if (g.GPSLongitudeRef === 'W') lon = -lon;
    return { lat: +lat.toFixed(6), lon: +lon.toFixed(6) };
  }

  function readJpeg(bytes) {
    const { segments } = jpegSegments(bytes);
    const res = { segments: [], exif: null, hasXmp: false, hasIptc: false, hasIcc: false, comments: [] };
    for (const s of segments) {
      const name = APP_NAMES[s.marker] || ('0x' + s.marker.toString(16));
      res.segments.push({ name, bytes: s.len });
      if (s.marker === 0xE1) {
        const head = latin1.decode(bytes.subarray(s.dataStart, Math.min(s.dataStart + 32, bytes.length)));
        if (head.startsWith('Exif\0')) { res.exif = readExif(bytes.subarray(s.dataStart + 6)); }
        else if (head.includes('http://ns.adobe.com/xap') || head.includes('<x:xmpmeta')) res.hasXmp = true;
      } else if (s.marker === 0xED) res.hasIptc = true;
      else if (s.marker === 0xE2) res.hasIcc = true;
      else if (s.marker === 0xFE) res.comments.push(latin1.decode(bytes.subarray(s.dataStart, s.dataStart + s.dataLen)).trim());
    }
    return res;
  }

  // Marcadores a ELIMINAR en el scrub (metadata). Se conservan JFIF (E0) y Adobe
  // (EE, necesario para la transformación de color) + todo lo estructural.
  function jpegDrop(marker, keepIcc) {
    if (marker === 0xE1) return true;                 // EXIF / XMP
    if (marker === 0xED) return true;                 // IPTC / Photoshop
    if (marker === 0xE2) return !keepIcc;             // ICC
    if (marker === 0xFE) return true;                 // COM
    if (marker >= 0xE3 && marker <= 0xEF && marker !== 0xEE) return true; // APP3..15 salvo Adobe
    return false;
  }

  function scrubJpeg(bytes, opts) {
    const keepIcc = !!(opts && opts.keepIcc);
    const { segments, sosAt } = jpegSegments(bytes);
    const parts = [bytes.subarray(0, 2)]; // SOI
    const removed = [];
    for (const s of segments) {
      if (jpegDrop(s.marker, keepIcc)) { removed.push(APP_NAMES[s.marker] || ('0x' + s.marker.toString(16))); continue; }
      parts.push(bytes.subarray(s.start, s.start + s.len));
    }
    // Scan + trailing desde el SOS (o desde donde hayamos quedado si no hubo SOS)
    if (sosAt >= 0) parts.push(bytes.subarray(sosAt));
    return { bytes: concat(parts), removed };
  }

  // ════════════════════════════════════════════════════════════════
  // PNG
  // ════════════════════════════════════════════════════════════════
  const PNG_SIG = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
  const PNG_META = new Set(['tEXt', 'zTXt', 'iTXt', 'eXIf', 'tIME']);

  function pngChunks(bytes) {
    const out = [];
    let p = 8;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    while (p + 8 <= bytes.length) {
      const len = dv.getUint32(p, false);
      const type = String.fromCharCode(bytes[p + 4], bytes[p + 5], bytes[p + 6], bytes[p + 7]);
      const total = 12 + len;
      if (p + total > bytes.length) break;
      out.push({ type, start: p, total, dataStart: p + 8, len });
      p += total;
      if (type === 'IEND') break;
    }
    return out;
  }

  function readPng(bytes) {
    const res = { text: [], hasExif: false, hasTime: false, chunks: 0 };
    for (const c of pngChunks(bytes)) {
      res.chunks++;
      if (c.type === 'tEXt') {
        const s = latin1.decode(bytes.subarray(c.dataStart, c.dataStart + c.len));
        const nul = s.indexOf('\0');
        res.text.push({ kind: 'tEXt', key: nul >= 0 ? s.slice(0, nul) : s, val: nul >= 0 ? s.slice(nul + 1) : '' });
      } else if (c.type === 'iTXt') {
        const s = latin1.decode(bytes.subarray(c.dataStart, c.dataStart + c.len));
        const nul = s.indexOf('\0');
        res.text.push({ kind: 'iTXt', key: nul >= 0 ? s.slice(0, nul) : s, val: '(itxt)' });
      } else if (c.type === 'zTXt') {
        const s = latin1.decode(bytes.subarray(c.dataStart, c.dataStart + Math.min(c.len, 80)));
        const nul = s.indexOf('\0');
        res.text.push({ kind: 'zTXt', key: nul >= 0 ? s.slice(0, nul) : s, val: '(zlib comprimido)' });
      } else if (c.type === 'eXIf') res.hasExif = true;
      else if (c.type === 'tIME') res.hasTime = true;
    }
    return res;
  }

  function scrubPng(bytes) {
    const parts = [new Uint8Array(PNG_SIG)];
    const removed = [];
    for (const c of pngChunks(bytes)) {
      if (PNG_META.has(c.type)) { removed.push(c.type); continue; }
      parts.push(bytes.subarray(c.start, c.start + c.total));
    }
    return { bytes: concat(parts), removed };
  }

  // ════════════════════════════════════════════════════════════════
  // OOXML (docx / xlsx / pptx)
  // ════════════════════════════════════════════════════════════════
  const OOXML_CORE = /<(dc|cp|dcterms):([\w]+)[^>]*>([^<]*)<\/\1:\2>/g;

  async function readOoxml(bytes) {
    const entries = parseZip(bytes);
    const res = { props: {}, hasCustom: false, hasThumbnail: false, files: entries.length };
    for (const e of entries) {
      if (e.name === 'docProps/core.xml' || e.name === 'docProps/app.xml') {
        const xml = dec.decode(await entryBytes(e));
        let m;
        OOXML_CORE.lastIndex = 0;
        while ((m = OOXML_CORE.exec(xml))) { if (m[3].trim()) res.props[m[2]] = m[3].trim(); }
        // app.xml usa tags planos (<Company>, <Application>…)
        for (const tag of ['Company', 'Manager', 'Application', 'AppVersion', 'Template', 'TotalTime']) {
          const mm = new RegExp('<' + tag + '>([^<]*)</' + tag + '>').exec(xml);
          if (mm && mm[1].trim()) res.props[tag] = mm[1].trim();
        }
      } else if (e.name === 'docProps/custom.xml') res.hasCustom = true;
      else if (e.name.startsWith('docProps/thumbnail')) res.hasThumbnail = true;
    }
    return res;
  }

  async function scrubOoxml(bytes) {
    const entries = parseZip(bytes);
    const removed = [];
    const keep = [];
    for (const e of entries) {
      if (e.name.startsWith('docProps/')) { removed.push(e.name); continue; }
      keep.push(e);
    }
    // Reconstruir las entradas conservadas (inflando) y limpiar las referencias.
    const out = [];
    for (const e of keep) {
      let data = await entryBytes(e);
      if (e.name === '[Content_Types].xml') {
        let s = dec.decode(data);
        s = s.replace(/<Override[^>]*PartName="\/docProps\/[^"]*"[^>]*\/>/g, '');
        data = new TextEncoder().encode(s);
      } else if (e.name === '_rels/.rels') {
        let s = dec.decode(data);
        s = s.replace(/<Relationship[^>]*Target="docProps\/[^"]*"[^>]*\/>/g, '');
        data = new TextEncoder().encode(s);
      }
      out.push({ name: e.name, data });
    }
    return { bytes: buildZip(out), removed };
  }

  // ════════════════════════════════════════════════════════════════
  // PDF  (blanqueo in-place — preserva offsets/xref)
  // ════════════════════════════════════════════════════════════════
  const PDF_INFO_KEYS = ['Title', 'Author', 'Subject', 'Keywords', 'Creator', 'Producer', 'CreationDate', 'ModDate'];

  function readPdf(bytes) {
    const s = latin1.decode(bytes);
    const res = { info: {}, hasXmp: false };
    for (const k of PDF_INFO_KEYS) {
      // /Key (valor literal) o /Key <hex>
      let m = new RegExp('/' + k + '\\s*\\(((?:\\\\.|[^\\\\)])*)\\)').exec(s);
      if (m && m[1]) { res.info[k] = m[1].replace(/\\(.)/g, '$1').trim(); continue; }
      m = new RegExp('/' + k + '\\s*<([0-9A-Fa-f\\s]+)>').exec(s);
      if (m && m[1]) res.info[k] = '(hex ' + m[1].replace(/\s/g, '').length / 2 + ' B)';
    }
    if (s.includes('<x:xmpmeta') || s.includes('/Metadata')) res.hasXmp = true;
    return res;
  }

  // Sobreescribe con espacios el rango [a,b) del buffer (preserva longitud/offsets).
  function blank(buf, a, b) { for (let i = a; i < b && i < buf.length; i++) buf[i] = 0x20; }

  function scrubPdf(bytes) {
    const out = bytes.slice();             // copia mutable
    const s = latin1.decode(out);
    const removed = [];
    for (const k of PDF_INFO_KEYS) {
      // valor literal (...)
      let re = new RegExp('/' + k + '\\s*\\(((?:\\\\.|[^\\\\)])*)\\)', 'g'), m;
      while ((m = re.exec(s))) { if (m[1].length) { const a = m.index + m[0].indexOf('(') + 1; blank(out, a, a + m[1].length); removed.push('/' + k); } }
      // valor hex <...>
      re = new RegExp('/' + k + '\\s*<([0-9A-Fa-f\\s]+)>', 'g');
      while ((m = re.exec(s))) { const a = m.index + m[0].indexOf('<') + 1; blank(out, a, a + m[1].length); removed.push('/' + k + ' (hex)'); }
    }
    // XMP: blanquear el interior de <x:xmpmeta>…</x:xmpmeta>
    const xa = s.indexOf('<x:xmpmeta');
    if (xa >= 0) { const xe = s.indexOf('</x:xmpmeta>', xa); if (xe >= 0) { blank(out, xa, xe + 12); removed.push('XMP'); } }
    return { bytes: out, removed: [...new Set(removed)] };
  }

  // ── despacho ────────────────────────────────────────────────────
  function read(bytes, name) {
    const fmt = detect(bytes, name);
    if (fmt === 'jpeg') return { fmt, data: readJpeg(bytes) };
    if (fmt === 'png') return { fmt, data: readPng(bytes) };
    if (fmt === 'pdf') return { fmt, data: readPdf(bytes) };
    return { fmt, data: null }; // ooxml es async → lo resuelve el render
  }
  async function scrub(bytes, name, opts) {
    const fmt = detect(bytes, name);
    if (fmt === 'jpeg') return scrubJpeg(bytes, opts);
    if (fmt === 'png') return scrubPng(bytes);
    if (fmt === 'pdf') return scrubPdf(bytes);
    if (fmt === 'ooxml') return await scrubOoxml(bytes);
    throw new Error('formato no soportado');
  }

  function concat(parts) {
    let n = 0; for (const p of parts) n += p.length;
    const out = new Uint8Array(n); let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  // ════════════════════════════════════════════════════════════════
  // Render (tool LAB)
  // ════════════════════════════════════════════════════════════════
  function render(container) {
    const esc = window.Triage.util.esc;
    container.innerHTML =
      '<div class="sec-hdr"><div class="sec-title">🧽 Metadata Scrub</div>' +
      '<span class="sec-cmds-badge">local · sin rastro</span></div>' +
      '<div class="lab-intro">Lee toda la metadata de un archivo y te devuelve una <b>copia limpia</b> ' +
      '(<code>nombre.cleaned.ext</code>, no toca el original). Todo <b>100% local</b> — nada se sube. ' +
      'JPEG · PNG · OOXML (docx/xlsx/pptx) · PDF.</div>' +
      '<div class="lab-drop" id="msDrop" tabindex="0"><div class="lab-drop-ic">🧽</div>' +
      '<div class="lab-drop-t">Arrastrá una imagen o documento acá o hacé click</div>' +
      '<div class="lab-drop-s">JPEG, PNG, docx/xlsx/pptx, PDF</div></div>' +
      '<input type="file" id="msFile" style="display:none">' +
      '<div id="msResults"></div>';
    const drop = container.querySelector('#msDrop');
    const input = container.querySelector('#msFile');
    drop.onclick = () => input.click();
    drop.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } };
    input.onchange = () => { if (input.files[0]) handle(input.files[0], container); };
    drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); };
    drop.ondragleave = () => drop.classList.remove('over');
    drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) handle(e.dataTransfer.files[0], container); };
  }

  function handle(file, container) {
    const results = container.querySelector('#msResults');
    const esc = window.Triage.util.esc;
    results.innerHTML = '<div class="lab-loading">⬡ Leyendo ' + esc(file.name) + ' …</div>';
    const reader = new FileReader();
    reader.onload = async (e) => {
      const bytes = new Uint8Array(e.target.result);
      try { await show(bytes, file.name, results); }
      catch (err) { results.innerHTML = '<div class="lab-err">Error: ' + esc(String(err)) + '</div>'; }
    };
    reader.readAsArrayBuffer(file);
  }

  async function show(bytes, name, results) {
    const U = window.Triage.util, esc = U.esc;
    const fmt = detect(bytes, name);
    if (!fmt) { results.innerHTML = '<div class="lab-note">Formato no soportado para scrub. Soportados: JPEG, PNG, docx/xlsx/pptx, PDF.</div>'; return; }
    const FMT = { jpeg: 'JPEG', png: 'PNG', ooxml: 'OOXML (Office)', pdf: 'PDF' };
    let html = '<div class="lab-panel"><div class="lab-panel-h">📋 Metadata detectada <span class="lab-dim">(' + FMT[fmt] + ')</span></div><div class="lab-panel-b">';
    let found = false;

    if (fmt === 'jpeg') {
      const d = readJpeg(bytes);
      if (d.exif && Object.keys(d.exif.tags).length) {
        found = true;
        const rows = Object.entries(d.exif.tags).map(([k, v]) => [esc(k), esc(String(v))]);
        html += '<div class="lab-sub">EXIF (' + d.exif.count + ' tags)</div>' + kv(rows);
        if (d.exif.gpsDecimal) html += '<div class="lab-note">📍 <b>Ubicación GPS</b>: ' + d.exif.gpsDecimal.lat + ', ' + d.exif.gpsDecimal.lon +
          ' <a class="lab-ext" href="https://www.openstreetmap.org/?mlat=' + d.exif.gpsDecimal.lat + '&mlon=' + d.exif.gpsDecimal.lon + '#map=15" target="_blank" rel="noopener noreferrer">↗ mapa</a> — esto revela dónde se tomó la foto.</div>';
      }
      const extra = [];
      if (d.hasXmp) extra.push('XMP'); if (d.hasIptc) extra.push('IPTC'); if (d.hasIcc) extra.push('perfil ICC'); if (d.comments.length) extra.push(d.comments.length + ' comentario(s)');
      if (extra.length) { found = true; html += '<div class="lab-note">También presente: ' + extra.map(esc).join(', ') + '.</div>'; }
      if (d.comments.length) html += kv(d.comments.map((c, i) => ['COM ' + (i + 1), esc(c.slice(0, 200))]));
    } else if (fmt === 'png') {
      const d = readPng(bytes);
      if (d.text.length) { found = true; html += '<div class="lab-sub">Chunks de texto</div>' + kv(d.text.map(t => [esc(t.kind + ' · ' + t.key), esc(String(t.val).slice(0, 200))])); }
      const extra = []; if (d.hasExif) extra.push('eXIf'); if (d.hasTime) extra.push('tIME (fecha)');
      if (extra.length) { found = true; html += '<div class="lab-note">También presente: ' + extra.join(', ') + '.</div>'; }
    } else if (fmt === 'ooxml') {
      const d = await readOoxml(bytes);
      const keys = Object.keys(d.props);
      if (keys.length) { found = true; html += '<div class="lab-sub">Propiedades del documento</div>' + kv(keys.map(k => [esc(k), esc(String(d.props[k]))])); }
      const extra = []; if (d.hasCustom) extra.push('propiedades custom'); if (d.hasThumbnail) extra.push('thumbnail');
      if (extra.length) { found = true; html += '<div class="lab-note">También presente: ' + extra.join(', ') + '.</div>'; }
    } else if (fmt === 'pdf') {
      const d = readPdf(bytes);
      const keys = Object.keys(d.info);
      if (keys.length) { found = true; html += '<div class="lab-sub">/Info</div>' + kv(keys.map(k => [esc(k), esc(String(d.info[k]))])); }
      if (d.hasXmp) { found = true; html += '<div class="lab-note">También presente: metadata XMP.</div>'; }
    }

    if (!found) html += '<div class="lab-note">No se detectó metadata removible. El archivo ya parece limpio (o usa campos no soportados en v1).</div>';
    html += '</div></div>';

    // Acción de scrub
    html += '<div class="lab-panel"><div class="lab-panel-h">🧽 Limpiar</div><div class="lab-panel-b">';
    if (fmt === 'jpeg') html += '<label class="lab-row1"><input type="checkbox" id="msIcc"> conservar perfil de color ICC</label>';
    if (fmt === 'pdf') html += '<div class="lab-note">⚠ En PDF se <b>blanquean</b> los valores in-place (preserva el archivo). No cubre objetos en <i>object streams</i> comprimidos ni versiones incrementales/firmadas — para esos casos usá una reescritura dedicada (qpdf/mat2).</div>';
    html += '<div class="lab-actions"><button class="rs-copy" id="msGo">⬇ Descargar copia limpia</button> <span id="msMsg" class="lab-dim"></span></div>';
    html += '</div></div>';
    results.innerHTML = html;

    results.querySelector('#msGo').onclick = async () => {
      const msg = results.querySelector('#msMsg');
      msg.textContent = 'procesando…';
      try {
        const opts = { keepIcc: !!(results.querySelector('#msIcc') && results.querySelector('#msIcc').checked) };
        const r = await scrub(bytes, name, opts);
        const dot = name.lastIndexOf('.');
        const outName = (dot > 0 ? name.slice(0, dot) + '.cleaned' + name.slice(dot) : name + '.cleaned');
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([r.bytes], { type: 'application/octet-stream' }));
        a.download = outName; document.body.appendChild(a); a.click(); a.remove();
        const saved = bytes.length - r.bytes.length;
        msg.innerHTML = '✓ ' + esc(outName) + ' — quitado: ' + (r.removed.length ? esc(r.removed.join(', ')) : '—') +
          (saved > 0 ? ' <span class="lab-dim">(−' + U.formatBytes(saved) + ')</span>' : '');
      } catch (err) { msg.textContent = 'error: ' + String(err); }
    };
  }

  function kv(rows) {
    return '<table class="lab-kv"><tbody>' + rows.map(r => '<tr><th>' + r[0] + '</th><td>' + r[1] + '</td></tr>').join('') + '</tbody></table>';
  }

  if (typeof window !== 'undefined' && window.LAB) {
    window.LAB.registerTool({ id: 'metascrub', label: 'Metadata Scrub', icon: '🧽', group: '🔬 Forensics', render });
  }

  return { detect, read, scrub, readJpeg, scrubJpeg, jpegSegments, readExif, gpsToDecimal, readPng, scrubPng, pngChunks, readOoxml, scrubOoxml, readPdf, scrubPdf };
})();

if (typeof window !== 'undefined') { window.Triage = window.Triage || {}; window.apt115Metascrub = metascrub; }
