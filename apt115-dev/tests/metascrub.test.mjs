// Tests de metascrub — lectura de metadata + scrub (copia limpia).
// Núcleo PURO en Node. Verificado además vs exiftool durante el desarrollo:
// JPEG/PNG/OOXML quedan SIN rastro; PDF blanquea in-place; todos siguen abriendo.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { metascrub as M } from '../src/tools/metascrub.js';
import { buildZip, parseZip } from '../src/app/zip.js';

const te = new TextEncoder();

// ── JPEG fabricado: SOI + APP1(EXIF: Make="ABC") + COM + SOS + scan + EOI ──
function jpegSample() {
  const tiff = [
    0x49, 0x49, 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00, // II, 42, IFD0@8
    0x01, 0x00,                                     // 1 entry
    0x0F, 0x01, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, // tag Make(0x010F) ASCII count4
    0x41, 0x42, 0x43, 0x00,                         // "ABC\0" inline
    0x00, 0x00, 0x00, 0x00,                         // next IFD = 0
  ];
  const app1payload = [...te.encode('Exif\0\0'), ...tiff];
  const app1len = app1payload.length + 2;
  const com = [...te.encode('secret comment')];
  const comLen = com.length + 2;
  return new Uint8Array([
    0xFF, 0xD8,                                   // SOI
    0xFF, 0xE1, (app1len >> 8) & 0xFF, app1len & 0xFF, ...app1payload,
    0xFF, 0xFE, (comLen >> 8) & 0xFF, comLen & 0xFF, ...com,
    0xFF, 0xDA, 0x00, 0x08, 1, 1, 0, 0, 0x3F, 0x00, // SOS (len 8)
    0x12, 0x34, 0x56, 0x78,                       // scan
    0xFF, 0xD9,                                   // EOI
  ]);
}

test('JPEG: lee EXIF y detecta GPS ausente', () => {
  const b = jpegSample();
  assert.equal(M.detect(b, 'x.jpg'), 'jpeg');
  const d = M.readJpeg(b);
  assert.equal(d.exif.tags.Make, 'ABC');
  assert.equal(d.comments[0], 'secret comment');
});

test('JPEG: scrub quita APP1(EXIF) y COM, conserva SOI/SOS/scan/EOI', () => {
  const b = jpegSample();
  const r = M.scrubJpeg(b, {});
  assert.ok(r.removed.includes('APP1 (EXIF/XMP)'));
  assert.ok(r.removed.some(x => x.startsWith('COM')));
  // la copia limpia NO contiene "Exif" ni el comentario
  const txt = Buffer.from(r.bytes).toString('latin1');
  assert.ok(!txt.includes('Exif'), 'no debe quedar el bloque EXIF');
  assert.ok(!txt.includes('secret comment'), 'no debe quedar el comentario');
  // sigue siendo un JPEG (SOI/EOI) y conserva el scan
  assert.deepEqual([...r.bytes.slice(0, 2)], [0xFF, 0xD8]);
  assert.deepEqual([...r.bytes.slice(-2)], [0xFF, 0xD9]);
  assert.ok(txt.includes('\x12\x34\x56\x78') || [...r.bytes].join(',').includes('18,52,86,120'));
});

test('JPEG: GPS → decimal con signo por hemisferio', () => {
  const g = { GPSLatitudeRef: 'S', GPSLatitude: [40, 26, 46], GPSLongitudeRef: 'W', GPSLongitude: [79, 58, 56] };
  const dec = M.gpsToDecimal(g);
  assert.equal(dec.lat < 0, true);
  assert.equal(dec.lon < 0, true);
  assert.ok(Math.abs(dec.lat + 40.446) < 0.01);
});

// ── PNG fabricado: sig + IHDR + tEXt + IEND ──
function pngSample() {
  const sig = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
  const chunk = (type, data) => {
    const len = data.length;
    return [(len >>> 24) & 255, (len >>> 16) & 255, (len >>> 8) & 255, len & 255, ...te.encode(type), ...data, 0, 0, 0, 0];
  };
  const ihdr = chunk('IHDR', [0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]);
  const text = chunk('tEXt', [...te.encode('Author\0Jane Secret')]);
  const iend = chunk('IEND', []);
  return new Uint8Array([...sig, ...ihdr, ...text, ...iend]);
}

test('PNG: lee tEXt y scrub lo elimina conservando IHDR/IEND', () => {
  const b = pngSample();
  assert.equal(M.detect(b, 'x.png'), 'png');
  const d = M.readPng(b);
  assert.equal(d.text[0].key, 'Author');
  assert.equal(d.text[0].val, 'Jane Secret');
  const r = M.scrubPng(b);
  assert.ok(r.removed.includes('tEXt'));
  const txt = Buffer.from(r.bytes).toString('latin1');
  assert.ok(!txt.includes('Jane Secret'));
  assert.ok(txt.includes('IHDR') && txt.includes('IEND'));
});

// ── OOXML fabricado con buildZip (STORE → testeable sin inflar) ──
function docxSample() {
  return buildZip([
    { name: '[Content_Types].xml', text: '<?xml version="1.0"?><Types><Override PartName="/docProps/core.xml" ContentType="x"/><Override PartName="/word/document.xml" ContentType="y"/></Types>' },
    { name: '_rels/.rels', text: '<?xml version="1.0"?><Relationships><Relationship Id="r1" Target="docProps/core.xml"/><Relationship Id="r2" Target="word/document.xml"/></Relationships>' },
    { name: 'docProps/core.xml', text: '<cp:coreProperties xmlns:dc="x" xmlns:cp="y"><dc:creator>Secret Author</dc:creator><dc:title>Confidential</dc:title></cp:coreProperties>' },
    { name: 'docProps/app.xml', text: '<Properties><Company>ACME Secret</Company></Properties>' },
    { name: 'word/document.xml', text: '<document>hola</document>' },
  ]);
}

test('OOXML: lee props y scrub borra docProps/ + limpia referencias', async () => {
  const b = docxSample();
  assert.equal(M.detect(b, 'x.docx'), 'ooxml');
  const d = await M.readOoxml(b);
  assert.equal(d.props.creator, 'Secret Author');
  assert.equal(d.props.Company, 'ACME Secret');

  const r = await M.scrubOoxml(b);
  assert.ok(r.removed.includes('docProps/core.xml'));
  const entries = parseZip(r.bytes).map(e => e.name);
  assert.ok(!entries.some(n => n.startsWith('docProps/')), 'no debe quedar docProps/');
  assert.ok(entries.includes('word/document.xml'), 'conserva el contenido');
  // referencias limpiadas
  const ct = parseZip(r.bytes).find(e => e.name === '[Content_Types].xml');
  const rels = parseZip(r.bytes).find(e => e.name === '_rels/.rels');
  assert.ok(!Buffer.from(ct.data).toString('utf8').includes('docProps'), '[Content_Types] sin docProps');
  assert.ok(!Buffer.from(rels.data).toString('utf8').includes('docProps'), '.rels sin docProps');
});

// ── PDF ──
test('PDF: lee /Info y scrub blanquea preservando longitud/offsets', () => {
  const pdf = '%PDF-1.4\n4 0 obj<< /Title (Secret Title) /Author (Spy Guy) /Producer (LeakyPDF) >>endobj\ntrailer<< /Info 4 0 R >>\n%%EOF';
  const b = te.encode(pdf);
  assert.equal(M.detect(b, 'x.pdf'), 'pdf');
  const d = M.readPdf(b);
  assert.equal(d.info.Author, 'Spy Guy');
  assert.equal(d.info.Title, 'Secret Title');
  const r = M.scrubPdf(b);
  assert.equal(r.bytes.length, b.length, 'longitud preservada (offsets/xref intactos)');
  const txt = Buffer.from(r.bytes).toString('latin1');
  assert.ok(!txt.includes('Spy Guy') && !txt.includes('Secret Title') && !txt.includes('LeakyPDF'));
  assert.ok(txt.includes('%PDF-1.4') && txt.includes('%%EOF'), 'estructura intacta');
});

test('detect: archivo no soportado devuelve null', () => {
  assert.equal(M.detect(new Uint8Array([1, 2, 3, 4]), 'x.bin'), null);
});
