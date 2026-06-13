// Archive / APK Inspector (Fase C): clasificación de entradas, detección de
// tipo, parser del string pool AXML y análisis estructural end-to-end.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { archive } from '../src/tools/archive.js';
import { buildZip } from '../src/app/zip.js';

const { classifyEntry, detectType, parseAxmlStrings, axmlPermissions, analyze, ext } = archive;

// Construye un AndroidManifest.xml binario (AXML) mínimo: solo cabecera + string
// pool UTF-8 (suficiente para que parseAxmlStrings recupere los nombres). Asume
// strings ASCII (charLen == byteLen < 128). Espeja el layout de ResStringPool.
function buildAxmlUtf8(strings) {
  const enc = new TextEncoder();
  const encoded = strings.map(s => {
    const b = enc.encode(s);
    return Uint8Array.from([s.length, b.length, ...b, 0]);
  });
  const offsets = [];
  let acc = 0;
  for (const e of encoded) { offsets.push(acc); acc += e.length; }
  const count = strings.length;
  const stringsStart = 28 + count * 4;
  const chunkSize = stringsStart + acc;
  const fileSize = 8 + chunkSize;
  const buf = new Uint8Array(fileSize);
  const dv = new DataView(buf.buffer);
  dv.setUint16(0, 0x0003, true); dv.setUint16(2, 0x0008, true); dv.setUint32(4, fileSize, true);
  const o = 8;
  dv.setUint16(o, 0x0001, true); dv.setUint16(o + 2, 0x001c, true);
  dv.setUint32(o + 4, chunkSize, true); dv.setUint32(o + 8, count, true);
  dv.setUint32(o + 12, 0, true); dv.setUint32(o + 16, 0x100, true); // flags: UTF8
  dv.setUint32(o + 20, stringsStart, true); dv.setUint32(o + 24, 0, true);
  for (let i = 0; i < count; i++) dv.setUint32(o + 28 + i * 4, offsets[i], true);
  let p = o + stringsStart;
  for (const e of encoded) { buf.set(e, p); p += e.length; }
  return buf;
}

test('ext: extensión final del nombre base', () => {
  assert.equal(ext('a/b/c.TXT'), 'txt');
  assert.equal(ext('libfoo.so'), 'so');
  assert.equal(ext('sin-extension'), '');
  assert.equal(ext('dir/'), '');
});

test('classifyEntry: zip-slip y rutas absolutas', () => {
  assert.deepEqual(classifyEntry({ name: '../../etc/passwd', compSize: 1, size: 1 }), ['path-traversal']);
  assert.deepEqual(classifyEntry({ name: 'a/../b', compSize: 1, size: 1 }), ['path-traversal']);
  assert.deepEqual(classifyEntry({ name: '/abs/x', compSize: 1, size: 1 }), ['absolute-path']);
  assert.deepEqual(classifyEntry({ name: 'C:\\win\\x', compSize: 1, size: 1 }), ['absolute-path']);
  assert.deepEqual(classifyEntry({ name: 'dir\\file', compSize: 1, size: 1 }), ['backslash-path']);
});

test('classifyEntry: doble extensión, ejecutables y anidados', () => {
  assert.deepEqual(classifyEntry({ name: 'factura.pdf.exe', compSize: 1, size: 1 }), ['double-extension', 'executable']);
  assert.deepEqual(classifyEntry({ name: 'foto.jpg.scr', compSize: 1, size: 1 }), ['double-extension', 'executable']);
  assert.deepEqual(classifyEntry({ name: 'tool.dll', compSize: 1, size: 1 }), ['executable']);
  assert.deepEqual(classifyEntry({ name: 'nested.zip', compSize: 1, size: 1 }), ['nested-archive']);
  // .pdf.zip: anidado pero no doble-extensión ejecutable
  assert.deepEqual(classifyEntry({ name: 'docs.pdf.zip', compSize: 1, size: 1 }), ['nested-archive']);
  assert.deepEqual(classifyEntry({ name: 'README.txt', compSize: 1, size: 1 }), []);
});

test('classifyEntry: ratio absurdo (zip-bomb) solo si la entrada es grande', () => {
  assert.deepEqual(classifyEntry({ name: 'bomb.bin', compSize: 1000, size: 5_000_000 }), ['high-ratio']);
  // pequeña pero muy comprimible: no alarma
  assert.deepEqual(classifyEntry({ name: 'small.txt', compSize: 10, size: 9999 }), []);
});

test('detectType: APK / JAR / OOXML / ODF / ZIP', () => {
  assert.equal(detectType(['AndroidManifest.xml', 'classes.dex', 'res/x']), 'APK');
  assert.equal(detectType(['AndroidManifest.xml', 'lib/arm64-v8a/liba.so']), 'APK');
  assert.equal(detectType(['META-INF/MANIFEST.MF', 'com/x/A.class']), 'JAR');
  assert.equal(detectType(['[Content_Types].xml', 'word/document.xml']), 'OOXML (docx/xlsx/pptx)');
  assert.equal(detectType(['mimetype', 'META-INF/container.xml']), 'ODF / EPUB');
  assert.equal(detectType(['a.txt', 'b/c.png']), 'ZIP');
});

test('parseAxmlStrings: recupera el string pool UTF-8', () => {
  const strs = ['manifest', 'uses-permission', 'android.permission.INTERNET', 'android.permission.READ_SMS'];
  const axml = buildAxmlUtf8(strs);
  assert.deepEqual(parseAxmlStrings(axml), strs);
});

test('parseAxmlStrings: no-AXML → [] (defensivo)', () => {
  assert.deepEqual(parseAxmlStrings(new TextEncoder().encode('<?xml version="1.0"?>')), []);
  assert.deepEqual(parseAxmlStrings(new Uint8Array(4)), []);
});

test('axmlPermissions: filtra y deduplica nombres de permiso', () => {
  const perms = axmlPermissions([
    'manifest', 'android.permission.INTERNET', 'android.permission.INTERNET',
    'com.foo.permission.C2D_MESSAGE', 'not.a.permission.lowercase', 'android.intent.action.MAIN',
  ]);
  assert.deepEqual(perms, ['android.permission.INTERNET', 'com.foo.permission.C2D_MESSAGE']);
});

test('analyze: ZIP genérico con totales y banderas', async () => {
  const zip = buildZip([
    { name: 'README.txt', text: 'hola' },
    { name: '../../escape.sh', text: '#!/bin/sh' },
    { name: 'setup.pdf.exe', text: 'MZ' },
    { name: 'inner.zip', text: 'PK' },
  ]);
  const res = await analyze(zip);
  assert.equal(res.ok, true);
  assert.equal(res.type, 'ZIP');
  assert.equal(res.totals.count, 4);
  assert.equal(res.totals.files, 4);
  const byName = Object.fromEntries(res.items.map(i => [i.name, i.flags]));
  assert.ok(byName['../../escape.sh'].includes('path-traversal'));
  assert.ok(byName['../../escape.sh'].includes('executable')); // .sh
  assert.ok(byName['setup.pdf.exe'].includes('double-extension'));
  assert.ok(byName['inner.zip'].includes('nested-archive'));
  assert.deepEqual(byName['README.txt'], []);
});

test('analyze: APK detecta dex/libs y extrae permisos del manifiesto', async () => {
  const axml = buildAxmlUtf8(['manifest', 'android.permission.INTERNET', 'android.permission.CAMERA']);
  const zip = buildZip([
    { name: 'AndroidManifest.xml', data: axml },
    { name: 'classes.dex', text: 'dex1' },
    { name: 'classes2.dex', text: 'dex2' },
    { name: 'lib/arm64-v8a/libnative.so', text: 'x' },
    { name: 'lib/x86_64/libnative.so', text: 'x' },
    { name: 'resources.arsc', text: 'x' },
  ]);
  const res = await analyze(zip);
  assert.equal(res.type, 'APK');
  assert.ok(res.apk);
  assert.deepEqual(res.apk.dexes, ['classes.dex', 'classes2.dex']);
  assert.deepEqual(res.apk.libs, ['arm64-v8a', 'x86_64']);
  assert.deepEqual(res.apk.permissions, ['android.permission.CAMERA', 'android.permission.INTERNET']);
});

test('analyze: no-ZIP → ok:false', async () => {
  const res = await analyze(new TextEncoder().encode('no soy un zip'));
  assert.equal(res.ok, false);
  assert.match(res.error, /Central Directory/);
});
