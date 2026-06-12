// Tests de Triage.util — detección de tipo (magic bytes), entropía, strings.
// Núcleo puro, sin globals del navegador → 100% reproducible.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bytesOf } from './_load.mjs';
import { util } from '../src/triage/util.js'; // módulo ESM convertido (Etapa 3)

test('detectType reconoce magic bytes de ejecutables', () => {
  assert.equal(util.detectType(bytesOf('MZ\x90\x00')).ext, 'exe/dll');
  assert.equal(util.detectType(bytesOf('MZ\x90\x00')).cat, 'exec');
  assert.equal(util.detectType(new Uint8Array([0x7F, 0x45, 0x4C, 0x46])).ext, 'elf/so');
  assert.equal(util.detectType(new Uint8Array([0xCF, 0xFA, 0xED, 0xFE])).ext, 'macho');
});

test('detectType reconoce documentos e imágenes', () => {
  assert.equal(util.detectType(bytesOf('%PDF-1.7')).ext, 'pdf');
  assert.equal(util.detectType(new Uint8Array([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])).ext, 'png');
  assert.equal(util.detectType(bytesOf('GIF89a')).ext, 'gif');
});

test('detectType desambigua ZIP → OOXML (docx)', () => {
  // refineZip exige [Content_Types].xml + word/ (como un .docx real)
  const zip = bytesOf('PK\x03\x04' + '.'.repeat(22) + '[Content_Types].xml' + '.'.repeat(8) + 'word/document.xml');
  assert.equal(util.detectType(zip).ext, 'docx');
});

test('entropy: 0 para datos uniformes, ~8 para máxima variedad', () => {
  const flat = new Uint8Array(256).fill(0x41);
  assert.equal(util.entropy(flat, 0, flat.length), 0);
  const full = new Uint8Array(256);
  for (let i = 0; i < 256; i++) full[i] = i; // los 256 valores, equiprobables → 8 bits
  assert.equal(util.entropy(full, 0, full.length), 8);
});

test('extractStrings encuentra ASCII y UTF-16LE embebidos', () => {
  const buf = bytesOf('\x00\x01HELLO_WORLD\x00\xffmalware.exe\x00');
  const res = util.extractStrings(buf, 5);
  const ascii = res.strings.map((s) => s.s);
  assert.ok(ascii.includes('HELLO_WORLD'), 'debería extraer HELLO_WORLD');
  assert.ok(ascii.includes('malware.exe'), 'debería extraer malware.exe');

  // UTF-16LE: cada char seguido de 0x00
  const u16 = bytesOf('P\x00o\x00w\x00e\x00r\x00S\x00h\x00e\x00l\x00l\x00');
  const r2 = util.extractStrings(u16, 5);
  assert.ok(r2.strings.some((s) => s.type === 'utf16' && s.s === 'PowerShell'));
});

test('extractStrings respeta minLen', () => {
  const buf = bytesOf('ab\x00abcdefgh\x00');
  const res = util.extractStrings(buf, 5);
  const found = res.strings.map((s) => s.s);
  assert.ok(!found.includes('ab'), 'no debería incluir strings cortos');
  assert.ok(found.includes('abcdefgh'));
});
