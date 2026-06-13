// Vault: serialización de notas a markdown + escritor/lector ZIP (Fase A4).

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  crc32, slugifyTitle, noteToMarkdown, parseMarkdownNote,
  buildZip, parseZip, inflateRaw, entryText, notesToZipEntries, mergeNotes,
} from '../src/app/vault.js';

const dec = new TextDecoder();
const enc = new TextEncoder();

test('crc32 coincide con valores conocidos', () => {
  // CRC-32 de "" = 0; de "123456789" = 0xCBF43926 (vector de referencia).
  assert.equal(crc32(new Uint8Array(0)), 0);
  assert.equal(crc32(enc.encode('123456789')), 0xCBF43926);
});

test('slugifyTitle: minúsculas, guiones, conserva acentos, fallback a id', () => {
  assert.equal(slugifyTitle('Recon & Privesc!', 'n_1'), 'recon-privesc');
  assert.equal(slugifyTitle('  Días de Polvo  ', 'n_2'), 'días-de-polvo');
  assert.equal(slugifyTitle('', 'n_3'), 'n_3');
  assert.equal(slugifyTitle('***', 'n_4'), 'n_4');
});

test('noteToMarkdown ↔ parseMarkdownNote: round-trip', () => {
  const note = { id: 'n_42', title: 'Mi: Nota "rara"', body: '# Hola\n\nver [[Otra]]\n', ts: '6/12/2026, 20:57:00' };
  const md = noteToMarkdown(note);
  assert.match(md, /^---\n/);
  assert.match(md, /\[\[Otra\]\]/); // wikilinks preservados
  const back = parseMarkdownNote('mi-nota.md', md);
  assert.equal(back.id, note.id);
  assert.equal(back.title, note.title);
  assert.equal(back.ts, note.ts);
  assert.equal(back.body, note.body);
});

test('parseMarkdownNote: sin frontmatter deriva título del nombre de archivo', () => {
  const n = parseMarkdownNote('algun/path/Plan-de-ataque.md', 'cuerpo suelto');
  assert.equal(n.title, 'Plan-de-ataque');
  assert.equal(n.body, 'cuerpo suelto');
  assert.ok(n.id && n.ts);
});

test('buildZip → parseZip: round-trip con CRC y contenido', () => {
  const entries = [
    { name: 'recon.md', text: '# Recon\n[[Privesc]]' },
    { name: 'días.md', text: 'acentos ñ' }, // nombre UTF-8
  ];
  const zip = buildZip(entries);
  // EOCD presente al final
  const dv = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  assert.equal(dv.getUint32(zip.length - 22, true), 0x06054b50);
  const got = parseZip(zip);
  assert.equal(got.length, 2);
  assert.equal(got[0].name, 'recon.md');
  assert.equal(got[1].name, 'días.md');
  assert.equal(got[0].method, 0); // STORE
  assert.equal(dec.decode(got[0].data), '# Recon\n[[Privesc]]');
  assert.equal(got[0].crc, crc32(enc.encode('# Recon\n[[Privesc]]')));
});

test('parseZip: ZIP inválido lanza', () => {
  assert.throws(() => parseZip(enc.encode('no soy un zip')), /End of Central Directory/);
});

test('inflateRaw + entryText: lee una entrada DEFLATE (método 8)', async () => {
  // Comprimir con CompressionStream y verificar que el lector la infla.
  const text = 'payload markdown '.repeat(20);
  const cs = new CompressionStream('deflate-raw');
  const w = cs.writable.getWriter();
  w.write(enc.encode(text)); w.close();
  const comp = new Uint8Array(await new Response(cs.readable).arrayBuffer());
  assert.equal(dec.decode(await inflateRaw(comp)), text);
  assert.equal(await entryText({ name: 'x.md', method: 8, data: comp }), text);
});

test('notesToZipEntries: nombres únicos ante títulos colisionantes', () => {
  const e = notesToZipEntries([
    { id: 'a', title: 'Recon', body: '', ts: '' },
    { id: 'b', title: 'Recon', body: '', ts: '' },
  ]);
  assert.equal(e[0].name, 'recon.md');
  assert.equal(e[1].name, 'recon-2.md');
});

test('mergeNotes: misma id reemplaza en su lugar, id nueva va al frente', () => {
  const base = [
    { id: 'a', title: 'A', body: 'vieja', ts: '' },
    { id: 'b', title: 'B', body: '', ts: '' },
  ];
  const merged = mergeNotes(base, [
    { id: 'a', title: 'A', body: 'NUEVA', ts: '' },
    { id: 'c', title: 'C', body: '', ts: '' },
  ]);
  assert.deepEqual(merged.map(n => n.id), ['c', 'a', 'b']);
  assert.equal(merged.find(n => n.id === 'a').body, 'NUEVA');
});

test('round-trip completo: notas → zip → parse → notas', () => {
  const notes = [
    { id: 'n_1', title: 'Recon', body: '[[Loot]] y notas', ts: '6/12/2026, 10:00:00' },
    { id: 'n_2', title: 'Loot', body: 'botín', ts: '6/12/2026, 11:00:00' },
  ];
  const zip = buildZip(notesToZipEntries(notes));
  const back = parseZip(zip).map(e => parseMarkdownNote(e.name, dec.decode(e.data)));
  assert.deepEqual(back, notes);
});
