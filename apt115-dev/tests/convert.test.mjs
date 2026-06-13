// Convert / Hash — secciones nuevas de Fase C: timestamp y regex tester.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { convert } from '../src/tools/convert.js';

const { tsConvert, regexTest, hashid } = convert;

test('tsConvert: epoch en segundos', () => {
  const r = tsConvert('1700000000');
  assert.equal(r.ok, true);
  assert.equal(r.srcKind, 'epoch en segundos');
  assert.equal(r.iso, '2023-11-14T22:13:20.000Z');
  assert.equal(r.epochS, 1700000000);
  assert.equal(r.epochMs, 1700000000000);
});

test('tsConvert: epoch en milisegundos y fecha ISO dan el mismo instante', () => {
  const ms = tsConvert('1700000000000');
  assert.equal(ms.srcKind, 'epoch en milisegundos');
  assert.equal(ms.iso, '2023-11-14T22:13:20.000Z');
  const iso = tsConvert('2023-11-14T22:13:20Z');
  assert.equal(iso.srcKind, 'fecha');
  assert.equal(iso.epochS, 1700000000);
});

test('tsConvert: entradas inválidas', () => {
  assert.equal(tsConvert('').ok, false);
  assert.equal(tsConvert('no es fecha').ok, false);
});

test('regexTest: matches simples y conteo', () => {
  const r = regexTest('\\d+', 'a1b22c333');
  assert.equal(r.ok, true);
  assert.equal(r.count, 3);
  assert.deepEqual(r.matches.map(m => m.match), ['1', '22', '333']);
  assert.equal(r.matches[1].index, 3);
});

test('regexTest: sintaxis /patrón/flags y grupos de captura', () => {
  const r = regexTest('/([a-z])(\\d)/gi', 'A1 b2');
  assert.equal(r.flags.includes('i'), true);
  assert.equal(r.count, 2);
  assert.deepEqual(r.matches[0].groups, ['A', '1']);
  assert.deepEqual(r.matches[1].groups, ['b', '2']);
});

test('regexTest: regex inválida y patrón vacío', () => {
  assert.equal(regexTest('(', 'x').ok, false);
  assert.equal(regexTest('', 'x').ok, false);
});

test('regexTest: match de ancho cero no cuelga', () => {
  const r = regexTest('a*', 'baa');
  assert.equal(r.ok, true);
  assert.ok(r.count > 0 && r.count < 100); // termina, no loop infinito
});

test('hashid: sigue reconociendo formatos (no se rompió al agregar el return)', () => {
  assert.match(hashid('d41d8cd98f00b204e9800998ecf8427e'), /MD5/);
  assert.match(hashid('$2b$12$' + 'x'.repeat(53)), /bcrypt/);
});
