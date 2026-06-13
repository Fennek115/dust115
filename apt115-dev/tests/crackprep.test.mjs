// Cracking-prep (Fase D): perfilador CUPP-lite, keyspace de máscaras y reglas.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { crackprep } from '../src/tools/crackprep.js';

const { profile, extractDateNums, leetVariants, maskKeyspace, applyRule, applyRules } = crackprep;

test('extractDateNums: varios formatos de fecha', () => {
  const a = extractDateNums('1990-05-15');
  assert.ok(a.includes('1990') && a.includes('90') && a.includes('1505') && a.includes('15051990'));
  const b = extractDateNums('15/05/1990');
  assert.ok(b.includes('1990') && b.includes('1505'));
  assert.deepEqual(extractDateNums('1985'), ['1985', '85']);
});

test('leetVariants: sustituciones 1337', () => {
  const v = leetVariants('password');
  assert.ok(v.includes('p455w0rd'));        // a→4 s→5 o→0
  assert.ok(v.some(x => x.includes('@')));   // variante con @ para a
});

test('profile: incluye base, capitalización, leet, año y sufijos', () => {
  const list = profile({ first: 'john', birth: '1990-05-15' }, { walks: false });
  assert.ok(list.includes('john'));
  assert.ok(list.includes('John'));
  assert.ok(list.includes('j0hn'));          // leet
  assert.ok(list.includes('john1990'));      // año al final
  assert.ok(list.includes('john1'));         // el 1 al final
  assert.ok(list.includes('john!'));         // símbolo
  assert.ok(list.includes('john1990!'));     // número + símbolo
});

test('profile: combina pares de palabras y respeta el límite', () => {
  const list = profile({ first: 'john', pet: 'rex' }, { walks: false });
  assert.ok(list.includes('johnrex') || list.includes('john.rex'));
  const capped = profile({ first: 'john', last: 'smith', pet: 'rex', company: 'acme', extra: 'a,b,c' }, { limit: 50 });
  assert.ok(capped.length <= 50);
  assert.equal(new Set(capped).size, capped.length); // sin duplicados
});

test('profile: walks incluidos/excluidos según opción', () => {
  assert.ok(profile({ first: 'x' }, { walks: true }).includes('qwerty'));
  assert.ok(!profile({ first: 'x' }, { walks: false }).includes('qwerty'));
});

test('maskKeyspace: producto de charsets', () => {
  assert.equal(maskKeyspace('?l?l?l?l', 1e9).combinations, String(26 ** 4));
  const r = maskKeyspace('?u?l?l?d?d', 1e9);
  assert.equal(r.combinations, String(26 * 26 * 26 * 10 * 10));
  assert.equal(r.length, 5);
  // literales cuentan como factor 1
  assert.equal(maskKeyspace('abc?d', 1e9).combinations, '10');
});

test('maskKeyspace: charsets grandes con BigInt (sin overflow)', () => {
  const r = maskKeyspace('?a?a?a?a?a?a?a?a?a?a', 1e9); // 95^10
  assert.equal(r.combinations, (95n ** 10n).toString());
});

test('maskKeyspace: errores', () => {
  assert.equal(maskKeyspace('', 1e9).ok, false);
  assert.equal(maskKeyspace('?z', 1e9).ok, false);
  assert.equal(maskKeyspace('?', 1e9).ok, false);
});

test('applyRule: funciones hashcat conocidas', () => {
  assert.equal(applyRule('password', ':'), 'password');
  assert.equal(applyRule('password', 'c'), 'Password');
  assert.equal(applyRule('Password', 'l'), 'password');
  assert.equal(applyRule('pass', 'u'), 'PASS');
  assert.equal(applyRule('password', '$1'), 'password1');
  assert.equal(applyRule('password', '^x'), 'xpassword');
  assert.equal(applyRule('password', 'r'), 'drowssap');
  assert.equal(applyRule('pass', 'd'), 'passpass');
  assert.equal(applyRule('password', 'so0'), 'passw0rd');
  assert.equal(applyRule('password', 'sa@ ss$'), 'p@$$word');
  assert.equal(applyRule('password', 'c $1 $2 $3'), 'Password123');
  assert.equal(applyRule('password', '[ ]'), 'asswor');     // borra primera y última
  assert.equal(applyRule('abc', 'T0'), 'Abc');              // toggle pos 0
});

test('applyRules: varias líneas → preview', () => {
  const res = applyRules('admin', 'c\n$1\nr');
  assert.deepEqual(res.map(x => x.result), ['Admin', 'admin1', 'nimda']);
});
