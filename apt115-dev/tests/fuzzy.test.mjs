// Tests de Triage.fuzzy — TLSH (hash + comparación). Sandbox: carga el motor
// TLSH vendorizado + fuzzy.js. compare() es UI (DOM), no se testea acá.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadTriage } from './_load.mjs';

const sb = loadTriage('vendor/fuzzy/tlsh.min.js', 'tools/triage/fuzzy.js');
const fuzzy = sb.Triage.fuzzy;

test('el motor TLSH se cargó en el sandbox', () => {
  assert.equal(typeof sb.TLSH, 'object');
  assert.equal(typeof sb.TLSH.hash, 'function');
});

test('hashBytes produce un TLSH (70 hex) sobre datos con suficiente complejidad', () => {
  // 1024 bytes pseudo-aleatorios deterministas → TLSH exige ~50+ bytes variados
  const buf = new Uint8Array(1024);
  let x = 0x12345678;
  for (let i = 0; i < buf.length; i++) { x = (x * 1103515245 + 12345) & 0x7fffffff; buf[i] = x & 0xff; }
  const h = fuzzy.hashBytes(buf);
  assert.match(h, /^[0-9A-Fa-f]{70}$/, 'TLSH de 70 hex, got: ' + h);
});

test('hashBytes devuelve null para entrada trivial (sin complejidad)', () => {
  assert.equal(fuzzy.hashBytes(new Uint8Array(8)), null);
});

test('compare es función (handler de UI)', () => {
  assert.equal(typeof fuzzy.compare, 'function');
});
