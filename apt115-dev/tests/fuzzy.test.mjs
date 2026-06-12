// Tests de fuzzy (TLSH) — módulo ESM convertido (Etapa 3). compare() es UI, no se testea.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { APT_DIR } from './_load.mjs';
import { fuzzy } from '../src/triage/fuzzy.js';

// El motor TLSH es un IIFE vendorizado que cuelga TLSH del global. fuzzy.js lo
// lee como window.TLSH, así que proveemos window y evaluamos el motor en el global.
globalThis.window = globalThis;
(0, eval)(readFileSync(path.join(APT_DIR, 'vendor/fuzzy/tlsh.min.js'), 'utf8'));

test('el motor TLSH quedó disponible como global', () => {
  assert.equal(typeof globalThis.TLSH, 'object');
  assert.equal(typeof globalThis.TLSH.hash, 'function');
});

test('hashBytes produce un TLSH (70 hex) sobre datos con suficiente complejidad', () => {
  const buf = new Uint8Array(1024);
  let x = 0x12345678;
  for (let i = 0; i < buf.length; i++) { x = (x * 1103515245 + 12345) & 0x7fffffff; buf[i] = x & 0xff; }
  assert.match(fuzzy.hashBytes(buf), /^[0-9A-Fa-f]{70}$/);
});

test('hashBytes devuelve null para entrada trivial', () => {
  assert.equal(fuzzy.hashBytes(new Uint8Array(8)), null);
});

test('compare es función (handler de UI)', () => {
  assert.equal(typeof fuzzy.compare, 'function');
});
