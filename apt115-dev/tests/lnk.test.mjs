// Tests de lnk.js — header/CLSID y FILETIME (require directo).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { requireModule } from './_load.mjs';

const lnk = requireModule('tools/triage/lnk.js');

const CLSID = [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];

function lnkHeader() {
  const b = new Uint8Array(0x4C); // HeaderSize
  b[0] = 0x4C;
  for (let i = 0; i < 16; i++) b[4 + i] = CLSID[i];
  return b;
}

test('isLnk valida HeaderSize 0x4C + CLSID', () => {
  assert.equal(lnk.isLnk(lnkHeader()), true);
  const bad = lnkHeader(); bad[4] = 0xFF; // CLSID roto
  assert.equal(lnk.isLnk(bad), false);
  assert.equal(lnk.isLnk(new Uint8Array(10)), false, 'muy corto');
});

test('filetime convierte FILETIME (100ns desde 1601) a fecha', () => {
  // 116444736000000000 = epoch Unix (1970-01-01) en unidades FILETIME
  const ft = 116444736000000000n;
  const b = new Uint8Array(8);
  for (let i = 0; i < 8; i++) b[i] = Number((ft >> BigInt(8 * i)) & 0xffn);
  assert.match(lnk.filetime(b, 0), /^1970-01-01 00:00:00 UTC$/);
});

test('filetime devuelve null para 0 y para fuera de rango', () => {
  assert.equal(lnk.filetime(new Uint8Array(8), 0), null);
  assert.equal(lnk.filetime(new Uint8Array(4), 0), null, 'sin 8 bytes');
});

test('parse no explota con un LNK mínimo (solo header)', () => {
  assert.doesNotThrow(() => lnk.parse(lnkHeader()));
});
