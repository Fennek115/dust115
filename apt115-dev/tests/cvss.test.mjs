// CVSS Calculator (Fase C): v3.1 (fórmula oficial) y v4.0 (port fiel de FIRST).
// Los scores v4.0 esperados se capturaron de la implementación de referencia de
// FIRST (github.com/FIRSTdotorg/cvss-v4-calculator) corrida como oráculo.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { cvss } from '../src/tools/cvss.js';

const { compute, parse, rating } = cvss;
const score = (vec) => { const r = compute(vec); assert.equal(r.ok, true, vec + ' → ' + (r.error || '')); return r.result; };

test('parse: prefijo y métricas', () => {
  assert.equal(parse('').ok, false);
  assert.equal(parse('AV:N/AC:L').ok, false);            // sin prefijo
  const p = parse('CVSS:3.1/AV:N/AC:L');
  assert.equal(p.ok, true);
  assert.equal(p.version, '3.1');
  assert.deepEqual(p.metrics, { AV: 'N', AC: 'L' });
});

test('compute v3.1: faltante obligatoria / valor inválido', () => {
  assert.match(compute('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H').error, /obligatoria A/);
  assert.match(compute('CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').error, /inválido AV/);
});

test('compute v3.1: scores base canónicos (conocidos de FIRST)', () => {
  assert.equal(score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').base, 9.8);
  assert.equal(score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H').base, 10.0);
  assert.equal(score('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H').base, 5.9);
  assert.equal(score('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H').base, 7.8);
});

test('compute v3.1: severidad y all-X (temporal/env == base)', () => {
  const r = score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
  assert.equal(r.baseSeverity, 'Critical');
  assert.equal(r.temporal, r.base);
  assert.equal(r.environmental, r.base);
});

test('compute v3.1: temporal con E/RL/RC (fórmula oficial)', () => {
  assert.equal(score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C').temporal, 9.4);
  assert.equal(score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:U/RC:U').temporal, 8.3);
});

test('compute v3.1: environmental baja con requisitos/modificadas', () => {
  const r = score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:L/AR:L/MC:L/MI:L/MA:L');
  assert.ok(r.environmental < r.base);
});

// ── v4.0: batería contra el oráculo oficial de FIRST ──
const V4_ORACLE = [
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L", 1],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", 6.9],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:P/VC:L/VI:H/VA:L/SC:H/SI:L/SA:N", 7.1],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 8.1],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:H/IR:L/AR:M", 8.8],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSI:S/MSA:S", 10],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAV:P/MAC:H", 5.4],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:H/SC:L/SI:N/SA:N", 4.1],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 5.3],
];

test('compute v4.0: batería coincide con el oráculo de FIRST', () => {
  for (const [vec, expected] of V4_ORACLE) {
    const r = score(vec);
    assert.equal(r.score, expected, vec);
  }
});

test('compute v4.0: faltante obligatoria y suplementales aceptadas', () => {
  assert.match(compute('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N').error, /obligatoria SA/);
  // suplemental U:Red (multi-carácter) no debe romper la validación
  const r = compute('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:Red/R:A');
  assert.equal(r.ok, true);
  assert.equal(r.result.score, 9.3);
});

test('rating: cortes de severidad', () => {
  assert.equal(rating(0), 'None');
  assert.equal(rating(3.9), 'Low');
  assert.equal(rating(4), 'Medium');
  assert.equal(rating(7), 'High');
  assert.equal(rating(9), 'Critical');
});
