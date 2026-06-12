// Tests del motor YARA (libyara-wasm) — compilación y matching reales, offline.
// Verifica el contrato que asume tools/yara/yara.js: compileErrors con flag
// `warning`, y el comportamiento todo-o-nada (un error no-warning → 0 matches).

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import path from 'node:path';
import { APT_DIR, bytesOf } from './_load.mjs';

const require = createRequire(import.meta.url);
let engine;

before(async () => {
  const Module = require(path.join(APT_DIR, 'vendor/yara/libyara-wasm.js'));
  engine = await Module();
});

function vec(v) { const a = []; for (let i = 0; i < v.size(); i++) a.push(v.get(i)); return a; }
function run(bytes, rules) {
  const res = engine.run(bytes, rules);
  const msgs = vec(res.compileErrors);
  return {
    errors: msgs.filter((m) => m.warning === false),
    warnings: msgs.filter((m) => m.warning !== false),
    matched: vec(res.matchedRules).map((r) => r.ruleName),
  };
}

const EICAR = bytesOf('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');

test('una regla compila y matchea su string', () => {
  const r = run(EICAR, 'rule eicar { strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $a }');
  assert.equal(r.errors.length, 0);
  assert.deepEqual(r.matched, ['eicar']);
});

test('condición sobre uint16 (cabecera MZ)', () => {
  const r = run(bytesOf('MZ\x90\x00'), 'rule mz { condition: uint16(0) == 0x5A4D }');
  assert.deepEqual(r.matched, ['mz']);
  const r2 = run(bytesOf('XX'), 'rule mz { condition: uint16(0) == 0x5A4D }');
  assert.equal(r2.matched.length, 0);
});

test('todo-o-nada: un error no-warning aborta TODAS las reglas', () => {
  const rules = [
    'rule ok { strings: $a = "EICAR" condition: $a }',
    'rule bad { condition: filename matches /x/ }', // variable externa no definida → error
  ].join('\n');
  const r = run(EICAR, rules);
  assert.equal(r.errors.length, 1, 'reporta el error');
  assert.equal(r.errors[0].warning, false);
  assert.equal(typeof r.errors[0].lineNumber, 'number', 'el error trae lineNumber (clave para el filtrado de packs)');
  assert.equal(r.matched.length, 0, 'NINGUNA regla corre, ni siquiera la válida');
});

test('el módulo pe está disponible en este build', () => {
  const r = run(bytesOf('MZ' + '\x00'.repeat(64)), 'import "pe"\nrule p { condition: uint16(0)==0x5A4D }');
  assert.equal(r.errors.length, 0, 'import "pe" no debe dar error');
});
