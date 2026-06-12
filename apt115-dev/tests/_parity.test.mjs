// Paridad de migración ESM (TRANSITORIO — borrar cuando termine la Etapa 3).
//
// Garantiza que cada módulo convertido a ESM en src/ produce resultados IDÉNTICOS
// a su versión vieja (global-script en tools/triage/, cargada en sandbox). Es la
// red de seguridad contra drift mientras conviven las dos formas.
//
// Para que la comparación sea determinista, NO proveemos los globals opcionales
// (SparkMD5/TLSH) a NINGUNA de las dos → ambas saltan imphash/telfhash igual y el
// resto del parseo debe ser byte-idéntico.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { loadTriage, bytesOf } from './_load.mjs';

// Igualdad ESTRUCTURAL entre realms: los objetos del módulo viejo se crean en el
// realm del sandbox vm (prototipos distintos a los del ESM en el realm principal),
// así que deepStrictEqual falla por prototipo aunque la estructura sea idéntica.
// JSON.stringify normaliza a estructura plana y compara contenido real.
const jsonEq = (a, b, msg) => assert.equal(JSON.stringify(a), JSON.stringify(b), msg);

// elf.js (ESM) hace `typeof window.TLSH`; sin window eso tira ReferenceError.
// Proveemos window pero NO TLSH ni SparkMD5 → ambas versiones saltan los hashes.
globalThis.window = globalThis;

// Viejo (global-script en sandbox, sin spark/tlsh) vs nuevo (ESM).
const old = loadTriage(
  'tools/triage/util.js', 'tools/triage/pe.js', 'tools/triage/elf.js',
  'tools/triage/macho.js', 'tools/triage/fuzzy.js'
).Triage;
const { util } = await import('../src/triage/util.js');
const { pe } = await import('../src/triage/pe.js');
const { elf } = await import('../src/triage/elf.js');
const { macho } = await import('../src/triage/macho.js');
const { fuzzy } = await import('../src/triage/fuzzy.js');

test('util: detectType / entropy / extractStrings idénticos', () => {
  const samples = [
    bytesOf('MZ\x90\x00'), bytesOf('%PDF-1.7'), new Uint8Array([0x7F, 0x45, 0x4C, 0x46]),
    bytesOf('\x00HELLO_WORLD\x00malware.exe\x00'), bytesOf('PK\x03\x04[Content_Types].xml word/'),
  ];
  for (const s of samples) {
    jsonEq(util.detectType(s), old.util.detectType(s), 'detectType');
    assert.equal(util.entropy(s, 0, s.length), old.util.entropy(s, 0, s.length));
    jsonEq(util.extractStrings(s, 4), old.util.extractStrings(s, 4), 'extractStrings');
  }
});

function readMagic(p, m0, m1) {
  if (!existsSync(p)) return null;
  const b = readFileSync(p);
  if (b[0] !== m0 || b[1] !== m1) return null;
  return new Uint8Array(b);
}

test('pe.parse idéntico (sin SparkMD5 en ninguno)', { skip: readMagic('/usr/x86_64-w64-mingw32/sys-root/mingw/bin/libssp-0.dll', 0x4d, 0x5a) ? false : 'no hay DLL' }, () => {
  const b = readMagic('/usr/x86_64-w64-mingw32/sys-root/mingw/bin/libssp-0.dll', 0x4d, 0x5a);
  jsonEq(pe.parse(b), old.pe.parse(b), 'pe.parse');
});

test('elf.parse idéntico (sin TLSH en ninguno)', { skip: readMagic('/bin/ls', 0x7f, 0x45) ? false : 'no hay /bin/ls' }, () => {
  const b = readMagic('/bin/ls', 0x7f, 0x45);
  jsonEq(elf.parse(b), old.elf.parse(b), 'elf.parse');
});

test('los módulos ESM exportan la misma superficie pública', () => {
  assert.deepEqual(Object.keys(util).sort(), Object.keys(old.util).sort());
  assert.deepEqual(Object.keys(fuzzy).sort(), Object.keys(old.fuzzy).sort());
  assert.equal(typeof pe.parse, typeof old.pe.parse);
  assert.equal(typeof elf.parse, typeof old.elf.parse);
  assert.equal(typeof macho.parse, typeof old.macho.parse);
});
