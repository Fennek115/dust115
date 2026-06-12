// Tests de Triage.pe — parser PE contra binarios reales (DLLs mingw, notepad).
// Carga spark-md5 antes que pe.js para que el imphash compute (es opcional).
// Oportunista: cada caso se salta si el archivo no está.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { requireModule } from './_load.mjs';
import { pe } from '../src/triage/pe.js'; // módulo ESM convertido (Etapa 3)

// pe.js usa el global SparkMD5 (opcional) para el imphash. Lo exponemos en
// globalThis para que el módulo ESM lo resuelva igual que en el navegador.
const SparkMD5 = requireModule('vendor/spark-md5.min.js');
globalThis.SparkMD5 = SparkMD5;
const Triage = { pe };

function readPE(p) {
  if (!existsSync(p)) return null;
  const buf = readFileSync(p);
  if (!(buf[0] === 0x4d && buf[1] === 0x5a)) return null; // MZ
  return new Uint8Array(buf);
}

const DLL32 = '/usr/i686-w64-mingw32/sys-root/mingw/bin/libssp-0.dll';
const DLL64 = '/usr/x86_64-w64-mingw32/sys-root/mingw/bin/libssp-0.dll';

test('SparkMD5 se cargó en el sandbox (para imphash)', () => {
  assert.equal(typeof SparkMD5, 'function');
});

test('parsea DLL mingw de 32-bit (i386)', { skip: readPE(DLL32) ? false : 'no hay DLL i686 mingw' }, () => {
  const pe = Triage.pe.parse(readPE(DLL32));
  assert.equal(pe.is64, false);
  assert.match(pe.machineName, /386|x86/i);
  assert.ok(pe.sections.length > 0, 'tiene secciones');
  assert.ok(pe.imports.length > 0, 'tiene imports (DT del PE)');
  assert.match(pe.imphash, /^[0-9a-f]{32}$/, 'imphash de 32 hex');
});

test('parsea DLL mingw de 64-bit (x86-64)', { skip: readPE(DLL64) ? false : 'no hay DLL x86_64 mingw' }, () => {
  const pe = Triage.pe.parse(readPE(DLL64));
  assert.equal(pe.is64, true);
  assert.match(pe.machineName, /x86-64|AMD|8664/i);
  assert.ok(pe.sections.some((s) => s.name === '.text'), 'tiene sección .text');
  assert.ok(pe.importCount > 0);
});

test('parsea notepad.exe si hay Windows montado', { skip: readPE('/mnt/c/Windows/System32/notepad.exe') ? false : 'no hay notepad.exe' }, () => {
  const pe = Triage.pe.parse(readPE('/mnt/c/Windows/System32/notepad.exe'));
  assert.ok(pe.optional && pe.optional.entryPoint > 0, 'entry point en pe.optional');
  assert.ok(pe.imports.length > 0, 'tiene imports');
});

test('no explota con un MZ truncado', () => {
  assert.doesNotThrow(() => Triage.pe.parse(new Uint8Array([0x4d, 0x5a, 0, 0, 0, 0])));
});
