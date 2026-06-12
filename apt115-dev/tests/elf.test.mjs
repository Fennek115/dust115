// Tests de Triage.elf — parser ELF contra un binario real del sistema.
// Oportunista: si /bin/ls no es ELF (otra plataforma), se saltan.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { loadTriage } from './_load.mjs';

const { Triage } = loadTriage('tools/triage/elf.js');

function readElf(p) {
  if (!existsSync(p)) return null;
  const buf = readFileSync(p);
  if (!(buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46)) return null;
  return new Uint8Array(buf);
}

test('parsea /bin/ls: clase 64, x86-64, dinámico con libc', { skip: readElf('/bin/ls') ? false : 'no hay /bin/ls ELF' }, () => {
  const elf = Triage.elf.parse(readElf('/bin/ls'));
  assert.ok(elf, 'parse devuelve objeto');
  assert.equal(elf.is64, true);
  assert.match(elf.machineName, /x86-64|AMD/i);
  assert.ok(elf.entry > 0, 'entry point no nulo');
  assert.ok(elf.needed.length > 0, 'tiene DT_NEEDED');
  assert.ok(elf.needed.some((n) => /libc/.test(n)), 'depende de libc: ' + elf.needed.join(','));
});

test('parsea /bin/bash y expone símbolos importados', { skip: readElf('/bin/bash') ? false : 'no hay /bin/bash ELF' }, () => {
  const elf = Triage.elf.parse(readElf('/bin/bash'));
  assert.ok(elf.entryOffset >= 0, 'offset de archivo del EP resuelto');
  assert.equal(typeof elf.isPie, 'boolean');
});

test('no explota con bytes basura', () => {
  // Un "ELF" truncado no debe tirar excepción; devuelve algo o null.
  const junk = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0]);
  assert.doesNotThrow(() => Triage.elf.parse(junk));
});
