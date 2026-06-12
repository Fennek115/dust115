// Tests de capa.js — normalización de APIs y matching de capacidades (require).
// No usamos run() (genera HTML y depende de window.Triage.util); probamos el
// núcleo de evaluación: normApi, gatherApis, evalClause sobre la base CAPS.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { capa } from '../src/triage/capa.js';

test('normApi: variantes A/W y alias Nt/Zw', () => {
  assert.deepEqual(capa.normApi('CreateFileA'), ['createfilea', 'createfile']);
  const nt = capa.normApi('NtAllocateVirtualMemory');
  assert.ok(nt.includes('ntallocatevirtualmemory'));
  assert.ok(nt.includes('zwallocatevirtualmemory'), 'alias Zw');
});

test('gatherApis recolecta y normaliza imports PE', () => {
  const ctx = { pe: { imports: [{ dll: 'kernel32.dll', funcs: [{ name: 'VirtualAllocEx' }, { name: 'CreateFileW' }] }] } };
  const apis = capa.gatherApis(ctx);
  assert.ok(apis.has('virtualallocex'));
  assert.ok(apis.has('createfile'), 'CreateFileW → createfile (sin sufijo)');
});

test('detecta "remote thread injection" con las 3 APIs requeridas', () => {
  const cap = capa.CAPS.find((c) => c.name === 'remote thread injection');
  assert.ok(cap, 'la CAP existe en la base');
  const ctx = { pe: { imports: [{ dll: 'k.dll', funcs: [
    { name: 'VirtualAllocEx' }, { name: 'WriteProcessMemory' }, { name: 'CreateRemoteThread' },
  ] }] } };
  const apis = capa.gatherApis(ctx);
  const allOk = cap.all.every((cl) => capa.evalClause(cl, apis, '').ok);
  assert.equal(allOk, true, 'las 3 cláusulas AND matchean');
});

test('NO detecta inyección en un binario benigno', () => {
  const cap = capa.CAPS.find((c) => c.name === 'remote thread injection');
  const ctx = { pe: { imports: [{ dll: 'k.dll', funcs: [{ name: 'GetStdHandle' }, { name: 'printf' }] }] } };
  const apis = capa.gatherApis(ctx);
  const allOk = cap.all.every((cl) => capa.evalClause(cl, apis, '').ok);
  assert.equal(allOk, false);
});
