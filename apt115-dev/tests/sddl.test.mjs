// SID / SDDL decoder (Fase D): SIDs well-known, RIDs de dominio y descriptores SDDL.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { sddl } from '../src/tools/sddl.js';

const { decodeSid, parseSddl, decode } = sddl;

test('decodeSid: SIDs well-known', () => {
  assert.equal(decodeSid('S-1-1-0').name, 'Everyone');
  assert.equal(decodeSid('S-1-5-18').name, 'Local System (SYSTEM)');
  assert.equal(decodeSid('S-1-5-32-544').name, 'BUILTIN\\Administrators');
  assert.equal(decodeSid('S-1-5-32-544').category, 'well-known');
});

test('decodeSid: RID de dominio', () => {
  const d = decodeSid('S-1-5-21-3623811015-3361044348-30300820-500');
  assert.equal(d.ok, true);
  assert.equal(d.name, 'DOMAIN\\Administrator');
  assert.equal(d.rid, '500');
  assert.equal(d.domain, 'S-1-5-21-3623811015-3361044348-30300820');
  assert.equal(decodeSid('S-1-5-21-1-2-3-512').name, 'DOMAIN\\Domain Admins');
});

test('decodeSid: objeto de dominio no-conocido y autoridad', () => {
  const d = decodeSid('S-1-5-21-1-2-3-1108');
  assert.equal(d.category, 'domain object');
  assert.equal(d.rid, '1108');
  assert.equal(decodeSid('S-1-5-12').authority, 'NT Authority');
});

test('decodeSid: inválido', () => {
  assert.equal(decodeSid('no-soy-un-sid').ok, false);
  assert.equal(decodeSid('').ok, false);
});

test('parseSddl: owner/group y DACL con ACEs', () => {
  const r = parseSddl('O:BAG:DUD:(A;;FA;;;SY)(A;OICI;FR;;;BU)');
  assert.equal(r.ok, true);
  assert.equal(r.owner.name, 'BUILTIN\\Administrators');
  assert.equal(r.group.name, 'Domain Users');
  assert.equal(r.dacl.aces.length, 2);

  const a0 = r.dacl.aces[0];
  assert.equal(a0.type, 'Access Allowed');
  assert.deepEqual(a0.rights.names, ['FILE_ALL_ACCESS']);
  assert.equal(a0.trustee.name, 'Local System (SYSTEM)');

  const a1 = r.dacl.aces[1];
  assert.deepEqual(a1.flags, ['Object Inherit', 'Container Inherit']);
  assert.deepEqual(a1.rights.names, ['FILE_GENERIC_READ']);
  assert.equal(a1.trustee.name, 'BUILTIN\\Users');
});

test('parseSddl: flags de ACL (Protected/Auto-inherited) y SACL', () => {
  const r = parseSddl('D:PAI(D;;FA;;;WD)S:(AU;SA;FA;;;WD)');
  assert.ok(r.dacl.flags.includes('Protected'));
  assert.ok(r.dacl.flags.includes('Auto-inherited'));
  assert.equal(r.dacl.aces[0].type, 'Access Denied');
  assert.equal(r.dacl.aces[0].trustee.name, 'Everyone (World)');
  assert.equal(r.sacl.aces[0].type, 'System Audit');
});

test('parseSddl: derechos en hex y SID completo como trustee', () => {
  const r = parseSddl('D:(A;;0x1200a9;;;S-1-5-21-1-2-3-1234)');
  assert.equal(r.dacl.aces[0].rights.hex, '0x1200a9');
  assert.equal(r.dacl.aces[0].trustee.name, 'DOMAIN principal (RID 1234)');
});

test('decode: autodetecta SID vs SDDL', () => {
  assert.equal(decode('S-1-5-18').kind, 'sid');
  assert.equal(decode('O:BAG:BA').kind, 'sddl');
  assert.equal(decode('').ok, false);
});
