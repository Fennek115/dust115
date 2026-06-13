// Tests de netcalc.js — IPv4 (subred/clasificación), IPv6 (BigInt) y VLSM.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { netcalc } from '../src/tools/netcalc.js';

const rowVal = (r, key) => (r.rows.find(x => x[0] === key) || [])[1];

test('calc IPv4: red, broadcast, usables y clasificación RFC1918', () => {
  const r = netcalc.calc('10.10.14.7/24');
  assert.equal(rowVal(r, 'Network'), '10.10.14.0');
  assert.equal(rowVal(r, 'Broadcast'), '10.10.14.255');
  assert.equal(rowVal(r, 'Netmask'), '255.255.255.0');
  assert.equal(rowVal(r, 'Hosts usables'), (254).toLocaleString());
  assert.match(rowVal(r, 'Tipo'), /RFC1918 10\/8/);
});

test('calc IPv4: /31 no reserva net/broadcast', () => {
  const r = netcalc.calc('192.168.1.0/31');
  assert.equal(rowVal(r, 'Hosts usables'), (2).toLocaleString());
  assert.match(rowVal(r, 'Tipo'), /Privada \(RFC1918 192\.168/);
});

test('ipv6Info: expande, comprime (RFC5952), red y tipo global', () => {
  const r = netcalc.ipv6Info('2001:db8::1/64');
  assert.equal(r.compressed, '2001:db8::1');
  assert.equal(r.expanded, '2001:0db8:0000:0000:0000:0000:0000:0001');
  assert.equal(rowVal(r, 'Red'), '2001:db8::/64');
  assert.match(rowVal(r, 'Tipo'), /Global unicast/);
});

test('ipv6Info: loopback y link-local', () => {
  assert.match(rowVal(netcalc.ipv6Info('::1'), 'Tipo'), /Loopback/);
  assert.match(rowVal(netcalc.ipv6Info('fe80::1'), 'Tipo'), /Link-local/);
});

test('ipv6Info: IPv4 embebida (::ffff:1.2.3.4)', () => {
  const r = netcalc.ipv6Info('::ffff:1.2.3.4');
  assert.equal(r.compressed, '::ffff:102:304');
});

test('ipv6Info: prefijo fuera de rango da error', () => {
  assert.ok(netcalc.ipv6Info('2001:db8::1/200').err);
  assert.ok(netcalc.ipv6Info('no-es-ipv6').err);
});

test('vlsm: asigna largest-first, alineado, con CIDR y usables correctos', () => {
  const r = netcalc.vlsm('10.0.0.0/24', [
    { name: 'Ventas', size: 50 },
    { name: 'TI', size: 25 },
    { name: 'Enlace', size: 2 },
  ]);
  assert.equal(r.rows.length, 3);
  assert.deepEqual(
    r.rows.map(x => [x.name, x.network + '/' + x.prefix, x.usable]),
    [['Ventas', '10.0.0.0/26', 62], ['TI', '10.0.0.64/27', 30], ['Enlace', '10.0.0.96/30', 2]],
  );
  assert.equal(r.rows[0].mask, '255.255.255.192');
  assert.equal(r.used, 100);
  assert.equal(r.free, 156);
});

test('vlsm: marca lo que no entra en el bloque base', () => {
  const r = netcalc.vlsm('10.0.0.0/29', [{ name: 'Grande', size: 100 }]);
  assert.ok(r.rows[0].err, 'no debería entrar 100 hosts en /29');
});
