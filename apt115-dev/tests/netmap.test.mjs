// Tests de netmap.js — parseo de nmap XML (-oX) y grepable (-oG) + agrupación.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { netmap } from '../src/tools/netmap.js';

const XML = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><hostname name="dc01"/>
<ports>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Samba smbd" version="4.10"/></port>
<port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/></port>
<port protocol="tcp" portid="9999"><state state="closed"/></port>
</ports>
<os><osmatch name="Linux 5.4" accuracy="95"/></os>
</host>
</nmaprun>`;

const GNMAP = [
  'Host: 10.0.0.5 (dc01.lab.local)\tStatus: Up',
  'Host: 10.0.0.5 (dc01.lab.local)\tPorts: 53/open/tcp//domain//, 88/open/tcp//kerberos-sec//, 445/open/tcp//microsoft-ds//\tIgnored State: closed (995)',
  'Host: 10.0.1.20 (web01)\tPorts: 80/open/tcp//http//, 22/open/tcp//ssh//',
].join('\n');

test('parseNmapXml: host, hostname, OS y sólo puertos abiertos', () => {
  const hosts = netmap.parseNmapXml(XML);
  assert.equal(hosts.length, 1);
  const h = hosts[0];
  assert.equal(h.ip, '10.0.0.5');
  assert.equal(h.hostname, 'dc01');
  assert.equal(h.os, 'Linux 5.4');
  assert.equal(h.ports.length, 2, 'descarta el puerto closed');
  const smb = h.ports.find(p => p.port === 445);
  assert.equal(smb.service, 'microsoft-ds');
  assert.equal(smb.product, 'Samba smbd');
  assert.equal(smb.version, '4.10');
});

test('parseGnmap: agrega varios hosts y parsea puertos abiertos', () => {
  const hosts = netmap.parseGnmap(GNMAP);
  assert.equal(hosts.length, 3, 'la línea Status y las dos con Ports → 3 entradas');
  const dc = hosts.find(h => h.ip === '10.0.0.5' && h.ports.length);
  assert.equal(dc.hostname, 'dc01.lab.local');
  assert.deepEqual(dc.ports.map(p => p.port).sort((a, b) => a - b), [53, 88, 445]);
  assert.equal(dc.ports.find(p => p.port === 88).service, 'kerberos-sec');
});

test('parse: autodetecta formato', () => {
  assert.equal(netmap.parse(XML).fmt, 'xml');
  assert.equal(netmap.parse(GNMAP).fmt, 'gnmap');
  assert.equal(netmap.parse('texto cualquiera').fmt, '');
});

test('isJuicy: resalta SMB/RDP/Kerberos por puerto o servicio', () => {
  assert.ok(netmap.isJuicy({ port: 445, service: 'microsoft-ds' }));
  assert.ok(netmap.isJuicy({ port: 3389, service: '' }));
  assert.ok(netmap.isJuicy({ port: 88, service: 'kerberos-sec' }));
  assert.ok(!netmap.isJuicy({ port: 9999, service: '' }));
});

test('groupBySubnet + toMarkdown: agrupa por /24 y marca jugosos', () => {
  const hosts = netmap.parseGnmap(GNMAP);
  const groups = netmap.groupBySubnet(hosts);
  assert.deepEqual(groups.map(g => g[0]), ['10.0.0.0/24', '10.0.1.0/24']);
  const md = netmap.toMarkdown(hosts);
  assert.match(md, /## 10\.0\.0\.0\/24/);
  assert.match(md, /445\/tcp/);
  assert.ok(md.includes('⭐'), 'al menos un servicio jugoso marcado');
});
