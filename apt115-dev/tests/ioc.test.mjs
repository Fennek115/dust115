// Tests de ioc.js — refang/defang y extracción de indicadores (require directo).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { requireModule } from './_load.mjs';

const ioc = requireModule('tools/ioc/ioc.js');

test('refang normaliza la ofuscación típica de reportes', () => {
  const r = ioc.refang('hxxps://evil[.]com y 185[.]220[.]101[.]4');
  assert.ok(r.includes('https://evil.com'));
  assert.ok(r.includes('185.220.101.4'));
});

test('defang vuelve a ofuscar para compartir seguro', () => {
  const d = ioc.defang('http://evil.com');
  assert.ok(/hxxp/.test(d));
  assert.ok(/\[\.\]/.test(d));
});

test('extract saca IPs, dominios, URLs, hashes, CVE y ATT&CK (refangueando)', () => {
  const report = [
    'El C2 hxxps://evil[.]com/panel resolvía a 185[.]220[.]101[.]4',
    'Hash del dropper: 44d88612fea8a8f36de82e1278abb02f',
    'sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'Explota CVE-2021-44228 (T1190), persiste con T1547.001',
    'contacto: actor@evil[.]com',
  ].join('\n');
  const r = ioc.extract(report);
  assert.deepEqual(r.ipv4, ['185.220.101.4']);
  assert.ok(r.url.includes('https://evil.com/panel'));
  assert.ok(r.domain.includes('evil.com'));
  assert.ok(r.md5.includes('44d88612fea8a8f36de82e1278abb02f'));
  assert.ok(r.sha256.includes('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'));
  assert.ok(r.cve.includes('CVE-2021-44228'));
  assert.ok(r.attack.includes('T1190') && r.attack.includes('T1547.001'));
  assert.ok(r.email.includes('actor@evil.com'));
});

test('extract dedup y no confunde un .exe con dominio', () => {
  const r = ioc.extract('descargá payload.exe y conectá a real-domain.com dos veces real-domain.com');
  assert.equal((r.domain || []).filter((d) => d === 'real-domain.com').length, 1, 'dedup');
  assert.ok(!(r.domain || []).includes('payload.exe'), 'payload.exe no es dominio');
});
