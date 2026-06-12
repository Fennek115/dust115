// Tests del núcleo de urlinsp — distancia, dominio registrado, IDN, análisis (require).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { requireModule } from './_load.mjs';

const U = requireModule('tools/urlinsp/urlinsp.js');

test('lev: distancia de edición', () => {
  assert.equal(U.lev('paypal', 'paypa1'), 1);
  assert.equal(U.lev('kitten', 'sitting'), 3);
  assert.equal(U.lev('igual', 'igual'), 0);
});

test('registeredDomain colapsa subdominios y respeta TLDs compuestos', () => {
  assert.equal(U.registeredDomain('a.b.evil.com'), 'evil.com');
  assert.equal(U.registeredDomain('mail.evil.co.uk'), 'evil.co.uk');
  assert.equal(U.registeredDomain('evil.com'), 'evil.com');
});

test('analyzeOne marca el dominio registrado real bajo subdominio de marca', () => {
  const r = U.analyzeOne('http://paypal.com.evil.ru/login');
  assert.equal(r.regDom, 'evil.ru', 'el dominio real es evil.ru, no paypal');
  assert.equal(r.host, 'paypal.com.evil.ru');
});

test('analyzeOne decodifica punycode a Unicode', () => {
  // xn--80ak6aa92e → "аррӏе" (homógrafo cirílico de apple)
  const r = U.analyzeOne('https://xn--80ak6aa92e.com');
  assert.ok(/[^\x00-\x7f]/.test(r.unicode), 'unicode trae caracteres no-ASCII: ' + r.unicode);
});

test('refang normaliza antes de analizar', () => {
  assert.ok(U.refang('hxxp://evil[.]com').includes('http://evil.com'));
});
