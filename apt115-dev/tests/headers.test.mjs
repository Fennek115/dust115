// Security Headers & CSP Analyzer (Fase C): parsing y scoring de headers HTTP.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { headers } from '../src/tools/headers.js';

const { parseHeaders, parseCsp, parseCookie, analyze, gradeOf } = headers;

test('parseHeaders: status line ignorada, set-cookie múltiple, case-insensitive', () => {
  const raw = [
    'HTTP/2 200',
    'Content-Type: text/html',
    'Set-Cookie: a=1; HttpOnly',
    'Set-Cookie: b=2; Secure',
    'X-Frame-Options: DENY',
  ].join('\n');
  const p = parseHeaders(raw);
  assert.equal(p.map['content-type'], 'text/html');
  assert.equal(p.map['x-frame-options'], 'DENY');
  assert.equal(p.cookies.length, 2);
  assert.equal(p.all.length, 4); // sin contar la status line
});

test('parseCsp: directivas y fuentes', () => {
  const d = parseCsp("default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'");
  assert.deepEqual(d['default-src'], ["'self'"]);
  assert.deepEqual(d['script-src'], ["'self'", "'unsafe-inline'"]);
  assert.deepEqual(d['object-src'], ["'none'"]);
});

test('parseCookie: flags Secure/HttpOnly/SameSite', () => {
  const c = parseCookie('sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax');
  assert.equal(c.name, 'sid');
  assert.equal(c.secure, true);
  assert.equal(c.httpOnly, true);
  assert.equal(c.sameSite, 'Lax');
  const c2 = parseCookie('t=1');
  assert.equal(c2.secure, false);
  assert.equal(c2.httpOnly, false);
  assert.equal(c2.sameSite, null);
});

test('gradeOf: cortes de nota', () => {
  assert.equal(gradeOf(100), 'A+');
  assert.equal(gradeOf(95), 'A+');
  assert.equal(gradeOf(85), 'A');
  assert.equal(gradeOf(70), 'C');
  assert.equal(gradeOf(10), 'F');
});

test('analyze: sin headers → ok:false', () => {
  assert.equal(analyze('').ok, false);
  assert.equal(analyze('basura sin dos puntos').ok, false);
});

test('analyze: respuesta desnuda baja la nota con críticos de HSTS y CSP', () => {
  const res = analyze('Content-Type: text/html\nServer: nginx/1.18.0');
  assert.equal(res.ok, true);
  const bads = res.findings.filter(f => f.level === 'bad').map(f => f.header);
  assert.ok(bads.includes('Strict-Transport-Security'));
  assert.ok(bads.includes('Content-Security-Policy'));
  assert.ok(res.findings.some(f => f.header === 'Server' && f.level === 'info')); // fuga de versión
  assert.ok(res.score < 60);
  assert.ok(['D', 'F'].includes(res.grade));
});

test('analyze: configuración fuerte saca nota alta', () => {
  const raw = [
    "Content-Security-Policy: default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
    'X-Frame-Options: DENY',
    'X-Content-Type-Options: nosniff',
    'Referrer-Policy: no-referrer',
    'Permissions-Policy: geolocation=()',
    'Set-Cookie: sid=abc; HttpOnly; Secure; SameSite=Strict',
  ].join('\n');
  const res = analyze(raw);
  assert.equal(res.findings.filter(f => f.level === 'bad').length, 0);
  assert.ok(res.score >= 85);
  assert.ok(['A', 'A+'].includes(res.grade));
});

test('analyze: CSP con unsafe-inline y comodín marca críticos', () => {
  const res = analyze("Content-Security-Policy: script-src 'self' 'unsafe-inline' *; default-src 'self'");
  const cspBad = res.findings.filter(f => f.header === 'Content-Security-Policy' && f.level === 'bad');
  assert.ok(cspBad.some(f => /unsafe-inline/.test(f.msg)));
  assert.ok(cspBad.some(f => /comod/.test(f.msg)));
});

test('analyze: cookie sin flags genera avisos', () => {
  const res = analyze('Set-Cookie: session=xyz');
  const ck = res.findings.filter(f => f.header === 'Set-Cookie');
  assert.ok(ck.some(f => /sin Secure/.test(f.msg)));
  assert.ok(ck.some(f => /sin HttpOnly/.test(f.msg)));
});
