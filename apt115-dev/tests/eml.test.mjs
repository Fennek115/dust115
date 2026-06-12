// Tests de eml.js — parser de headers/MIME y decodificadores (require directo).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { requireModule, bytesOf } from './_load.mjs';

const eml = requireModule('tools/triage/eml.js');

const SAMPLE = [
  'Return-Path: <bounce@mailer.ru>',
  'Received: from mx.evil.ru (1.2.3.4) by mail.corp.local',
  'From: "Soporte PayPal" <security@paypa1-support.com>',
  'Reply-To: collect@evil.ru',
  'To: victima@corp.local',
  'Subject: Tu cuenta fue suspendida',
  'Message-ID: <abc@evil.ru>',
  'MIME-Version: 1.0',
  'Content-Type: text/plain',
  '',
  'Ingresá a http://paypa1-support.com/login ahora.',
].join('\r\n');

test('isEml puntúa headers de correo y rechaza binario', () => {
  assert.equal(eml.isEml(bytesOf(SAMPLE)), true);
  assert.equal(eml.isEml(new Uint8Array([0x4d, 0x5a, 0x90, 0x00])), false);
});

test('splitHeadBody parte en la línea en blanco', () => {
  const { head, body } = eml.splitHeadBody(SAMPLE);
  assert.ok(head.startsWith('Return-Path'));
  assert.ok(body.startsWith('Ingresá'));
});

test('parseHeaders mapea (lowercase) y hace unfolding', () => {
  const { head } = eml.splitHeadBody(SAMPLE);
  const { map } = eml.parseHeaders(head);
  assert.equal(map['subject'], 'Tu cuenta fue suspendida');
  assert.equal(map['from'], '"Soporte PayPal" <security@paypa1-support.com>');

  const folded = 'Subject: linea uno\r\n  continuacion\r\nTo: x@y.com';
  const r = eml.parseHeaders(folded);
  assert.equal(r.map['subject'], 'linea uno continuacion');
});

test('parseAddr extrae display, addr y dominio', () => {
  const a = eml.parseAddr('"Soporte PayPal" <security@paypa1-support.com>');
  assert.equal(a.addr, 'security@paypa1-support.com');
  assert.equal(a.domain, 'paypa1-support.com');
  assert.equal(a.display, 'Soporte PayPal');
});

test('decodificadores base64 y quoted-printable', () => {
  assert.deepEqual([...eml.b64ToBytes('SGVsbG8=')], [...bytesOf('Hello')]);
  assert.equal(eml.qpToString('=41=42=43'), 'ABC');
  assert.equal(eml.qpToString('fin de=\r\nlinea'), 'fin delinea'); // soft break
});

test('extractUrls saca URLs del cuerpo', () => {
  const urls = eml.extractUrls('mirá http://paypa1-support.com/login. y https://ok.com/a)');
  assert.ok(urls.includes('http://paypa1-support.com/login'));
  assert.ok(urls.includes('https://ok.com/a'));
});

test('dangerOf marca extensiones peligrosas (incl. doble extensión)', () => {
  assert.ok(eml.dangerOf('factura.pdf.exe'), 'doble extensión .pdf.exe');
  assert.ok(eml.dangerOf('macro.vbs'));
  assert.equal(eml.dangerOf('documento.pdf'), null);
  assert.equal(eml.dangerOf('sinpunto'), null);
});
