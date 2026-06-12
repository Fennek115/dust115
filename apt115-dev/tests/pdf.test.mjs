// Tests de pdf.js — núcleo síncrono estilo pdfid (require directo, sin window).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { requireModule, bytesOf } from './_load.mjs';

const pdf = requireModule('tools/triage/pdf.js');

test('isPdf ubica %PDF en el primer KB', () => {
  assert.equal(pdf.isPdf(bytesOf('%PDF-1.7\n')), 0);
  assert.equal(pdf.isPdf(bytesOf('\xef\xbb\xbf%PDF-1.4')), 3); // tras BOM
  assert.equal(pdf.isPdf(bytesOf('no es pdf')), -1);
});

test('decodeName deshace la ofuscación #xx', () => {
  assert.equal(pdf.decodeName('/J#61vaScript'), '/JavaScript');
  assert.equal(pdf.decodeName('OpenAction'), 'OpenAction');
});

test('scanNames cuenta nombres y marca los ofuscados', () => {
  const s = '/OpenAction /JavaScript /J#61vaScript /Launch';
  const { counts, obf } = pdf.scanNames(s);
  assert.equal(counts.JavaScript, 2, 'cuenta la forma clara + la ofuscada');
  assert.equal(obf.JavaScript, 1, 'una venía ofuscada');
  assert.equal(counts.OpenAction, 1);
  assert.equal(counts.Launch, 1);
});

test('structCounts no cuenta obj dentro de endobj (lookbehind)', () => {
  const s = '1 0 obj\n<<>>\nendobj\nstream\n...\nendstream\nstartxref\nxref\n';
  const c = pdf.structCounts(s);
  assert.equal(c.obj, 1);
  assert.equal(c.endobj, 1);
  assert.equal(c.stream, 1);
  assert.equal(c.endstream, 1);
  assert.equal(c.xref, 1, 'xref real, no el de startxref');
  assert.equal(c.startxref, 1);
});

test('extractTargets saca URIs y destinos de /Launch', () => {
  const s = '/URI (http://evil.example/c2) /Launch /Win << /F (cmd.exe) >>';
  const { uris, launch } = pdf.extractTargets(s);
  assert.ok(uris.includes('http://evil.example/c2'));
  assert.ok(launch.includes('cmd.exe'));
});

test('countWord cuenta ocurrencias solapadas-no', () => {
  assert.equal(pdf.countWord('aXaXa', 'aX'), 2);
});
