// Render markdown de las notas + extensión de enlaces [[wiki]] (Fase A).

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { renderMarkdown, extractWikiLinks } from '../src/app/markdown.js';

test('markdown básico: negrita, itálica, encabezado, código', () => {
  assert.match(renderMarkdown('**fuerte**'), /<strong>fuerte<\/strong>/);
  assert.match(renderMarkdown('*enfasis*'), /<em>enfasis<\/em>/);
  assert.match(renderMarkdown('# Título'), /<h1>Título<\/h1>/);
  assert.match(renderMarkdown('`code`'), /<code>code<\/code>/);
});

test('[[wiki]] → <a> con data-wl y handler', () => {
  const html = renderMarkdown('ver [[Recon]] ahora');
  assert.match(html, /<a class="wl" data-wl="Recon" onclick="openWikiLink\(this\)">Recon<\/a>/);
  assert.match(html, /ver /);
  assert.match(html, / ahora/);
});

test('linkExists=false marca wl-missing', () => {
  const html = renderMarkdown('[[NoExiste]]', { linkExists: () => false });
  assert.match(html, /class="wl wl-missing"/);
  const ok = renderMarkdown('[[Existe]]', { linkExists: () => true });
  assert.doesNotMatch(ok, /wl-missing/);
});

test('extractWikiLinks: en orden y sin duplicar (case-insensitive)', () => {
  assert.deepEqual(extractWikiLinks('[[A]] y [[B]] y [[a]]'), ['A', 'B']);
  assert.deepEqual(extractWikiLinks('sin enlaces'), []);
  assert.deepEqual(extractWikiLinks(''), []);
});

test('título con comillas se escapa en el atributo', () => {
  const html = renderMarkdown('[[a "b" c]]');
  assert.match(html, /data-wl="a &quot;b&quot; c"/);
});
