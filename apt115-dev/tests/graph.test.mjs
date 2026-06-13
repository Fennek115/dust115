// Grafo de notas: construcción desde [[wiki]] + render SVG (Fase A3).

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildGraph, renderGraphSvg } from '../src/app/graph.js';

const notes = [
  { id: 'a', title: 'Recon', body: 'arrancar por [[Privesc]] y [[Loot]]', ts: '' },
  { id: 'b', title: 'Privesc', body: 'volver a [[Recon]]', ts: '' },
  { id: 'c', title: 'Loot', body: 'sin enlaces', ts: '' },
];

test('buildGraph: aristas por título, grado contado', () => {
  const g = buildGraph(notes);
  assert.equal(g.nodes.length, 3);
  // Recon→Privesc, Recon→Loot, Privesc→Recon
  assert.equal(g.edges.length, 3);
  assert.deepEqual(g.edges.find(e => e.from === 'b'), { from: 'b', to: 'a' });
  const recon = g.nodes.find(n => n.id === 'a');
  assert.equal(recon.deg, 3); // 2 salientes + 1 entrante
  assert.equal(g.nodes.find(n => n.id === 'c').deg, 1); // solo entrante
});

test('buildGraph: ignora enlaces a notas inexistentes y autoenlaces', () => {
  const g = buildGraph([
    { id: 'x', title: 'A', body: '[[A]] y [[NoExiste]]', ts: '' },
  ]);
  assert.equal(g.edges.length, 0);
  assert.equal(g.nodes[0].deg, 0);
});

test('buildGraph: deduplica pares repetidos', () => {
  const g = buildGraph([
    { id: 'x', title: 'A', body: '[[B]] [[B]] [[b]]', ts: '' },
    { id: 'y', title: 'B', body: '', ts: '' },
  ]);
  assert.equal(g.edges.length, 1);
});

test('buildGraph: nota sin título queda como nodo aislado', () => {
  const g = buildGraph([{ id: 'z', title: '', body: '', ts: '' }]);
  assert.equal(g.nodes[0].title, '(sin título)');
  assert.equal(g.edges.length, 0);
});

test('renderGraphSvg: nodos, aristas y click→focusNote', () => {
  const svg = renderGraphSvg(buildGraph(notes), { size: 300 });
  assert.match(svg, /<svg viewBox="0 0 300 300"/);
  assert.equal((svg.match(/<circle /g) || []).length, 3);
  assert.equal((svg.match(/<line /g) || []).length, 3);
  assert.match(svg, /onclick="focusNote\('a'\)"/);
  assert.match(svg, />Recon</); // etiqueta
});

test('renderGraphSvg: grafo vacío → mensaje', () => {
  assert.match(renderGraphSvg(buildGraph([])), /Sin notas para graficar/);
});

test('renderGraphSvg: determinista (mismo grafo, mismo SVG)', () => {
  const g = buildGraph(notes);
  assert.equal(renderGraphSvg(g), renderGraphSvg(g));
});
