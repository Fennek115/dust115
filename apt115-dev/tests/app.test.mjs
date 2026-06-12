// Smoke test del cheatsheet (src/app/) — ejecuta el entry empaquetado en un
// sandbox vm con DOM/localStorage stubeados y verifica: (1) el init corre sin
// errores, (2) toda función referenciada por handlers inline (en index.html y
// en el HTML que genera el propio app) quedó colgada de window, (3) los flujos
// básicos (búsqueda, checklist, historial de copiado) mutan estado/DOM.
// No reemplaza la verificación en navegador — caza ReferenceErrors y wiring roto.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import * as esbuild from 'esbuild';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const SRC = path.join(HERE, '..', 'src');
const INDEX_HTML = path.join(HERE, '..', '..', 'static', 'apt115', 'index.html');

// ─── DOM stub mínimo ──────────────────────────────────────

function makeClassList() {
  const s = new Set();
  return {
    add(...c) { c.forEach(x => s.add(x)); },
    remove(...c) { c.forEach(x => s.delete(x)); },
    toggle(c, force) {
      const on = force === undefined ? !s.has(c) : !!force;
      on ? s.add(c) : s.delete(c);
      return on;
    },
    contains(c) { return s.has(c); },
  };
}

function makeEl(id) {
  const qs = new Map();
  const el = {
    id, tagName: 'DIV', children: [],
    style: {}, dataset: {},
    value: '', textContent: '', innerHTML: '', title: '', className: '',
    scrollTop: 0, width: 0, height: 0, checked: false, files: null,
    classList: makeClassList(),
    insertAdjacentHTML(_pos, html) { el.innerHTML += html; },
    appendChild(c) { el.children.push(c); return c; },
    removeChild() {},
    querySelector(sel) { if (!qs.has(sel)) qs.set(sel, makeEl('_q')); return qs.get(sel); },
    querySelectorAll() { return []; },
    addEventListener() {}, focus() {}, select() {}, click() {},
  };
  return el;
}

function makeSandbox() {
  const els = new Map();
  const byId = (id) => { if (!els.has(id)) els.set(id, makeEl(id)); return els.get(id); };

  const store = new Map();
  const localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
  };

  const document = {
    getElementById: byId,
    querySelector: () => makeEl('_q'),
    querySelectorAll: () => [],
    createElement: (tag) => { const e = makeEl('_' + tag); e.tagName = tag.toUpperCase(); return e; },
    addEventListener() {},
    body: makeEl('_body'),
    activeElement: { tagName: 'BODY' },
    execCommand() { return true; },
  };

  // Dataset mínimo para ejercitar render/búsqueda/checklist.
  const section = (id, label) => ({
    id, label, icon: '✦', group: 'TEST',
    groups: [{ t: 'Grupo', c: [['Escaneo nmap básico', 'nmap -sC -sV {RHOST}', ['high']]] }],
  });

  const ctx = {
    document, localStorage,
    navigator: { clipboard: { writeText() {} } },
    location: { reload() {} },
    setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0, clearInterval() {},
    requestAnimationFrame: () => 0,
    alert() {}, confirm: () => true,
    URL: { createObjectURL: () => 'blob:x', revokeObjectURL() {} },
    Blob: class { constructor() {} },
    FileReader: class { readAsText() {} },
    Date, JSON, Object, Array, String, Math, RegExp, console,
    CORE_DATA: [section('test', 'Test Core')],
    MITRE_DATA: [section('mitre', 'Test Mitre')],
    INTEL_DATA: [section('intel', 'Test Intel')],
  };
  ctx.window = ctx;
  ctx.globalThis = ctx;
  vm.createContext(ctx);
  return { ctx, byId, store };
}

async function bundleAppEntry() {
  const r = await esbuild.build({
    stdin: { contents: `import './app/index.js';\n`, resolveDir: SRC, sourcefile: '_entry.js', loader: 'js' },
    bundle: true, format: 'iife', target: ['es2020'], legalComments: 'none', write: false,
  });
  return r.outputFiles[0].text;
}

// Nombres de función referenciados por handlers inline en un HTML.
function inlineHandlerNames(html) {
  const names = new Set();
  for (const m of html.matchAll(/\bon(?:click|input|change|blur|keydown)="(?:if\([^)]*\)\s*)?(\w+)\(/g)) {
    if (m[1] !== 'event') names.add(m[1]);
  }
  return names;
}

const code = await bundleAppEntry();

test('el init del app corre sin errores en el sandbox', () => {
  const { ctx, byId } = makeSandbox();
  vm.runInContext(code, ctx);
  // El render dejó las secciones armadas con la fila del dataset fake
  const sections = byId('sections');
  assert.ok(sections.innerHTML.includes('Escaneo nmap básico'));
  assert.ok(sections.innerHTML.includes('nmap -sC -sV'));
  // Sidebar con las secciones del dataset (se insertan tras .sb-top)
  const sbTop = byId('sidebar').querySelector('.sb-top');
  assert.ok(sbTop.innerHTML.includes('Test Core'));
  assert.ok(sbTop.innerHTML.includes('Test Mitre'));
});

test('todo handler inline (index.html + HTML generado) existe en window', () => {
  const { ctx, byId } = makeSandbox();
  vm.runInContext(code, ctx);
  // Forzar render de los paneles que generan HTML con handlers
  ctx.window.doSearch('nmap');
  const generated = [
    byId('sections').innerHTML,
    byId('searchResults').innerHTML,
    byId('favList').innerHTML,
    byId('notesList').innerHTML,
    readFileSync(INDEX_HTML, 'utf8'),
  ].join('\n');
  for (const name of inlineHandlerNames(generated)) {
    assert.equal(typeof ctx.window[name], 'function', `window.${name} no está colgado`);
  }
});

test('showToast queda global (lo consumen registry.js/triage.js)', () => {
  const { ctx } = makeSandbox();
  vm.runInContext(code, ctx);
  assert.equal(typeof ctx.window.showToast, 'function');
});

test('búsqueda: encuentra en el dataset y refleja el conteo', () => {
  const { ctx, byId } = makeSandbox();
  vm.runInContext(code, ctx);
  ctx.window.doSearch('nmap');
  const sr = byId('searchResults');
  assert.ok(sr.classList.contains('on'));
  // 3 secciones × 1 comando que matchea
  assert.ok(sr.innerHTML.includes('Found <span>3</span>'));
  ctx.window.doSearch('');
  assert.ok(!sr.classList.contains('on'));
});

test('checklist: toggleDone persiste en cs_done y actualiza el progreso global', () => {
  const { ctx, byId, store } = makeSandbox();
  vm.runInContext(code, ctx);
  ctx.window.toggleDone('c_test_0_0');
  assert.deepEqual(JSON.parse(store.get('cs_done')), { c_test_0_0: true });
  assert.equal(byId('globalProgress').textContent, '✔ 1/3');
  ctx.window.toggleDone('c_test_0_0');
  assert.deepEqual(JSON.parse(store.get('cs_done')), {});
});

test('copiado: doCopy registra en el historial (cs_hist, tope 20)', () => {
  const { ctx, byId, store } = makeSandbox();
  vm.runInContext(code, ctx);
  const rc = byId('c_test_0_0');
  rc.textContent = 'nmap -sC -sV 10.10.10.10';
  ctx.window.doCopy(makeEl('_btn'), 'c_test_0_0');
  const hist = JSON.parse(store.get('cs_hist'));
  assert.equal(hist.length, 1);
  assert.equal(hist[0].c, 'nmap -sC -sV 10.10.10.10');
  ctx.window.clearHistory();
  assert.deepEqual(JSON.parse(store.get('cs_hist')), []);
});

test('favoritos: toggleFavItem persiste y el contador refleja', () => {
  const { ctx, byId, store } = makeSandbox();
  vm.runInContext(code, ctx);
  ctx.window.toggleFavItem('c_test_0_0', 'Escaneo', makeEl('_btn'));
  assert.deepEqual(JSON.parse(store.get('cs_favs')), { c_test_0_0: true });
  assert.equal(byId('favCount').textContent, '1');
  assert.ok(byId('favList').innerHTML.includes('Escaneo nmap básico'));
  ctx.window.clearAllFavs();
  assert.deepEqual(JSON.parse(store.get('cs_favs')), {});
});
