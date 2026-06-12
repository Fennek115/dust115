// Hook release() del registry de analyzers — al cargar un archivo nuevo,
// triage.js llama analyzers.releaseAll() para que los analyzers con estado
// perezoso (ctx/buffers a nivel módulo) suelten el archivo anterior.

import { test } from 'node:test';
import assert from 'node:assert/strict';

// analyzers.js asume window/Triage.util al importar (patrón documentado en el README).
globalThis.window = globalThis;
globalThis.Triage = globalThis.Triage || { util: {} };

const { analyzers } = await import('../src/triage/analyzers.js');

test('releaseAll: invoca los hooks, tolera analyzers sin release y no corta ante un hook que tira', () => {
  let first = 0, last = 0;
  analyzers.register({ id: 't_rel', run: () => '', release() { first++; } });
  analyzers.register({ id: 't_sin_release', run: () => '' });
  analyzers.register({ id: 't_throw', run: () => '', release() { throw new Error('boom'); } });
  analyzers.register({ id: 't_rel2', run: () => '', release() { last++; } });

  analyzers.releaseAll();
  assert.equal(first, 1);
  assert.equal(last, 1, 'el hook que tira no debe frenar la iteración');

  analyzers.releaseAll();
  assert.equal(first, 2, 'releaseAll es re-invocable');
});

test('el stub del analyzer yara delega release en Triage.yara cuando existe', () => {
  const stub = analyzers.all().find(a => a.id === 'yara');
  assert.ok(stub, 'el stub yara está registrado');
  assert.equal(typeof stub.release, 'function');
  stub.release(); // sin Triage.yara cargado: no debe tirar
  let released = 0;
  globalThis.Triage.yara = { release() { released++; } };
  stub.release();
  assert.equal(released, 1);
  delete globalThis.Triage.yara;
});
