// Tests de sqlitef — parser forense SQLite + recuperación de borrados.
// Genera DBs reales con node:sqlite (sin dependencias externas), borra filas y
// confirma: schema + filas vivas correctas, y que el carving recupera filas
// borradas de páginas liberadas SIN falsos positivos. Verificado además vs el
// módulo sqlite3 de Python durante el desarrollo.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { sqlitef as S } from '../src/tools/sqlitef.js';

function buildDb(fn) {
  const path = join(tmpdir(), 'apt115_sqf_' + Math.random().toString(36).slice(2) + '.db');
  const db = new DatabaseSync(path);
  db.exec('PRAGMA secure_delete=OFF');
  db.exec('PRAGMA page_size=4096');
  fn(db);
  db.close();
  const bytes = new Uint8Array(readFileSync(path));
  rmSync(path, { force: true });
  return bytes;
}

test('isSqlite + parseHeader', () => {
  const b = buildDb(db => { db.exec('CREATE TABLE x(a)'); });
  assert.equal(S.isSqlite(b), true);
  assert.equal(S.isSqlite(new Uint8Array([1, 2, 3])), false);
  const h = S.parseHeader(b);
  assert.equal(h.pageSize, 4096);
  assert.equal(h.encodingName, 'UTF-8');
});

test('schema + filas vivas', () => {
  const b = buildDb(db => {
    db.exec('CREATE TABLE visits(id INTEGER PRIMARY KEY, url TEXT, n INTEGER)');
    const ins = db.prepare('INSERT INTO visits VALUES(?,?,?)');
    for (let i = 1; i <= 20; i++) ins.run(i, 'https://s' + i + '.test', i * 2);
  });
  const r = S.parse(b);
  const t = r.schema.find(x => x.name === 'visits');
  assert.ok(t && t.type === 'table');
  const live = S.readTable(b, t.rootpage, 1000);
  assert.equal(live.length, 20);
  // valores correctos
  const row = live.find(x => x.rowid === 7);
  assert.equal(row.values[1], 'https://s7.test');
  assert.equal(row.values[2], 14);
});

test('recupera filas borradas de páginas liberadas, SIN falsos positivos', () => {
  const b = buildDb(db => {
    db.exec('CREATE TABLE t(id INTEGER PRIMARY KEY, a TEXT, n INTEGER)');
    const ins = db.prepare('INSERT INTO t VALUES(?,?,?)');
    for (let i = 1; i <= 2000; i++) ins.run(i, 'record-data-value-' + String(i).padStart(5, '0') + '-padding-xxxxxxxx', i);
    db.exec('DELETE FROM t WHERE id BETWEEN 500 AND 1500'); // libera páginas enteras
  });
  const r = S.parse(b);
  assert.ok(r.header.freelistPages > 0, 'debe haber páginas en la freelist');
  const del = S.recoverDeleted(b, r.header, 100000, r.schema);
  assert.ok(del.length > 200, 'debe recuperar bastantes filas borradas (recuperó ' + del.length + ')');
  // CADA fila recuperada debe ser internamente consistente (dato ↔ rowid) → 0 falsos positivos
  let bad = 0;
  for (const d of del) {
    const expect = 'record-data-value-' + String(d.rowid).padStart(5, '0') + '-padding-xxxxxxxx';
    if (!(d.values[1] === expect && d.values[2] === d.rowid)) bad++;
  }
  assert.equal(bad, 0, 'ningún registro recuperado debe ser un falso positivo');
  // al menos algunos del rango borrado [500,1500]
  assert.ok(del.some(d => d.rowid >= 500 && d.rowid <= 1500), 'recupera filas del rango borrado');
});

test('varint y serialSize (ECMA del formato SQLite)', () => {
  assert.deepEqual(S.varint(new Uint8Array([0x00]), 0), [0, 1]);
  assert.deepEqual(S.varint(new Uint8Array([0x7f]), 0), [127, 1]);
  assert.deepEqual(S.varint(new Uint8Array([0x81, 0x00]), 0), [128, 2]);
  // serial types: 0..4 fijos, 5→6, 6/7→8, 8/9→0, text/blob
  assert.equal(S.serialSize(4), 4);
  assert.equal(S.serialSize(5), 6);
  assert.equal(S.serialSize(7), 8);
  assert.equal(S.serialSize(9), 0);
  assert.equal(S.serialSize(13), 0);  // text (13-13)/2 = 0
  assert.equal(S.serialSize(25), 6);  // text (25-13)/2 = 6
  assert.equal(S.serialSize(24), 6);  // blob (24-12)/2 = 6
});

test('parse devuelve null si no es SQLite', () => {
  assert.equal(S.parse(new Uint8Array(200)), null);
});
