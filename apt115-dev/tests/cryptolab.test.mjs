// Tests del núcleo de cryptolab — parseo, XOR (clave/brute), magic (require).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bytesOf } from './_load.mjs';

import { cryptolab as C } from '../src/tools/cryptolab.js';

test('parseBytes: hex, base64 y texto', () => {
  assert.deepEqual([...C.parseBytes('4d5a', 'hex')], [0x4d, 0x5a]);
  assert.deepEqual([...C.parseBytes('\\x4d\\x5a', 'hex')], [0x4d, 0x5a]);
  assert.deepEqual([...C.parseBytes('TVo=', 'b64')], [0x4d, 0x5a]);
  assert.deepEqual([...C.parseBytes('MZ', 'text')], [0x4d, 0x5a]);
});

test('detectMagic reconoce cabeceras', () => {
  assert.match(C.detectMagic(bytesOf('MZ\x90\x00')), /MZ/);
  assert.match(C.detectMagic(new Uint8Array([0x7F, 0x45, 0x4C, 0x46])), /ELF/);
  assert.equal(C.detectMagic(bytesOf('hola')), null);
});

test('xorKey es involutivo (cifrar==descifrar con la misma clave)', () => {
  const data = bytesOf('payload secreto de prueba');
  const key = bytesOf('k3y');
  const enc = C.xorKey(data, key);
  assert.notDeepEqual([...enc], [...data]);
  assert.deepEqual([...C.xorKey(enc, key)], [...data]);
});

test('xorBruteSingle recupera la clave: magic MZ va primero (estilo xortool)', () => {
  const plain = bytesOf('MZ\x90\x00 este es un ejecutable de prueba con texto en ingles the system');
  const KEY = 0x42;
  const enc = C.xorKey(plain, Uint8Array.of(KEY));
  const ranked = C.xorBruteSingle(enc, 8);
  assert.equal(ranked[0].key, KEY, 'el candidato con magic MZ en offset 0 rankea primero');
  assert.deepEqual([...ranked[0].bytes], [...plain], 'descifra al plaintext original');
});
