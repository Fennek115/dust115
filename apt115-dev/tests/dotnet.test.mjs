// Tests de Triage.dotnet — parser de metadata .NET / CLR (ECMA-335 II).
// Dos frentes:
//   1. Oportunista contra assemblies .NET reales del framework (si están en
//      este entorno WSL); verificado byte-a-byte vs dnfile durante el desarrollo.
//   2. Un assembly .NET MÍNIMO fabricado a mano (portable, sin depender de
//      archivos externos): ejercita COR20 + metadata root + tabla #~ + lectura
//      de Module/Assembly/AssemblyRef + detección de ofuscador.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';

import { pe } from '../src/triage/pe.js';
import { dotnet } from '../src/triage/dotnet.js';

// ── Fabricador de un .NET mínimo válido ─────────────────────────────
// PE32 con una sección .text que contiene COR20 + metadata (BSJB) + tabla #~
// con Module/Assembly/AssemblyRef (1 fila cada una) + heap #Strings.
function buildMinimalDotNet() {
  const b = new Uint8Array(0x600);
  const dv = new DataView(b.buffer);
  const u16 = (o, v) => dv.setUint16(o, v, true);
  const u32 = (o, v) => dv.setUint32(o, v, true);
  const ascii = (o, s) => { for (let i = 0; i < s.length; i++) b[o + i] = s.charCodeAt(i); };

  // DOS + PE
  b[0] = 0x4d; b[1] = 0x5a;          // 'MZ'
  u32(0x3c, 0x80);                    // e_lfanew
  ascii(0x80, 'PE\0\0');
  // COFF @0x84
  u16(0x84, 0x14c);                  // machine x86
  u16(0x86, 1);                      // numSections
  u16(0x94, 0xe0);                   // sizeOptional
  u16(0x96, 0x2102);                 // characteristics (EXECUTABLE|32BIT|DLL)
  // Optional header @0x98 (PE32)
  u16(0x98, 0x10b);                  // magic PE32
  u32(0xa8, 0x2000);                 // entryPoint RVA
  u32(0xb4, 0x400000);              // imageBase
  u16(0xdc, 3);                      // subsystem console
  u32(0xf4, 16);                     // numRva → ddStart = 0xf8
  // DataDirectory[14] = CLR (COR20) @ 0xf8 + 14*8 = 0x168
  u32(0x168, 0x2000);               // RVA del COR20
  u32(0x16c, 72);                    // size
  // Section header .text @ opt(0x98)+sizeOptional(0xe0) = 0x178
  ascii(0x178, '.text');
  u32(0x180, 0x400);                // vsize
  u32(0x184, 0x2000);              // vaddr
  u32(0x188, 0x400);                // rawsize
  u32(0x18c, 0x200);                // rawptr → RVA 0x2000 ↔ file 0x200

  // COR20 @ file 0x200 (RVA 0x2000)
  u32(0x200, 72);                    // cb
  u16(0x204, 2); u16(0x206, 5);      // runtime 2.5
  u32(0x208, 0x2100);              // MetaData RVA
  u32(0x20c, 0x200);                // MetaData size
  u32(0x210, 0x09);                 // Flags: ILONLY | STRONGNAMESIGNED
  u32(0x214, 0x06000001);          // EntryPointToken → MethodDef[1]

  // Metadata root @ file 0x300 (RVA 0x2100)
  u32(0x300, 0x424a5342);          // 'BSJB'
  u16(0x304, 1); u16(0x306, 1);
  u32(0x30c, 12);                   // verLen
  ascii(0x310, 'v4.0.30319');       // + nulls (buffer ya en 0)
  u16(0x31c, 0);                    // flags
  u16(0x31e, 2);                    // 2 streams
  // stream0 header @0x320: #~  (off 0x80, size 0x80)
  u32(0x320, 0x80); u32(0x324, 0x80); ascii(0x328, '#~');
  // stream1 header @0x32c: #Strings (off 0x100, size 0x100)
  u32(0x32c, 0x100); u32(0x330, 0x100); ascii(0x334, '#Strings');

  // #~ stream @ 0x300 + 0x80 = 0x380
  b[0x386] = 0;                      // heapSizes = 0 (índices de 2 bytes)
  b[0x384] = 2; b[0x385] = 0;        // major/minor
  b[0x387] = 1;                      // reserved
  // valid bitmask: Module(0) | Assembly(0x20) | AssemblyRef(0x23)
  const valid = (1n << 0n) | (1n << 0x20n) | (1n << 0x23n);
  dv.setBigUint64(0x388, valid, true);
  dv.setBigUint64(0x390, 0n, true);  // sorted
  // row counts (orden de índice: 0, 0x20, 0x23) @0x398
  u32(0x398, 1); u32(0x39c, 1); u32(0x3a0, 1);
  // tablas @0x3a4
  // Module (10 b): Generation, Name=1, Mvid, EncId, EncBaseId
  u16(0x3a4, 0); u16(0x3a6, 1);
  // Assembly (22 b) @0x3ae: HashAlgId(u32), Maj,Min,Bld,Rev, Flags(u32), PubKey(blob), Name, Culture
  u32(0x3ae, 0x8004); u16(0x3b2, 1); u16(0x3b4, 0); u16(0x3b6, 0); u16(0x3b8, 0);
  u32(0x3ba, 0); u16(0x3be, 0); u16(0x3c0, 14); u16(0x3c2, 0); // Name=14
  // AssemblyRef (20 b) @0x3c4: Maj,Min,Bld,Rev, Flags(u32), PubKeyOrToken(blob), Name, Culture, Hash
  u16(0x3c4, 4); u16(0x3c6, 0); u16(0x3c8, 0); u16(0x3ca, 0);
  u32(0x3cc, 0); u16(0x3d0, 0); u16(0x3d2, 20); u16(0x3d4, 0); u16(0x3d6, 0); // Name=20

  // #Strings heap @ 0x300 + 0x100 = 0x400
  // idx 0 = '', idx1='MyModule.dll', idx14='MyAsm', idx20='mscorlib', luego marca
  ascii(0x401, 'MyModule.dll');      // 12 chars, null en 0x40d
  ascii(0x40e, 'MyAsm');             // null en 0x413  → idx 14
  ascii(0x414, 'mscorlib');          // null en 0x41c  → idx 20
  ascii(0x41d, 'ConfusedByAttribute'); // marca de ConfuserEx (en el heap)
  return b;
}

test('parse: COR20 + metadata root del .NET fabricado', () => {
  const b = buildMinimalDotNet();
  const p = pe.parse(b);
  assert.ok(p, 'el fabricado debe parsear como PE');
  const d = dotnet.parse(p, b);
  assert.ok(d, 'debe detectarse como .NET');
  assert.equal(d.cor.runtime, '2.5');
  assert.equal(d.metaVersion, 'v4.0.30319');
  assert.deepEqual(d.cor.flagNames, ['ILONLY', 'STRONGNAMESIGNED']);
  assert.equal(d.cor.entryDesc, 'MethodDef[1]');
});

test('parse: streams y tabla #~', () => {
  const b = buildMinimalDotNet();
  const d = dotnet.parse(pe.parse(b), b);
  assert.deepEqual(d.streams.map(s => s.name).sort(), ['#Strings', '#~']);
  assert.equal(d.tables.kind, '#~');
  assert.equal(d.tables.validCount, 3);
  assert.equal(d.tables.summary.Module, 1);
  assert.equal(d.tables.summary.AssemblyRef, 1);
});

test('parse: lee Module / Assembly / AssemblyRef del heap #Strings', () => {
  const b = buildMinimalDotNet();
  const d = dotnet.parse(pe.parse(b), b);
  assert.equal(d.tables.module, 'MyModule.dll');
  assert.equal(d.tables.assembly.name, 'MyAsm');
  assert.equal(d.tables.assembly.version, '1.0.0.0');
  assert.equal(d.tables.assemblyRefs.length, 1);
  assert.equal(d.tables.assemblyRefs[0].name, 'mscorlib');
  assert.equal(d.tables.assemblyRefs[0].version, '4.0.0.0');
});

test('heurística: detecta firma de ConfuserEx en #Strings', () => {
  const b = buildMinimalDotNet();
  const d = dotnet.parse(pe.parse(b), b);
  const sig = d.heuristics.signatures.find(s => s.name === 'ConfuserEx');
  assert.ok(sig, 'debe detectar ConfuserEx');
  assert.equal(sig.evidence, 'ConfusedByAttribute');
});

test('parse: PE no-managed (sin CLR dir) devuelve null', () => {
  const b = buildMinimalDotNet();
  const dv = new DataView(b.buffer);
  dv.setUint32(0x168, 0, true); // borra el RVA del COR20
  assert.equal(dotnet.parse(pe.parse(b), b), null);
});

test('parse: tolera basura / pe nulo sin tirar', () => {
  assert.equal(dotnet.parse(null, new Uint8Array(0)), null);
  const junk = new Uint8Array(0x600); junk[0] = 0x4d; junk[1] = 0x5a;
  assert.doesNotThrow(() => dotnet.parse(pe.parse(junk), junk));
});

test('esquema: coherencia de tablas y coded indexes (ECMA-335)', () => {
  // Todas las tablas 0x00..0x2C tienen esquema.
  for (let t = 0; t <= 0x2c; t++) assert.ok(dotnet.SCHEMA[t], 'falta esquema 0x' + t.toString(16));
  // HasCustomAttribute referencia 22 tablas con 5 bits de tag.
  assert.equal(dotnet.CODED.HasCustomAttribute.tables.length, 22);
  assert.equal(dotnet.CODED.HasCustomAttribute.bits, 5);
  // Firmas de ofuscador bien formadas.
  for (const o of dotnet.OBFUSCATORS) { assert.ok(o.name && o.why); assert.ok(o.sigs.length); }
});

// ── Oportunista: assemblies .NET reales del framework Windows ───────
const REAL = [
  '/mnt/c/Windows/Microsoft.NET/Framework/v4.0.30319/AddInProcess.exe',
  '/mnt/c/Windows/Microsoft.NET/Framework64/v4.0.30319/System.Xml.dll',
];
for (const path of REAL) {
  test('real: ' + path.split('/').pop(), { skip: !existsSync(path) }, () => {
    const b = new Uint8Array(readFileSync(path));
    const d = dotnet.parse(pe.parse(b), b);
    assert.ok(d && d.cor, 'debe parsear como .NET');
    assert.match(d.metaVersion, /^v\d+\./);
    assert.ok(d.tables.summary.TypeDef > 0);
    assert.ok(d.tables.summary.MethodDef > 0);
    assert.ok(d.tables.module && d.tables.module.length > 0);
  });
}
