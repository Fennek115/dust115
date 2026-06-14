// Tests de jumplist — Jump Lists de Windows (automaticDestinations + customDestinations).
//
// Verificación con ORÁCULO horneada:
//   - DESTLIST = stream DestList de un automaticDestinations-ms REAL (6 entradas, Win10/11
//     v6). parseDestList es el código NUEVO; los entry-id coinciden EXACTO con los nombres
//     de los streams SHLLINK del CFB (1..6), verificado en vivo durante el desarrollo.
//   - E2E = un automaticDestinations-ms REAL completo (CFB). analyze() reúsa cfb.js + lnk.js;
//     los LNKs embebidos se cruzaron byte-a-byte vs LnkParse3 (stream '1' del sample de 6
//     entradas → local_base_path 'C:\\Users\\Dust\\Desktop').
// Embebidos en base64 → npm test corre offline. lnk.parse necesita window.Triage.util.

import { test } from 'node:test';
import assert from 'node:assert/strict';

globalThis.window = globalThis;
globalThis.window.Triage = {};
await import('../src/triage/util.js');
const { cfb } = await import('../src/triage/cfb.js');
const { lnk } = await import('../src/triage/lnk.js');
const { jumplist: J } = await import('../src/tools/jumplist.js');

const DESTLIST = "BgAAAAYAAAAGAAAAH4VhQggAAAAAAAAADQAAAAAAAACLgT+vgeJp+zQwJ5KwrcpJvpSQEO/Il/eFnfvWYS3xEbkDxO+7ch6DNDAnkrCtykm+lJAQ78iX94Wd+9ZhLfERuQPE77tyHoNsYXRhbWwtMDIzNjk1AAAAAQAAAAAAAAAAAKhBlbbyhnrB3AEAAAAAAgAAAAQAAAAAAAAAAAAAADIAawBuAG8AdwBuAGYAbwBsAGQAZQByADoAewA3ADUANABBAEMAOAA4ADYALQBEAEYANgA0AC0ANABDAEIAQQAtADgANgBCADUALQBGADcARgBCAEYANABGAEIAQwBFAEYANQB9AAAAAAAdr8nfPzlqXzQwJ5KwrcpJvpSQEO/Il/eGnfvWYS3xEbkDxO+7ch6DNDAnkrCtykm+lJAQ78iX94ad+9ZhLfERuQPE77tyHoNsYXRhbWwtMDIzNjk1AAAAAgAAAAAAAAAK159BSpIf+W7B3AEBAAAAAwAAAAMAAAAAAAAAAAAAADIAawBuAG8AdwBuAGYAbwBsAGQAZQByADoAewAzADcANABEAEUAMgA5ADAALQAxADIAMwBGAC0ANAA1ADYANQAtADkAMQA2ADQALQAzADkAQwA0ADkAMgA1AEUANAA2ADcAQgB9AAAAAAC/xNlA0TuBATQwJ5KwrcpJvpSQEO/Il/eBnfvWYS3xEbkDxO+7ch6DNDAnkrCtykm+lJAQ78iX94Gd+9ZhLfERuQPE77tyHoNsYXRhbWwtMDIzNjk1AAAABgAAAAAAAADNzGxA0T8d+W7B3AEFAAAABwAAAAMAAAAAAAAAAAAAADIAawBuAG8AdwBuAGYAbwBsAGQAZQByADoAewAxADgAOQA4ADkAQgAxAEQALQA5ADkAQgA1AC0ANAA1ADUAQgAtADgANAAxAEMALQBBAEIANwBDADcANABFADQARABEAEYAQwB9AAAAAABDCHpYr/A3kDQwJ5KwrcpJvpSQEO/Il/eEnfvWYS3xEbkDxO+7ch6DNDAnkrCtykm+lJAQ78iX94Sd+9ZhLfERuQPE77tyHoNsYXRhbWwtMDIzNjk1AAAABQAAAAAAAAAzM3NA0T8d+W7B3AEEAAAABgAAAAMAAAAAAAAAAAAAADIAawBuAG8AdwBuAGYAbwBsAGQAZQByADoAewA0AEIARAA4AEQANQA3ADEALQA2AEQAMQA5AC0ANAA4AEQAMwAtAEIARQA5ADcALQA0ADIAMgAyADIAMAAwADgAMABFADQAMwB9AAAAAADvuq3YGEijDDQwJ5KwrcpJvpSQEO/Il/eDnfvWYS3xEbkDxO+7ch6DNDAnkrCtykm+lJAQ78iX94Od+9ZhLfERuQPE77tyHoNsYXRhbWwtMDIzNjk1AAAABAAAAAAAAACamXlA0T8d+W7B3AEDAAAABQAAAAMAAAAAAAAAAAAAADIAawBuAG8AdwBuAGYAbwBsAGQAZQByADoAewAzADMARQAyADgAMQAzADAALQA0AEUAMQBFAC0ANAA2ADcANgAtADgAMwA1AEEALQA5ADgAMwA5ADUAQwAzAEIAQwAzAEIAQgB9AAAAAAAR9Wcfym4ntDQwJ5KwrcpJvpSQEO/Il/eCnfvWYS3xEbkDxO+7ch6DNDAnkrCtykm+lJAQ78iX94Kd+9ZhLfERuQPE77tyHoNsYXRhbWwtMDIzNjk1AAAAAwAAAAAAAAAAAIBA0T8d+W7B3AECAAAABAAAAAMAAAAAAAAAAAAAADIAawBuAG8AdwBuAGYAbwBsAGQAZQByADoAewBGAEQARAAzADkAQQBEADAALQAyADMAOABGAC0ANAA2AEEARgAtAEEARABCADQALQA2AEMAOAA1ADQAOAAwADMANgA5AEMANwB9AAAAAAA=";
const E2E = "0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAABAAAAAQAAAAAAAAAAEAAAAgAAAAEAAAD+////AAAAAAAAAAD////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////9/////v////7///8EAAAA/v///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////1IAbwBvAHQAIABFAG4AdAByAHkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWAAUA//////////8CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGC98dNywdwBAwAAAIACAAAAAAAAMQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAgD///////////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMwEAAAAAAABEAGUAcwB0AEwAaQBzAHQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEgACAQEAAAADAAAA/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAAADWAAAAAAAAAEQAZQBzAHQATABpAHMAdABQAHIAbwBwAGUAcgB0AHkAUwB0AG8AcgBlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsAAIA////////////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQAAAAQAAAAAAAAAAQAAAAIAAAADAAAABAAAAP7///8GAAAABwAAAAgAAAD+/////v////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////9MAAAAARQCAAAAAADAAAAAAAAARoEAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAqAAUAB9ogFMch6BCaRCi6ggAKzAwnZIAYYAAAAAAbQBzAHQAZQBhAG0AcwA6AHMAeQBzAHQAZQBtAC0AaQBuAGkAdABpAGEAdABlAGQAAAAAAFYAAAAaAO++AgBBAHAAcABYAHMAegAyAHcAOABrAHIAMwB2AHEAYQA1AGgAMAB4AGcAeAB5ADcAYgBkAHQAOQA4ADEANgB5AHkAcQBuAHQAbQAAADwAAAA5AAAACQAAoC0AAAAxU1BTVShMn3mfOUuo0OHULeHV8xEAAAAHAAAAAAsAAAD//wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYAAAABAAAAAAAAAAAAgD8BAAAAAAAAAAIAAAAAAAAAPf0tCRBeTPYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAACAP6HO8dNywdwB//////////8BAAAAAAAAAAAAAAAYAG0AcwB0AGUAYQBtAHMAOgBzAHkAcwB0AGUAbQAtAGkAbgBpAHQAaQBhAHQAZQBkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const u8 = (b64) => new Uint8Array(Buffer.from(b64, 'base64'));

test('parseDestList: header v6 + conteo', () => {
  const d = J.parseDestList(u8(DESTLIST));
  assert.equal(d.version, 6);
  assert.equal(d.nEntries, 6);
  assert.equal(d.nPinned, 6);
  assert.equal(d.entries.length, 6);
});

test('parseDestList: entry-ids, orden MRU, hostname, pin, path', () => {
  const d = J.parseDestList(u8(DESTLIST));
  assert.deepEqual(d.entries.map(e => e.entryId), [1, 2, 6, 5, 4, 3]);
  assert.ok(d.entries.every(e => e.hostname === 'lataml-023695'));
  assert.ok(d.entries.every(e => e.pinned === true));
  assert.deepEqual(d.entries.map(e => e.stream), ['1', '2', '6', '5', '4', '3']);
  assert.match(d.entries[0].path, /^knownfolder:\{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5\}$/);
  assert.match(d.entries[0].lastAccess, /^2026-/);
});

test('analyze automatic: reúsa CFB + DestList (muestra real)', () => {
  const a = J.analyze(u8(E2E), { cfb, lnk });
  assert.equal(a.kind, 'automatic');
  assert.equal(a.cfbVersion, 6);
  assert.equal(a.nEntries, 1);
  assert.equal(a.rows[0].entryId, 1);
  assert.equal(a.rows[0].stream, '1');
  assert.match(a.rows[0].lastAccess, /^2026-/);
  assert.equal(a.orphans.length, 0);
});

test('analyzeCustom: talla LNKs por firma', () => {
  const CLSID = [0x01,0x14,0x02,0x00,0x00,0x00,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46];
  const oneLnk = () => { const b = new Uint8Array(0x4C); b[0]=0x4C; for (let i=0;i<16;i++) b[4+i]=CLSID[i]; return b; };
  const buf = new Uint8Array(0x4C*2 + 8);
  buf.set(oneLnk(), 0); buf.set(oneLnk(), 0x4C + 8);
  const c = J.analyze(buf, { cfb, lnk });
  assert.equal(c.kind, 'custom');
  assert.equal(c.count, 2);
});

test('appName: AppIDs conocidos vs desconocidos', () => {
  assert.equal(J.appName('16f2f0042ddbe0e8'), 'Windows Terminal');
  assert.equal(J.appName('f01b4d95cf55d32a'), 'Windows Explorer');
  assert.equal(J.appName('deadbeefdeadbeef'), null);
});

test('filetime: FILETIME → ISO', () => {
  assert.equal(J.filetime(0, 0), '');
  assert.match(J.filetime(0xd53e8000, 0x019db1de), /^\d{4}-/);
});
