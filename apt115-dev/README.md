# apt115-dev — tooling de desarrollo de APT115

Vive **fuera de `static/`**: Hugo no lo sirve ni lo deploya. Acá van la red de
seguridad de tests y (en la Etapa 2) el build con esbuild. No agrega ninguna
dependencia de runtime al tool: APT115 sigue siendo 100% client-side y offline.

## Tests

Regresión de los parsers del triage. Cada parser se carga en un sandbox `vm`
con un `window` falso mínimo (`tests/_load.mjs`) y se corre contra fixtures
sintéticos + muestras-oráculo reales del sistema. **Cero dependencias**: usa el
runner nativo `node --test`.

```bash
cd apt115-dev
node --test            # o: npm test
```

Las muestras reales son **oportunistas**: un caso se salta (no falla) si el
binario no está en la máquina (`/bin/ls`, DLLs mingw, `/mnt/c/.../notepad.exe`).
Esto mantiene el suite verde en cualquier entorno y a la vez aprovecha binarios
reales cuando existen.

### Cobertura actual (12 suites, 56 tests)

| Suite              | Qué prueba                                                      | Entrada | Carga |
|--------------------|-----------------------------------------------------------------|---------|-------|
| `util.test.mjs`    | magic bytes (detectType), entropía, extractStrings              | sintética | sandbox |
| `pe.test.mjs`      | parser PE: clase, máquina, secciones, imports, imphash          | DLLs mingw, notepad | sandbox |
| `elf.test.mjs`     | parser ELF: clase, máquina, entry, DT_NEEDED                    | /bin/ls, /bin/bash | sandbox |
| `yara.test.mjs`    | motor libyara-wasm: compila/matchea, todo-o-nada, `lineNumber`  | EICAR, buffers | require |
| `pdf.test.mjs`     | pdfid: isPdf, ofuscación `#xx`, struct, /URI + /Launch          | sintética | require |
| `eml.test.mjs`     | headers/unfolding, parseAddr, b64/QP, URLs, dobles extensiones  | sintética | require |
| `capa.test.mjs`    | normApi (A/W, Nt/Zw), gatherApis, matching de inyección         | sintética | require |
| `lnk.test.mjs`     | isLnk (CLSID), FILETIME→fecha                                   | sintética | require |
| `fuzzy.test.mjs`   | TLSH hashBytes (70 hex / null)                                  | sintética | sandbox |
| `ioc.test.mjs`     | refang/defang, extracción IP/dominio/URL/hash/CVE/ATT&CK        | sintética | require |
| `cryptolab.test.mjs`| parseBytes, XOR clave/brute (magic-first), detectMagic         | sintética | require |
| `urlinsp.test.mjs` | Levenshtein, registeredDomain, punycode→Unicode, refang        | sintética | require |

### Pendiente de cobertura

- **Necesitan fixture binario fabricado** en `tests/fixtures/`: `macho`, `vba`/`cfb`, `steg`.
- **Necesitan refactor primero (Etapa 3)**: `peid` advierte `module.exports` pero toma
  `Triage.util` y registra el analyzer al cargar (sin guardia `typeof window`) → no se puede
  requerir en Node todavía. Se arregla al pasar a ESM.

### Cómo agregar un test

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadTriage, bytesOf } from './_load.mjs';

const { Triage } = loadTriage('tools/triage/<parser>.js'); // + deps si hace falta
test('...', () => { /* assert sobre Triage.<parser>.parse(bytes) */ });
```

`loadTriage(...rutas)` evalúa archivos (relativos a `static/apt115/`) en un mismo
sandbox, en orden. Para imphash, cargá `vendor/spark-md5.min.js` antes de `pe.js`.

## Build (esbuild) — Etapa 2, esqueleto

```bash
node build.mjs     # → dist/apt115.bundle.js (dev) + apt115.bundle.min.js (prod)
```

Toma los `<script src>` de `index.html` (fuente de verdad del orden) y produce un
bundle file://-safe. `dist/` está gitignoreado (es prueba de build; el artefacto a
deployar se decidirá al cablearlo en `index.html`).

**Hallazgo clave (define la Etapa 3):** el build **concatena** en vez de bundlear por
imports. Motivo: el código comparte estado entre `<script>` vía el scope léxico global
(`data/core.js` define `const CORE_DATA=…`; `app.js` hace `const D=[...CORE_DATA,…]`).
Empaquetar por imports convierte cada archivo en un módulo ESM aislado → esos `const`
dejan de compartirse y `app.js` los ve `undefined` (probado: esbuild dejaba afuera
core/mitre/intel y tree-shakeaba los data/). La concatenación reproduce el comportamiento
actual exacto. **El bundling real por imports llega en la Etapa 3**, cuando cada archivo
exporte/importe explícito.

Lazy (NO entran al bundle, se cargan en runtime): libyara-wasm, capstone, packs YARA,
peid-userdb, gtfobins/lolbas. `capstone-core.js` usa `import(url)` con url dinámica, así
que esbuild no lo empaqueta solo.

**Pendiente de Etapa 2** (tras verificar el bundle sirviéndolo y clickeando el tool):
cablear `index.html` para que cargue el bundle único, y decidir dónde vive el artefacto
(commitearlo en `static/apt115/` vs. construirlo en CI).
