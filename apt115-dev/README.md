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

## Build (esbuild) — HÍBRIDO (Etapa 3 en curso)

```bash
node build.mjs     # → dist/apt115.bundle.js (dev) + apt115.bundle.min.js (prod)
```

Toma los `<script src>` de `index.html` (fuente de verdad del orden) y produce un
bundle file://-safe. `dist/` está gitignoreado (prueba de build; el artefacto a deployar
se decide al cablear `index.html`).

El build refleja la migración en curso:
- **Convertidos a ESM** (`util`/`pe`/`elf`/`macho`, en `src/triage/`): esbuild los
  empaqueta por **imports reales** (grafo de deps, tree-shaking) y los re-expone en
  `window.Triage` para los consumidores aún no migrados (back-compat).
- **Resto** (aún global-script en `static/apt115/tools/`): se **concatena** en orden.
  Motivo de la concatenación: el código comparte estado entre `<script>` por el scope
  léxico global (`data/core.js` define `const CORE_DATA=…`; `app.js` hace
  `const D=[...CORE_DATA,…]`). Empaquetar eso por imports los aísla en módulos y rompe el
  contrato (probado: esbuild tree-shakeaba core/mitre/intel). Se concatena hasta que esos
  archivos también exporten/importen explícito.

A medida que se convierte más, los archivos pasan del bloque concatenado al de imports.

Lazy (NO entran al bundle): libyara-wasm, capstone (`import(url)` dinámico), packs YARA,
peid-userdb, gtfobins/lolbas.

## Migración a ESM (Etapa 3)

`src/` es el nuevo source ESM (vive en `apt115-dev/`, no se sirve). Patrón **strangler**:
se convierte un archivo a la vez dejando el viejo intacto (runtime sin riesgo), con
`tests/_parity.test.mjs` garantizando que el ESM nuevo da salida **byte-idéntica** al viejo
(comparación estructural por JSON, porque el viejo corre en otro realm `vm`).

Convertir un parser = cambiar el wrapper `window.Triage.X = (function(){…})()` por
`export const X = (function(){…})()`. Las refs a globals opcionales (`SparkMD5`, `window.TLSH`,
`window.MAGIC_EXTRA`) quedan igual (resuelven en el bundle/navegador). Luego: repuntar su
`*.test.mjs` a `import` del src/, sumar el caso en `_parity.test.mjs`, y agregar la entrada
en `CONVERTED` de `build.mjs`.

**Hechos:** `util`, `pe`, `elf`, `macho` (los core sin deps de otros módulos). `_parity` y
los tests de comportamiento en verde.
**Pendiente:** el resto de parsers/analyzers, los tools del LAB, `app.js` y los `data/`
(estos últimos comparten `const` global → convertir a `export`/`window.` explícito).
`_parity.test.mjs` y los viejos `tools/` se borran al completar la migración + flip.

**Pendiente de tu lado** (el "flip", tras verificar el bundle en navegador): cablear
`index.html` a un `<script>` único, borrar los viejos `tools/` ya migrados, y decidir dónde
vive el artefacto (commitear en `static/apt115/` vs build en CI).
