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

## Build (esbuild) — HÍBRIDO, PRESERVANDO POSICIÓN (Etapa 3 en curso)

```bash
node build.mjs     # → static/apt115/apt115.bundle.js (DEPLOY) + dist/ (dev)
```

> **WORKFLOW:** `index.html` ya carga UN solo `<script src="apt115.bundle.js">`. Tras
> **cualquier** cambio de fuente (`src/` o `tools/` o `data/`), hay que correr
> `node build.mjs` para regenerar `static/apt115/apt115.bundle.js` y **commitear el
> bundle** junto con el cambio. Editar un `tools/*.js` suelto ya no surte efecto sin rebuild.

El manifiesto de fuentes (orden de carga) vive en `SOURCES` dentro de `build.mjs` (no en
index.html). Cada fuente se emite **en su posición**:
- **Convertida a ESM** (en `src/`): esbuild la empaqueta sola (IIFE) y la inserta acá; cuelga
  su API de `window.Triage` para los consumidores aún no migrados (back-compat).
- **No convertida**: se concatena su contenido viejo acá. Motivo: comparten estado por el
  scope léxico global (`data/core.js` define `const CORE_DATA`; `app.js` hace
  `const D=[...CORE_DATA]`), que el bundling por imports rompería (probado: tree-shakeaba
  core/mitre/intel). Se concatenan hasta exportar explícito.

**Por qué preservar la posición:** los analyzers/tools se registran en orden de carga
(`Triage.analyzers.register` / `LAB.registerTool`). Insertar cada módulo en su posición
permite convertir CUALQUIER archivo de a uno sin reordenar la cadena.

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

**Hechos:** `util`, `pe`, `elf`, `macho`, `fuzzy` (parsers/libs order-independent). `_parity`
y los tests de comportamiento en verde. El **flip ya pasó** (index.html carga el bundle;
verificado en navegador con `.exe`/ELF reales).

**Pendiente:** los analyzers (`pdf`/`eml`/`capa`/`lnk`/`vba`/`peid`/…) y tools del LAB
(`ioc`/`convert`/…) que se **auto-registran** — ahora convertibles de a uno gracias al build
position-preserving, pero conviene convertir antes el framework (`analyzers.js`/`registry.js`).
`cfb.js` necesita reestructura (usa `api` interno + asignación condicional, no el wrapper
estándar). `app.js` y los `data/` comparten `const` global → pasar a `export`/`window.`
explícito. `_parity.test.mjs` y los viejos `tools/` ya migrados se borran al completar todo.
