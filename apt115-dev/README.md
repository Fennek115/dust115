# apt115-dev — tooling de desarrollo de APT115

Vive **fuera de `static/`**: Hugo no lo sirve ni lo deploya. Acá van el código
fuente ESM (`src/`), la red de seguridad de tests, el build con esbuild y el
type-check JSDoc. No agrega ninguna dependencia de runtime al tool: APT115
sigue siendo 100% client-side y offline.

Documentos hermanos:
- **`ARCHITECTURE.md`** — mapa del sistema: framework LAB/triage, pipeline de build, qué es lazy y por qué.
- **`CONTRIBUTING.md`** — recetas de cambio: workflow del bundle, cómo agregar un analyzer/tool/test.
- **`../static/apt115/README.md`** — README de usuario (qué hace la app).

## Workflow esencial (lo único que NO se puede saltear)

```bash
cd apt115-dev
npm run build       # regenera static/apt115/apt115.bundle.js (DEPLOY)
npm test            # node --test
npm run typecheck   # tsc --checkJs sobre src/app/
```

> `index.html` carga UN solo `<script src="apt115.bundle.js">`. Tras **cualquier**
> cambio en `src/`, correr `npm run build` y **commitear el bundle junto con el
> cambio**. No hay archivos sueltos que editar en `static/apt115/`: todo el código
> propio vive en `src/`.

## Tests

Regresión de los parsers del triage + smoke del cheatsheet. **Cero dependencias
de test**: usa el runner nativo `node --test`. Los parsers con núcleo puro se
importan directo del `src/`; el vendor `spark-md5` se requiere desde
`static/apt115/vendor/` (`tests/_load.mjs`).

Las muestras reales son **oportunistas**: un caso se salta (no falla) si el
binario no está en la máquina (`/bin/ls`, DLLs mingw, `/mnt/c/.../notepad.exe`).
Esto mantiene el suite verde en cualquier entorno y a la vez aprovecha binarios
reales cuando existen.

### Cobertura actual (13 suites, 63 tests)

| Suite               | Qué prueba                                                      | Entrada |
|---------------------|-----------------------------------------------------------------|---------|
| `util.test.mjs`     | magic bytes (detectType), entropía, extractStrings              | sintética |
| `pe.test.mjs`       | parser PE: clase, máquina, secciones, imports, imphash          | DLLs mingw, notepad |
| `elf.test.mjs`      | parser ELF: clase, máquina, entry, DT_NEEDED                    | /bin/ls, /bin/bash |
| `yara.test.mjs`     | motor libyara-wasm: compila/matchea, todo-o-nada, `lineNumber`  | EICAR, buffers |
| `pdf.test.mjs`      | pdfid: isPdf, ofuscación `#xx`, struct, /URI + /Launch          | sintética |
| `eml.test.mjs`      | headers/unfolding, parseAddr, b64/QP, URLs, dobles extensiones  | sintética |
| `capa.test.mjs`     | normApi (A/W, Nt/Zw), gatherApis, matching de inyección         | sintética |
| `lnk.test.mjs`      | isLnk (CLSID), FILETIME→fecha                                   | sintética |
| `fuzzy.test.mjs`    | TLSH hashBytes (70 hex / null)                                  | sintética |
| `ioc.test.mjs`      | refang/defang, extracción IP/dominio/URL/hash/CVE/ATT&CK        | sintética |
| `cryptolab.test.mjs`| parseBytes, XOR clave/brute (magic-first), detectMagic          | sintética |
| `urlinsp.test.mjs`  | Levenshtein, registeredDomain, punycode→Unicode, refang         | sintética |
| `app.test.mjs`      | cheatsheet: init en sandbox DOM, handlers inline ↔ window, búsqueda/checklist/favoritos/historial | DOM stub |

`app.test.mjs` empaqueta `src/app/index.js` con esbuild y lo ejecuta en un `vm`
con DOM/localStorage stubeados. Su test más valioso es el **invariante de
handlers inline**: escanea el HTML generado + `index.html` y exige que toda
función referenciada en `onclick=` exista en `window` (caza wiring roto al
refactorizar). No reemplaza la verificación en navegador.

### Pendiente de cobertura

Necesitan fixture binario fabricado en `tests/fixtures/`: `macho`, `vba`/`cfb`,
`steg`, `peid` (tarea aparte del roadmap, no bloquea).

### Cómo agregar un test

Los módulos son ESM: importá directo del `src/` y asertá sobre el núcleo puro.

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pdf } from '../src/triage/pdf.js';

test('...', () => { /* assert sobre pdf.<helper>(…) */ });
```

Gotcha: los módulos con globals opcionales asumen que `window` existe
(`typeof window.TLSH`) → si hace falta, setear `globalThis.window = globalThis`
antes del import. `node --test` corre cada archivo en proceso separado, así que
no hay contaminación de globals entre suites.

## Build (esbuild) — un bundle, posición preservada

```bash
npm run build      # → static/apt115/apt115.bundle.js (DEPLOY) + dist/ (dev sin minificar)
```

El manifiesto de fuentes (orden de carga) vive en `SOURCES` dentro de
`build.mjs`. **35 de 37 fuentes están en ESM** (`CONVERTED` mapea ruta vieja →
módulo en `src/`); cada una se empaqueta como IIFE independiente y se emite **en
su posición**. Solo se concatenan los 2 vendor third-party (`spark-md5`/`tlsh`),
que el build sigue leyendo de `static/apt115/vendor/`.

Detalles y decisiones (por qué esbuild y no ESM nativo, por qué la posición
importa, qué queda lazy) en `ARCHITECTURE.md`.

## Typecheck (JSDoc + tsc, sin migrar a TS)

```bash
npm run typecheck   # tsc -p tsconfig.json (checkJs, noEmit)
```

Cubre `src/app/` (el cheatsheet, partido en módulos en la Etapa 4). Los DOM
helpers tipados viven en `src/app/util.js` (`$`, `$in`, `$$`). El resto de
`src/` no está tipado (se verificó contra oráculos con tests); extender el
include de `tsconfig.json` es trabajo aparte.

## Historial de la migración (Fase 0, cerrada jun 2026)

Patrón **strangler**: se convirtió un archivo a la vez dejando el viejo intacto,
con un test de paridad transitorio (`_parity.test.mjs`, ya borrado) que comparaba
la salida ESM contra el viejo corriendo en sandbox `vm`. Recetas de conversión
por forma de módulo (parser / analyzer / tool / data) en `CONTRIBUTING.md`.

- **Etapas 1–2:** tests de regresión + build híbrido con flip de `index.html`
  (37 `<script>` → 1 bundle), verificado en navegador.
- **Etapa 3:** libs/parsers, framework, los 18 analyzers, todos los tools del
  LAB y los `data/` a ESM (34 módulos).
- **Etapa 4:** `app.js` (cheatsheet, 1200 LOC) partido en 13 módulos en
  `src/app/` por responsabilidad (state/render/búsqueda/favoritos/notas/custom/
  intel/sesión/ui), JSDoc + `tsc --checkJs`, smoke test con DOM stub, y borrado
  de los fuentes viejos de `static/apt115/` + `_parity.test.mjs`.
