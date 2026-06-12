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

### Cobertura actual

| Suite            | Qué prueba                                                        | Entrada |
|------------------|-------------------------------------------------------------------|---------|
| `util.test.mjs`  | magic bytes (detectType), entropía, extractStrings                | sintética |
| `pe.test.mjs`    | parser PE: clase, máquina, secciones, imports, imphash            | DLLs mingw, notepad |
| `elf.test.mjs`   | parser ELF: clase, máquina, entry, DT_NEEDED                      | /bin/ls, /bin/bash |
| `yara.test.mjs`  | motor libyara-wasm: compila/matchea, todo-o-nada, `lineNumber`    | EICAR, buffers |

### Pendiente (misma mecánica, ir sumando)

macho, vba/cfb, lnk, pdf, eml, capa, peid, steg, fuzzy, ioc, convert,
cryptolab, urlinsp. Los que no tienen muestra nativa (macho, vba) necesitan un
fixture fabricado y commiteado en `tests/fixtures/`.

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
