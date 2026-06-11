# Motor YARA en el Lab de Triage (APT115) — COMPLETO

> **Estado: IMPLEMENTADO** (antes era un handoff de "falta el motor").
> El analyzer `yara` del Malware Triage ya corre reglas YARA reales contra el
> archivo cargado, **100% local** (ni un byte sale del navegador). Este doc pasa
> a ser referencia de mantenimiento.

## Qué motor se usó

- **`libyara-wasm`** (npm `libyara-wasm@1.2.1`): libyara —el motor de YARA de
  VirusTotal— compilado a WASM con Emscripten. Es el mismo motor que usa la
  operación "YARA Rules" de CyberChef. Es **YARA clásico** (no YARA-X): se eligió
  por venir como **single-file** con el `.wasm` embebido en base64 dentro del
  `.js`, lo que lo hace **offline / file:// safe sin fetch de red** (verificado).
  - YARA-X oficial (wasm-pack) y `@litko/yara-x` (NAPI nativo, sólo Node) quedaron
    descartados: el primero exige toolchain Rust; el segundo no corre en browser.

## Archivos

- `vendor/yara/libyara-wasm.js` — motor vendorizado (≈1.2 MB, WASM embebido).
- `vendor/LICENSE-libyara-wasm.txt` — ISC (wrapper) + BSD-3 (libyara/YARA).
- `tools/yara/yara.js` — define `window.Triage.yara.scan(ctx)`, lazy-load del
  motor, UI de editor de reglas + render de coincidencias. Reglas de ejemplo
  inline en `DEFAULT_RULES`.
- `tools/tools.css` — sección `/* Motor YARA */` (editor `.yr-editor`, tabla
  `.yr-matches`, etc.).
- `index.html` — `<script src="tools/yara/yara.js">` antes de `triage.js`.

## Cómo funciona (contrato)

- El analyzer `yara` (en `tools/triage/analyzers.js`) detecta en runtime
  `window.Triage.yara.scan` y delega en él. `scan(ctx)` devuelve una **UI**
  (editor con reglas de ejemplo + botón Escanear); **no** auto-escanea, así
  cargar un archivo no baja el motor.
- El motor se carga **perezosamente** al primer "Escanear" (`ensureEngine()`,
  promesa cacheada; reintenta si falla).
- API del motor: `engine.run(uint8array, reglasString)` → objeto `YaraCC` con
  `compileErrors` (vector: `{message, lineNumber}` — mezcla errores y
  advertencias, sin nivel), `matchedRules` (vector: `{ruleName, metadata,
  resolvedMatches}`), `consoleLogs`. Cada match: `{location, matchLength,
  stringIdentifier, data, dataLength}`.
- **Importante**: se pasa `ctx.bytes` (Uint8Array), NO un string. Embind copia
  los bytes crudos; un string los corrompería por encoding UTF-8. El preview
  hex/ASCII se reconstruye desde `ctx.bytes` (el `data` del match viene como
  string y se rompe con bytes binarios).

## Verificación hecha

- Instancia y escanea en entorno que simula browser **sin red** (XHR forzado a
  fallar) → OK, offline confirmado.
- Las 5 reglas de ejemplo compilan sin errores y matchean un buffer sintético.
- Regla `mz` contra bytes `4D 5A …` matchea en offset 0; buffer sin MZ → 0.
- Pendiente sólo: prueba manual en el sitio desplegado (jsdom no corre WASM
  cómodo, pero el camino de browser ya se simuló en Node con `vm`).

## Para mantener / extender

- Cambiar reglas de ejemplo: editar `DEFAULT_RULES` en `tools/yara/yara.js`.
  Este build **sí incluye el módulo `pe`** (verificado: `all-yara.yar` de Mandiant,
  que hace `import "pe"`, compila con 0 errores). `import "math"` no está
  confirmado — si una regla lo usa, probá antes. `uint8/16/32` van siempre.
- Packs de reglas: viven en `data/yara-rules-<id>.js` (setean
  `window.YARA_PACKS[<id>] = {name,count,rules}`), se cargan lazy desde el
  selector del editor. Hay uno: `mandiant` (169 reglas, BSD-2). Para sumar otro,
  agregá el data file + una `<option>` en `scan()` + la entrada en `PACK_SRC`.
- Subir el motor de versión: `npm pack libyara-wasm`, copiar `dist/libyara-wasm.js`
  a `vendor/yara/`. Confirmar que sigue siendo single-file (base64 `AGFzbQ`…).
