# APT115 — Cómo hacer cambios

Recetas operativas. El mapa del sistema está en `ARCHITECTURE.md`.

## El ciclo de cambio (siempre el mismo)

1. Editar el código en **`apt115-dev/src/`** (única fuente de verdad — en
   `static/apt115/` no queda código propio editable, solo el bundle, vendor y
   datos lazy).
2. `cd apt115-dev && npm run build` — regenera `static/apt115/apt115.bundle.js`.
3. `npm test` — la suite completa (`node --test`, cero deps).
4. `npm run typecheck` — si tocaste `src/app/`.
5. **Verificar en navegador** (servido con `hugo server` o abriendo
   `static/apt115/index.html` como file://; Capstone solo anda servido).
6. Commitear **el cambio + el bundle juntos**. Un feature = un commit.

> El error clásico: editar `src/` y olvidar el rebuild. El bundle deployado no
> cambia solo; si el diff no incluye `apt115.bundle.js`, el cambio no salió.

## Agregar un analyzer del triage

1. Crear `src/triage/<id>.js` con la forma estándar:

```js
export const miAnalyzer = (function () {
  const Tri = (typeof window !== 'undefined') ? window.Triage : null;
  function helperPuro(bytes) { /* núcleo testeable sin DOM */ }
  if (Tri && Tri.analyzers) {
    Tri.analyzers.register({
      id: 'mianalyzer', title: 'Mi Analyzer', icon: '🔬',
      applies(ctx) { return /* magic bytes / ctx.pe / ctx.elf */; },
      run(ctx) { return '<div>…HTML…</div>'; },   // string o Promise
    });
  }
  return { helperPuro };   // la API testeable en Node
})();
```

2. Sumarlo a `SOURCES` **en la posición de la cadena donde debe aparecer su
   panel** (orden de registro = orden de carga) y a `CONVERTED` en `build.mjs`.
3. Test en `tests/<id>.test.mjs` importando del `src/`, idealmente verificado
   contra un oráculo real (olefile/oletools, readelf, LIEF, pdfid, exiftool…)
   sobre muestras benignas. `node --check` no alcanza: correr el analyzer
   sobre muestras reales y confirmar 0 errores antes de dar por hecho.
4. Rebuild + verificación en navegador con archivos reales.

Un **tool del LAB** es igual pero registra con
`LAB.registerTool({ id, label, icon, group, render })` (guardado por
`if (window.LAB)`) y vive en `src/tools/`.

## Tocar el cheatsheet (`src/app/`)

- El estado persistente (claves `cs_*` de localStorage) vive en
  `src/app/state.js`; las **reasignaciones** de esos bindings deben pasar por
  los helpers de state.js (un import ESM no puede reasignar desde afuera).
- Toda función nueva referenciada por `onclick` inline (en `index.html` o en
  HTML generado) debe colgarse de `window` en `src/app/index.js`. El test
  `app.test.mjs` lo verifica automáticamente (escanea los handlers inline).
- Tipado JSDoc obligatorio acá: `npm run typecheck` debe quedar en 0 errores.
  Para leer `.value` usá los helpers `$in`/`$$` de `src/app/util.js`.

## Agregar un pack YARA

El pipeline de vendorización (filtrar reglas que no compilan en libyara-wasm,
todo-o-nada, mapeo error→regla por `lineNumber`) está documentado en
`static/apt115/tools/yara/HANDOFF.md`. El pack resultante va a
`static/apt115/data/yara-rules-<id>.js` (lazy, NO entra al bundle) + su
licencia en `vendor/`, y se agrega el `<option>` en `src/triage/yara.js`.

## Reglas de oro

- **Nada de CDN ni fetch a internet en runtime.** Vendorizar siempre.
- **`file://` tiene que seguir andando** (salvo Capstone, excepción conocida).
- **No editar `static/apt115/apt115.bundle.js` a mano** (generado) ni el theme
  de Hugo.
- Motor nuevo = vendorizar → cargar lazy → **verificar en Node contra un
  oráculo ANTES de cablear la UI**.
- Git: commits chicos, un feature por commit. El bundle siempre viaja con su
  cambio.
