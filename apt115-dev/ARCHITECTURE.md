# APT115 — Arquitectura

Mapa del sistema para quien va a tocar el código. El README de usuario está en
`static/apt115/README.md`; las recetas de cambio en `CONTRIBUTING.md`.

## Restricciones de diseño (no negociables)

1. **100% client-side, offline, cero CDN en runtime.** Todo motor/dato se
   vendoriza en `static/apt115/vendor/` o `data/` y se carga lazy. Nada de
   fetch a internet en ejecución; la fuente (Fira Code) es self-hosted.
2. **Nada sale del navegador.** El triage procesa el archivo localmente; los
   lookups (VirusTotal/MalwareBazaar/urlscan) son opt-in y solo abren un link.
3. **`file://` debe funcionar.** La app se puede abrir como archivo local sin
   servidor. Esto dicta el formato del bundle (IIFE, no `type=module`, que en
   file:// muere por CORS). Única excepción conocida: Capstone usa `import()`
   dinámico y no corre en file:// (sí servido).
4. **Estética terminal-clean**: paleta violeta (`--accent: #9141ac`), Fira
   Code, sobrio. Reusar las clases CSS existentes (`lab-*`).

## Layout

```
static/apt115/            ← lo DEPLOYADO (Hugo lo sirve en /apt115/)
  index.html              ← carga UN <script src="apt115.bundle.js">
  apt115.bundle.js        ← artefacto de build, minificado, SE COMMITEA
  style/… fonts/… tools.css
  vendor/                 ← motores vendorizados: libyara-wasm, capstone (WASM),
                            spark-md5, tlsh + licencias
  data/                   ← datos lazy: packs YARA (4), peid-userdb,
                            gtfobins/lolbas
apt115-dev/               ← desarrollo (FUERA de static/, no se sirve)
  src/                    ← código fuente ESM (única fuente de verdad)
    app/                  ← cheatsheet (state/render/búsqueda/favoritos/…)
    lab/                  ← framework: registry (LAB), capstone-core
    triage/               ← parsers + analyzers del Malware Triage
    tools/                ← tools del LAB (ioc, urlinsp, cryptolab, …)
    data/                 ← datasets del cheatsheet + magic-extra + payloads
  build.mjs               ← esbuild → apt115.bundle.js
  tests/                  ← node --test (cero deps)
  tsconfig.json           ← checkJs sobre src/app/
```

## Runtime: dos frameworks de registro

- **LAB / TOOLS** (`src/lab/registry.js`, global `window.LAB`): cada
  herramienta llama `LAB.registerTool({ id, label, icon, group, render })` al
  cargar. Render perezoso (al click en el sidebar). Helper compartido
  `LAB.copy(text)`.
- **Triage analyzers** (`src/triage/analyzers.js`, global `window.Triage`):
  registro pluggable `Triage.analyzers.register({ id, title, icon,
  applies(ctx), run(ctx) })`. `ctx = { bytes, dv, file, pe, elf, macho }`.
  La orquestación (dropzone, armar `ctx`, correr lo que aplica) está en
  `src/triage/triage.js`. **El orden de los paneles = orden de registro =
  orden de carga**: fileinfo → hashes → entropy → pe → rich → resources →
  elf → macho → strings → capa → vba → lnk → pdf → eml → yara → peid →
  epdisasm → steg.
- **`LAB.capstone`** (`src/lab/capstone-core.js`): única fuente de verdad del
  motor Capstone (carga perezosa, una instancia por sesión). Lo consumen el
  tool `disasm` y el analyzer `epdisasm`; nadie reimporta el WASM por su cuenta.
- **Cheatsheet** (`src/app/`): la app original de comandos. Los módulos
  comparten estado vía `src/app/state.js` (dueño de las claves `cs_*` de
  localStorage) y los handlers de la UI se cuelgan de `window` en
  `src/app/index.js` (el HTML usa `onclick` inline). `showToast` es global a
  propósito: lo consumen registry y triage.

**Los módulos comparten estado por globals de window, no por imports** entre
entries del bundle (dentro de `src/app/` sí hay imports reales: es un solo
entry). Cada módulo convertido se auto-cuelga de window al cargar
(`if (typeof window !== 'undefined') window.Triage.X = X`).

## Build: un bundle, posición preservada

`build.mjs` tiene el manifiesto `SOURCES` (las 37 fuentes en orden de carga) y
el mapa `CONVERTED` (ruta vieja → módulo en `src/`). Para cada fuente, **en su
posición**: si está convertida, esbuild la empaqueta sola (IIFE, importada por
efecto secundario); si no (solo los vendor `spark-md5`/`tlsh`), se concatena su
contenido desde `static/apt115/vendor/`. Salida minificada a
`static/apt115/apt115.bundle.js` (~457 KB) + copia sin minificar en `dist/`.

Por qué así:

- **IIFE y no ESM nativo:** `file://` es modo soportado y los `type=module`
  se rompen ahí (CORS).
- **Posición preservada:** los analyzers/tools se registran en orden de carga;
  mover una fuente de lugar reordenaría los paneles o rompería deps captadas
  al cargar (`const U = Triage.util` en el framework).
- **El bundle se commitea:** GitHub Pages sirve `static/` tal cual; no hay
  paso de build en CI para la app (el workflow de Hugo solo copia).

## Qué queda LAZY (fuera del bundle)

Pesados y opcionales; se cargan recién cuando el usuario los usa:

| Asset | Tamaño | Quién lo carga |
|-------|--------|----------------|
| `vendor/yara/` (libyara-wasm) | ~1.2 MB | analyzer `yara` |
| `data/yara-rules-*.js` (4 packs: Mandiant 169, GCTI 91, ReversingLabs 1240, signature-base 5271) | hasta ~6 MB | selector de packs |
| `vendor/capstone/` (WASM x86/ARM/MIPS) | ~1.8 MB | `LAB.capstone` vía `import()` |
| `data/peid-userdb.js` (4445 firmas) | ~1 MB | analyzer `peid` |
| `data/gtfobins.js` / `lolbas.js` | — | tool `lolref` |

## Memoria (decisiones de jun 2026)

El costo dominante no era el pico durante el análisis sino lo retenido después.
Reglas vigentes:

- **El archivo tiene un solo dueño efímero.** Los analyzers con botones
  perezosos (yara/pdf/epdisasm/steg) guardan `lastCtx` a nivel módulo para sus
  handlers; TODOS implementan **`release()`**, y `triage.js` llama
  `Triage.analyzers.releaseAll()` al cargar un archivo nuevo — ANTES de leerlo,
  para liberar el anterior antes de alocar el siguiente. Un analyzer nuevo con
  estado perezoso DEBE implementar `release()` (ver CONTRIBUTING).
- **El heap WASM de Emscripten solo crece** (nunca devuelve memoria). El motor
  YARA copia el archivo a su heap en cada `run`; tras escanear un archivo
  > `ENGINE_RECYCLE_BYTES` (32 MB, en `src/triage/yara.js`) se suelta la
  instancia (`enginePromise = null`) para que el GC devuelva todo el heap. El
  próximo escaneo re-instancia: el script ya está cargado, init sub-segundo.
- **Los packs YARA no se vuelcan al editor.** Seleccionar un pack lo deja como
  `activePack` (run() lee `window.YARA_PACKS[id].rules` directo); el textarea
  muestra solo un encabezado. Evita duplicar ~6 MB de texto en un nodo DOM.
  Escribir en el editor desactiva el pack.
- **PDF no retiene el decode latin1** del archivo (sería una copia entera como
  string): `streams()` re-decodifica bajo demanda.
- **steg tiene topes**: el nivel de píxel aborta por encima de 40 MP (el RGBA
  son W×H×4 bytes), y los planos de bit se dibujan submuestreados por encima
  de 4 MP (el χ²/stream LSB siguen usando los datos completos).

Pendiente conocido (fuera de alcance por ahora): los pases pesados corren en el
hilo principal (el escaneo YARA con signature-base congela la UI mientras
dura); moverlos a un Web Worker es una fase aparte.

## Notas técnicas que muerden

- **libyara-wasm** soporta módulos `pe/elf/math/hash/dotnet/time/console` (NO
  `magic/cuckoo/macho/dex`). La compilación es **todo-o-nada**: un solo error
  fatal y no corre ninguna regla. Los packs se filtran a vendor-time (detalle
  en `static/apt115/tools/yara/HANDOFF.md`).
- **Authenticode:** `DataDirectory[4]` guarda un OFFSET DE ARCHIVO, no un RVA.
- **Mach-O:** la firma de código va SIEMPRE en big-endian aunque la slice sea
  little-endian; el bit `LC_REQ_DYLD` (0x80000000) se SUMA, no se OR-ea (en JS
  `|` da int32 negativo y los load commands nunca matchean).
- **Capstone** no corre en `file://` (import dinámico); detectado y avisado en
  la UI.
- El detector de tipos (`src/triage/util.js`) usa ~49 firmas curadas con
  refiners + 196 de Apache Tika (`src/data/magic-extra.js`).
