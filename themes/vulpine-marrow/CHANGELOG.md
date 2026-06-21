# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] — 2026-06-20

### Added
- **Lightbox** sin dependencias (`js/lightbox.js` + `09-lightbox.css`): click/tap
  en imágenes, SVG o diagramas mermaid abre un overlay a pantalla completa con
  zoom (rueda), *pan* (arrastre), **pinch** táctil de dos dedos, barra de
  controles y atajos de teclado (`+`/`-`/`0`/`Esc`). Delegación de eventos sobre
  `.post-content` para que funcione con SVG renderizados async.
- **Tablas responsive** (`layouts/_default/_markup/render-table.html`): las tablas
  markdown se envuelven en `.table-wrap` con scroll horizontal **dentro de su
  caja** (no empujan el ancho de la página), *scroll shadows* sin JS como pista de
  desplazamiento (sombra **violeta** de la paleta, visible en móvil), y celdas que
  ya no se cortan a mitad de palabra.
- Botón flotante **«subir al inicio»** (`#vm-top`): aparece tras desplazarse,
  scroll suave (respeta `prefers-reduced-motion`), violeta sólido con flecha
  blanca y `env(safe-area-inset-bottom)` para el notch. Vive en el footer y se
  suma al bundle JS (`js/backtotop.js`).

### Changed
- **Tipografía y ancho de lectura** de los posts: columna de lectura unificada y
  anchos manejados por tokens de espaciado; prosa justificada e imágenes/figuras
  centradas para una lectura más pareja (`02-layout.css`, `tokens/spacing.css`,
  `07-shortcodes.css`).

Detalle de cada feature en [`docs/features.md`](docs/features.md).

## [0.1.0] — 2026-06-19

Primera versión: extracción del *skin* Vulpine Marrow del sitio dust115 a un tema
Hugo autónomo.

### Added
- Tema **standalone** derivado de Terminal (panr, MIT): se vendorizaron las
  piezas base necesarias y se cortó la dependencia.
- Modo claro / oscuro con toggle en el header, persistencia en `localStorage` y
  anti-FOUC.
- Tokens del design system (`assets/css/tokens/`) + Fira Code self-hosted.
- Diagramas **mermaid theme-aware** (carga condicional + re-render al cambiar de
  tema).
- **Digital garden**: wikilinks `[[ ]]` y backlinks «Mencionado en».
- Página **Synapsis**: grafo dirigido de los wikilinks (mermaid/dagre) + índice
  cronológico.
- Listado feed de columna única; navegación prev/next consciente de la serie;
  TOC opt-in.
- Shortcodes: `listening`, `ascii`, `commit`, `codice-list`, `callout`,
  `command`, `figure`, `badge`, `tlp`.
- Pipeline de CSS en un bundle ordenado (tokens → base → skin),
  `Concat`+`minify`+`fingerprint`.
- Logo de texto parametrizable vía `params.logo.logoText` (default `dust115`).
- `exampleSite/` con posts de demostración que ejercitan todas las features.
- Capturas en `images/` (`screenshot.png`, `tn.png` y showcase) + footer con
  lema «mortui vivos docent» y enlace al repo.
- Documentación en `docs/` (architecture, configuration, features, shortcodes).
