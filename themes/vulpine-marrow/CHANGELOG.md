# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] — 2026-06-20

### Added
- Botón flotante **«subir al inicio»** (`#vm-top`): aparece tras desplazarse,
  scroll suave (respeta `prefers-reduced-motion`), violeta sólido con flecha
  blanca y `env(safe-area-inset-bottom)` para el notch. Vive en el footer y se
  suma al bundle JS (`js/backtotop.js`). Ver `docs/features.md`.

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
