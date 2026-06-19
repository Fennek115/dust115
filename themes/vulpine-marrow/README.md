# Vulpine Marrow — tema Hugo

Tema del archivo digital **Dust115**. Violeta profundo sobre negro, tipografía
**Fira Code**, estética HUD «terminal-clean». Es un tema **autónomo**: deriva del
tema [Terminal](https://github.com/panr/hugo-theme-terminal) de panr (MIT) pero
ya **no depende de él** — las piezas base necesarias están vendorizadas dentro
del tema (ver `LICENSE.md`).

> El sistema de diseño que da nombre al tema («Vulpine Marrow») tiene su fuente
> de verdad en la herramienta **/apt115/** del sitio; este tema es la
> implementación de ese lenguaje visual para el blog.

## Instalación

```toml
# hugo.toml
theme = "vulpine-marrow"
```

Coloca el tema en `themes/vulpine-marrow/`. Requiere Hugo **extended** ≥ 0.128
(usa `resources.Concat`, `minify`, `fingerprint` y `Page.Store`).

## Documentación

- [`docs/architecture.md`](docs/architecture.md) — cómo está construido por
  dentro: origen standalone, herencia de plantillas, pipelines de CSS y JS.
- [`docs/configuration.md`](docs/configuration.md) — parámetros de `hugo.toml`,
  menú y estructura de contenido esperada.
- [`docs/features.md`](docs/features.md) — cómo funciona cada feature (tema
  claro/oscuro, mermaid, garden, Synapsis, paginación por serie).
- [`docs/shortcodes.md`](docs/shortcodes.md) — referencia de los 9 shortcodes.
- [`CHANGELOG.md`](CHANGELOG.md) — historial de versiones.

## Características

- **Modo claro / oscuro** con toggle en el header (`☾`/`☀`). El estado se
  persiste en `localStorage` (`vm-theme`) y se aplica antes del primer paint
  (script anti-FOUC en `extended_head.html`); la clase `.vm-light` en `<html>`
  conmuta toda la paleta vía tokens.
- **Tokens del design system** (`assets/css/tokens/`): colores, tipografía y
  spacing. El skin (`assets/css/skin/`) puentea las variables del tema a los
  tokens `--vm-*`, así el modo claro se propaga solo.
- **Fira Code self-hosted** (`static/vm/fonts/`, 7 subsets woff2, sin CDN).
- **Diagramas mermaid theme-aware**: render hook para ```` ```mermaid ````
  (`_markup/render-codeblock-mermaid.html`); mermaid se carga solo en páginas
  que lo usan y se **re-renderiza al cambiar de tema** con paletas violeta para
  claro y oscuro (`extended_footer.html`).
- **Digital garden**: wikilinks `[[clave]]` / `[[clave|alias]]`
  (`partials/wikilinks.html`, post-procesa el HTML ya renderizado) y
  **backlinks** «Mencionado en» (`partials/backlinks.html`). La clave es el
  último segmento del `RelPermalink`.
- **Synapsis** (`_default/synapsis.html`): página-hub con un grafo dirigido de
  los wikilinks (mermaid/dagre, layout en capas estilo Sugiyama) + índice
  cronológico del blog por año. Úsala con `layout: "synapsis"` en una página.
- **Listado feed** de columna única (`partials/post-card.html`): serie ⟐,
  título, meta, summary y chips de tag — sin covers. Usado por home, `/posts`
  y páginas de tag.
- **Navegación prev/next consciente de la serie**
  (`partials/posts_pagination.html`): el Códice navega por `weight` dentro del
  Códice; el blog por fecha dentro del blog, sin fugas entre ambos.
- **Tabla de contenidos** opt-in por página (`toc: true`).
- **Highlighting de sintaxis** (Chroma, clases) + botón de copia en bloques de
  código (`assets/js/code.js`).

## Shortcodes

`listening`, `ascii`, `commit`, `codice-list`, `callout`, `command`, `figure`,
`badge`, `tlp`. Referencia de uso completa en `docs/shortcodes.md` del sitio.

| Shortcode | Propósito |
|-----------|-----------|
| `listening` | Bloque «escuchando ahora» (track/artist/album) |
| `ascii` | Envuelve arte braille/ASCII con tamaño correcto |
| `commit` | Pie estilo git-commit |
| `codice-list` | Lista capítulos del Códice por rango de `weight` |
| `callout` | Aside resaltado (info/tip/warning/danger) |
| `command` | Bloque de comando copiable |
| `figure` | Imagen con caption + crédito (resuelve page-bundle) |
| `badge` | Etiqueta inline de color por token |
| `tlp` | Banner Traffic Light Protocol (clear/green/amber/red) |

## Estructura

```
themes/vulpine-marrow/
├── theme.toml
├── README.md
├── LICENSE.md                  # MIT propio + atribución a panr/Terminal
├── layouts/
│   ├── _default/               # baseof, single, list, term, terms, synapsis
│   │   └── _markup/            # render hook de mermaid
│   ├── index.html · 404.html
│   ├── codice/list.html        # landing del Códice
│   ├── partials/               # head, footer, header, cover, comments,
│   │                           # post-date, pagination, posts_pagination,
│   │                           # logo, post-card, wikilinks, backlinks,
│   │                           # extended_head, extended_footer
│   └── shortcodes/             # los 9 de arriba
├── assets/
│   ├── css/
│   │   ├── tokens/             # colors, typography, spacing (design system)
│   │   ├── base/               # CSS base vendorizado de Terminal (MIT)
│   │   └── skin/               # overrides Vulpine Marrow (01..08, ordenados)
│   └── js/                     # code.js (copia), menu.js
└── static/
    ├── vm/fonts/               # Fira Code woff2 + licencia OFL
    ├── vm/tokens/fonts.css     # @font-face (ruta relativa ../fonts/)
    └── apple-touch-icon.png
```

### Carga de CSS

`partials/head.html` arma **un solo bundle** concatenando, en orden explícito:
`tokens → base (Terminal) → skin (overrides)`, luego `minify` + `fingerprint`.
Las fuentes se enlazan aparte (`static/vm/tokens/fonts.css`) porque su `url()`
es relativa y así sigue siendo correcta bajo un `baseURL` con subpath.

## Atribución

Deriva del tema **Terminal** de panr (MIT). Ver `LICENSE.md`.
