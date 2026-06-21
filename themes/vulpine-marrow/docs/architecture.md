# Arquitectura

Cómo está construido el tema por dentro. Para *usarlo* mirá
[`configuration.md`](configuration.md) y [`features.md`](features.md).

## Origen: standalone, derivado de Terminal

Vulpine Marrow nació como una capa de *skin* sobre el tema
[Terminal](https://github.com/panr/hugo-theme-terminal) de panr, pero terminó
**autónomo**: las piezas base que aún se usaban se vendorizaron dentro del tema
y se cortó la dependencia. No hace falta tener Terminal instalado.

Qué se heredó de Terminal (MIT, ver [`../LICENSE.md`](../LICENSE.md)):

| Pieza | Archivo | Rol |
|-------|---------|-----|
| Esqueleto HTML | `layouts/_default/baseof.html` | `<html>`, contenedor, bloques `main`/`footer` |
| Cabecera `<head>` | `layouts/partials/head.html` | meta + OG + carga de CSS (reescrito) |
| Pie | `layouts/partials/footer.html` | footer + bundle JS (reescrito: lema + repo) |
| Cover, comentarios, fecha, paginación | `partials/{cover,comments,post-date,pagination}.html` | utilidades sin cambios |
| Listado de taxonomías | `_default/terms.html` | índice de `/tags/` |
| CSS base | `assets/css/base/*.css` | reset, tipografía, code, syntax, etc. |
| JS | `assets/js/{code,menu}.js` | botón de copia en bloques + menú móvil |

Todo lo demás (single, list, term, index, 404, synapsis, codice, los partials
del garden, el header, los shortcodes y el *skin* CSS) es propio.

## Herencia de plantillas

`baseof.html` define el armazón y delega en bloques:

```
baseof.html
├── <head> → partial "head.html" → partial "extended_head.html"
├── partial "header.html" → partial "logo.html"
├── block "main"  ← lo definen single/list/term/index/synapsis/404/codice/list
└── block "footer" → partial "footer.html" → partial "extended_footer.html"
```

- **`head.html`** arma el CSS (ver abajo) y mete metadatos OG/Twitter/RSS.
- **`extended_head.html`** inyecta el script anti-FOUC del modo claro (corre
  *antes* del primer paint) y un `<meta>` de ambientación del sitio.
- **`extended_footer.html`** cablea el toggle de tema y, si la página tiene
  diagramas, carga y re-renderiza mermaid.

## Pipeline de CSS

`head.html` produce **un solo bundle**, concatenando en orden explícito y luego
`minify` + `fingerprint`:

```
tokens/{colors,typography,spacing}.css   ← design system (define --vm-*)
        │
base/{buttons,code,footer,gist,header,   ← Terminal, orden alfabético original
      main,menu,pagination,post,syntax,
      terminal,terms}.css
        │
skin/{01-bridge … 08-synapsis}.css       ← overrides Vulpine Marrow (ganan)
        ↓
/css/vm-bundle.<hash>.css                 ← un request, cacheable
```

El **orden importa**: los tokens definen las variables, la base de Terminal
pinta el chasis y el *skin* lo sobreescribe al final (como hacía el viejo
`static/style.css`). El bridge (`skin/01-bridge.css`) mapea las variables de
Terminal (`--background`, `--accent`, …) a los tokens `--vm-*`, así el modo
claro y la paleta se propagan solos.

### Las fuentes van aparte (y por qué)

`static/vm/tokens/fonts.css` (los `@font-face` de Fira Code) **no** entra al
bundle: se enlaza directo con `<link>`. Su `url()` apunta a `../fonts/` —
**relativo**— y así sigue resolviendo bien aunque el sitio esté servido bajo un
subpath del `baseURL` (p. ej. `…/dust115/`). Si entrara al bundle fingerprinted
(servido desde `/css/…`), esa ruta relativa se rompería. Las fuentes son los
únicos archivos con `url()`, por eso son la única excepción al bundle.

### El *skin* está partido en 9

`skin/01..09.css` son cortes contiguos del antiguo `static/style.css` (más el
lightbox, agregado después). El número fija el orden de carga (se concatena en
secuencia). Reparto:

| Archivo | Contenido |
|---------|-----------|
| `01-bridge.css` | bridge de variables, body/fuente, links, tags, botones, code, header/footer, paginación, posts base |
| `02-layout.css` | ancho único del sitio (`--vm-home`), home curada, listado feed, vista de post (prosa justificada, imágenes/figuras centradas, tablas responsive) |
| `03-garden.css` | wikilinks + backlinks |
| `04-codice.css` | índice del Códice |
| `05-elements.css` | blockquotes, hr, estilo base de tablas, scrollbar, selección, callouts, TOC, mermaid |
| `06-header.css` | header de una fila, logo `dust115$`, botón de tema, menú |
| `07-shortcodes.css` | command / figure (centrada) / badge / tlp |
| `08-synapsis.css` | página Synapsis |
| `09-lightbox.css` | lightbox de imágenes/SVG/mermaid (overlay, barra, sombras) |

## Pipeline de JS

`footer.html` concatena `js/menu.js` + `js/code.js` + `js/lightbox.js` (vía
`js.Build`) en un `bundle.js` minificado **y con `fingerprint`** (el hash en el
nombre invalida la caché del navegador cuando cambia el JS). `code.js` agrega el
botón de copia a los bloques de código; `lightbox.js` da el visor de imágenes
(ver *Features*); `menu.js` es el menú móvil de Terminal (inerte si no hay
`.menu`, se conserva por compatibilidad). El resto del JS (toggle de tema,
mermaid) lo maneja `extended_footer.html` inline.

### Render hooks

`layouts/_default/_markup/` contiene los render hooks de markdown:

- `render-codeblock-mermaid.html` — detecta los bloques ```` ```mermaid ````.
- `render-table.html` — envuelve cada tabla en `<div class="table-wrap">` para
  el scroll horizontal responsive (ver *Features → Tablas*).

## Requisitos

- **Hugo extended ≥ 0.128** — usa `resources.Concat`, `minify`, `fingerprint`,
  `js.Build` y `Page.Store`.
- Sin Node ni PostCSS: todo el procesamiento de assets es nativo de Hugo.
