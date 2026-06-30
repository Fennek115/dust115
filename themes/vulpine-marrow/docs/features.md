# Features

Cómo funciona cada característica distintiva del tema. Para la lista de
parámetros, ver [`configuration.md`](configuration.md).

## Modo claro / oscuro

- **Estado** en `localStorage` bajo la clave `vm-theme` (`"light"` | `"dark"`).
- **Anti-FOUC**: `partials/extended_head.html` corre un script *síncrono* en el
  `<head>` que añade la clase `.vm-light` a `<html>` **antes** del primer paint,
  así no hay parpadeo al recargar en claro.
- **Toggle**: el botón `#vm-theme-toggle` vive en el header; el handler está en
  `extended_footer.html`. Al clickear conmuta `.vm-light`, persiste el estado y
  cambia el ícono `☾`/`☀`.
- **Paleta**: toda la diferencia claro/oscuro sale de tokens. `.vm-light` en
  `<html>` redefine los `--vm-*` (en `assets/css/tokens/colors.css`) y, como el
  resto del CSS referencia esas variables, el tema entero conmuta sin reglas
  duplicadas.

## Diagramas mermaid (theme-aware)

1. **Detección**: el render hook `layouts/_default/_markup/render-codeblock-mermaid.html`
   convierte ` ```mermaid ` en `<pre class="mermaid">` y marca la página con
   `Page.Store.Set "hasMermaid" true`.
2. **Carga condicional**: `extended_footer.html` importa mermaid (ESM, por CDN)
   **solo** en páginas marcadas.
3. **Theme-aware**: define dos paletas de `themeVariables` (violeta sobre
   superficie oscura / sobre bone-white) y elige según `.vm-light`.
4. **Re-render al togglear**: mermaid hornea los colores dentro del SVG al
   renderizar, así que un cambio de tema no basta. El script guarda el código
   fuente de cada diagrama en `data-vm-src` antes del primer render y, al
   togglear, lo restaura y re-ejecuta `mermaid.run()` con la paleta nueva.
5. `securityLevel: 'loose'` está activo para permitir nodos clickeables (lo usa
   Synapsis).

> mermaid se carga por CDN (`cdn.jsdelivr.net`). Para self-hostearlo, cambiá el
> `import` en `extended_footer.html`.

## Digital garden: wikilinks + backlinks

Sintaxis dentro de la prosa:

```
[[clave]]          → enlace con el título de la nota destino
[[clave|alias]]    → enlace con texto propio
```

La **clave** es el último segmento del `RelPermalink` de la nota destino
(p. ej. `/posts/mi-nota/` → `mi-nota`).

- **`partials/wikilinks.html`** post-procesa el **HTML ya renderizado**
  (`.Content`, no `.RawContent`): así los `[[ ]]` que aparecen dentro de
  shortcodes, TOC o mermaid quedan intactos y solo se expanden los de la prosa.
  Itera `.Site.RegularPages` para resolver claves; lo que no matchea queda como
  `span.wikilink--broken` (enlace roto visible).
- **`partials/backlinks.html`** escanea el `.RawContent` del resto de páginas
  buscando la clave de la nota actual y arma el bloque «Mencionado en».

Ambos están cableados en `single.html` y son *opt-in* por contenido (solo
aparecen si hay `[[ ]]`). El alcance es todo el sitio (blog + cualquier sección).

## Synapsis (mapa del jardín)

Layout `layouts/_default/synapsis.html`, activado por `layout: "synapsis"` en
una página. Dos secciones:

1. **Grafo dirigido jerárquico**: Hugo recorre las páginas, extrae los `[[ ]]`
   con `findRE`, resuelve claves (igual que wikilinks) y emite una definición
   `flowchart TD` de mermaid con nodos, aristas dirigidas (cita → citada),
   `click` por nodo y un `classDef hub` para las notas más citadas. mermaid/dagre
   la dibuja en capas (layout Sugiyama). Reusa la carga y el theming de mermaid.
2. **Índice cronológico**: los posts del blog (`Type == "posts"`) agrupados por
   año con `GroupByDate`, sin JS.

## Navegación prev/next consciente de la serie

`partials/posts_pagination.html` reemplaza el prev/next del tema base:

- Páginas de una serie marcada (en el sitio de origen: «Códice del Polvo»)
  navegan por `weight` **dentro de esa serie**.
- El resto del blog navega por **fecha**, excluyendo la serie.

Así el prev/next nunca se fuga de un grupo al otro. La serie objetivo está
hardcodeada en el partial; cambiá el `$series` si usás otro nombre.

## Listado feed

`partials/post-card.html` renderiza cada entrada como **columna única sin
cover**: etiqueta de serie `⟐`, título, meta (fecha · lectura), summary y chips
de tag. Lo usan la home (`index.html`, primeros 6 + «ver archivo completo»),
`/posts` (`list.html`, paginado) y las páginas de tag (`term.html`). La home y
`/posts` **excluyen** la serie del Códice; las páginas de tag muestran todo.

## Búsqueda full-text

Buscador client-side **sin dependencias ni CDN**, en tres piezas:

1. **Índice** (`layouts/index.json`): un output JSON de la home (requiere
   `"JSON"` en `[outputs] home` — ver [`configuration.md`](configuration.md)).
   Emite un array con `title`, `url`, `date`, `section`, `series`, `summary`,
   `tags` y `content` (`.Plain`) de cada página. **Alcance: sólo el blog** —
   filtra `Type == "posts"` y resta la serie del Códice (mismo criterio que el
   listado feed), además de las páginas con `noindex`. Así el índice no carga el
   peso del Códice (que es un libro aparte).
2. **UI** (`layouts/_default/search.html`, activada por `layout: "search"` en una
   página, p. ej. `content/buscar.md` → `/buscar/`): un input y un contenedor de
   resultados. El acceso es un **icono de lupa** en el header
   (`partials/header.html`), junto al toggle de tema, que enlaza a `/buscar/`.
3. **Motor** (`js/search.js`, en el bundle JS del footer; sólo actúa si la página
   tiene `.vm-search`): hace `fetch` del índice **una vez** (carga perezosa al
   enfocar el input o al primer tecleo), normaliza sin diacríticos, tokeniza y
   **rankea con AND** (todos los tokens deben aparecer) ponderando por campo —
   título ×8, tag exacto ×6, summary ×3, cuerpo ×1—. Resalta las coincidencias con
   `<mark>`, arma un *snippet* de contexto cuando el match está sólo en el cuerpo,
   y precarga la query desde `?q=` en la URL. Debounce de 120 ms.

Estilos en `10-portafolio-search.css`. Para cambiar el alcance (incluir otras
secciones, o todo el sitio) se edita el filtro de `layouts/index.json`. El
`content` se **capa a 8000 chars** por entrada (`substr`) para acotar el peso del
índice sin perder la búsqueda en el cuerpo de un post típico; subí ese número si
tus posts son muy largos y querés recall total.

## Portafolio (landing por tag)

`layouts/portafolio/list.html` (sección `portafolio`, activada por
`content/portafolio/_index.md`) reúne los posts etiquetados con el tag
**`proyecto`** bajo una URL propia `/portafolio/`, presentados con el mismo
`post-card.html` del feed y ordenados por fecha descendente. Los posts **no salen
del stream del blog** —el tag sólo los agrupa—, así que sumar/quitar uno es
agregar/sacar el tag. El tag objetivo está hardcodeado en el layout; cambiá el
`intersect (slice "proyecto")` si usás otro nombre.

Como `proyecto` es un marcador **interno** (no un tema del post), se **oculta** de
los chips de tags en `post-card.html` y de la lista de términos en `terms.html`
(ambos filtran `ne . "proyecto"`); la página `/tags/proyecto/` sigue existiendo
pero no se enlaza. Si renombrás el tag, actualizá esos dos filtros también.

## Tabla de contenidos

Opt-in con `toc: true` por página (o `Toc` global). `single.html` arma el bloque
con `.TableOfContents` y `TocTitle`. Los headings reciben un ancla `#` al hover.

## Footer

`partials/footer.html` muestra un lema en latín (`mortui vivos docent`) y un
enlace al repo del tema. Es deliberadamente opinado; editá el partial para tu
propio lema/enlace.

## Layout de lectura del post

Todo el sitio —home, archivo y posts— comparte **un único ancho** (`--vm-home`,
880px por defecto): el header, la prosa, las imágenes y el footer se alinean al
mismo borde. No hay *breakout* (los medios no se ensanchan más que el texto), lo
que evita el desajuste visual entre artículo y figuras.

Dentro del post (`02-layout.css`, scope `.post--single .post-content`):

- **Prosa justificada** en párrafos y listas (`text-align: justify` con
  `text-align-last: left`). **Sin guiones**: el sitio renderiza `lang="en"`, así
  que `hyphens: auto` partiría en inglés sobre texto en español.
- **Imágenes y figuras centradas.** La base de Terminal trae `img{display:block}`
  y `figure{width:fit-content}` sin centrado, así que las imágenes en markdown
  plano quedaban a la izquierda; se les agrega `margin-inline: auto`, y a
  `.vm-figure` (shortcode `figure`) `margin: 24px auto`.

## Tablas (responsive)

Las tablas markdown se envuelven automáticamente en `<div class="table-wrap">`
vía el render hook `layouts/_default/_markup/render-table.html`. El wrapper hace
scroll horizontal, de modo que en pantallas angostas la tabla se desliza **dentro
de su caja** en vez de empujar el ancho de toda la página.

- **Anchos** (`02-layout.css`): la tabla usa `width: 100%` (en desktop llena la
  columna y envuelve el contenido) con `min-width: 34rem` (en móvil no se achica
  más allá de ~544px, así que se desborda → scroll).
- **Sin cortes a mitad de palabra**: la base aplica `word-break: break-word` a
  *todo* (selector universal), que partía «Sofisticació|n». Se desactiva en
  `th, td` (`word-break: normal`), así las celdas rompen sólo entre palabras.
- **Pista de scroll** sin JS: en móvil, cuando la tabla se desborda, el wrapper
  pinta una sombra **violeta** (`rgba(196, 113, 237, .5)`, el `--vm-purple` de la
  paleta) en el borde hacia el que hay más tabla, como señal de que se puede
  deslizar. Usa la técnica de *scroll shadows*: dos "tapas" del color de fondo
  con `background-attachment: local` (se mueven con el contenido) sobre dos
  sombras fijas al borde (`scroll`). Sólo aparecen cuando hay más tabla para
  deslizar; si entra entera (desktop), las tapas las cubren y no se ve degradado.
  El violeta reemplaza al negro original, que casi no se distinguía sobre el
  fondo oscuro.

## Lightbox

`js/lightbox.js` + `09-lightbox.css`. Al hacer click/tap en una imagen, SVG o
diagrama mermaid dentro de un post, se abre un overlay a pantalla completa. Usa
**delegación de eventos** sobre `.post-content`, así que funciona aunque mermaid
renderice su `<svg>` de forma asíncrona. Sin dependencias.

Controles:

- **Rueda del mouse** → zoom alrededor del cursor.
- **Arrastrar** (mouse o un dedo) → *pan*.
- **Pinch con dos dedos** (táctil) → zoom alrededor del punto medio. El stage
  tiene `touch-action: none`, así que el gesto lo calcula el JS rastreando los
  punteros activos.
- **Barra** (esquina) → alejar / restablecer / acercar / cerrar.
- **Teclado** → `+` / `-` zoom, `0` restablecer, `Esc` cerrar.

El caption se toma del `figcaption` de la figura si existe.

## Botón «subir al inicio»

`js/backtotop.js` + estilos en `05-elements.css`. El botón `#vm-top` vive en
`partials/footer.html` (presente en todas las páginas) y forma parte del bundle
JS junto a `menu`, `code` y `lightbox`.

- **Aparición**: oculto al cargar; aparece (`.is-visible`) tras desplazarse más de
  `500px`. El scroll se escucha con `passive` + `requestAnimationFrame` (sin
  *layout thrashing*).
- **Acción**: vuelve arriba con scroll suave; respeta `prefers-reduced-motion`
  (salto instantáneo si el usuario lo pide).
- **Estilo**: cuadrado redondeado, violeta sólido (`--vm-accent`) con flecha
  blanca; al pasar el cursor vira a `--vm-purple` con glow. Posición fija abajo a
  la derecha, respetando el notch con `env(safe-area-inset-bottom)`. Funciona en
  claro y oscuro sin reglas duplicadas (el violeta es el mismo token en ambos).
