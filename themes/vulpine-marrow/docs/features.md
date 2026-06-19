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

## Tabla de contenidos

Opt-in con `toc: true` por página (o `Toc` global). `single.html` arma el bloque
con `.TableOfContents` y `TocTitle`. Los headings reciben un ancla `#` al hover.

## Footer

`partials/footer.html` muestra un lema en latín (`mortui vivos docent`) y un
enlace al repo del tema. Es deliberadamente opinado; editá el partial para tu
propio lema/enlace.
