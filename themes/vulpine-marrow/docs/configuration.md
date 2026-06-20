# Configuración

Parámetros de `hugo.toml` que el tema lee, y la estructura de contenido que
espera. Para el detalle de cada feature, ver [`features.md`](features.md).

## Mínimo

```toml
baseURL = "https://ejemplo.org/"
languageCode = "es"
title = "Mi sitio"
theme = "vulpine-marrow"

[pagination]
  pagerSize = 10
```

## Parámetros (`[params]`)

| Param | Default | Para qué |
|-------|---------|----------|
| `contentTypeName` | `"posts"` | tipo de contenido del feed principal (home, `/posts`, prev/next) |
| `subtitle` | — | bajada bajo el header en la home |
| `autoCover` | `false` | si una página tiene `cover.*` en su bundle, se usa de portada |
| `Toc` | `false` | activa la tabla de contenidos por defecto (override por página con `toc:`) |
| `TocTitle` | `"Table of Contents"` | título del bloque TOC |
| `minuteReadingTime` | `"min de lectura"` | sufijo del tiempo de lectura |
| `ReadOtherPosts` | — | título del bloque prev/next en el blog |
| `newerPosts` / `olderPosts` | `"Newer/Older posts"` | etiquetas de la paginación del listado |
| `missingContentMessage` | `"Page not found..."` | título del 404 |
| `missingBackButtonLabel` | `"Back to home page"` | enlace de vuelta del 404 |
| `dateFormat` | `"2006-01-02"` | formato de fecha (layout de referencia de Go) |
| `oneHeadingSize` | `false` | iguala el tamaño de todos los headings |
| `FullWidthTheme` / `CenterTheme` | `false` | ancho del contenedor (ver nota) |
| `Keywords` | — | meta keywords global |
| `Twitter.site` / `Twitter.creator` | — | Twitter Card |

> El *skin* fija el ancho de lectura en **720px centrado** (`.container`), así que
> `FullWidthTheme`/`CenterTheme` casi no cambian nada visible; se conservan por
> compatibilidad con el `baseof` heredado.

### Logo

El header usa un logo de texto `<logoText>$` (el `$` es un cursor parpadeante
decorativo). El texto sale de `params.logo.logoText` (default `dust115`):

```toml
[params.logo]
  logoText = "mi-sitio"   # se renderiza como  mi-sitio$
```

## Menú

El header renderiza `.Site.Menus.main` en una fila. El ítem con
`identifier = "apt115"` (o cualquiera que apunte a un sitio externo) se marca con
una flecha `↗`; ajustá esa condición en `partials/header.html` si tu enlace
externo tiene otro identifier.

```toml
[[menu.main]]
  identifier = "about"
  name = "about"
  url = "/about"
  weight = 1
# … archive, etc.
```

## Estructura de contenido esperada

- **Blog**: páginas con `Type == "posts"` (por `contentTypeName`). El listado
  feed (home, `/posts`, tags) las muestra como columna única con etiqueta de
  serie, meta, summary y tags.
- **Page bundles**: para portadas, poné `cover.*` (o `cover:` en front matter)
  dentro de la carpeta del post; `autoCover`/`partials/cover.html` lo resuelven.
- **Series**: el front matter `series: ["…"]` se muestra como etiqueta `⟐` y
  además **agrupa la navegación prev/next** (ver `features.md` → paginación).
- **Synapsis**: una página con `layout: "synapsis"` (p. ej.
  `content/synapsis.md`) dispara el layout dedicado.

### Front matter típico de un post

```yaml
---
title: "Título"
date: 2025-01-01T20:00:00-03:00
tags: ["uno", "dos"]
series: ["Mi serie"]        # opcional: etiqueta + agrupa prev/next
summary: "Resumen del listado."
cover: "portada.png"        # opcional (recurso del bundle)
coverCredit: "Autor"        # opcional
toc: true                   # opcional: tabla de contenidos
---
```

## Highlighting de sintaxis

El tema asume Chroma con clases CSS (los estilos están en `base/syntax.css`):

```toml
[markup.highlight]
  noClasses = false
```
