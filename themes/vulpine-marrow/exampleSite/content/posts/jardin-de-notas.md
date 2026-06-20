---
title: "El jardín de notas"
date: 2024-04-08T19:15:00-03:00
tags: ["demo", "garden", "wikilinks"]
summary: "Cómo funcionan los wikilinks, los backlinks y la página Synapsis."
---

Vulpine Marrow trae un pequeño *digital garden*: las notas se enlazan entre sí
con wikilinks y cada nota muestra quién la menciona.

## Wikilinks

Dentro de la prosa se escribe `[[clave]]` o `[[clave|texto visible]]`, donde la
clave es el último segmento de la URL de la nota destino. El tema resuelve el
enlace al renderizar; si no existe una nota con esa clave, el wikilink queda
marcado como roto para que sea fácil de detectar. Por ejemplo, desde aquí se
puede volver a la [[bienvenida]] o saltar a los [[diagramas-y-flujos|diagramas]].

## Backlinks

Al pie de cada nota aparece un bloque «Mencionado en» con las notas que la
enlazan. Como este post menciona tanto la bienvenida como los diagramas, ambas
mostrarán este artículo entre sus backlinks. La relación es automática: no hay
que mantener listas a mano.

{{< callout type="info" >}}
Los wikilinks se procesan sobre el HTML ya renderizado, así que conviven sin
problema con bloques de código, diagramas y otros shortcodes: solo se expanden
los que están en la prosa.
{{< /callout >}}

## Synapsis

La página **Synapsis** reúne todo el jardín en un solo lugar: un grafo dirigido
—generado a partir de estos mismos wikilinks y dibujado con mermaid— más un
índice cronológico de los posts por año. Es una buena forma de ver, de un
vistazo, cómo se conectan las notas del sitio.
