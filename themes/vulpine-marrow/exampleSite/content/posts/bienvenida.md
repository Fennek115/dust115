---
title: "Bienvenida a Vulpine Marrow"
date: 2024-02-12T20:00:00-03:00
tags: ["demo", "hugo", "tema"]
summary: "Qué muestra este sitio de ejemplo y cómo levantarlo en local."
---

Este sitio existe para mostrar el tema **Vulpine Marrow** en funcionamiento:
paleta violeta sobre negro, tipografía Fira Code, modo claro/oscuro y un puñado
de shortcodes pensados para escritura técnica. Cada post de la lista ejercita una
parte distinta del tema.

## Qué vas a encontrar

La home y el listado del archivo usan un *feed* de columna única: etiqueta de
serie, título, metadatos y resumen. El contenido de un post se renderiza en una
columna de lectura angosta para que el texto respire. Si querés ver diagramas en
acción, pasá por [[diagramas-y-flujos]]; si te interesa cómo se conectan las
notas entre sí, está [[jardin-de-notas|el jardín de notas]].

### Código y comandos

El resaltado de sintaxis viene de Chroma, con clases CSS. Un bloque normal se ve
así, y cualquier mención `en línea` queda con su propio estilo:

```bash
hugo new site mi-sitio
cd mi-sitio
git clone https://github.com/Fennek115/vulpine-marrow themes/vulpine-marrow
echo 'theme = "vulpine-marrow"' >> hugo.toml
```

Cuando lo que se quiere es invitar a copiar una sola orden, el shortcode
`command` agrega un botón de copia y un prompt decorativo:

{{< command >}}hugo server -D{{< /command >}}

## Avisos y etiquetas

Para destacar una nota al margen está el shortcode `callout`, con cuatro tipos
de color:

{{< callout type="tip" >}}
El modo claro/oscuro se recuerda entre visitas: el botón del header guarda tu
preferencia y se aplica antes del primer *paint*, así que no hay parpadeo al
recargar.
{{< /callout >}}

Y para marcar un estado o una severidad en mitad de una frase, las insignias:
este tema está {{< badge green >}}estable{{< /badge >}} y listo para usar.
