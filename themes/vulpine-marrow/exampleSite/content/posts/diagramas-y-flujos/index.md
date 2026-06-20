---
title: "Diagramas y flujos"
date: 2024-03-19T21:30:00-03:00
tags: ["demo", "mermaid", "diagramas"]
summary: "Diagramas mermaid que se adaptan al tema, una figura con caption y un banner TLP."
---

Vulpine Marrow carga [mermaid](https://mermaid.js.org/) solo en las páginas que
lo necesitan, y elige la paleta según el modo activo: si cambiás entre claro y
oscuro, los diagramas se vuelven a dibujar con los colores correctos. Después de
leer la introducción en [[bienvenida]], este es el mejor lugar para verlo.

## Un flujo de decisión

Un `flowchart` se escribe como un bloque de código con el lenguaje `mermaid`:

```mermaid
flowchart TD
    A[Escribir el post] --> B{¿Lleva diagrama?}
    B -->|Sí| C[Bloque mermaid]
    B -->|No| D[Solo prosa]
    C --> E[Hugo marca la página]
    D --> F[Publicar]
    E --> F[Publicar]
```

## Una secuencia

Los diagramas de secuencia también funcionan, útiles para describir un
intercambio entre partes:

```mermaid
sequenceDiagram
    participant Autor
    participant Hugo
    participant Lector
    Autor->>Hugo: escribe un bloque mermaid
    Hugo->>Lector: entrega el pre.mermaid
    Lector->>Lector: el navegador lo dibuja
```

## Imágenes con caption

El shortcode `figure` resuelve la imagen como recurso del *page bundle* y le
agrega pie y crédito:

{{< figure src="captura.png" alt="Página Synapsis del tema" caption="La página Synapsis: grafo de notas e índice cronológico." credit="Vulpine Marrow" >}}

Para posts de inteligencia o material sensible, el banner TLP deja clara la
clasificación de un vistazo:

{{< tlp amber >}}distribución limitada — material de ejemplo{{< /tlp >}}

Si te interesan el resto de los bloques reutilizables, seguí por la
[[caja-de-herramientas]].
