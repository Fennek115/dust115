# Shortcodes — Vulpine Marrow

Referencia de todos los shortcodes del sitio: qué hacen, parámetros y ejemplos de uso.
Los archivos viven en `layouts/shortcodes/` y su estilo en `static/style.css`
(salvo los inline antiguos, que llevan estilo en línea). Paleta y reglas: tokens
`--vm-*` y "glow only on intent".

> Sintaxis Hugo: `{{</* nombre */>}}` para shortcodes que NO procesan markdown interno,
> `{{%/* nombre */%}}` para los que sí. Acá todos usan la forma `{{< >}}`.

---

## listening

Bloque "lo que estoy escuchando" con borde de acento. Apertura típica de los capítulos
del Códice.

| Parámetro | Req. | Descripción |
|-----------|------|-------------|
| `track`   | sí   | Nombre del tema |
| `artist`  | sí   | Artista |
| `album`   | no   | Álbum (línea secundaria) |

```text
{{< listening track="Bleed" artist="Meshuggah" album="obZen" >}}
```

---

## ascii

Envuelve arte ASCII / braille en un `<pre>` con el tamaño correcto. El placeholder
`[tu ascii aquí]` se usa como marcador en los capítulos nuevos del Códice.

| Parámetro | Req. | Descripción |
|-----------|------|-------------|
| (interno) | sí   | El arte va entre las etiquetas de apertura y cierre |

```text
{{< ascii >}}
⠀⠀⢀⣴⣶⣶⣦⡀
⠀⢰⣿⠟⠛⠿⣿⣧
{{< /ascii >}}
```

---

## commit

Pie estilo commit de git. Cierra muchos posts/capítulos.

| Parámetro | Req. | Descripción |
|-----------|------|-------------|
| `hash`    | sí   | Hash corto |
| `date`    | sí   | Fecha del commit |
| `message` | no   | Mensaje del commit |

```text
{{< commit hash="a7d9f82" date="2025-02-08 03:47 AM" message="Reflections on eternal recurrence" >}}
```

---

## codice-list

Lista automáticamente los capítulos del Códice cuyo `weight` cae en un rango. Lo usa
`content/codice/_index.md`; el índice no se desincroniza al agregar/quitar capítulos.

| Parámetro | Req. | Descripción |
|-----------|------|-------------|
| `min`     | sí   | Límite inferior del `weight` |
| `max`     | sí   | Límite superior del `weight` |

```text
{{< codice-list min="1000" max="1999" >}}   {{/* Era I */}}
```

Rangos en uso: Era I `1000–1999`, Era II `2000–2999`, Vesper `3000–3049`,
Dust `3050–3139`, epílogos `3140–3999`.

---

## callout

Aviso destacado (reemplaza los `prompt` de Chirpy). Procesa markdown interno. Color por tipo.

| Parámetro | Req. | Valores | Descripción |
|-----------|------|---------|-------------|
| `type`    | no   | `info` (default), `tip`, `warning`, `danger` | Color del borde por token |

```text
{{< callout type="warning" >}}
Esto **desactiva** controles de seguridad. Usar solo en el honeypot.
{{< /callout >}}
```

Colores: info=violeta, tip=verde, warning=naranja, danger=rojo.

---

## command

Bloque de comando copiable (estilo CommandRow del design system). El prompt es decorativo
y no se copia; el botón "copiar" copia solo el comando. Soporta varias líneas. El script de
copia se inyecta una sola vez por página.

| Parámetro | Req. | Descripción |
|-----------|------|-------------|
| `prompt`  | no   | Prompt mostrado a la izquierda (default `$`) |
| (interno) | sí   | El comando va entre las etiquetas |

```text
{{< command >}}nxc smb 10.10.4.0/24 --gen-relay-list relay.txt{{< /command >}}

{{< command prompt="PS>" >}}Get-Process | Where-Object { $_.CPU -gt 100 }{{< /command >}}
```

---

## figure

Imagen con caption y crédito opcional (formaliza `cover` / `coverCredit`). Si `src` coincide
con un recurso del page bundle, lo resuelve; si no, usa la ruta tal cual (útil para `/algo.png`
en `static/`).

| Parámetro | Req. | Descripción |
|-----------|------|-------------|
| `src`     | sí   | Archivo del bundle o ruta estática |
| `alt`     | no   | Texto alternativo (default = `caption`) |
| `caption` | no   | Pie de imagen |
| `credit`  | no   | Crédito (línea tenue bajo el caption) |

```text
{{< figure src="diagrama-c2.png" alt="Arquitectura C2" caption="Flujo de un implant" credit="Vulpine Marrow" >}}
```

> Sobrescribe el `figure` nativo de Hugo. Si necesitás el nativo, renombrá este shortcode.

---

## badge

Etiqueta / insignia inline de color por token (severidad, estado, categoría). Acepta el color
por parámetro o posicional.

| Parámetro | Req. | Valores | Descripción |
|-----------|------|---------|-------------|
| `color` / posicional | no | `accent` (default), `purple`, `green`, `teal`, `red`, `pink`, `orange`, `yellow` | Color del texto y borde |
| (interno) | sí   | | El texto de la etiqueta |

```text
estado {{< badge red >}}CRÍTICO{{< /badge >}} · {{< badge green >}}resuelto{{< /badge >}} · {{< badge color="orange" >}}P1{{< /badge >}}
```

---

## tlp

Banner TLP (Traffic Light Protocol) para posts de intel. Se puede usar solo (banner) o con una
nota interna.

| Parámetro | Req. | Valores | Descripción |
|-----------|------|---------|-------------|
| `level` / posicional | no | `clear` (default), `green`, `amber`, `red` | Nivel TLP |
| (interno) | no   | | Nota opcional a la derecha |

```text
{{< tlp amber >}}distribución limitada — solo el equipo{{< /tlp >}}

{{< tlp red >}}{{< /tlp >}}
```

---

## Notas de mantenimiento

- Estilo de los 4 shortcodes nuevos (`command`/`figure`/`badge`/`tlp`): sección
  "Shortcodes Vulpine Marrow" al final de `static/style.css`.
- Todo el color sale de tokens `--vm-*` (`static/vm/tokens/colors.css`), así que claro/oscuro
  se resuelven solos.
- Al empaquetar el tema (`themes/vulpine-marrow/`), mover estos archivos a
  `themes/vulpine-marrow/layouts/shortcodes/` y el CSS a los parciales del tema.
